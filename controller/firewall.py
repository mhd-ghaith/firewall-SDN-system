from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import hub
from webob import Response
from datetime import datetime
import json
import sqlite3
import os

FIREWALL_INSTANCE_NAME = 'firewall_api'
PROTO_MAP     = {"tcp": 6, "udp": 17, "icmp": 1}
PROTO_MAP_REV = {6: "tcp", 17: "udp", 1: "icmp"}
DB_PATH       = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'firewall.db')
MAX_LOGS      = 10000
STATS_INTERVAL = 5  # seconds between flow stats requests


# ── Database helpers ──
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    c    = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id         INTEGER  PRIMARY KEY AUTOINCREMENT,
            src        TEXT     NOT NULL DEFAULT '',
            dst        TEXT     NOT NULL DEFAULT '',
            proto      TEXT     NOT NULL DEFAULT '',
            sport      INTEGER,
            dport      INTEGER,
            action     TEXT     NOT NULL DEFAULT 'block',
            priority   INTEGER  NOT NULL DEFAULT 100,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id        INTEGER  PRIMARY KEY AUTOINCREMENT,
            rule_id   INTEGER  REFERENCES rules(id) ON DELETE SET NULL,
            src_ip    TEXT     NOT NULL DEFAULT '',
            dst_ip    TEXT     NOT NULL DEFAULT '',
            protocol  TEXT     NOT NULL DEFAULT '',
            src_port  INTEGER,
            dst_port  INTEGER,
            action    TEXT     NOT NULL DEFAULT '',
            timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Track packet counts per rule to detect new blocked packets
    c.execute('''
        CREATE TABLE IF NOT EXISTS rule_stats (
            rule_id       INTEGER PRIMARY KEY REFERENCES rules(id) ON DELETE CASCADE,
            packet_count  INTEGER NOT NULL DEFAULT 0,
            last_updated  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def db_load_rules():
    conn = get_db()
    rows = conn.execute(
        'SELECT id, src, dst, proto, sport, dport, action, priority FROM rules ORDER BY priority DESC, id'
    ).fetchall()
    conn.close()
    return [{
        'id': r['id'], 'src': r['src'], 'dst': r['dst'],
        'proto': r['proto'], 'sport': r['sport'], 'dport': r['dport'],
        'action': r['action'], 'priority': r['priority']
    } for r in rows]


def db_insert_rule(rule):
    conn   = get_db()
    cursor = conn.execute(
        'INSERT INTO rules (src, dst, proto, sport, dport, action, priority) VALUES (?,?,?,?,?,?,?)',
        (rule.get('src',''), rule.get('dst',''), rule.get('proto',''),
         rule.get('sport') or None, rule.get('dport') or None,
         rule.get('action','block'),
         rule.get('priority', 200 if rule.get('action')=='block' else 100))
    )
    rule_id = cursor.lastrowid
    # Initialize stats tracking for this rule
    conn.execute('INSERT OR IGNORE INTO rule_stats (rule_id, packet_count) VALUES (?, 0)', (rule_id,))
    conn.commit()
    conn.close()
    return rule_id


def db_delete_rule(rule):
    conn = get_db()
    conn.execute('DELETE FROM rules WHERE src=? AND dst=? AND proto=?',
                 (rule.get('src',''), rule.get('dst',''), rule.get('proto','')))
    conn.commit()
    conn.close()


def db_update_rule(old, new):
    conn = get_db()
    conn.execute(
        'UPDATE rules SET src=?,dst=?,proto=?,sport=?,dport=?,action=?,priority=? WHERE src=? AND dst=? AND proto=?',
        (new.get('src',''), new.get('dst',''), new.get('proto',''),
         new.get('sport') or None, new.get('dport') or None,
         new.get('action','block'),
         new.get('priority', 200 if new.get('action')=='block' else 100),
         old.get('src',''), old.get('dst',''), old.get('proto',''))
    )
    conn.commit()
    conn.close()


def db_insert_log(rule_id, src_ip, dst_ip, protocol, src_port, dst_port, action):
    conn = get_db()
    conn.execute(
        'INSERT INTO logs (rule_id, src_ip, dst_ip, protocol, src_port, dst_port, action) VALUES (?,?,?,?,?,?,?)',
        (rule_id, src_ip or '', dst_ip or '', protocol or '',
         src_port or None, dst_port or None, action or '')
    )
    conn.commit()
    conn.close()
    db_cleanup_logs()


def db_cleanup_logs():
    conn  = get_db()
    count = conn.execute('SELECT COUNT(*) FROM logs').fetchone()[0]
    if count > MAX_LOGS:
        conn.execute('''DELETE FROM logs WHERE id NOT IN
            (SELECT id FROM logs ORDER BY id DESC LIMIT ?)''', (MAX_LOGS,))
        conn.commit()
    conn.close()


def db_get_rule_stat(rule_id):
    conn  = get_db()
    row   = conn.execute('SELECT packet_count FROM rule_stats WHERE rule_id=?', (rule_id,)).fetchone()
    conn.close()
    return row['packet_count'] if row else 0


def db_update_rule_stat(rule_id, packet_count):
    conn = get_db()
    conn.execute('''INSERT INTO rule_stats (rule_id, packet_count, last_updated)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(rule_id) DO UPDATE SET
                    packet_count=excluded.packet_count,
                    last_updated=excluded.last_updated''',
                 (rule_id, packet_count))
    conn.commit()
    conn.close()


def _log_event(action):
    return {
        'block':         'Traffic Blocked',
        'allow':         'Traffic Allowed',
        'rule_added':    'Rule Added',
        'rule_deleted':  'Rule Deleted',
        'rule_modified': 'Rule Modified',
    }.get(action, action.replace('_',' ').title())


def _log_details(row):
    action = row['action']
    parts  = []
    if row['src_ip']:   parts.append('src={}'.format(row['src_ip']))
    if row['dst_ip']:   parts.append('dst={}'.format(row['dst_ip']))
    if row['protocol']: parts.append('proto={}'.format(row['protocol']))
    if row['src_port']: parts.append('sport={}'.format(row['src_port']))
    if row['dst_port']: parts.append('dport={}'.format(row['dst_port']))
    body = ' '.join(parts)
    if action == 'block':
        return 'Packet dropped — {}'.format(body)
    elif action in ('rule_added', 'rule_deleted', 'rule_modified'):
        return '{} — {}'.format(_log_event(action), body)
    return body


def db_load_logs(limit=500):
    conn = get_db()
    rows = conn.execute(
        '''SELECT id, rule_id, src_ip, dst_ip, protocol, src_port, dst_port, action,
                  strftime('%H:%M:%S', timestamp) as time, timestamp
           FROM logs ORDER BY id DESC LIMIT ?''', (limit,)
    ).fetchall()
    conn.close()
    return [{
        'id': r['id'], 'rule_id': r['rule_id'],
        'src_ip': r['src_ip'], 'dst_ip': r['dst_ip'],
        'protocol': r['protocol'], 'src_port': r['src_port'],
        'dst_port': r['dst_port'], 'action': r['action'],
        'time': r['time'], 'timestamp': r['timestamp'],
        'event':   _log_event(r['action']),
        'details': _log_details(r)
    } for r in reversed(rows)]


def db_clear_logs():
    conn = get_db()
    conn.execute('DELETE FROM logs')
    conn.execute('UPDATE rule_stats SET packet_count=0')
    conn.commit()
    conn.close()


# ── Firewall App ──
class Firewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS    = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(Firewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths   = {}
        init_db()
        self.rules = db_load_rules()
        self.logger.info("Database initialized at: %s", DB_PATH)
        self.logger.info("Loaded %d rules from database", len(self.rules))
        wsgi = kwargs['wsgi']
        wsgi.register(FirewallController, {FIREWALL_INSTANCE_NAME: self})
        self.logger.info("Firewall initialized and REST API ready")
        # Start background stats polling thread
        self.monitor_thread = hub.spawn(self._monitor_loop)

    def _monitor_loop(self):
        """Periodically request flow stats from all switches."""
        while True:
            hub.sleep(STATS_INTERVAL)
            for dp in list(self.datapaths.values()):
                self._request_flow_stats(dp)

    def _request_flow_stats(self, datapath):
        """Send OFPFlowStatsRequest to a switch."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        req     = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """
        Called when a switch replies with flow stats.
        Compare packet_count of each drop flow against our stored count.
        If it increased → new packets were blocked → log them.
        """
        body     = ev.msg.body
        datapath = ev.msg.datapath

        for stat in body:
            # Only care about drop flows (no actions = instructions=[])
            if stat.instructions:
                continue
            if stat.priority == 0:
                continue

            match = stat.match
            # Try to find which rule this flow corresponds to
            rule = self._match_rule_to_stat(match)
            if not rule:
                continue

            rule_id       = rule.get('id')
            new_count     = stat.packet_count
            stored_count  = db_get_rule_stat(rule_id)

            if new_count > stored_count:
                # New packets were blocked since last check
                delta = new_count - stored_count
                self.logger.info(
                    "[STATS] Rule ID=%d blocked %d new packet(s) on switch %s",
                    rule_id, delta, datapath.id
                )
                # Log one entry per new blocked batch
                db_insert_log(
                    rule_id,
                    rule.get('src', ''),
                    rule.get('dst', ''),
                    rule.get('proto', ''),
                    rule.get('sport'),
                    rule.get('dport'),
                    'block'
                )
                db_update_rule_stat(rule_id, new_count)

    def _match_rule_to_stat(self, match):
        """Find which firewall rule corresponds to an OpenFlow match."""
        for rule in self.rules:
            if rule['action'] != 'block':
                continue
            fields = self.build_match_fields(rule)
            matched = True
            for key, val in fields.items():
                try:
                    if match[key] != val:
                        matched = False
                        break
                except Exception:
                    matched = False
                    break
            if matched:
                return rule
        return None

    def add_log(self, rule_id, src_ip, dst_ip, protocol, src_port, dst_port, action):
        db_insert_log(rule_id, src_ip, dst_ip, protocol, src_port, dst_port, action)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        match    = parser.OFPMatch()
        actions  = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s connected — re-applying %d rules", datapath.id, len(self.rules))
        for rule in self.rules:
            self._push_rule_to_switch(datapath, rule)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod     = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def add_drop_flow(self, datapath, priority, match):
        parser = datapath.ofproto_parser
        mod    = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            match=match, instructions=[]
        )
        datapath.send_msg(mod)

    def delete_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        mod     = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                    match=match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)

    def build_match_fields(self, rule):
        match_fields = {'eth_type': 0x0800}
        if rule.get('src'):   match_fields['ipv4_src'] = rule['src']
        if rule.get('dst'):   match_fields['ipv4_dst'] = rule['dst']
        if rule.get('proto'):
            proto_num = PROTO_MAP.get(rule['proto'].lower())
            if proto_num:
                match_fields['ip_proto'] = proto_num
                if proto_num == 6:
                    if rule.get('sport'): match_fields['tcp_src'] = int(rule['sport'])
                    if rule.get('dport'): match_fields['tcp_dst'] = int(rule['dport'])
                if proto_num == 17:
                    if rule.get('sport'): match_fields['udp_src'] = int(rule['sport'])
                    if rule.get('dport'): match_fields['udp_dst'] = int(rule['dport'])
        return match_fields

    def _push_rule_to_switch(self, datapath, rule):
        parser       = datapath.ofproto_parser
        match_fields = self.build_match_fields(rule)
        match        = parser.OFPMatch(**match_fields)
        priority     = rule.get('priority', 200 if rule.get('action')=='block' else 100)
        if rule['action'] == 'block':
            self.add_drop_flow(datapath, priority, match)
        else:
            ofproto = datapath.ofproto
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            self.add_flow(datapath, priority, match, actions)

    def apply_rule_to_switches(self, rule, rule_id=None):
        for dp in self.datapaths.values():
            self._push_rule_to_switch(dp, rule)

    def remove_rule_from_switches(self, rule):
        for dp in self.datapaths.values():
            parser       = dp.ofproto_parser
            match_fields = self.build_match_fields(rule)
            match        = parser.OFPMatch(**match_fields)
            self.delete_flow(dp, match)

    def is_blocked(self, ip_pkt, tcp_pkt=None, udp_pkt=None):
        for rule in self.rules:
            if rule['action'] != 'block':
                continue
            if rule.get('src') and rule['src'] != ip_pkt.src:
                continue
            if rule.get('dst') and rule['dst'] != ip_pkt.dst:
                continue
            if rule.get('proto'):
                proto_num = PROTO_MAP.get(rule['proto'].lower())
                if proto_num and proto_num != ip_pkt.proto:
                    continue
            if rule.get('sport') and tcp_pkt:
                if tcp_pkt.src_port != int(rule['sport']): continue
            if rule.get('dport') and tcp_pkt:
                if tcp_pkt.dst_port != int(rule['dport']): continue
            if rule.get('sport') and udp_pkt:
                if udp_pkt.src_port != int(rule['sport']): continue
            if rule.get('dport') and udp_pkt:
                if udp_pkt.dst_port != int(rule['dport']): continue
            return True, rule.get('id')
        return False, None

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        pkt     = packet.Packet(msg.data)
        eth     = pkt.get_protocol(ethernet.ethernet)
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if not eth:
            return

        src = eth.src
        dst = eth.dst
        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id][src] = in_port

        # Check block rules before forwarding
        if ip_pkt:
            blocked, rule_id = self.is_blocked(ip_pkt, tcp_pkt, udp_pkt)
            if blocked:
                # First packet of a blocked flow hits packet_in before drop flow is installed
                proto_name = PROTO_MAP_REV.get(ip_pkt.proto, str(ip_pkt.proto))
                sport = tcp_pkt.src_port if tcp_pkt else (udp_pkt.src_port if udp_pkt else None)
                dport = tcp_pkt.dst_port if tcp_pkt else (udp_pkt.dst_port if udp_pkt else None)
                self.logger.info("[PACKET-IN] Rule ID=%d blocking packet from %s to %s", rule_id, ip_pkt.src, ip_pkt.dst)
                self.add_log(rule_id, ip_pkt.src, ip_pkt.dst, proto_name, sport, dport, 'block')
                # Initialize stat tracking for this rule
                stored = db_get_rule_stat(rule_id)
                db_update_rule_stat(rule_id, stored)
                return

        if dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions, idle_timeout=10, hard_timeout=30)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


# ── REST Controller ──
class FirewallController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(FirewallController, self).__init__(req, link, data, **config)
        self.firewall = data[FIREWALL_INSTANCE_NAME]

    @route('firewall', '/firewall/rules', methods=['GET'])
    def get_rules(self, req, **kwargs):
        return Response(content_type='application/json',
                        body=json.dumps({'rules': db_load_rules()}).encode())

    @route('firewall', '/firewall/rules/add', methods=['POST'])
    def add_rule(self, req, **kwargs):
        data = json.loads(req.body) if req.body else {}
        rule = {
            'src':      data.get('src', ''),
            'dst':      data.get('dst', ''),
            'proto':    data.get('proto', ''),
            'sport':    data.get('sport') or None,
            'dport':    data.get('dport') or None,
            'action':   data.get('action', 'block'),
            'priority': int(data.get('priority', 200 if data.get('action')=='block' else 100))
        }
        rule_id    = db_insert_rule(rule)
        rule['id'] = rule_id
        self.firewall.rules.append(rule)
        self.firewall.apply_rule_to_switches(rule, rule_id)
        self.firewall.add_log(
            rule_id, rule['src'], rule['dst'], rule['proto'],
            rule['sport'], rule['dport'], 'rule_added'
        )
        return Response(content_type='application/json',
                        body=json.dumps({'status': 'ok', 'id': rule_id}).encode())

    @route('firewall', '/firewall/rules/delete', methods=['POST'])
    def delete_rule(self, req, **kwargs):
        data = json.loads(req.body) if req.body else {}
        rule = {
            'src':    data.get('src', ''),
            'dst':    data.get('dst', ''),
            'proto':  data.get('proto', ''),
            'sport':  data.get('sport') or None,
            'dport':  data.get('dport') or None,
            'action': data.get('action', 'block')
        }
        self.firewall.add_log(
            data.get('id'), rule['src'], rule['dst'], rule['proto'],
            rule['sport'], rule['dport'], 'rule_deleted'
        )
        db_delete_rule(rule)
        self.firewall.rules = [
            r for r in self.firewall.rules
            if not (r['src']==rule['src'] and r['dst']==rule['dst'] and r['proto']==rule['proto'])
        ]
        self.firewall.remove_rule_from_switches(rule)
        return Response(content_type='application/json',
                        body=json.dumps({'status': 'ok'}).encode())

    @route('firewall', '/firewall/rules/modify', methods=['POST'])
    def modify_rule(self, req, **kwargs):
        data = json.loads(req.body) if req.body else {}
        old  = data.get('old', {})
        new  = data.get('new', {})
        new.setdefault('priority', 200 if new.get('action')=='block' else 100)
        db_update_rule(old, new)
        self.firewall.rules = [
            r for r in self.firewall.rules
            if not (r['src']==old.get('src','') and r['dst']==old.get('dst','') and r['proto']==old.get('proto',''))
        ]
        self.firewall.remove_rule_from_switches(old)
        self.firewall.rules.append(new)
        self.firewall.apply_rule_to_switches(new)
        self.firewall.add_log(
            None, new.get('src',''), new.get('dst',''), new.get('proto',''),
            new.get('sport'), new.get('dport'), 'rule_modified'
        )
        return Response(content_type='application/json',
                        body=json.dumps({'status': 'ok'}).encode())

    @route('firewall', '/firewall/logs', methods=['GET'])
    def get_logs(self, req, **kwargs):
        return Response(content_type='application/json',
                        body=json.dumps({'logs': db_load_logs()}).encode())

    @route('firewall', '/firewall/logs/add', methods=['POST'])
    def add_log_route(self, req, **kwargs):
        data = json.loads(req.body) if req.body else {}
        self.firewall.add_log(
            data.get('rule_id'), data.get('src_ip',''), data.get('dst_ip',''),
            data.get('protocol',''), data.get('src_port'), data.get('dst_port'),
            data.get('action','block')
        )
        return Response(content_type='application/json',
                        body=json.dumps({'status': 'ok'}).encode())

    @route('firewall', '/firewall/logs/clear', methods=['POST'])
    def clear_logs(self, req, **kwargs):
        db_clear_logs()
        return Response(content_type='application/json',
                        body=json.dumps({'status': 'ok'}).encode())
