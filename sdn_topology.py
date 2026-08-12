from mininet.net import Containernet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
import docker
import builtins

setLogLevel('info')

def clean_containers():
    client = docker.from_env()
    names = [
        'mn.h_attacker', 'mn.h_web1', 'mn.h_web2',
        'mn.h_app1', 'mn.h_app2', 'mn.h_work1',
        'mn.h_work2', 'mn.h_db'
    ]
    for name in names:
        try:
            c = client.containers.get(name)
            c.remove(force=True)
            print(f"*** Removed container {name}")
        except:
            pass

def run_test(net):
    h_attacker = net.get('h_attacker')
    h_web1     = net.get('h_web1')
    h_web2     = net.get('h_web2')
    h_app1     = net.get('h_app1')
    h_work1    = net.get('h_work1')
    h_db       = net.get('h_db')

    print("\n*** ================================================")
    print("*** Running Firewall Test...")
    print("*** ================================================")

    print("\n[TEST] Attacker → Web Server 1 (HTTP)...")
    result = h_attacker.cmd('curl -s --max-time 3 http://10.0.1.1')
    if 'Web Server' in result:
        print(">>> ACCESS GRANTED -- Attacker reached Web Server 1 (not blocked yet)")
    else:
        print(">>> ACCESS DENIED  -- Attacker blocked from Web Server 1")

    print("\n[TEST] Attacker → Web Server 2 (HTTP)...")
    result = h_attacker.cmd('curl -s --max-time 3 http://10.0.1.2')
    if 'Web Server' in result:
        print(">>> ACCESS GRANTED -- Attacker reached Web Server 2 (not blocked yet)")
    else:
        print(">>> ACCESS DENIED  -- Attacker blocked from Web Server 2")

    print("\n[TEST] Attacker → App Server 1 (Internal Network)...")
    result = h_attacker.cmd('ping -c2 -W2 10.0.2.1')
    if '0 received' in result or 'unreachable' in result:
        print(">>> ACCESS DENIED  -- Attacker blocked from Internal Network (expected)")
    else:
        print(">>> ACCESS GRANTED -- Attacker reached Internal Network (unexpected!)")

    print("\n[TEST] Workstation → Web Server 1 (HTTP)...")
    result = h_work1.cmd('curl -s --max-time 3 http://10.0.1.1')
    if 'Web Server' in result:
        print(">>> ACCESS GRANTED -- Workstation can reach Web Server 1 (expected)")
    else:
        print(">>> ACCESS DENIED  -- Workstation blocked from Web Server 1 (unexpected!)")

    print("\n[TEST] Workstation → App Server 1...")
    result = h_work1.cmd('ping -c2 -W2 10.0.2.1')
    if '0 received' in result or 'unreachable' in result:
        print(">>> ACCESS DENIED  -- Workstation blocked from App Server")
    else:
        print(">>> ACCESS GRANTED -- Workstation can reach App Server (expected)")

    print("\n[TEST] App Server 1 → Database...")
    result = h_app1.cmd('ping -c2 -W2 10.0.2.5')
    if '0 received' in result or 'unreachable' in result:
        print(">>> ACCESS DENIED  -- App Server blocked from Database")
    else:
        print(">>> ACCESS GRANTED -- App Server can reach Database (expected)")

    print("\n[TEST] Attacker → Database (critical asset)...")
    result = h_attacker.cmd('ping -c2 -W2 10.0.2.5')
    if '0 received' in result or 'unreachable' in result:
        print(">>> ACCESS DENIED  -- Attacker blocked from Database (expected)")
    else:
        print(">>> ACCESS GRANTED -- Attacker reached Database (critical risk!)")

    print("\n*** ================================================")
    print("*** Test Complete -- Check logs at http://127.0.0.1:5000/logs")
    print("*** ================================================\n")


print("\n*** Cleaning up old containers...")
clean_containers()

net = Containernet(controller=RemoteController, switch=OVSSwitch)

net.addController('c0', controller=RemoteController,
                  ip='127.0.0.1', port=6633)

h_attacker = net.addDocker('h_attacker', ip='10.0.0.100', dimage="iwaseyusuke/mininet")

h_web1  = net.addDocker('h_web1',  ip='10.0.1.1', dimage="iwaseyusuke/mininet")
h_web2  = net.addDocker('h_web2',  ip='10.0.1.2', dimage="iwaseyusuke/mininet")

h_app1  = net.addDocker('h_app1',  ip='10.0.2.1', dimage="iwaseyusuke/mininet")
h_app2  = net.addDocker('h_app2',  ip='10.0.2.2', dimage="iwaseyusuke/mininet")
h_work1 = net.addDocker('h_work1', ip='10.0.2.3', dimage="iwaseyusuke/mininet")
h_work2 = net.addDocker('h_work2', ip='10.0.2.4', dimage="iwaseyusuke/mininet")
h_db    = net.addDocker('h_db',    ip='10.0.2.5', dimage="iwaseyusuke/mininet")

s1 = net.addSwitch('s1')
s2 = net.addSwitch('s2')
s3 = net.addSwitch('s3')
s4 = net.addSwitch('s4')
s5 = net.addSwitch('s5')

net.addLink(h_attacker, s1)
net.addLink(s1, s2)
net.addLink(s2, h_web1)
net.addLink(s2, h_web2)
net.addLink(s2, s3)
net.addLink(s3, s4)
net.addLink(s4, h_app1)
net.addLink(s4, h_app2)
net.addLink(s4, h_work1)
net.addLink(s4, h_work2)
net.addLink(s4, h_db)
net.addLink(s4, s5)

net.start()

print("\n*** Starting web servers on DMZ hosts...")
h_web1.cmd('cd /tmp && echo "Web Server 1 - DMZ" > index.html && python3 -m http.server 80 &')
h_web2.cmd('cd /tmp && echo "Web Server 2 - DMZ" > index.html && python3 -m http.server 80 &')

print("\n*** ================================================")
print("*** Topology: DMZ + Internal Network")
print("*** ================================================")
print("*** ATTACKER    : h_attacker  (10.0.0.100)")
print("*** DMZ         : h_web1      (10.0.1.1)  -- Web Server 1")
print("***             : h_web2      (10.0.1.2)  -- Web Server 2")
print("*** INTERNAL    : h_app1      (10.0.2.1)  -- App Server 1")
print("***             : h_app2      (10.0.2.2)  -- App Server 2")
print("***             : h_work1     (10.0.2.3)  -- Workstation 1")
print("***             : h_work2     (10.0.2.4)  -- Workstation 2")
print("***             : h_db        (10.0.2.5)  -- Database")
print("*** FIREWALLS   : s1 (External), s3 (Internal Firewall 1), s5 (Internal Firewall 2)")
print("*** SWITCHES    : s2 (DMZ Switch), s4 (Internal Switch)")
print("*** ================================================")

builtins.run_test = run_test
builtins.net = net

CLI(net)
net.stop()
