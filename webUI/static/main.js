let rules = [];
let editingIndex = -1;

// ── Utilities ──
function isValidIP(ip) {
  if (ip === '') return true;
  const regex = /^(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$/;
  return regex.test(ip);
}

function isValidPort(port) {
  if (port === '' || port === null || port === undefined) return true;
  const n = parseInt(port);
  return !isNaN(n) && n >= 1 && n <= 65535;
}

function isValidPriority(p) {
  const n = parseInt(p);
  return !isNaN(n) && n >= 1 && n <= 65535;
}

function protoBadge(p) {
  const m = { tcp: 'badge-tcp', udp: 'badge-udp', icmp: 'badge-icmp' };
  return `<span class="badge ${m[p] || 'badge-info'}">${p || 'any'}</span>`;
}

function actionBadge(a) {
  return a === 'block'
    ? '<span class="badge badge-block">⛔ block</span>'
    : '<span class="badge badge-allow">✅ allow</span>';
}

function portDisplay(port) {
  return port
    ? `<span style="font-family:var(--font-mono);font-size:0.8rem;color:var(--text-primary)">${port}</span>`
    : `<span style="color:var(--text-muted)">—</span>`;
}

function showAlert(msg, type = 'error') {
  const el = document.getElementById('formAlert');
  if (!el) return;
  el.innerHTML = `<div class="alert alert-${type}">${msg}</div>`;
  setTimeout(() => { el.innerHTML = ''; }, 4000);
}

function showModalAlert(msg, type = 'error') {
  const el = document.getElementById('modalAlert');
  if (!el) return;
  el.innerHTML = `<div class="alert alert-${type}">${msg}</div>`;
  setTimeout(() => { el.innerHTML = ''; }, 4000);
}

// ── Render rules table ──
function renderRules() {
  const tbody   = document.getElementById('rulesTable');
  const counter = document.getElementById('rulesCount');
  const topbar  = document.getElementById('ruleCounter');

  if (counter) counter.textContent = `${rules.length} rule${rules.length !== 1 ? 's' : ''}`;
  if (topbar)  topbar.textContent  = `${rules.length} active rule${rules.length !== 1 ? 's' : ''}`;

  if (!rules.length) {
    tbody.innerHTML = `<tr><td colspan="10">
      <div class="empty-state">
        <div class="empty-state-icon">🔒</div>
        <div class="empty-state-text">No rules defined. Add one above to get started.</div>
      </div>
    </td></tr>`;
    return;
  }

  tbody.innerHTML = rules.map((rule, i) => `
    <tr>
      <td class="mono" style="color:var(--text-muted)">${i + 1}</td>
      <td class="mono">${rule.src || '<span style="color:var(--text-muted)">any</span>'}</td>
      <td class="mono">${rule.dst || '<span style="color:var(--text-muted)">any</span>'}</td>
      <td>${protoBadge(rule.proto)}</td>
      <td>${portDisplay(rule.sport)}</td>
      <td>${portDisplay(rule.dport)}</td>
      <td>${actionBadge(rule.action)}</td>
      <td class="mono" style="color:var(--text-muted)">${rule.priority || '—'}</td>
      <td><button class="btn btn-warning btn-sm" onclick="openModal(${i})">✏️ Edit</button></td>
      <td><button class="btn btn-danger btn-sm" onclick="deleteRule(${i})">🗑 Remove</button></td>
    </tr>`).join('');
}

// ── API helper ──
function apiCall(endpoint, payload) {
  return fetch(endpoint, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(payload)
  })
    .then(r => r.json())
    .then(data => {
      if (data.status !== 'ok' && data.status !== 'success') {
        showAlert('Controller error: ' + (data.message || 'unknown'), 'error');
      }
    })
    .catch(() => showAlert('Cannot reach controller. Is Ryu running?', 'error'));
}

// ── Add Rule ──
function addRule() {
  const src      = (document.getElementById('src').value || '').trim();
  const dst      = (document.getElementById('dst').value || '').trim();
  const proto    = document.getElementById('proto').value;
  const action   = document.getElementById('action').value;
  const sport    = (document.getElementById('sport').value || '').trim();
  const dport    = (document.getElementById('dport').value || '').trim();
  const priority = (document.getElementById('priority').value || '').trim();

  if (src === '' && dst === '') {
    showAlert('Enter at least a Source IP or Destination IP.', 'error'); return;
  }
  if (!isValidIP(src)) {
    showAlert('Invalid Source IP address.', 'error'); return;
  }
  if (!isValidIP(dst)) {
    showAlert('Invalid Destination IP address.', 'error'); return;
  }
  if (src !== '' && dst !== '' && src === dst) {
    showAlert('Source and Destination IP cannot be the same.', 'error'); return;
  }
  if (proto === 'icmp' && (sport || dport)) {
    showAlert('Ports are not applicable for ICMP protocol.', 'error'); return;
  }
  if (!isValidPort(sport)) {
    showAlert('Source Port must be between 1 and 65535.', 'error'); return;
  }
  if (!isValidPort(dport)) {
    showAlert('Destination Port must be between 1 and 65535.', 'error'); return;
  }
  if (!isValidPriority(priority)) {
    showAlert('Priority must be a number between 1 and 65535.', 'error'); return;
  }

  const rule = {
    src,
    dst,
    proto,
    sport:    sport    ? parseInt(sport)    : null,
    dport:    dport    ? parseInt(dport)    : null,
    action,
    priority: priority ? parseInt(priority) : (action === 'block' ? 200 : 100)
  };

  rules.push(rule);
  renderRules();
  clearInputs();
  showAlert('Rule added successfully.', 'success');
  apiCall('/api/rules/add', rule);
}

// ── Delete Rule ──
function deleteRule(index) {
  if (!confirm('Remove this rule?')) return;
  const rule = rules[index];
  rules.splice(index, 1);
  renderRules();
  apiCall('/api/rules/delete', rule);
}

// ── Modal: Open ──
function openModal(index) {
  editingIndex = index;
  const rule   = rules[index];

  document.getElementById('editSrc').value      = rule.src    || '';
  document.getElementById('editDst').value      = rule.dst    || '';
  document.getElementById('editProto').value    = rule.proto  || 'tcp';
  document.getElementById('editSport').value    = rule.sport  || '';
  document.getElementById('editDport').value    = rule.dport  || '';
  document.getElementById('editAction').value   = rule.action || 'block';
  document.getElementById('editPriority').value = rule.priority || (rule.action === 'block' ? 200 : 100);

  toggleEditPorts();
  document.getElementById('modalAlert').innerHTML = '';
  document.getElementById('editModal').classList.add('open');
}

// ── Modal: Close ──
function closeModal() {
  document.getElementById('editModal').classList.remove('open');
  editingIndex = -1;
}

// ── Modal: Save ──
function saveEdit() {
  const newSrc      = (document.getElementById('editSrc').value      || '').trim();
  const newDst      = (document.getElementById('editDst').value      || '').trim();
  const newProto    = document.getElementById('editProto').value;
  const newSport    = (document.getElementById('editSport').value    || '').trim();
  const newDport    = (document.getElementById('editDport').value    || '').trim();
  const newAction   = document.getElementById('editAction').value;
  const newPriority = (document.getElementById('editPriority').value || '').trim();

  if (newSrc === '' && newDst === '') {
    showModalAlert('Enter at least a Source IP or Destination IP.', 'error'); return;
  }
  if (!isValidIP(newSrc)) {
    showModalAlert('Invalid Source IP address.', 'error'); return;
  }
  if (!isValidIP(newDst)) {
    showModalAlert('Invalid Destination IP address.', 'error'); return;
  }
  if (newSrc !== '' && newDst !== '' && newSrc === newDst) {
    showModalAlert('Source and Destination IP cannot be the same.', 'error'); return;
  }
  if (newProto === 'icmp' && (newSport || newDport)) {
    showModalAlert('Ports are not applicable for ICMP protocol.', 'error'); return;
  }
  if (!isValidPort(newSport)) {
    showModalAlert('Source Port must be between 1 and 65535.', 'error'); return;
  }
  if (!isValidPort(newDport)) {
    showModalAlert('Destination Port must be between 1 and 65535.', 'error'); return;
  }
  if (!isValidPriority(newPriority)) {
    showModalAlert('Priority must be a number between 1 and 65535.', 'error'); return;
  }

  const oldRule = { ...rules[editingIndex] };
  const newRule = {
    src:      newSrc,
    dst:      newDst,
    proto:    newProto,
    sport:    newSport    ? parseInt(newSport)    : null,
    dport:    newDport    ? parseInt(newDport)    : null,
    action:   newAction,
    priority: newPriority ? parseInt(newPriority) : (newAction === 'block' ? 200 : 100)
  };

  rules[editingIndex] = newRule;
  renderRules();
  closeModal();
  apiCall('/api/rules/modify', { old: oldRule, new: newRule });
}

// ── Toggle ports in modal ──
function toggleEditPorts() {
  const proto = document.getElementById('editProto').value;
  const row   = document.getElementById('editPortsRow');
  if (row) {
    row.style.opacity = proto !== 'icmp' ? '1' : '0.4';
    if (proto === 'icmp') {
      document.getElementById('editSport').value = '';
      document.getElementById('editDport').value = '';
    }
  }
}

// ── Update edit priority when action changes ──
function updateEditPriority() {
  const action = document.getElementById('editAction').value;
  document.getElementById('editPriority').value = action === 'block' ? '200' : '100';
}

// ── Clear add-rule inputs ──
function clearInputs() {
  ['src', 'dst', 'sport', 'dport'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const actionEl = document.getElementById('action');
  if (actionEl) {
    actionEl.value = 'block';
    const prioEl = document.getElementById('priority');
    if (prioEl) prioEl.value = '200';
  }
}

// ── Close modal on overlay click ──
document.addEventListener('click', function(e) {
  const overlay = document.getElementById('editModal');
  if (overlay && e.target === overlay) closeModal();
});

// ── Close modal on Escape ──
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') closeModal();
});

// ── Load rules on page load ──
window.onload = function () {
  fetch('/api/rules')
    .then(r => r.json())
    .then(data => {
      if (data.rules) rules = data.rules;
      renderRules();
    })
    .catch(() => {
      showAlert('Could not load rules. Is Ryu running?', 'error');
      renderRules();
    });
};
