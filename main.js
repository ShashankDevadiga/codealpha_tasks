/* ═══════════════════════════════════════════════════════════
   SHIELD-NIDS  —  main.js
   All simulation logic, rendering, and interactivity
════════════════════════════════════════════════════════════ */

/* ════════════════════════════════════════════
   STATE
════════════════════════════════════════════ */
let simRunning    = true;
let totalPkts     = 0, totalAlerts = 0, pktId = 0;
let critCnt       = 0, highCnt = 0, medCnt = 0, lowCnt = 0;
let alertLog      = [], packetLog = [], timelineLog = [];
let trafficHistory = new Array(60).fill(0);
let sparkData      = new Array(20).fill(0);
let blockedIPs     = new Set();
let activeAttacks  = {};
let protoFilter    = 'all';
let sevFilter      = 'all';
let geoHits        = {};
let tickCount      = 0;
let canvas, ctx;

let respState = {
  block: true, rate: false, email: true,
  siem: false, quarantine: false, rst: false,
};

/* ════════════════════════════════════════════
   CONSTANTS / DATA
════════════════════════════════════════════ */
const PROTOCOLS = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP'];

const PROTO_COLORS = {
  TCP: '#388bfd', UDP: '#3fb950', HTTP: '#d29922',
  HTTPS: '#8b5cf6', DNS: '#2dd4bf', ICMP: '#f85149',
};

const RULES_DEF = [
  { sid: '1000001', cat: 'Scan',   sig: 'ET SCAN Nmap SYN Scan Detected',          pri: 'HIGH',     enabled: true,  hits: 0 },
  { sid: '1000002', cat: 'SQLi',   sig: 'ET WEB SQL Injection UNION SELECT',        pri: 'CRITICAL', enabled: true,  hits: 0 },
  { sid: '1000003', cat: 'DoS',    sig: 'ET DOS SYN Flood From External Host',      pri: 'CRITICAL', enabled: true,  hits: 0 },
  { sid: '1000004', cat: 'Brute',  sig: 'ET BRUTE SSH Login Failure (5+ times)',    pri: 'HIGH',     enabled: true,  hits: 0 },
  { sid: '1000005', cat: 'XSS',    sig: 'ET WEB XSS Script Tag in Parameter',       pri: 'MEDIUM',   enabled: true,  hits: 0 },
  { sid: '1000006', cat: 'C2',     sig: 'ET MALWARE C2 Beacon Heartbeat',           pri: 'CRITICAL', enabled: true,  hits: 0 },
  { sid: '1000007', cat: 'Recon',  sig: 'ET RECON OS Fingerprinting TTL Probe',     pri: 'LOW',      enabled: true,  hits: 0 },
  { sid: '1000008', cat: 'RCE',    sig: 'ET WEB Remote Code Execution via eval()',  pri: 'CRITICAL', enabled: false, hits: 0 },
  { sid: '1000009', cat: 'MITM',   sig: 'ET NETWORK ARP Spoofing Detected',         pri: 'HIGH',     enabled: true,  hits: 0 },
  { sid: '1000010', cat: 'Exfil',  sig: 'ET DNS Data Exfiltration Tunneling',       pri: 'HIGH',     enabled: true,  hits: 0 },
  { sid: '1000011', cat: 'LFI',    sig: 'ET WEB LFI Attempt /etc/passwd',           pri: 'HIGH',     enabled: true,  hits: 0 },
  { sid: '1000012', cat: 'Trojan', sig: 'ET TROJAN Reverse Shell Callback',         pri: 'CRITICAL', enabled: false, hits: 0 },
];
let ruleData = RULES_DEF.map(r => ({ ...r }));

const ATTACKS = {
  portscan: {
    label: 'Port Scan', sev: 'high', proto: 'TCP', sid: '1000001',
    msgs: ['Nmap SYN Scan Detected', 'Stealth XMAS Scan', 'Port Sweep Detected', 'TCP FIN Scan'],
  },
  sqli: {
    label: 'SQL Injection', sev: 'critical', proto: 'HTTP', sid: '1000002',
    msgs: ['UNION SELECT Injection', 'Blind SQLi Time-based', 'Error-based SQLi', 'SQLi via User-Agent'],
  },
  dos: {
    label: 'DoS Attack', sev: 'critical', proto: 'TCP', sid: '1000003',
    msgs: ['SYN Flood Detected', 'UDP Amplification', 'HTTP Slowloris', 'ICMP Flood'],
  },
  brute: {
    label: 'Brute Force', sev: 'high', proto: 'TCP', sid: '1000004',
    msgs: ['SSH Brute Force', 'HTTP Basic Auth Brute', 'RDP Login Flood', 'FTP Credential Stuffing'],
  },
  xss: {
    label: 'XSS Attack', sev: 'medium', proto: 'HTTP', sid: '1000005',
    msgs: ['Reflected XSS Detected', 'Stored XSS Script Tag', 'DOM-based XSS', 'XSS via Cookie'],
  },
};

const GEO = [
  { flag: '🇷🇺', name: 'Russia',        ip: '185.220.x.x' },
  { flag: '🇨🇳', name: 'China',         ip: '103.x.x.x'   },
  { flag: '🇺🇸', name: 'United States', ip: '104.x.x.x'   },
  { flag: '🇩🇪', name: 'Germany',       ip: '91.x.x.x'    },
  { flag: '🇧🇷', name: 'Brazil',        ip: '177.x.x.x'   },
  { flag: '🇳🇱', name: 'Netherlands',   ip: '45.x.x.x'    },
];

const MITRE = [
  { tactic: 'Reconnaissance',    techs: ['T1595', 'T1592', 'T1589'] },
  { tactic: 'Initial Access',    techs: ['T1190', 'T1133', 'T1566'] },
  { tactic: 'Execution',         techs: ['T1059', 'T1203', 'T1204'] },
  { tactic: 'Defense Evasion',   techs: ['T1027', 'T1070', 'T1562'] },
  { tactic: 'Command & Control', techs: ['T1071', 'T1095', 'T1090'] },
];

const SEV_MAP = {
  critical: { cls: 'crit', icon: '🔴', badge: 'badge-red',   color: 'var(--red)'   },
  high:     { cls: 'high', icon: '🟠', badge: 'badge-amber', color: 'var(--amber)' },
  medium:   { cls: 'med',  icon: '🔵', badge: 'badge-blue',  color: 'var(--blue)'  },
  low:      { cls: 'low',  icon: '🟢', badge: 'badge-green', color: 'var(--green)' },
};

/* ════════════════════════════════════════════
   UTILITIES
════════════════════════════════════════════ */
const rnd   = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
const rndEl = arr     => arr[Math.floor(Math.random() * arr.length)];
const rndIP = ()      => `${rnd(1,254)}.${rnd(0,254)}.${rnd(0,254)}.${rnd(1,254)}`;
const nowStr = ()     => new Date().toISOString().slice(11, 19);

/* ════════════════════════════════════════════
   TOAST NOTIFICATION
════════════════════════════════════════════ */
function toast(title, sub, color) {
  const t = document.getElementById('toast');
  document.getElementById('toast-title').textContent = title;
  document.getElementById('toast-sub').textContent   = sub;
  t.style.borderLeftColor = color || 'var(--border)';
  t.classList.add('show');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.remove('show'), 3000);
}

/* ════════════════════════════════════════════
   TAB SWITCHING
════════════════════════════════════════════ */
function switchTab(name, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('panel-' + name).classList.add('active');
  if (name === 'rules')    renderRules();
  if (name === 'alerts')   renderAlertTable();
  if (name === 'packets')  renderPackets();
  if (name === 'response') { renderTimeline(); renderMitre(); }
}

/* ════════════════════════════════════════════
   SIMULATION TOGGLE
════════════════════════════════════════════ */
function toggleSim() {
  simRunning = !simRunning;
  document.getElementById('sim-btn').textContent   = simRunning ? 'Pause' : 'Resume';
  document.getElementById('sim-led').className     = 'sim-led' + (simRunning ? '' : ' paused');
  document.getElementById('sim-label').textContent = simRunning ? 'Simulation running' : 'Simulation paused';
}

/* ════════════════════════════════════════════
   ATTACK SIMULATION
════════════════════════════════════════════ */
function triggerAttack(type) {
  const btn = document.getElementById('atk-' + type);
  if (activeAttacks[type]) {
    clearTimeout(activeAttacks[type]);
    delete activeAttacks[type];
    btn.classList.remove('on');
    return;
  }
  btn.classList.add('on');
  const atk   = ATTACKS[type];
  const srcIP = rndIP();

  const fire = () => {
    if (!activeAttacks[type]) return;
    generateAlert(atk.sev, rndEl(atk.msgs), srcIP, '192.168.1.' + rnd(1, 20), atk.proto, atk.sid);
    const rule = ruleData.find(r => r.sid === atk.sid);
    if (rule) rule.hits++;
    activeAttacks[type] = setTimeout(fire, rnd(400, 1200));
  };

  activeAttacks[type] = setTimeout(fire, 50);
  toast('Attack: ' + atk.label, 'Source: ' + srcIP, 'var(--red)');

  // Auto-stop after 10 s
  setTimeout(() => {
    if (activeAttacks[type]) {
      clearTimeout(activeAttacks[type]);
      delete activeAttacks[type];
      btn.classList.remove('on');
    }
  }, 10000);
}

/* ════════════════════════════════════════════
   ALERT GENERATION
════════════════════════════════════════════ */
function generateAlert(sev, msg, srcIP, dstIP, proto, sid) {
  totalAlerts++;
  const entry = {
    time:  nowStr(),
    sev:   sev   || 'low',
    msg:   msg   || 'Unknown alert',
    srcIP: srcIP  || rndIP(),
    dstIP: dstIP  || '192.168.1.' + rnd(1, 50),
    proto: proto  || rndEl(PROTOCOLS),
    sid:   sid    || '10000' + rnd(1, 12),
  };

  alertLog.unshift(entry);
  if (alertLog.length > 300) alertLog.pop();

  if      (sev === 'critical') { critCnt++; addTimeline('🔴 Critical: ' + msg, entry.srcIP); }
  else if (sev === 'high')       highCnt++;
  else if (sev === 'medium')     medCnt++;
  else                           lowCnt++;

  if (respState.block && sev === 'critical') {
    blockedIPs.add(entry.srcIP);
    updateBlockedList();
  }

  updateMetrics();
  renderFeedItem(entry);
  bumpGeo();

  const badge = document.getElementById('alert-badge');
  badge.style.display = 'inline';
  badge.textContent   = totalAlerts;
  document.getElementById('alert-cnt-badge').textContent = totalAlerts + ' alerts';
}

/* ════════════════════════════════════════════
   ALERT FEED (dashboard)
════════════════════════════════════════════ */
function renderFeedItem(entry) {
  const feed        = document.getElementById('alert-feed');
  const placeholder = feed.querySelector('.placeholder');
  if (placeholder) placeholder.remove();

  const s   = SEV_MAP[entry.sev] || SEV_MAP.low;
  const div = document.createElement('div');
  div.className = 'alert-item ' + s.cls;
  div.innerHTML = `
    <div class="alert-icon ${s.cls}">${s.icon}</div>
    <div class="alert-body">
      <div class="alert-title">${entry.msg}</div>
      <div class="alert-meta">
        <span>${entry.srcIP} → ${entry.dstIP}</span>
        <span>${entry.proto}</span>
        <span>SID:${entry.sid}</span>
      </div>
    </div>
    <div class="alert-time">${entry.time}</div>`;

  feed.insertBefore(div, feed.firstChild);
  while (feed.children.length > 40) feed.removeChild(feed.lastChild);
}

/* ════════════════════════════════════════════
   METRICS
════════════════════════════════════════════ */
function updateMetrics() {
  document.getElementById('m-crit').textContent    = critCnt;
  document.getElementById('m-high').textContent    = highCnt;
  document.getElementById('m-med').textContent     = medCnt;
  document.getElementById('m-low').textContent     = lowCnt;
  document.getElementById('s-alerts').textContent  = totalAlerts;
  document.getElementById('s-blocked').textContent = blockedIPs.size;
  document.getElementById('s-pkts').textContent    = totalPkts.toLocaleString();
}

/* ════════════════════════════════════════════
   ALERT TABLE (Alerts tab)
════════════════════════════════════════════ */
function renderAlertTable() {
  const q        = (document.getElementById('alert-search').value || '').toLowerCase();
  const filtered = alertLog.filter(a => {
    if (sevFilter !== 'all' && a.sev !== sevFilter) return false;
    if (q && !JSON.stringify(a).toLowerCase().includes(q)) return false;
    return true;
  });

  const tbody = document.getElementById('alert-tbody');
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text3);padding:20px">No matching alerts</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.slice(0, 80).map(a => {
    const s  = SEV_MAP[a.sev] || SEV_MAP.low;
    const pc = PROTO_COLORS[a.proto] || '#888';
    return `<tr>
      <td class="mono" style="font-size:10px">${a.time}</td>
      <td><span class="badge ${s.badge}">${a.sev.toUpperCase()}</span></td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${a.msg}</td>
      <td class="mono">${a.srcIP}</td>
      <td class="mono">${a.dstIP}</td>
      <td><span class="ptag" style="background:${pc}">${a.proto}</span></td>
      <td><button class="btn danger" onclick="blockIP('${a.srcIP}')">Block</button></td>
    </tr>`;
  }).join('');
}

function setSev(v, el) {
  sevFilter = v;
  document.querySelectorAll('#sev-pills .pill').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  renderAlertTable();
}

function clearAlerts() {
  alertLog = []; critCnt = 0; highCnt = 0; medCnt = 0; lowCnt = 0; totalAlerts = 0;
  document.getElementById('alert-tbody').innerHTML = '';
  document.getElementById('alert-feed').innerHTML  =
    '<div class="placeholder" style="color:var(--text3);font-size:12px;text-align:center;padding:20px">No alerts yet.</div>';
  updateMetrics();
  document.getElementById('alert-badge').style.display = 'none';
  document.getElementById('alert-cnt-badge').textContent = '0 alerts';
}

/* ════════════════════════════════════════════
   IP BLOCKING
════════════════════════════════════════════ */
function blockIP(ip) {
  blockedIPs.add(ip);
  updateMetrics();
  updateBlockedList();
  toast('IP Blocked', ip + ' added to deny list', 'var(--red)');
}

function updateBlockedList() {
  const el = document.getElementById('blocked-list');
  if (!blockedIPs.size) { el.textContent = 'None blocked'; return; }
  el.innerHTML = [...blockedIPs].slice(-10).reverse().map(ip =>
    `<span style="display:inline-block;background:var(--red-bg);color:var(--red);padding:2px 7px;border-radius:4px;margin:2px 2px 2px 0">${ip}</span>`
  ).join('');
}

/* ════════════════════════════════════════════
   RULES
════════════════════════════════════════════ */
function renderRules() {
  document.getElementById('rules-tbody').innerHTML = ruleData.map((r, i) => `
    <tr>
      <td>
        <label class="toggle">
          <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="toggleRule(${i}, this.checked)">
          <span class="track"></span>
        </label>
      </td>
      <td class="mono" style="font-size:11px">${r.sid}</td>
      <td><span class="badge badge-blue">${r.cat}</span></td>
      <td style="font-size:11px;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${r.sig}</td>
      <td><span class="badge ${SEV_MAP[r.pri.toLowerCase()]?.badge || 'badge-green'}">${r.pri}</span></td>
      <td style="font-weight:700;color:${r.hits > 0 ? 'var(--amber)' : 'var(--text2)'}">${r.hits}</td>
    </tr>`).join('');
  document.getElementById('s-rules').textContent = ruleData.filter(r => r.enabled).length;
}

function toggleRule(i, v) {
  ruleData[i].enabled = v;
  document.getElementById('s-rules').textContent = ruleData.filter(r => r.enabled).length;
}

function addCustomRule() {
  const text = document.getElementById('rule-editor').value.trim();
  if (!text) { toast('Error', 'Rule editor is empty', 'var(--red)'); return; }
  const sidM = text.match(/sid:(\d+)/);
  const msgM = text.match(/msg:"([^"]+)"/);
  ruleData.push({
    sid:     sidM ? sidM[1] : '9999' + rnd(0, 999),
    cat:     'Custom',
    sig:     msgM ? msgM[1] : text.slice(0, 50),
    pri:     'MEDIUM',
    enabled: true,
    hits:    0,
  });
  renderRules();
  document.getElementById('rule-editor').value = '';
  toast('Rule Added', 'Custom rule loaded into engine', 'var(--green)');
}

function validateRule() {
  const text = document.getElementById('rule-editor').value.trim();
  if (!text) { toast('Error', 'Nothing to validate', 'var(--red)'); return; }
  const ok = text.includes('alert') && text.includes('msg:') && text.includes('sid:');
  toast(
    ok ? 'Syntax OK ✔' : 'Syntax Error ✖',
    ok ? 'Rule structure is valid' : 'Missing alert / msg / sid field',
    ok ? 'var(--green)' : 'var(--red)'
  );
}

/* ════════════════════════════════════════════
   PACKETS
════════════════════════════════════════════ */
function addPacket(src, dst, proto, len, flags, info, flagged) {
  pktId++;
  packetLog.unshift({ id: pktId, time: nowStr(), srcIP: src, dstIP: dst, proto, len, flags, info, flagged });
  if (packetLog.length > 600) packetLog.pop();
  document.getElementById('pkt-cnt-label').textContent = pktId + ' captured';
}

function renderPackets() {
  const rows = packetLog.filter(p => protoFilter === 'all' || p.proto === protoFilter).slice(0, 100);
  document.getElementById('pkt-tbody').innerHTML = rows.map(p => {
    const pc = PROTO_COLORS[p.proto] || '#666';
    return `<tr class="${p.flagged ? 'flagged' : ''}">
      <td style="color:var(--text3)">${p.id}</td>
      <td>${p.time}</td>
      <td>${p.srcIP}</td>
      <td>${p.dstIP}</td>
      <td><span class="ptag" style="background:${pc}">${p.proto}</span></td>
      <td>${p.len}</td>
      <td style="color:var(--text3)">${p.flags}</td>
      <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;color:${p.flagged ? 'var(--red)' : 'var(--text2)'}">${p.info}</td>
    </tr>`;
  }).join('');
}

function setProto(v, el) {
  protoFilter = v;
  document.querySelectorAll('#proto-pills .pill').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  renderPackets();
}

/* ════════════════════════════════════════════
   GEO SOURCES
════════════════════════════════════════════ */
function bumpGeo() {
  const g = rndEl(GEO);
  geoHits[g.name] = (geoHits[g.name] || 0) + 1;
  renderGeo();
}

function renderGeo() {
  const max = Math.max(...Object.values(geoHits), 1);
  document.getElementById('geo-grid').innerHTML = GEO.map(g => {
    const c   = geoHits[g.name] || 0;
    const pct = Math.round(c / max * 100);
    return `<div class="geo-item">
      <div class="geo-flag">${g.flag}</div>
      <div class="geo-name">${g.name}</div>
      <div class="geo-count">${c} alerts</div>
      <div class="geo-bar-track"><div class="geo-bar-fill" style="width:${pct}%"></div></div>
    </div>`;
  }).join('');
}

/* ════════════════════════════════════════════
   PROTOCOL DISTRIBUTION BARS
════════════════════════════════════════════ */
function renderProtoBars() {
  const protos = ['TCP', 'UDP', 'HTTP', 'DNS', 'ICMP', 'HTTPS'];
  const vals   = [58, 18, 12, 7, 3, 2];
  document.getElementById('proto-bars').innerHTML = protos.map((p, i) =>
    `<div class="proto-row">
      <div class="proto-name">${p}</div>
      <div class="proto-track">
        <div class="proto-fill" style="width:${vals[i]}%;background:${PROTO_COLORS[p] || '#888'}"></div>
      </div>
      <div class="proto-pct">${vals[i]}%</div>
    </div>`
  ).join('');
}

/* ════════════════════════════════════════════
   RESPONSE PANEL
════════════════════════════════════════════ */
function toggleResp(key) {
  respState[key]  = !respState[key];
  const on        = respState[key];
  const card      = document.getElementById('resp-' + key);
  card.classList.toggle('on', on);
  const statusEl  = card.querySelector('.resp-status');
  statusEl.innerHTML = `
    <div class="status-dot" style="background:${on ? 'var(--green)' : 'var(--border2)'}"></div>
    <span style="color:${on ? 'var(--green)' : 'var(--text3)'}">${on ? 'ENABLED' : 'DISABLED'}</span>`;
  toast(
    key.toUpperCase() + ' ' + (on ? 'Enabled' : 'Disabled'),
    'Response policy updated',
    on ? 'var(--green)' : 'var(--amber)'
  );
}

/* ════════════════════════════════════════════
   INCIDENT TIMELINE
════════════════════════════════════════════ */
function addTimeline(msg, ip) {
  timelineLog.unshift({ msg, ip, time: nowStr() });
  if (timelineLog.length > 20) timelineLog.pop();
  if (document.getElementById('panel-response').classList.contains('active')) renderTimeline();
}

function renderTimeline() {
  const el = document.getElementById('timeline');
  if (!timelineLog.length) {
    el.innerHTML = '<div style="color:var(--text3);font-size:12px">No incidents yet.</div>';
    return;
  }
  el.innerHTML = timelineLog.slice(0, 8).map(t =>
    `<div class="tl-item">
      <div class="tl-dot" style="background:var(--red)"></div>
      <div class="tl-text">${t.msg}</div>
      <div class="tl-time">${t.time} · ${t.ip}</div>
    </div>`
  ).join('');
}

/* ════════════════════════════════════════════
   MITRE ATT&CK HEATMAP
════════════════════════════════════════════ */
function renderMitre() {
  const levels = [
    'var(--bg3)',
    'rgba(210,153,34,.25)',
    'rgba(248,81,73,.4)',
    'rgba(248,81,73,.75)',
  ];
  document.getElementById('mitre-heatmap').innerHTML = MITRE.map(m =>
    `<div class="mitre-row">
      <div class="mitre-tactic">${m.tactic}</div>
      <div class="mitre-cells">
        ${m.techs.map(t => {
          const v = rnd(0, 3);
          return `<div class="mcell"
            style="background:${levels[v]}"
            title="${t}: ${['None','Low','Medium','High'][v]}"></div>`;
        }).join('')}
        <span style="font-size:9px;color:var(--text3);margin-left:6px">${m.techs.join(' · ')}</span>
      </div>
    </div>`
  ).join('');
}

/* ════════════════════════════════════════════
   SIDEBAR THREAT LIST
════════════════════════════════════════════ */
function renderSbThreats() {
  const counts = {};
  alertLog.slice(0, 60).forEach(a => {
    const k = a.msg.split(' ').slice(0, 3).join(' ');
    counts[k] = (counts[k] || 0) + 1;
  });
  const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 4);
  const el  = document.getElementById('sb-threats');
  if (!top.length) {
    el.innerHTML = '<div style="font-size:11px;color:var(--text3);padding:4px">No threats yet</div>';
    return;
  }
  el.innerHTML = top.map(([k, v]) =>
    `<div class="sb-row">
      <span class="sb-name" style="font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:120px">${k}</span>
      <span style="color:var(--red);font-size:11px;font-weight:700">${v}</span>
    </div>`
  ).join('');
}

/* ════════════════════════════════════════════
   SPARKLINE (sidebar)
════════════════════════════════════════════ */
function renderSparkline() {
  const max = Math.max(...sparkData, 1);
  document.getElementById('sparkline').innerHTML = sparkData.map(v =>
    `<div class="spark-bar" style="height:${Math.max(2, Math.round(v / max * 20))}px"></div>`
  ).join('');
}

/* ════════════════════════════════════════════
   TRAFFIC CANVAS (Chart)
════════════════════════════════════════════ */
function setupCanvas() {
  canvas = document.getElementById('trafficCanvas');
  if (!canvas) return;
  const wrap    = canvas.parentElement;
  canvas.width  = wrap.clientWidth  || 400;
  canvas.height = wrap.clientHeight || 80;
  ctx           = canvas.getContext('2d');
}

function drawTraffic() {
  if (!canvas || !ctx) return;
  const w    = canvas.width;
  const h    = canvas.height;
  const data = trafficHistory;
  const max  = Math.max(...data, 1);
  const step = w / (data.length - 1);
  const pts  = data.map((v, i) => [i * step, h - (v / max) * (h - 6)]);

  ctx.clearRect(0, 0, w, h);

  // Fill gradient
  ctx.beginPath();
  ctx.moveTo(0, h);
  pts.forEach(([x, y]) => ctx.lineTo(x, y));
  ctx.lineTo(w, h);
  ctx.closePath();
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, 'rgba(56,139,253,0.35)');
  grad.addColorStop(1, 'rgba(56,139,253,0.02)');
  ctx.fillStyle = grad;
  ctx.fill();

  // Line
  ctx.beginPath();
  pts.forEach(([x, y], i) => (i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y)));
  ctx.strokeStyle = '#388bfd';
  ctx.lineWidth   = 1.5;
  ctx.lineJoin    = 'round';
  ctx.stroke();
}

/* ════════════════════════════════════════════
   MAIN TICK  (runs every 800 ms)
════════════════════════════════════════════ */
function tick() {
  if (simRunning) {
    tickCount++;

    // Packet rate
    const base  = rnd(40, 120);
    const bonus = Object.keys(activeAttacks).length * rnd(20, 70);
    const rate  = base + bonus;
    totalPkts  += rate;

    trafficHistory.shift(); trafficHistory.push(rate);
    sparkData.shift();      sparkData.push(rate);

    document.getElementById('top-clock').textContent = nowStr() + ' UTC';
    document.getElementById('pkt-rate').textContent  = rate + ' pkt/s';

    // Background packet capture
    for (let i = 0; i < rnd(1, 3); i++) {
      const proto   = rndEl(PROTOCOLS);
      const src     = rndIP();
      const dst     = '192.168.' + rnd(1, 5) + '.' + rnd(1, 50);
      const len     = rnd(40, 1500);
      const flags   = rndEl(['SYN', 'ACK', 'SYN-ACK', 'FIN', 'RST', 'PSH-ACK', 'URG']);
      const flagged = Math.random() < 0.025;
      addPacket(src, dst, proto, len, flags, flagged ? '⚠ Suspicious payload detected' : 'Normal traffic', flagged);
      if (flagged)
        generateAlert(rndEl(['low', 'low', 'medium']), 'Anomalous packet detected', src, dst, proto, null);
    }

    // Occasional background alert
    if (Math.random() < 0.06) {
      generateAlert(
        rndEl(['low', 'low', 'low', 'medium']),
        rndEl(['Unusual DNS query volume', 'ICMP Echo sweep', 'HTTP anomaly score', 'Potential port probe']),
        rndIP(), null, null, null
      );
    }

    // Bump rule hits
    if (tickCount % 6 === 0)
      ruleData.forEach(r => { if (r.enabled && Math.random() < 0.08) r.hits++; });

    // Render
    drawTraffic();
    renderSparkline();
    renderSbThreats();
    updateMetrics();

    // Update visible tab panels
    if (document.getElementById('panel-packets').classList.contains('active')  && tickCount % 3 === 0) renderPackets();
    if (document.getElementById('panel-alerts').classList.contains('active')   && tickCount % 4 === 0) renderAlertTable();
    if (document.getElementById('panel-rules').classList.contains('active')    && tickCount % 8 === 0) renderRules();
  }

  setTimeout(tick, 800);
}

/* ════════════════════════════════════════════
   INIT
════════════════════════════════════════════ */
window.addEventListener('DOMContentLoaded', () => {
  setupCanvas();
  window.addEventListener('resize', () => { setupCanvas(); drawTraffic(); });

  // Seed initial data
  GEO.forEach(g => { geoHits[g.name] = rnd(0, 4); });

  renderGeo();
  renderProtoBars();
  renderRules();
  renderMitre();
  renderTimeline();

  tick();
});
