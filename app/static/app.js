/* ═══════════════════════════════════════════════════════════════════════════
   NET-SONAR · app.js
   Full SPA logic: live scan SSE, history, device registry, diff
   ═══════════════════════════════════════════════════════════════════════════ */

'use strict';

// ── State ─────────────────────────────────────────────────────────────────────
let liveDevices   = [];   // devices from the most recently loaded scan
const scanProgress = new Map(); // IP → {phase:'a'|'b', startMs} while port-scanning
let activeNet     = 'ALL';
let activeRole    = 'ALL';
let searchStr     = '';
let sortCol       = 'ip';
let sortDir       = 1;
let historyPage   = 1;
let scanRunning   = false;
let sseSource     = null;
let scanHistoryCache = []; // [{id, started_at, host_count, subnets, ...}]

// ── Historical view state ─────────────────────────────────────────────────────
let histDevices    = [];
let histActiveNet  = 'ALL';
let histActiveRole = 'ALL';
let histSearchStr  = '';
let histSortCol    = 'ip';
let histSortDir    = 1;
let currentHistScanId = null;

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await loadStatus();
  if (!scanRunning) loadLastScan();
  setInterval(updateClock, 1000);
  updateClock();
  document.getElementById('searchBox').addEventListener('input', e => {
    searchStr = e.target.value.trim();
    renderTable();
  });
});

function updateClock() {
  const el = document.getElementById('ftr-time');
  if (el) el.textContent = new Date().toLocaleString('en-GB');
}

// ── Tab switching ─────────────────────────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.ntab[data-tab]').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  document.querySelector(`.ntab[data-tab="${name}"]`).classList.add('active');

  if (name === 'history') loadHistory();
  if (name === 'devices') loadKnownDevices();
  if (name === 'notify')  loadNotifications();
  if (name === 'risk')    loadRisk();
  if (name === 'graph')   loadGraphView();
  if (name === 'diff')    loadDiffSelectors();
}

// ── API helpers ───────────────────────────────────────────────────────────────
async function apiFetch(path, opts = {}) {
  const res = await fetch('/api' + path, opts);
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`HTTP ${res.status}: ${err}`);
  }
  return res.json();
}

// ── Status & initial load ─────────────────────────────────────────────────────
async function loadStatus() {
  try {
    const s = await apiFetch('/status');
    document.getElementById('meta-interval').textContent =
      s.scan_interval_minutes > 0 ? `every ${s.scan_interval_minutes}min` : 'manual';
    if (s.last_scan) {
      document.getElementById('meta-last-scan').textContent =
        new Date(s.last_scan.started_at).toLocaleString('en-GB');
      document.getElementById('meta-hosts').textContent = s.last_scan.host_count;
      if (s.last_scan.duration_s != null) {
        const m = Math.floor(s.last_scan.duration_s / 60);
        const sec = s.last_scan.duration_s % 60;
        document.getElementById('meta-duration').textContent =
          m > 0 ? `${m}m ${sec}s` : `${sec}s`;
      }
    }
    if (s.next_scan_at) {
      document.getElementById('meta-next-scan').textContent =
        new Date(s.next_scan_at).toLocaleTimeString('en-GB', {hour:'2-digit', minute:'2-digit'});
    } else if (s.scan_interval_minutes === 0) {
      document.getElementById('meta-next-scan').textContent = 'manual';
    }

    // Notification badge
    _updateNotifyBadge(s.unread_notifications || 0);

    // If a scan was already running when the page loaded (e.g. after F5),
    // pre-populate the live table with devices already found, then reconnect
    // to SSE so new host_done events continue filling in the table.
    if (s.scan_running && !scanRunning) {
      scanRunning = true;
      liveDevices = [];
      document.getElementById('scanBtn').disabled = true;
      setScanStatus('running', '● SCANNING...');
      clearLog();
      buildNetTabs([]);
      renderTable();
      buildTopology();
      buildRttBars();
      buildDevSummary();
      logLine('Reconnecting to scan in progress...', 'log-info');
      // Load partial backlog before opening the SSE stream
      try {
        const partial = await apiFetch('/scan/partial');
        // 1. Completed devices (host_done)
        (partial.devices || []).forEach(msg => {
          const dev = {
            ip: msg.ip, mac: msg.mac, hostname: msg.hostname,
            rtt_ms: msg.rtt_ms, role: msg.role, ports: msg.ports || [],
            os_guess: msg.os_guess, subnet: msg.subnet, iface: msg.iface,
            vendor: msg.vendor, model: msg.model, services: msg.services || [],
            tags: msg.tags || [],
          };
          liveDevices.push(dev);
        });
        // 2. Ping-done devices not yet port-scanned (no ports yet)
        (partial.ping_devices || []).forEach(msg => {
          if (!liveDevices.find(d => d.ip === msg.ip)) {
            liveDevices.push({
              ip: msg.ip, mac: msg.mac, hostname: msg.hostname,
              rtt_ms: msg.rtt_ms, role: msg.role, ports: [],
              os_guess: null, subnet: msg.subnet, iface: msg.iface,
              vendor: msg.vendor, model: msg.model, services: msg.services || [],
              tags: msg.tags || [],
            });
          }
        });
        // 3. IPs currently being port-scanned → restore progress bars
        (partial.scanning_ips || []).forEach(ip => {
          scanProgress.set(ip, { phase: 'a', startMs: Date.now() });
        });
        if (liveDevices.length) {
          const subnets = [...new Set(liveDevices.map(d => d.subnet).filter(Boolean))];
          buildNetTabs(subnets);
          renderTable();
          buildTopology();
          buildRttBars();
          buildDevSummary();
          logLine(`Backlog: ${liveDevices.length} hosts (${partial.scanning_ips?.length || 0} scanning).`, 'log-ok');
        }
      } catch (e) { /* non fatal */ }
      startSSE();
    }
  } catch (e) { console.warn('status error', e); }
}

async function loadLastScan() {
  try {
    const resp = await apiFetch('/scans?per_page=1&page=1');
    document.getElementById('cnt-scans').textContent = resp.total;
    if (resp.items.length > 0) {
      const scan = resp.items[0];
      await loadScanIntoLive(scan.id);
    } else {
      showEmptyLive();
    }
  } catch (e) { console.warn('loadLastScan error', e); }
}

async function loadScanIntoLive(scanId) {
  try {
    const scan = await apiFetch(`/scans/${scanId}`);
    liveDevices = scan.devices;

    // Update stat cards
    document.getElementById('cnt-hosts').textContent = scan.host_count;
    document.getElementById('cnt-subnets').textContent = scan.subnets.length;

    // Count known devices
    const known = await apiFetch('/devices');
    document.getElementById('cnt-known').textContent = known.length;

    // Rebuild UI
    buildNetTabs(scan.subnets);
    renderTable();
    buildTopology();
    buildRttBars();
    buildDevSummary();
  } catch (e) { console.warn('loadScanIntoLive error', e); }
}

function showEmptyLive() {
  document.getElementById('tablePanel').innerHTML =
    '<div class="empty-state">// NO SCANS YET — CLICK "START SCAN" TO BEGIN</div>';
}

// ── Scan trigger ──────────────────────────────────────────────────────────────
async function triggerScan() {
  if (scanRunning) return;

  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  scanRunning = true;
  setScanStatus('running', '● SCANNING...');
  clearLog();
  liveDevices = [];
  renderTable();
  buildNetTabs([]);
  buildTopology();
  buildRttBars();
  buildDevSummary();

  try {
    await apiFetch('/scan', { method: 'POST' });
    startSSE();
  } catch (e) {
    setScanStatus('error', '● ERROR');
    logLine('Error starting scan: ' + e.message, 'log-err');
    btn.disabled = false;
    scanRunning = false;
  }
}

function startSSE() {
  if (sseSource) { sseSource.close(); sseSource = null; }
  sseSource = new EventSource('/api/scan/stream');

  sseSource.onmessage = (e) => {
    handleSSEMessage(JSON.parse(e.data));
  };
  sseSource.onerror = () => {
    setScanStatus('error', '● SSE ERROR');
    logLine('Connessione SSE persa.', 'log-err');
    scanRunning = false;
    document.getElementById('scanBtn').disabled = false;
    sseSource.close();
  };
}

function handleSSEMessage(msg) {
  switch (msg.type) {

    case 'log':
      logLine(msg.msg, msg.level === 'ok' ? 'log-ok' : msg.level === 'warn' ? 'log-warn' : 'log-info');
      break;

    case 'subnet_start':
      logLine(`[${msg.iface}] Scanning ${msg.subnet}...`, 'log-info');
      break;

    case 'subnet_ping_done':
      logLine(msg.msg, 'log-ok');
      break;

    case 'host_ping_done': {
      // Host found by ping sweep — show immediately before port scan
      const idx2 = liveDevices.findIndex(d => d.ip === msg.ip);
      const earlyDev = {
        ip: msg.ip, mac: msg.mac, hostname: msg.hostname,
        rtt_ms: msg.rtt_ms, role: msg.role, ports: [],
        os_guess: null, subnet: msg.subnet, iface: msg.iface,
        vendor: msg.vendor, model: msg.model, services: msg.services || [],
        tags: msg.tags || [],
      };
      if (idx2 >= 0) liveDevices[idx2] = earlyDev; else liveDevices.push(earlyDev);
      const subnets2 = [...new Set(liveDevices.map(d => d.subnet).filter(Boolean))];
      buildNetTabs(subnets2);
      renderTable();
      buildTopology();
      buildRttBars();
      buildDevSummary();
      break;
    }

    case 'port_scan_start':
      setScanStatus('running', `● ${msg.index}/${msg.total} PORT SCAN`);
      if (msg.ip) { scanProgress.set(msg.ip, { phase: 'a', startMs: Date.now() }); renderTable(); }
      break;

    case 'port_scan_progress':
      if (msg.ip) { scanProgress.set(msg.ip, { phase: 'b', startMs: Date.now() }); renderTable(); }
      break;

    case 'host_done': {
      // Add or update device in liveDevices
      const idx = liveDevices.findIndex(d => d.ip === msg.ip);
      const dev = {
        ip: msg.ip, mac: msg.mac, hostname: msg.hostname,
        rtt_ms: msg.rtt_ms, role: msg.role, ports: msg.ports || [],
        os_guess: msg.os_guess, subnet: msg.subnet, iface: msg.iface,
        vendor: msg.vendor, model: msg.model, services: msg.services || [],
        tags: msg.tags || [],
      };
      if (idx >= 0) liveDevices[idx] = dev; else liveDevices.push(dev);
      scanProgress.delete(dev.ip);
      // Rebuild subnet tabs if new subnet
      const subnets = [...new Set(liveDevices.map(d => d.subnet).filter(Boolean))];
      buildNetTabs(subnets);
      renderTable();
      buildTopology();
      buildRttBars();
      buildDevSummary();
      break;
    }

    case 'done':
      scanProgress.clear();
      setScanStatus('done', '● SCAN COMPLETE');
      logLine(msg.msg, 'log-ok');
      scanRunning = false;
      document.getElementById('scanBtn').disabled = false;
      sseSource.close();
      // Reload stat cards and refresh notification badge
      loadStatus();
      loadLastScan();
      break;

    case 'error':
      scanProgress.clear();
      setScanStatus('error', '● ERROR');
      logLine(msg.msg, 'log-err');
      scanRunning = false;
      document.getElementById('scanBtn').disabled = false;
      sseSource.close();
      break;
  }
}

function setScanStatus(cls, text) {
  const el = document.getElementById('scan-status-badge');
  el.className = 'status-' + cls;
  el.textContent = text;
}

// ── Net tabs ──────────────────────────────────────────────────────────────────
function buildNetTabs(subnets) {
  const c = document.getElementById('netTabs');
  c.innerHTML = '';
  const allBtn = _btn('ALL', 'ALL', subnets.reduce((a,s) => {
    return a + liveDevices.filter(d => d.subnet === s).length;
  }, liveDevices.length > 0 ? 0 : 0));
  // use total count for ALL
  const allCount = liveDevices.length;
  allBtn.innerHTML = `ALL <span style="color:var(--green3);font-size:.62rem">${allCount}</span>`;
  allBtn.className = 'ntab' + (activeNet === 'ALL' ? ' active' : '');
  allBtn.onclick = () => setNet(allBtn, 'ALL');
  c.appendChild(allBtn);
  subnets.forEach(s => {
    const cnt = liveDevices.filter(d => d.subnet === s).length;
    const b = _btn(s, s, cnt);
    b.innerHTML = `${s} <span style="color:var(--green3);font-size:.62rem">${cnt}</span>`;
    b.className = 'ntab' + (activeNet === s ? ' active' : '');
    b.onclick = () => setNet(b, s);
    c.appendChild(b);
  });
}

function _btn(net, label, cnt) {
  const b = document.createElement('button');
  b.dataset.net = net;
  return b;
}

function setNet(btn, net) {
  activeNet = net;
  document.querySelectorAll('#netTabs .ntab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderTable();
}

function setFilter(btn, role) {
  activeRole = role;
  document.querySelectorAll('#live-filter-btns .fbtn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderTable();
}

// ── Table render ──────────────────────────────────────────────────────────────
function getFiltered() {
  return liveDevices.filter(d => {
    if (activeNet !== 'ALL' && d.subnet !== activeNet) return false;
    if (activeRole !== 'ALL' && d.role !== activeRole) return false;
    if (searchStr) {
      const q = searchStr.toLowerCase();
      const portMatch = (d.ports || []).some(p =>
        String(p.port).includes(q) || (p.service || '').toLowerCase().includes(q)
      );
      if (!d.ip.includes(q) &&
          !(d.mac || '').toLowerCase().includes(q) &&
          !(d.hostname || '').toLowerCase().includes(q) &&
          !(d.role || '').toLowerCase().includes(q) &&
          !(d.iface || '').toLowerCase().includes(q) &&
          !portMatch) return false;
    }
    return true;
  }).sort((a, b) => {
    let av = a[sortCol], bv = b[sortCol];
    if (sortCol === 'ip')     { av = ipToInt(av || ''); bv = ipToInt(bv || ''); }
    if (sortCol === 'rtt_ms') { av = av ?? 9999; bv = bv ?? 9999; }
    if (av < bv) return -sortDir;
    if (av > bv) return  sortDir;
    return 0;
  });
}

function renderTable() {
  const panel = document.getElementById('tablePanel');
  const data  = getFiltered();

  if (!data.length) {
    panel.innerHTML = '<div class="empty-state">// NO HOSTS MATCH CURRENT FILTER</div>';
    return;
  }

  // Group by subnet
  const groups = {};
  data.forEach(d => {
    const key = d.subnet || '?';
    if (!groups[key]) groups[key] = [];
    groups[key].push(d);
  });

  let html = '';
  for (const [subnet, rows] of Object.entries(groups)) {
    const gw = rows.find(r => r.role === 'GATEWAY/ROUTER');
    html += `<div class="subnet-block">
      <div class="subnet-hdr" onclick="toggleSubnet(this)">
        <span class="snet-arrow open">&#9654;</span>
        <span class="snet-label">${esc(subnet)}</span>
        <span class="snet-count">${rows.length} host</span>
        ${gw ? `<span class="snet-gw">GW: ${esc(fmtIp(gw.ip))}</span>` : ''}
      </div>
      <div class="subnet-body">
        <table><thead><tr>`;

    const cols = [
      {k:'type',     l:'Type'},
      {k:'ip',       l:'IP Address'},
      {k:'mac',      l:'MAC / OUI'},
      {k:'vendor',   l:'Vendor'},
      {k:'rtt_ms',   l:'RTT'},
      {k:'role',     l:'Role'},
      {k:'iface',    l:'Interface'},
      {k:'hostname', l:'Hostname'},
      {k:'ports',    l:'Open Ports'},
      {k:'os_guess', l:'OS'},
      {k:'model',    l:'Model'},
      {k:'services', l:'Services'},
    ];
    cols.forEach(c => {
      if (c.k === 'type' || c.k === 'ports' || c.k === 'os_guess' || c.k === 'vendor' || c.k === 'model' || c.k === 'services') {
        html += `<th>${c.l}</th>`;
        return;
      }
      const arrow = sortCol === c.k
        ? (sortDir === 1 ? '&#9650;' : '&#9660;')
        : '<span style="opacity:.2">&#9650;</span>';
      html += `<th onclick="setSort('${c.k}')">${c.l} <span class="sort-arrow">${arrow}</span></th>`;
    });
    html += '</tr></thead><tbody>';

    rows.forEach(d => {
      html += `<tr class="${rowClass(d.role)}">
        <td style="text-align:center">${fmtIpType(d.ip)}</td>
        <td class="ip">${fmtIp(d.ip)}</td>
        <td class="mac">${fmtMac(d.mac)}</td>
        <td style="font-size:.65rem;color:var(--amber)">${esc(d.vendor || '')}</td>
        <td>${fmtRtt(d.rtt_ms)}</td>
        <td><span class="badge ${badgeClass(d.role)}">${esc(d.role || 'Host')}</span>${fmtTags(d.tags)}</td>
        <td class="iface">${esc(d.iface || '')}</td>
        <td class="hostname">${esc(d.hostname || 'N/A')}</td>
        <td class="ports">${scanProgress.has(d.ip) ? fmtScanProgress(scanProgress.get(d.ip)) : fmtPorts(d.ports)}</td>
        <td style="font-size:.62rem;color:var(--textdim)">${esc(d.os_guess || '')}</td>
        <td style="font-size:.62rem;color:var(--textdim)">${esc(d.model || '')}</td>
        <td style="font-size:.60rem;color:var(--textdim)">${fmtServices(d.services)}</td>
      </tr>`;
    });
    html += '</tbody></table></div></div>';
  }
  panel.innerHTML = html;
}

function toggleSubnet(hdr) {
  const body  = hdr.nextElementSibling;
  const arrow = hdr.querySelector('.snet-arrow');
  const open  = arrow.classList.toggle('open');
  body.style.display = open ? '' : 'none';
}

function setSort(col) {
  if (sortCol === col) sortDir *= -1; else { sortCol = col; sortDir = 1; }
  renderTable();
}

// ── Topology SVG ──────────────────────────────────────────────────────────────
function buildTopology(devices, svgId) {
  const devs  = devices !== undefined ? devices : liveDevices;
  const sid   = svgId || 'topo-svg';
  const svg   = document.getElementById(sid);
  if (!svg) return;
  const patId = sid.replace(/[^a-z0-9]/gi, '') + 'bg';
  const W = 260, H = 220, cx = 130, cy = 100;
  const gw     = devs.find(d => d.role === 'GATEWAY/ROUTER');
  const others = devs.filter(d => d.role !== 'GATEWAY/ROUTER').slice(0, 20);
  let out = '';

  out += `<defs><pattern id="${patId}" width="20" height="20" patternUnits="userSpaceOnUse">`
       + '<path d="M20 0L0 0 0 20" fill="none" stroke="#0d1a0d" stroke-width="1"/></pattern></defs>';
  out += `<rect width="${W}" height="${H}" fill="url(#${patId})"/>`;

  others.forEach((d, i) => {
    const angle = (i / others.length) * Math.PI * 2 - Math.PI / 2;
    const r = 78, x = cx + r * Math.cos(angle), y = cy + r * Math.sin(angle);
    const c = rttColor(d.rtt_ms);
    out += `<line x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}" stroke="${c}" stroke-width="0.5" stroke-opacity="0.3"/>`;
  });
  others.forEach((d, i) => {
    const angle = (i / others.length) * Math.PI * 2 - Math.PI / 2;
    const r = 78, x = cx + r * Math.cos(angle), y = cy + r * Math.sin(angle);
    const c = rttColor(d.rtt_ms);
    // For IPv4: show last octet; for IPv6: show last 4 hex chars
    const ipStr = d.ip || '?';
    const last = ipStr.includes(':')
      ? ipStr.split('%')[0].replace(/:/g,'').slice(-4)
      : '.' + ipStr.split('.').pop();
    out += `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="4" fill="${c}" fill-opacity="0.85"/>`;
    out += `<text x="${(x+6).toFixed(1)}" y="${(y+3).toFixed(1)}" font-family="Share Tech Mono,monospace" font-size="6" fill="${c}" fill-opacity="0.7">${last}</text>`;
  });

  if (gw) {
    out += `<circle cx="${cx}" cy="${cy}" r="10" fill="none" stroke="#00ff88" stroke-width="1.5"/>`;
    out += `<circle cx="${cx}" cy="${cy}" r="6" fill="#00ff88" fill-opacity="0.9"/>`;
    out += `<text x="${cx}" y="${cy+22}" font-family="Orbitron,monospace" font-size="6" fill="#00ff88" text-anchor="middle">${gw.ip}</text>`;
    out += `<text x="${cx}" y="${cy+30}" font-family="Share Tech Mono,monospace" font-size="5" fill="#3d5c3d" text-anchor="middle">GATEWAY</text>`;
  } else {
    out += `<circle cx="${cx}" cy="${cy}" r="8" fill="none" stroke="var(--green3)" stroke-width="1" stroke-dasharray="3 2"/>`;
    out += `<text x="${cx}" y="${cy+4}" font-family="Share Tech Mono,monospace" font-size="6" fill="var(--green3)" text-anchor="middle">?</text>`;
  }

  out += `<text x="4" y="215" font-family="Share Tech Mono,monospace" font-size="5" fill="#1a3a1a">`
       + `● &lt;10ms  ● &lt;50ms  ● &lt;120ms  ● HIGH</text>`;
  svg.innerHTML = out;
}

function rttColor(rtt) {
  if (!rtt && rtt !== 0) return '#3d5c3d';
  if (rtt <= 10)  return '#00ff41';
  if (rtt <= 50)  return '#7fff00';
  if (rtt <= 120) return '#ffb700';
  return '#ff3333';
}

// ── RTT bars ──────────────────────────────────────────────────────────────────
function buildRttBars(devices, containerId) {
  const devs = devices !== undefined ? devices : liveDevices;
  const cid  = containerId || 'rttBars';
  const bands = [
    {l:'0–2ms',   max:2,   col:'#00ff41'},
    {l:'3–10ms',  max:10,  col:'#7fff00'},
    {l:'11–30ms', max:30,  col:'#c8ff00'},
    {l:'31–60ms', max:60,  col:'#ffb700'},
    {l:'61–120ms',max:120, col:'#ff6600'},
    {l:'>120ms',  max:9999,col:'#ff3333'},
  ];
  let prev = 0;
  const counts = bands.map(b => {
    const c = devs.filter(d => (d.rtt_ms ?? 0) > prev && (d.rtt_ms ?? 0) <= b.max).length;
    prev = b.max; return c;
  });
  const maxC = Math.max(...counts, 1);
  document.getElementById(cid).innerHTML = bands.map((b, i) => `
    <div class="rtt-bar-row">
      <div class="rtt-bar-lbl">${b.l}</div>
      <div class="rtt-bar-bg">
        <div class="rtt-bar-fill" style="width:${(counts[i]/maxC*100).toFixed(0)}%;background:${b.col}"></div>
      </div>
      <div class="rtt-bar-cnt">${counts[i]}</div>
    </div>`).join('');
}

// ── Device summary ────────────────────────────────────────────────────────────
function buildDevSummary(devices, containerId) {
  const devs = devices !== undefined ? devices : liveDevices;
  const cid  = containerId || 'devList';

  // Deduplicate by MAC: if the same physical device appears as both IPv4 and IPv6,
  // count it only once (keep whichever entry comes first — IPv4 is always listed first).
  const seenMac = new Set();
  const uniqueDevs = devs.filter(d => {
    if (!d.mac) return true;  // no MAC → always include (can't deduplicate)
    if (seenMac.has(d.mac)) return false;
    seenMac.add(d.mac);
    return true;
  });

  const roles = {};
  uniqueDevs.forEach(d => { roles[d.role] = (roles[d.role] || 0) + 1; });
  const noMac  = uniqueDevs.filter(d => !d.mac).length;
  const noHost = uniqueDevs.filter(d => !d.hostname).length;
  let html = Object.entries(roles).map(([k,v]) =>
    `<div class="dev-item"><span class="dk">${esc(k)}</span><span class="dv">${v}</span></div>`
  ).join('');
  html += `<div class="dev-item" style="margin-top:.3rem;border-top:1px solid var(--border);padding-top:.3rem">
    <span class="dk">Unresolved MACs</span><span class="dv" style="color:var(--amber)">${noMac}</span></div>
  <div class="dev-item">
    <span class="dk">Hostname N/A</span><span class="dv" style="color:var(--amber)">${noHost}</span></div>`;
  document.getElementById(cid).innerHTML = html;
}

// ── Log stream ────────────────────────────────────────────────────────────────
function logLine(msg, cls = 'log-info') {
  const el = document.getElementById('logStream');
  const d  = document.createElement('div');
  d.className = 'log-line ' + cls;
  const t = new Date().toLocaleTimeString('en-GB');
  d.textContent = `[${t}] ${msg}`;
  el.appendChild(d);
  el.scrollTop = el.scrollHeight;
}
function clearLog() {
  document.getElementById('logStream').innerHTML = '';
}

// ── History tab ───────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const resp = await apiFetch(`/scans?page=${historyPage}&per_page=20`);
    scanHistoryCache = resp.items;
    document.getElementById('history-total').textContent = `${resp.total} total scans`;
    const tbody = document.getElementById('historyBody');
    tbody.innerHTML = resp.items.map(s => {
      const started = new Date(s.started_at).toLocaleString('en-GB');
      const dur = s.finished_at
        ? _durStr(new Date(s.finished_at) - new Date(s.started_at))
        : '—';
      const subnets = (s.subnets || []).join(', ') || '—';
      const statusColor = s.status === 'done' ? 'var(--green2)' : s.status === 'error' ? 'var(--red)' : 'var(--amber)';
      return `<tr>
        <td style="color:var(--green3);font-family:'Orbitron',monospace">#${s.id}</td>
        <td>${started}</td>
        <td>${dur}</td>
        <td style="font-size:.65rem;color:var(--textdim)">${esc(subnets)}</td>
        <td style="font-family:'Orbitron',monospace;color:var(--green)">${s.host_count}</td>
        <td><span style="color:${statusColor};font-size:.65rem">● ${s.status.toUpperCase()}</span></td>
        <td>
          <button class="fbtn" onclick="openScanDetail(${s.id})">DETAIL</button>
          <button class="fbtn" onclick="openHistoricalView(${s.id})">VIEW</button>
          <button class="fbtn btn-del" onclick="deleteScan(${s.id})" title="Delete scan">&#128465;</button>
        </td>
      </tr>`;
    }).join('');

    // Pagination
    const totalPages = Math.ceil(resp.total / 20);
    const pager = document.getElementById('historyPager');
    pager.innerHTML = Array.from({length: totalPages}, (_, i) => i + 1).map(p =>
      `<button class="page-btn ${p === historyPage ? 'active' : ''}" onclick="gotoHistoryPage(${p})">${p}</button>`
    ).join('');
  } catch(e) { console.error('loadHistory', e); }
}

async function gotoHistoryPage(p) {
  historyPage = p;
  await loadHistory();
}

async function deleteScan(scanId) {
  try {
    await apiFetch(`/scans/${scanId}`, { method: 'DELETE' });
    await loadHistory();
    await loadStatus();
  } catch(e) { alert('Error deleting scan: ' + e.message); }
}

async function openScanDetail(scanId) {
  try {
    const scan = await apiFetch(`/scans/${scanId}`);
    document.getElementById('scanDetailTitle').textContent = `SCAN #${scanId} — ${new Date(scan.started_at).toLocaleString('en-GB')}`;
    document.getElementById('scanDetail').classList.remove('hidden');
    document.getElementById('scanDetail')._devices = scan.devices;
    document.getElementById('scanDetail')._scanId  = scanId;
    filterDetail();
  } catch (e) { console.error('openScanDetail', e); }
}

function filterDetail() {
  const detail   = document.getElementById('scanDetail');
  const devices  = detail._devices || [];
  const q        = document.getElementById('detailSearch').value.trim().toLowerCase();
  const filtered = q
    ? devices.filter(d =>
        d.ip.includes(q) || (d.mac||'').toLowerCase().includes(q) ||
        (d.hostname||'').toLowerCase().includes(q))
    : devices;
  document.getElementById('detailCount').textContent = `${filtered.length} host`;
  document.getElementById('scanDetailContent').innerHTML = _devicesTable(filtered);
}

function closeScanDetail() {
  document.getElementById('scanDetail').classList.add('hidden');
}

// ── Known devices ──────────────────────────────────────────────────────────────
async function loadKnownDevices() {
  const search  = document.getElementById('devSearch')?.value.trim() || '';
  const trusted = document.getElementById('trustedOnly')?.checked || false;
  try {
    let url = '/devices';
    const params = [];
    if (search)  params.push(`search=${encodeURIComponent(search)}`);
    if (trusted) params.push('trusted_only=true');
    if (params.length) url += '?' + params.join('&');

    const devices = await apiFetch(url);
    document.getElementById('cnt-known').textContent = devices.length;
    const tbody = document.getElementById('devBody');
    if (!devices.length) {
      tbody.innerHTML = '<tr><td colspan="15" class="empty-state">// NO DEVICES IN REGISTRY</td></tr>';
      return;
    }
    tbody.innerHTML = devices.map(d => {
      const firstSeen = d.first_seen ? new Date(d.first_seen).toLocaleString('en-GB') : '—';
      const lastSeen  = d.last_seen  ? new Date(d.last_seen).toLocaleString('en-GB')  : '—';
      const ports = fmtPorts(d.last_ports || []);
      return `<tr>
        <td class="mac">${fmtMac(d.mac)}</td>
        <td style="font-size:.65rem;color:var(--amber)">${esc(d.vendor||'')}</td>
        <td style="font-size:.62rem;color:var(--textdim)">${esc(d.model||'')}</td>
        <td style="color:${d.alias ? 'var(--amber)' : 'var(--textdim)'}">
          ${d.alias ? esc(d.alias) : '<span style="opacity:.4">—</span>'}</td>
        <td style="text-align:center">${fmtIpType(d.last_ip)}</td>
        <td class="ip">${fmtIp(d.last_ip)}</td>
        <td class="hostname">${esc(d.last_hostname || 'N/A')}</td>
        <td style="font-size:.65rem;color:var(--textdim)">${firstSeen}</td>
        <td style="font-size:.65rem;color:var(--textdim)">${lastSeen}</td>
        <td class="ports">${ports}</td>
        <td style="font-size:.62rem;color:var(--textdim)">${esc(d.last_os || '')}</td>
        <td style="font-size:.60rem;color:var(--textdim)">${fmtServices(d.services)}</td>
        <td style="text-align:center" id="uptime-${esc(d.mac.replace(/:/g,''))}">
          <span style="color:var(--textdim);font-size:.60rem">…</span></td>
        <td style="text-align:center">${d.is_trusted
          ? '<span style="color:var(--green2)">✔</span>'
          : '<span style="color:var(--textdim)">—</span>'}</td>
        <td>
          <button class="fbtn btn-edit" onclick="openEditModal('${esc(d.mac)}','${esc(d.alias||'')}',${d.is_trusted},\`${esc(d.notes||'')}\`,'${esc(d.role_override||'')}')" title="Edit device">&#9998;</button>
          <button class="fbtn" onclick="openDeviceHistory('${esc(d.mac)}')" title="Latency &amp; uptime history">&#128200;</button>
          <button class="fbtn btn-del" onclick="deleteDevice('${esc(d.mac)}')" title="Delete device">&#128465;</button>
        </td>
      </tr>`;
    }).join('');

    // Asynchronously load uptime % for each device
    devices.forEach(d => _loadUptimeBadge(d.mac));
  } catch (e) { console.error('loadKnownDevices', e); }
}

async function _loadUptimeBadge(mac) {
  try {
    const h = await apiFetch(`/devices/${encodeURIComponent(mac)}/history?limit=1`);
    const id = 'uptime-' + mac.replace(/:/g, '');
    const el = document.getElementById(id);
    if (!el) return;
    if (h.total === 0 || h.uptime_pct === null) {
      el.innerHTML = '<span style="color:var(--textdim);font-size:.6rem">—</span>';
      return;
    }
    const pct = h.uptime_pct;
    const col = pct >= 95 ? 'var(--green2)' : pct >= 80 ? 'var(--amber)' : 'var(--red)';
    el.innerHTML = `<span style="color:${col};font-size:.65rem;font-family:'Orbitron',monospace">${pct}%</span>`;
  } catch (_) { /* non-fatal */ }
}

async function deleteDevice(mac) {
  try {
    await apiFetch(`/devices/${encodeURIComponent(mac)}`, { method: 'DELETE' });
    await loadKnownDevices();
  } catch(e) { alert('Error deleting device: ' + e.message); }
}

// ── Device RTT / uptime history modal ─────────────────────────────────────────
async function openDeviceHistory(mac) {
  const modal   = document.getElementById('historyModal');
  const content = document.getElementById('historyModalContent');
  modal.classList.remove('hidden');
  content.innerHTML = '<div style="color:var(--textdim);padding:1rem">Loading…</div>';
  try {
    const data = await apiFetch(`/devices/${encodeURIComponent(mac)}/history?limit=60`);
    content.innerHTML = _renderHistoryModal(mac, data);
  } catch (e) {
    content.innerHTML = `<div style="color:var(--red);padding:1rem">Error: ${esc(e.message)}</div>`;
  }
}

function closeHistoryModal() {
  document.getElementById('historyModal').classList.add('hidden');
}

function _renderHistoryModal(mac, data) {
  if (!data.items || data.items.length === 0) {
    return `<div style="color:var(--textdim);padding:1rem">
      No history yet — run at least one scan after this device appears.
    </div>`;
  }
  const items = data.items;
  const upPct = data.uptime_pct !== null ? data.uptime_pct : null;
  const uptCol = upPct === null ? 'var(--textdim)'
               : upPct >= 95   ? 'var(--green2)'
               : upPct >= 80   ? 'var(--amber)'
               : 'var(--red)';

  // Stats row
  const avgRtt = (() => {
    const ups = items.filter(i => i.is_up && i.rtt_ms != null);
    if (!ups.length) return null;
    return (ups.reduce((s, i) => s + i.rtt_ms, 0) / ups.length).toFixed(1);
  })();
  const maxRtt = (() => {
    const rtts = items.filter(i => i.rtt_ms != null).map(i => i.rtt_ms);
    return rtts.length ? Math.max(...rtts).toFixed(1) : null;
  })();

  let html = `
  <div style="display:flex;gap:1.2rem;flex-wrap:wrap;padding:.6rem 0 .8rem">
    <div style="text-align:center">
      <div style="font-size:.58rem;color:var(--textdim)">UPTIME</div>
      <div style="font-size:1.1rem;font-family:'Orbitron',monospace;color:${uptCol}">
        ${upPct !== null ? upPct + '%' : '—'}</div>
      <div style="font-size:.55rem;color:var(--textdim)">${data.total} scans</div>
    </div>
    <div style="text-align:center">
      <div style="font-size:.58rem;color:var(--textdim)">AVG RTT</div>
      <div style="font-size:1.1rem;font-family:'Orbitron',monospace;color:var(--green)">
        ${avgRtt !== null ? avgRtt + ' ms' : '—'}</div>
    </div>
    <div style="text-align:center">
      <div style="font-size:.58rem;color:var(--textdim)">MAX RTT</div>
      <div style="font-size:1.1rem;font-family:'Orbitron',monospace;color:var(--amber)">
        ${maxRtt !== null ? maxRtt + ' ms' : '—'}</div>
    </div>
  </div>`;

  // SVG sparkline
  html += _rttSparkline(items);

  // Availability bar (last 30 scans as dots)
  html += '<div style="margin-top:.6rem;font-size:.55rem;color:var(--textdim);margin-bottom:.2rem">AVAILABILITY (most recent →)</div>';
  html += '<div style="display:flex;flex-wrap:wrap;gap:2px;margin-bottom:.4rem">';
  const recent = items.slice(-60);
  recent.forEach(i => {
    const col = !i.is_up ? '#ff3333'
              : i.rtt_ms == null ? '#3d5c3d'
              : rttColor(i.rtt_ms);
    const ts = new Date(i.scanned_at).toLocaleString('en-GB');
    const tip = i.is_up ? `${ts}  ${i.rtt_ms != null ? i.rtt_ms + ' ms' : 'up'}` : `${ts}  OFFLINE`;
    html += `<div title="${esc(tip)}" style="width:10px;height:10px;border-radius:2px;background:${col};cursor:default"></div>`;
  });
  html += '</div>';

  return html;
}

function _rttSparkline(items) {
  const W = 560, H = 80, PAD = 4;
  const rtts = items.map(i => (i.is_up && i.rtt_ms != null) ? i.rtt_ms : null);
  const validRtts = rtts.filter(v => v !== null);
  if (validRtts.length < 2) {
    return '<div style="color:var(--textdim);font-size:.6rem;padding:.3rem 0">Not enough RTT data for chart.</div>';
  }

  const maxVal = Math.max(...validRtts, 1);
  const n = items.length;
  const xStep = (W - PAD * 2) / Math.max(n - 1, 1);

  // Build polyline points (only where rtt != null)
  let pathPoints = '';
  let filled = '';
  const pts = [];
  items.forEach((item, i) => {
    if (item.is_up && item.rtt_ms != null) {
      const x = PAD + i * xStep;
      const y = PAD + (H - PAD * 2) * (1 - item.rtt_ms / maxVal);
      pts.push([x, y]);
    }
  });

  if (pts.length >= 2) {
    pathPoints = pts.map(([x,y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
    const base = H - PAD;
    filled = `<polyline points="${pts[0][0].toFixed(1)},${base} ${pathPoints} ${pts[pts.length-1][0].toFixed(1)},${base}"
                fill="#00ff4115" stroke="none"/>`;
  }

  // Offline markers
  let offlineMark = '';
  items.forEach((item, i) => {
    if (!item.is_up) {
      const x = PAD + i * xStep;
      offlineMark += `<line x1="${x.toFixed(1)}" y1="${PAD}" x2="${x.toFixed(1)}" y2="${H-PAD}"
                        stroke="#ff333355" stroke-width="1"/>`;
    }
  });

  // Y-axis labels
  const yLabels = [0, Math.round(maxVal/2), Math.round(maxVal)].map((v, i) => {
    const y = H - PAD - (v / maxVal) * (H - PAD * 2);
    return `<text x="${W-1}" y="${y.toFixed(1)}" font-family="Share Tech Mono,monospace" font-size="7"
              fill="var(--textdim)" text-anchor="end" dominant-baseline="middle">${v}ms</text>`;
  }).join('');

  return `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:80px;background:#060f06;border:1px solid var(--border);border-radius:3px">
    <line x1="${PAD}" y1="${PAD}" x2="${PAD}" y2="${H-PAD}" stroke="var(--border)" stroke-width="0.5"/>
    <line x1="${PAD}" y1="${H-PAD}" x2="${W-PAD}" y2="${H-PAD}" stroke="var(--border)" stroke-width="0.5"/>
    ${offlineMark}
    ${filled}
    ${pts.length >= 2 ? `<polyline points="${pathPoints}" fill="none" stroke="var(--green2)" stroke-width="1.5"/>` : ''}
    ${pts.map(([x,y]) => `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="2" fill="var(--green2)" fill-opacity="0.7"/>`).join('')}
    ${yLabels}
  </svg>`;
}

function fmtIp(ip) {
  if (!ip) return '<span style="color:var(--textdim)">—</span>';
  // Strip IPv6 zone-id / scope suffix (e.g. fe80::1%enp2s0 → fe80::1)
  const clean = ip.includes(':') ? ip.split('%')[0] : ip;
  return esc(clean);
}

function fmtIpType(ip) {
  if (!ip) return '';
  const isV6 = ip.includes(':');
  return isV6
    ? '<span style="font-size:.5rem;background:#1a2a4a;color:#6ac8ff;border:1px solid #2a4a7a;border-radius:2px;padding:1px 4px">IPv6</span>'
    : '<span style="font-size:.5rem;background:#1a2a1a;color:#6aff88;border:1px solid #2a5a2a;border-radius:2px;padding:1px 4px">IPv4</span>';
}

function openEditModal(mac, alias, trusted, notes, roleOverride) {
  document.getElementById('editMac').value          = mac;
  document.getElementById('editAlias').value        = alias;
  document.getElementById('editNotes').value        = notes;
  document.getElementById('editTrusted').checked    = trusted;
  document.getElementById('editRoleOverride').value = roleOverride || '';
  document.getElementById('editModal').classList.remove('hidden');
}

function closeModal() {
  document.getElementById('editModal').classList.add('hidden');
}

async function saveDevice() {
  const mac          = document.getElementById('editMac').value;
  const alias        = document.getElementById('editAlias').value.trim();
  const notes        = document.getElementById('editNotes').value.trim();
  const trusted      = document.getElementById('editTrusted').checked;
  const roleOverride = document.getElementById('editRoleOverride').value;
  try {
    await apiFetch(`/devices/${encodeURIComponent(mac)}`, {
      method: 'PATCH',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        alias: alias || null,
        notes: notes || null,
        is_trusted: trusted,
        role_override: roleOverride || '',
      }),
    });
    closeModal();
    loadKnownDevices();
  } catch (e) { alert('Error saving device: ' + e.message); }
}

// ── Diff tab ──────────────────────────────────────────────────────────────────
async function loadDiffSelectors(preSelectA) {
  try {
    const resp = await apiFetch('/scans?per_page=50&page=1');
    const opts = resp.items.map(s =>
      `<option value="${s.id}">#${s.id} — ${new Date(s.started_at).toLocaleString('en-GB')} (${s.host_count} host)</option>`
    ).join('');
    document.getElementById('diffSelA').innerHTML = opts;
    document.getElementById('diffSelB').innerHTML = opts;
    if (preSelectA != null) {
      document.getElementById('diffSelA').value = String(preSelectA);
      const selB = document.getElementById('diffSelB');
      for (let i = 0; i < selB.options.length; i++) {
        if (selB.options[i].value !== String(preSelectA)) {
          selB.value = selB.options[i].value;
          break;
        }
      }
    } else if (resp.items.length >= 2) {
      document.getElementById('diffSelA').value = resp.items[1].id;
      document.getElementById('diffSelB').value = resp.items[0].id;
    }
  } catch (e) { console.error('loadDiffSelectors', e); }
}

async function runDiff() {
  const idA = document.getElementById('diffSelA').value;
  const idB = document.getElementById('diffSelB').value;
  if (!idA || !idB || idA === idB) {
    document.getElementById('diffResult').innerHTML =
      '<div class="empty-state">// Select two different scans</div>';
    return;
  }
  try {
    const d = await apiFetch(`/scans/diff/${idA}/${idB}`);
    let html = '';

    const sections = [
      { key: 'appeared',    cls: 'diff-appeared',    title: `▲ NEW DEVICES (${d.appeared.length})` },
      { key: 'disappeared', cls: 'diff-disappeared', title: `▼ DISAPPEARED (${d.disappeared.length})` },
      { key: 'changed',     cls: 'diff-changed',     title: `↔ CHANGED (${d.changed.length})` },
    ];
    sections.forEach(sec => {
      html += `<div class="diff-section ${sec.cls}">
        <div class="diff-section-title">${sec.title}</div>`;
      if (sec.key === 'changed') {
        if (!d.changed.length) { html += '<div class="empty-state" style="padding:.8rem">// No changes</div>'; }
        else d.changed.forEach(c => {
          html += `<div style="margin-bottom:.5rem">
            ${_devicesTable([c.before])}
            <div style="color:var(--green3);font-size:.6rem;padding:.2rem .4rem">↓ AFTER:</div>
            ${_devicesTable([c.after])}
          </div>`;
        });
      } else {
        const items = d[sec.key];
        if (!items.length) html += '<div class="empty-state" style="padding:.8rem">// No items</div>';
        else html += _devicesTable(items);
      }
      html += '</div>';
    });
    document.getElementById('diffResult').innerHTML = html;
  } catch (e) {
    document.getElementById('diffResult').innerHTML =
      `<div class="empty-state" style="color:var(--red)">// Error: ${esc(e.message)}</div>`;
  }
}

// ── Historical view ───────────────────────────────────────────────────────────
async function openHistoricalView(scanId) {
  try {
    const scan = await apiFetch(`/scans/${scanId}`);
    currentHistScanId = scanId;
    histDevices    = scan.devices;
    histActiveNet  = 'ALL';
    histActiveRole = 'ALL';
    histSearchStr  = '';
    histSortCol    = 'ip';
    histSortDir    = 1;

    // Update banner title
    const started = new Date(scan.started_at).toLocaleString('en-GB');
    document.getElementById('hist-scan-title').textContent =
      `SCAN #${scanId} — ${started} — ${scan.host_count} host`;

    // Reveal and activate the historical tab button
    document.getElementById('tab-btn-historical').style.display = '';
    switchTab('historical');

    // Reset search box and filter buttons
    const sb = document.getElementById('histSearchBox');
    if (sb) sb.value = '';
    document.querySelectorAll('#hist-filter-btns .fbtn').forEach(b => b.classList.remove('active'));
    const allFbtn = document.querySelector('#hist-filter-btns .fbtn[data-role="ALL"]');
    if (allFbtn) allFbtn.classList.add('active');

    // Build full UI
    const subnets = [...new Set(histDevices.map(d => d.subnet).filter(Boolean))];
    buildHistNetTabs(subnets);
    renderHistTable();
    buildTopology(histDevices, 'hist-topo-svg');
    buildRttBars(histDevices, 'histRttBars');
    buildDevSummary(histDevices, 'histDevList');
  } catch (e) { console.error('openHistoricalView', e); }
}

function buildHistNetTabs(subnets) {
  const c = document.getElementById('histNetTabs');
  c.innerHTML = '';
  const allBtn = document.createElement('button');
  allBtn.innerHTML = `ALL <span style="color:var(--green3);font-size:.62rem">${histDevices.length}</span>`;
  allBtn.className = 'ntab' + (histActiveNet === 'ALL' ? ' active' : '');
  allBtn.onclick = () => setHistNet(allBtn, 'ALL');
  c.appendChild(allBtn);
  subnets.forEach(s => {
    const cnt = histDevices.filter(d => d.subnet === s).length;
    const b = document.createElement('button');
    b.innerHTML = `${s} <span style="color:var(--green3);font-size:.62rem">${cnt}</span>`;
    b.className = 'ntab' + (histActiveNet === s ? ' active' : '');
    b.onclick = () => setHistNet(b, s);
    c.appendChild(b);
  });
}

function setHistNet(btn, net) {
  histActiveNet = net;
  document.querySelectorAll('#histNetTabs .ntab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderHistTable();
}

function setHistFilter(btn, role) {
  histActiveRole = role;
  document.querySelectorAll('#hist-filter-btns .fbtn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderHistTable();
}

function setHistSort(col) {
  if (histSortCol === col) histSortDir *= -1; else { histSortCol = col; histSortDir = 1; }
  renderHistTable();
}

function histSearchChanged(val) {
  histSearchStr = val.trim();
  renderHistTable();
}

function getHistFiltered() {
  return histDevices.filter(d => {
    if (histActiveNet !== 'ALL' && d.subnet !== histActiveNet) return false;
    if (histActiveRole !== 'ALL' && d.role !== histActiveRole) return false;
    if (histSearchStr) {
      const q = histSearchStr.toLowerCase();
      const portMatch = (d.ports || []).some(p =>
        String(p.port).includes(q) || (p.service || '').toLowerCase().includes(q)
      );
      if (!d.ip.includes(q) &&
          !(d.mac || '').toLowerCase().includes(q) &&
          !(d.hostname || '').toLowerCase().includes(q) &&
          !(d.role || '').toLowerCase().includes(q) &&
          !(d.iface || '').toLowerCase().includes(q) &&
          !portMatch) return false;
    }
    return true;
  }).sort((a, b) => {
    let av = a[histSortCol], bv = b[histSortCol];
    if (histSortCol === 'ip')     { av = ipToInt(av || ''); bv = ipToInt(bv || ''); }
    if (histSortCol === 'rtt_ms') { av = av ?? 9999; bv = bv ?? 9999; }
    if (av < bv) return -histSortDir;
    if (av > bv) return  histSortDir;
    return 0;
  });
}

function renderHistTable() {
  const panel = document.getElementById('histTablePanel');
  const data  = getHistFiltered();

  if (!data.length) {
    panel.innerHTML = '<div class="empty-state">// NO HOSTS MATCH CURRENT FILTER</div>';
    return;
  }

  const groups = {};
  data.forEach(d => {
    const key = d.subnet || '?';
    if (!groups[key]) groups[key] = [];
    groups[key].push(d);
  });

  let html = '';
  for (const [subnet, rows] of Object.entries(groups)) {
    const gw = rows.find(r => r.role === 'GATEWAY/ROUTER');
    html += `<div class="subnet-block">
      <div class="subnet-hdr" onclick="toggleSubnet(this)">
        <span class="snet-arrow open">&#9654;</span>
        <span class="snet-label">${esc(subnet)}</span>
        <span class="snet-count">${rows.length} host</span>
        ${gw ? `<span class="snet-gw">GW: ${esc(fmtIp(gw.ip))}</span>` : ''}
      </div>
      <div class="subnet-body">
        <table><thead><tr>`;

    const cols = [
      {k:'type',     l:'Type'},
      {k:'ip',       l:'IP Address'},
      {k:'mac',      l:'MAC / OUI'},
      {k:'vendor',   l:'Vendor'},
      {k:'rtt_ms',   l:'RTT'},
      {k:'role',     l:'Role'},
      {k:'iface',    l:'Interface'},
      {k:'hostname', l:'Hostname'},
      {k:'ports',    l:'Open Ports'},
      {k:'os_guess', l:'OS'},
      {k:'model',    l:'Model'},
      {k:'services', l:'Services'},
    ];
    cols.forEach(c => {
      if (c.k === 'type' || c.k === 'ports' || c.k === 'os_guess' || c.k === 'vendor' || c.k === 'model' || c.k === 'services') {
        html += `<th>${c.l}</th>`;
        return;
      }
      const arrow = histSortCol === c.k
        ? (histSortDir === 1 ? '&#9650;' : '&#9660;')
        : '<span style="opacity:.2">&#9650;</span>';
      html += `<th onclick="setHistSort('${c.k}')">${c.l} <span class="sort-arrow">${arrow}</span></th>`;
    });
    html += '</tr></thead><tbody>';

    rows.forEach(d => {
      html += `<tr class="${rowClass(d.role)}">
        <td style="text-align:center">${fmtIpType(d.ip)}</td>
        <td class="ip">${fmtIp(d.ip)}</td>
        <td class="mac">${fmtMac(d.mac)}</td>
        <td style="font-size:.65rem;color:var(--amber)">${esc(d.vendor || '')}</td>
        <td>${fmtRtt(d.rtt_ms)}</td>
        <td><span class="badge ${badgeClass(d.role)}">${esc(d.role || 'Host')}</span></td>
        <td class="iface">${esc(d.iface || '')}</td>
        <td class="hostname">${esc(d.hostname || 'N/A')}</td>
        <td class="ports">${fmtPorts(d.ports)}</td>
        <td style="font-size:.62rem;color:var(--textdim)">${esc(d.os_guess || '')}</td>
        <td style="font-size:.62rem;color:var(--textdim)">${esc(d.model || '')}</td>
        <td style="font-size:.60rem;color:var(--textdim)">${fmtServices(d.services)}</td>
      </tr>`;
    });
    html += '</tbody></table></div></div>';
  }
  panel.innerHTML = html;
}

async function openDiffFromHistorical() {
  if (!currentHistScanId) return;
  // Switch tab manually so loadDiffSelectors default selection doesn't override our pre-selection
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.ntab[data-tab]').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-diff').classList.add('active');
  document.querySelector('.ntab[data-tab="diff"]').classList.add('active');
  await loadDiffSelectors(currentHistScanId);
}

// ── Notifications ─────────────────────────────────────────────────────────────
let notifyPage   = 1;
let notifyFilter = 'all';

function _updateNotifyBadge(count) {
  const badge = document.getElementById('notify-badge');
  if (!badge) return;
  if (count > 0) {
    badge.textContent = count > 99 ? '99+' : count;
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }
}

function setNotifyFilter(btn, type) {
  notifyFilter = type;
  notifyPage   = 1;
  document.querySelectorAll('#notify-filter-btns .fbtn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  loadNotifications();
}

async function loadNotifications() {
  try {
    const typeParam = notifyFilter !== 'all' ? `&event_type=${notifyFilter}` : '';
    const resp      = await apiFetch(`/notifications?page=${notifyPage}&per_page=50${typeParam}`);

    document.getElementById('notify-total').textContent =
      `${resp.total} event${resp.total !== 1 ? 's' : ''}`;

    const list = document.getElementById('notifyList');
    if (!resp.items.length) {
      list.innerHTML = '<div class="empty-state">// NO EVENTS RECORDED YET</div>';
      document.getElementById('notifyPager').innerHTML = '';
      return;
    }

    list.innerHTML = resp.items.map(ev => _renderNotifyCard(ev)).join('');

    // Pagination
    const totalPages = Math.ceil(resp.total / 50);
    document.getElementById('notifyPager').innerHTML =
      Array.from({length: totalPages}, (_, i) => i + 1).map(p =>
        `<button class="page-btn ${p === notifyPage ? 'active' : ''}"
           onclick="gotoNotifyPage(${p})">${p}</button>`
      ).join('');
  } catch(e) { console.error('loadNotifications', e); }
}

async function gotoNotifyPage(p) {
  notifyPage = p;
  await loadNotifications();
}

function _renderNotifyCard(ev) {
  const cfg = _notifyConfig(ev.event_type);
  const ts  = new Date(ev.created_at).toLocaleString('en-GB');
  const label = ev.alias
    ? `<span style="color:var(--amber)">${esc(ev.alias)}</span>`
    : (ev.hostname && ev.hostname !== 'N/A'
        ? `<span style="color:var(--text)">${esc(ev.hostname)}</span>`
        : `<span style="color:var(--textdim)">unknown</span>`);

  let extraHtml = '';
  const x = ev.extra || {};

  if (ev.event_type === 'ports_changed') {
    if (x.opened && x.opened.length) {
      const chips = x.opened.map(p =>
        `<span class="port-chip port-common" title="${esc(p.service||'')}">+${p.port}/${p.proto}</span>`
      ).join('');
      extraHtml += `<div class="notify-ports"><span class="notify-port-lbl" style="color:var(--green2)">OPENED</span>${chips}</div>`;
    }
    if (x.closed && x.closed.length) {
      const chips = x.closed.map(p =>
        `<span class="port-chip" style="border-color:#ff333355;color:var(--red)" title="${esc(p.service||'')}">-${p.port}/${p.proto}</span>`
      ).join('');
      extraHtml += `<div class="notify-ports"><span class="notify-port-lbl" style="color:var(--red)">CLOSED</span>${chips}</div>`;
    }
  }

  const vendor = x.vendor ? `<span class="notify-meta-chip">${esc(x.vendor)}</span>` : '';
  const role   = x.role   ? `<span class="notify-meta-chip">${esc(x.role)}</span>` : '';

  return `
  <div class="notify-card notify-card-${ev.event_type}">
    <div class="notify-card-stripe"></div>
    <div class="notify-card-body">
      <div class="notify-card-top">
        <span class="notify-type-badge notify-badge-${ev.event_type}">${cfg.icon} ${cfg.label}</span>
        <span class="notify-scan-ref">SCAN #${ev.scan_id}</span>
        <span class="notify-ts">${esc(ts)}</span>
      </div>
      <div class="notify-card-main">
        <span class="notify-mac">${fmtMac(ev.mac)}</span>
        <span class="notify-ip">${fmtIp(ev.ip)}</span>
        ${label}
        ${vendor}${role}
      </div>
      ${extraHtml}
    </div>
  </div>`;
}

function _notifyConfig(type) {
  switch (type) {
    case 'new':           return { icon: '▲', label: 'NEW DEVICE',     col: 'var(--amber)'  };
    case 'disappeared':   return { icon: '▼', label: 'DISAPPEARED',    col: 'var(--red)'    };
    case 'reappeared':    return { icon: '↺', label: 'REAPPEARED',     col: 'var(--blue)'   };
    case 'ports_changed': return { icon: '⬡', label: 'PORT CHANGE',    col: 'var(--green)'  };
    default:              return { icon: '◆', label: type.toUpperCase(), col: 'var(--textdim)' };
  }
}

// ── Graph View ────────────────────────────────────────────────────────────────
let _graphObserver = null;

async function loadGraphView() {
  const panel = document.getElementById('graphPanel');
  panel.innerHTML = '<div class="empty-state">// LOADING SCAN DATA...</div>';

  try {
    // Paginate: API caps per_page at 100
    let allScans = [];
    let page = 1;
    while (true) {
      const resp = await apiFetch(`/scans?per_page=100&page=${page}`);
      allScans = allScans.concat(resp.items);
      if (allScans.length >= resp.total || !resp.items.length) break;
      page++;
    }
    if (!allScans.length) {
      panel.innerHTML = '<div class="empty-state">// NO SCANS YET — RUN A SCAN FIRST</div>';
      return;
    }

    // Disconnect any previous observer
    if (_graphObserver) { _graphObserver.disconnect(); _graphObserver = null; }

    panel.innerHTML = '';
    allScans.forEach(scan => {
      const card = document.createElement('div');
      card.className = 'graph-scan-card';
      card.dataset.scanId = scan.id;
      card.innerHTML = _graphCardShell(scan);
      panel.appendChild(card);
    });

    // Lazy-load each card when it scrolls into view
    _graphObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting && !entry.target.dataset.loaded) {
          entry.target.dataset.loaded = '1';
          _loadGraphCard(entry.target, entry.target.dataset.scanId);
        }
      });
    }, { rootMargin: '300px' });

    document.querySelectorAll('.graph-scan-card').forEach(c => _graphObserver.observe(c));

  } catch (e) {
    panel.innerHTML = `<div class="empty-state" style="color:var(--red)">// ERROR: ${esc(e.message)}</div>`;
  }
}

function _graphCardShell(scan) {
  const started  = new Date(scan.started_at).toLocaleString('en-GB');
  const dur      = scan.finished_at ? _durStr(new Date(scan.finished_at) - new Date(scan.started_at)) : '—';
  const subnets  = (scan.subnets || []).join(', ') || '—';
  const stCol    = scan.status === 'done' ? 'var(--green2)' : scan.status === 'error' ? 'var(--red)' : 'var(--amber)';
  return `
    <div class="graph-card-hdr">
      <span class="graph-card-id">SCAN #${scan.id}</span>
      <span class="graph-card-date">${esc(started)}</span>
      <span class="graph-card-pill"><span class="graph-pill-lbl">DURATION</span>${esc(dur)}</span>
      <span class="graph-card-pill"><span class="graph-pill-lbl">HOSTS</span>${scan.host_count}</span>
      <span class="graph-card-pill"><span class="graph-pill-lbl">SUBNET</span>${esc(subnets)}</span>
      <span style="font-size:.62rem;color:${stCol};margin-left:auto">● ${scan.status.toUpperCase()}</span>
    </div>
    <div class="graph-card-body graph-card-loading">
      <span style="color:var(--textdim);font-size:.7rem">// loading visualization…</span>
    </div>`;
}

async function _loadGraphCard(cardEl, scanId) {
  try {
    const scan    = await apiFetch(`/scans/${scanId}`);
    const devices = scan.devices || [];

    const topoId = `gtopo-${scanId}`;
    const rttId  = `grtt-${scanId}`;
    const devId  = `gdev-${scanId}`;

    const bodyEl = cardEl.querySelector('.graph-card-body');
    bodyEl.classList.remove('graph-card-loading');
    bodyEl.innerHTML = `
      <div class="graph-col graph-col-topo">
        <div class="side-title">&#9632; Topology Map</div>
        <svg id="${topoId}" viewBox="0 0 260 220" style="width:100%;max-width:260px;height:210px"></svg>
      </div>
      <div class="graph-col graph-col-rtt">
        <div class="side-title">&#9632; RTT Distribution</div>
        <div class="rtt-bars" id="${rttId}"></div>
      </div>
      <div class="graph-col graph-col-dev">
        <div class="side-title">&#9632; Device Summary</div>
        <div class="dev-list" id="${devId}"></div>
      </div>
      <div class="graph-col graph-col-heur">
        <div class="side-title">&#9632; Heuristics</div>
        <div class="dev-list">${_graphHeuristics(devices)}</div>
      </div>`;

    buildTopology(devices, topoId);
    buildRttBars(devices, rttId);
    buildDevSummary(devices, devId);
  } catch (e) {
    const bodyEl = cardEl.querySelector('.graph-card-body');
    if (bodyEl) bodyEl.innerHTML = `<span style="color:var(--red);font-size:.7rem">// error loading scan #${scanId}</span>`;
  }
}

function _graphHeuristics(devices) {
  if (!devices.length) return '<div style="color:var(--textdim);font-size:.65rem">No data</div>';

  // Unique open ports
  const allPorts = new Set();
  devices.forEach(d => (d.ports || []).forEach(p => allPorts.add(p.port)));

  // RTT stats
  const rtts   = devices.map(d => d.rtt_ms).filter(r => r != null);
  const avgRtt = rtts.length ? (rtts.reduce((a, b) => a + b, 0) / rtts.length).toFixed(1) : null;
  const maxRtt = rtts.length ? Math.max(...rtts) : null;

  // Counts
  const withPorts = devices.filter(d => d.ports && d.ports.length > 0).length;
  const ipv6Count = devices.filter(d => d.ip && d.ip.includes(':')).length;
  const ipv4Count = devices.filter(d => d.ip && !d.ip.includes(':')).length;
  const noMac     = devices.filter(d => !d.mac).length;

  // OS distribution (top 3)
  const osMap = {};
  devices.forEach(d => { if (d.os_guess) { const k = d.os_guess.slice(0, 20); osMap[k] = (osMap[k] || 0) + 1; } });
  const topOs = Object.entries(osMap).sort((a, b) => b[1] - a[1]).slice(0, 3);

  const row = (lbl, val, col = 'var(--text)') =>
    `<div class="dev-item"><span class="dk">${lbl}</span><span class="dv" style="color:${col}">${val}</span></div>`;

  const maxRttCol = maxRtt == null ? 'var(--textdim)' : maxRtt > 100 ? 'var(--red)' : maxRtt > 50 ? 'var(--amber)' : 'var(--green2)';

  let html = '';
  html += row('Avg RTT',       avgRtt !== null ? avgRtt + ' ms' : '—');
  html += row('Max RTT',       maxRtt !== null ? maxRtt + ' ms' : '—', maxRttCol);
  html += row('Unique Ports',  allPorts.size);
  html += row('With Open Ports', withPorts);
  html += row('IPv4 Hosts',    ipv4Count);
  if (ipv6Count) html += row('IPv6 Hosts', ipv6Count, 'var(--blue)');
  if (noMac)     html += row('Unknown MAC', noMac, 'var(--amber)');

  if (topOs.length) {
    html += `<div class="dev-item" style="margin-top:.35rem;border-top:1px solid var(--border);padding-top:.35rem">
      <span class="dk" style="font-size:.58rem;color:var(--textdim)">TOP OS</span></div>`;
    topOs.forEach(([os, cnt]) => html += row(os, cnt, 'var(--amber)'));
  }
  return html;
}

// ── Shared table renderer (for history detail / diff) ─────────────────────────
function _devicesTable(devices) {
  if (!devices.length) return '';
  return `<table>
    <thead><tr>
      <th>IP</th><th>MAC</th><th>Vendor</th><th>RTT</th><th>Role</th>
      <th>Interface</th><th>Hostname</th><th>Ports</th><th>OS</th><th>Model</th><th>Services</th>
    </tr></thead>
    <tbody>${devices.map(d => `<tr class="${rowClass(d.role)}">
      <td class="ip">${esc(d.ip)}</td>
      <td class="mac">${fmtMac(d.mac)}</td>
      <td style="font-size:.65rem;color:var(--amber)">${esc(d.vendor||'')}</td>
      <td>${fmtRtt(d.rtt_ms)}</td>
      <td><span class="badge ${badgeClass(d.role)}">${esc(d.role||'Host')}</span></td>
      <td class="iface">${esc(d.iface||'')}</td>
      <td class="hostname">${esc(d.hostname||'N/A')}</td>
      <td class="ports">${fmtPorts(d.ports||[])}</td>
      <td style="font-size:.62rem;color:var(--textdim)">${esc(d.os_guess||'')}</td>
      <td style="font-size:.62rem;color:var(--textdim)">${esc(d.model||'')}</td>
      <td style="font-size:.60rem;color:var(--textdim)">${fmtServices(d.services)}</td>
    </tr>`).join('')}</tbody>
  </table>`;
}

// ── Formatters ─────────────────────────────────────────────────────────────────
function esc(s) {
  if (!s) return '';
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function fmtMac(mac) {
  if (!mac) return '<span style="color:#2a3a2a">N/A</span>';
  const oui  = mac.substring(0, 8);
  const rest = mac.substring(8);
  return `<span class="oui">${esc(oui)}</span>${esc(rest)}`;
}

function fmtRtt(rtt) {
  if (rtt == null) return '<span style="color:var(--textdim)">—</span>';
  const cls = rttClass(rtt);
  return `<span class="rtt ${cls}">${rtt} ms</span>`;
}

function fmtScanProgress({ phase, startMs }) {
  const elapsed = Math.max(0, (Date.now() - startMs) / 1000);
  return `<div class="port-scan-bar"><div class="port-scan-fill port-scan-fill-${phase}" style="animation-delay:-${elapsed.toFixed(3)}s"></div></div>`;
}

function fmtPorts(ports) {
  if (!ports || !ports.length) return '<span style="color:var(--textdim);font-size:.62rem">—</span>';
  return ports.slice(0, 8).map(p => {
    let cls = 'port-chip';
    if ([80, 443, 8080, 8443].includes(p.port)) cls += ' port-http';
    else if (p.port === 22) cls += ' port-ssh';
    else if ([21,23,25,110,143,3389].includes(p.port)) cls += ' port-common';
    return `<span class="${cls}" title="${esc(p.service||'')} ${esc(p.version||'')}">${p.port}/${p.proto}</span>`;
  }).join('') + (ports.length > 8 ? `<span style="color:var(--textdim);font-size:.58rem"> +${ports.length-8}</span>` : '');
}

// ── Service label/icon mapping ─────────────────────────────────────────────────
const _SVC_MAP = [
  // UPnP / DLNA / AV
  { re: /AVTransport/i,          icon: '▶', label: 'AV Transport',  col: '#00c864' },
  { re: /ContentDirectory/i,     icon: '▤', label: 'DLNA Content',  col: '#00c864' },
  { re: /RenderingControl/i,     icon: '◎', label: 'AV Renderer',   col: '#00c864' },
  { re: /ConnectionManager/i,    icon: '⇄', label: 'UPnP ConnMgr',  col: '#4ec9f0' },
  { re: /X_MS_MediaReceiver/i,   icon: '▣', label: 'WMP Share',     col: '#f0a040' },
  { re: /QPlay/i,                icon: '▷', label: 'QPlay',         col: '#00b4cc' },
  { re: /PlayQueue/i,            icon: '≡', label: 'Play Queue',    col: '#a0c864' },
  { re: /WANIPConn|WANPPPConn/i, icon: '⊙', label: 'WAN IP',        col: '#4ec9f0' },
  { re: /Layer3Forwarding/i,     icon: '⊙', label: 'Routing',       col: '#4ec9f0' },
  { re: /WANCommonIfc/i,         icon: '⊙', label: 'WAN Iface',     col: '#4ec9f0' },
  // mDNS service types (_foo._tcp)
  { re: /^_airplay\./i,          icon: '◈', label: 'AirPlay',       col: '#5ac8fa' },
  { re: /^_raop\./i,             icon: '♪', label: 'AirPlay Audio', col: '#5ac8fa' },
  { re: /^_homekit\./i,          icon: '⌂', label: 'HomeKit',       col: '#5ac8fa' },
  { re: /^_googlecast\./i,       icon: '⊙', label: 'Chromecast',    col: '#4285f4' },
  { re: /^_spotify/i,            icon: '♫', label: 'Spotify',       col: '#1db954' },
  { re: /^_https\./i,            icon: '🔒', label: 'HTTPS',         col: '#00c864' },
  { re: /^_http\./i,             icon: '⊕', label: 'HTTP',          col: '#4ec9f0' },
  { re: /^_ssh\./i,              icon: '🔑', label: 'SSH',           col: '#ff6060' },
  { re: /^_sftp/i,               icon: '🔑', label: 'SFTP',          col: '#ff6060' },
  { re: /^_ftp\./i,              icon: '⇅', label: 'FTP',           col: '#ff9040' },
  { re: /^_smb\.|^_cifs\./i,    icon: '▣', label: 'SMB/CIFS',      col: '#f0a040' },
  { re: /^_(ipp|printer|pdl)/i,  icon: '⎙', label: 'Print',         col: '#c090f0' },
  { re: /^_nfs\./i,              icon: '⊟', label: 'NFS',           col: '#f0a040' },
  { re: /^_afp/i,                icon: '◈', label: 'AFP',           col: '#5ac8fa' },
  { re: /^_rdp\./i,              icon: '▣', label: 'RDP',           col: '#f0a040' },
  { re: /^_vnc\./i,              icon: '◉', label: 'VNC',           col: '#ff9040' },
  { re: /^_daap\./i,             icon: '♫', label: 'iTunes Music',  col: '#5ac8fa' },
  { re: /^_mqtt\./i,             icon: '⇌', label: 'MQTT',          col: '#a0c864' },
  // from smb-enum-shares script
  { re: /^smb:/i,                icon: '▣', label: null,            col: '#f0a040' },
  { re: /^SMB shares$/i,         icon: '▣', label: 'SMB Shares',    col: '#f0a040' },
  // WSD (Windows Service Discovery)
  { re: /WSD/i,                  icon: '▣', label: 'WSD',           col: '#f0a040' },
  // upnp: prefix from upnp-info script
  { re: /^upnp:/i,               icon: '⊕', label: null,            col: '#4ec9f0' },
];

function _parseSvcLabel(s, mapEntry) {
  if (mapEntry.label !== null && mapEntry.label !== undefined) return mapEntry.label;
  // Strip known prefixes and trim
  const stripped = s.replace(/^(smb:|upnp:)/i, '');
  // For URNs, extract the device/service name segment: urn:...:device:Foo:1 → Foo
  const urnMatch = stripped.match(/:(?:device|service):([^:]+)/i);
  if (urnMatch) return urnMatch[1];
  return stripped.slice(0, 22);
}

function fmtServices(services) {
  if (!services || !services.length) return '<span style="color:var(--textdim);font-size:.60rem">—</span>';

  const chips = services.slice(0, 7).map(s => {
    // Defaults for unmapped services: extract meaningful label from URN or mDNS
    let icon = '◦', col = '#556655';
    let label = s;
    const urnMatch = s.match(/:(?:device|service):([^:]+)/i);
    if (urnMatch)          label = urnMatch[1];
    else { const m = s.match(/^_([^.]+)\./); if (m) label = m[1]; }
    if (label.length > 20) label = label.slice(0, 20);

    for (const m of _SVC_MAP) {
      if (m.re.test(s)) {
        icon  = m.icon;
        col   = m.col;
        label = _parseSvcLabel(s, m);
        break;
      }
    }

    return `<span style="display:inline-flex;align-items:center;gap:2px;`
         + `background:${col}12;border:1px solid ${col}55;border-radius:3px;`
         + `padding:1px 5px;margin:1px 1px 2px;font-size:.58rem;color:${col};`
         + `cursor:default;white-space:nowrap" title="${esc(s)}">${icon} ${esc(label)}</span>`;
  }).join('');

  const more = services.length > 7
    ? `<span style="color:var(--textdim);font-size:.55rem"> +${services.length - 7}</span>`
    : '';
  return chips + more;
}

function rttClass(r) {
  if (r <= 2)   return 'rtt-0';
  if (r <= 10)  return 'rtt-1';
  if (r <= 30)  return 'rtt-2';
  if (r <= 60)  return 'rtt-3';
  if (r <= 120) return 'rtt-4';
  return 'rtt-5';
}

function badgeClass(role) {
  if (role === 'GATEWAY/ROUTER') return 'badge-gw';
  if (role === 'DNS SERVER')     return 'badge-dns';
  if (role === 'THIS HOST')      return 'badge-me';
  return 'badge-host';
}

function fmtTags(tags) {
  if (!tags || !tags.length) return '';
  return tags.map(t => {
    const cls = t === 'DNS1' ? 'badge-tag-dns1'
              : t === 'DNS2' ? 'badge-tag-dns2'
              : t === 'DHCP' ? 'badge-tag-dhcp'
              : 'badge-tag-other';
    return `<span class="badge-tag ${cls}">${t}</span>`;
  }).join('');
}

function rowClass(role) {
  if (role === 'GATEWAY/ROUTER') return 'row-gw';
  if (role === 'DNS SERVER')     return 'row-dns';
  if (role === 'THIS HOST')      return 'row-me';
  return '';
}

// ── Game of Life — header background ────────────────────────────────────────
(function golInit() {
  const canvas = document.getElementById('gol-canvas');
  if (!canvas) return;
  const ctx  = canvas.getContext('2d');
  const CELL = 6;        // px per cell
  const TICK = 130;      // ms between generations
  const FILL = '#00ff41';

  let cols, rows, grid;

  function resize() {
    const hdr = canvas.parentElement;
    canvas.width  = hdr.offsetWidth;
    canvas.height = hdr.offsetHeight;
    cols = Math.max(1, Math.floor(canvas.width  / CELL));
    rows = Math.max(1, Math.floor(canvas.height / CELL));
    grid = new Uint8Array(cols * rows);
    for (let i = 0; i < grid.length; i++) grid[i] = Math.random() < 0.28 ? 1 : 0;
    // warm up
    for (let i = 0; i < 8; i++) step();
  }

  function idx(r, c) {
    return ((r + rows) % rows) * cols + ((c + cols) % cols);
  }

  function step() {
    const next = new Uint8Array(cols * rows);
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        let n = grid[idx(r-1,c-1)] + grid[idx(r-1,c)] + grid[idx(r-1,c+1)]
              + grid[idx(r,  c-1)]                    + grid[idx(r,  c+1)]
              + grid[idx(r+1,c-1)] + grid[idx(r+1,c)] + grid[idx(r+1,c+1)];
        const alive = grid[idx(r, c)];
        next[idx(r, c)] = (alive && (n === 2 || n === 3)) || (!alive && n === 3) ? 1 : 0;
      }
    }
    grid = next;
  }

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = FILL;
    for (let r = 0; r < rows; r++)
      for (let c = 0; c < cols; c++)
        if (grid[idx(r, c)])
          ctx.fillRect(c * CELL + 1, r * CELL + 1, CELL - 2, CELL - 2);
  }

  // Re-seed if population collapses (< 2%)
  function maybeReseed() {
    const alive = grid.reduce((s, v) => s + v, 0);
    if (alive < cols * rows * 0.02) {
      for (let i = 0; i < grid.length; i++) grid[i] = Math.random() < 0.28 ? 1 : 0;
    }
  }

  let lastTick = 0;
  let tickCount = 0;
  function loop(ts) {
    requestAnimationFrame(loop);
    if (ts - lastTick < TICK) return;
    lastTick = ts;
    step();
    draw();
    if (++tickCount % 50 === 0) maybeReseed();
  }

  window.addEventListener('resize', resize);
  resize();
  draw();
  requestAnimationFrame(loop);
})();

function ipToInt(ip) {
  if (!ip) return 0;
  // IPv6 — sort lexicographically (after stripping scope)
  if (ip.includes(':')) return ip.split('%')[0];
  const p = ip.split('.');
  if (p.length !== 4) return 0;
  return p.reduce((a, b) => a * 256 + parseInt(b, 10), 0);
}

function _durStr(ms) {
  const s = Math.round(ms / 1000);
  if (s < 60)  return `${s}s`;
  if (s < 3600) return `${Math.floor(s/60)}m ${s%60}s`;
  return `${Math.floor(s/3600)}h ${Math.floor((s%3600)/60)}m`;
}

// ══════════════════════════════════════════════════════════════════════════════
// TAB: RISK
// ══════════════════════════════════════════════════════════════════════════════

let _riskData   = null;
let _riskFilter = 'ALL';

async function loadRisk() {
  try {
    _riskData = await apiFetch('/risk');
    _renderRiskSummary(_riskData);
    _renderRiskList();
  } catch(e) {
    document.getElementById('riskList').innerHTML =
      `<p style="color:var(--red);text-align:center">${esc(String(e))}</p>`;
    console.error('loadRisk', e);
  }
}

function setRiskFilter(btn, level) {
  document.querySelectorAll('#risk-filter-btns .fbtn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  _riskFilter = level;
  _renderRiskList();
}

function _renderRiskSummary(data) {
  const summary = document.getElementById('riskSummary');
  summary.classList.remove('hidden');

  const ns = data.network_score || 0;
  document.getElementById('riskNetGauge').innerHTML =
    _riskGaugeSvg(ns, _riskColor(ns), 52, 52, 21, 6, 10);

  const counts = data.level_counts || {};
  const order  = ['CRITICAL','HIGH','MEDIUM','LOW','MINIMAL'];
  document.getElementById('riskLevelCounts').innerHTML = order.map(lv => {
    const n   = counts[lv] || 0;
    const col = _riskLevelColor(lv);
    return `<div class="risk-count-pill" style="border-color:${col}44;background:${col}11">
      <span class="risk-count-num" style="color:${col}">${n}</span>
      <span class="risk-count-lbl" style="color:${col}">${lv}</span>
    </div>`;
  }).join('');
}

function _renderRiskList() {
  if (!_riskData) return;
  const devices = _riskData.devices || [];
  const visible = _riskFilter === 'ALL'
    ? devices
    : devices.filter(d => d.level === _riskFilter);

  document.getElementById('risk-total').textContent =
    `${visible.length} / ${devices.length} devices`;

  document.getElementById('riskList').innerHTML =
    visible.length === 0
      ? '<p style="color:var(--textdim);text-align:center;padding:2rem">No devices matching filter</p>'
      : visible.map(_renderRiskCard).join('');
}

function _renderRiskCard(d) {
  const col   = _riskLevelColor(d.level);
  const cats  = d.category_scores || {};
  const gauge = _riskGaugeSvg(d.score, col, 64, 64, 26, 6, 11);

  const catDefs = [
    { key: 'ports',   label: 'Ports',   cap: 60 },
    { key: 'role',    label: 'Role',    cap: 30 },
    { key: 'os',      label: 'OS/EoL',  cap: 45 },
    { key: 'surface', label: 'Surface', cap: 20 },
    { key: 'flags',   label: 'Flags',   cap: 20 },
  ];
  const catBars = catDefs.map(c => {
    const v   = cats[c.key] || 0;
    const pct = Math.round((v / c.cap) * 100);
    return v === 0 ? '' : `
      <div class="risk-cat-row">
        <span class="risk-cat-lbl">${c.label}</span>
        <div class="risk-cat-bar-track">
          <div class="risk-cat-bar-fill" style="width:${pct}%;background:${col}"></div>
        </div>
        <span class="risk-cat-val" style="color:${col}">${v}</span>
      </div>`;
  }).filter(Boolean).join('');

  const fItems = (d.findings || []).map(f => {
    const fc = _riskSevColor(f.severity);
    return `<li class="risk-finding">
      <span class="risk-sev-dot" style="background:${fc}"></span>${esc(f.text)}
    </li>`;
  }).join('');

  const more = '';  // show all findings

  const name   = esc(d.alias || d.last_hostname || d.last_ip || '—');
  const alias  = esc(d.alias || '');
  const hn     = esc(d.last_hostname || '');
  const ip     = esc(d.last_ip || '—');
  const mac    = esc(d.mac || '—');
  const vendor = esc(d.last_vendor || '');
  const role   = esc(d.last_role || '');

  return `<div class="risk-card" style="border-color:${col}44">
  <div class="risk-card-left">
    ${gauge}
    <div class="risk-level-badge" style="color:${col};border-color:${col}">${esc(d.level)}</div>
    <div class="risk-score-pts" style="color:${col}">${d.score} pts</div>
  </div>
  <div class="risk-card-body">
    <div class="risk-dev-name">${name}</div>
    <div class="risk-dev-meta">
      ${ alias && hn ? `<span class="risk-meta-chip">${hn}</span>` : '' }
      <span class="risk-meta-chip">${ip}</span>
      <span class="risk-meta-chip" style="color:var(--textdim);font-size:.58rem">${mac}</span>
      ${ vendor ? `<span class="risk-meta-chip" style="color:var(--textdim)">${vendor}</span>` : '' }
      ${ role   ? `<span class="risk-meta-chip" style="color:var(--blue)">${role}</span>` : '' }
    </div>
    ${ catBars ? `<div class="risk-cats">${catBars}</div>` : '' }
    ${ fItems  ? `<ul class="risk-findings-list">${fItems}${more}</ul>` : '' }
  </div>
</div>`;
}

function _riskGaugeSvg(score, color, w, h, r, sw, fs) {
  const cx = w / 2, cy = h / 2;
  const circ   = 2 * Math.PI * r;
  const filled = Math.min(score, 100) / 100 * circ;
  const gap    = circ - filled;
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" class="risk-gauge-svg">
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none"
      stroke="var(--border)" stroke-width="${sw}"/>
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none"
      stroke="${color}" stroke-width="${sw}"
      stroke-dasharray="${filled.toFixed(1)} ${gap.toFixed(1)}"
      stroke-linecap="round"
      transform="rotate(-90 ${cx} ${cy})"/>
    <text x="${cx}" y="${cy}" text-anchor="middle" dominant-baseline="central"
      font-family="Orbitron,monospace" font-size="${fs}" fill="${color}">${score}</text>
  </svg>`;
}

function _riskColor(score) {
  if (score >= 75) return 'var(--red)';
  if (score >= 50) return 'var(--amber)';
  if (score >= 25) return '#ffcc00';
  if (score >= 10) return 'var(--green)';
  return 'var(--textdim)';
}

function _riskLevelColor(level) {
  const map = { CRITICAL:'var(--red)', HIGH:'var(--amber)', MEDIUM:'#ffcc00', LOW:'var(--green)', MINIMAL:'var(--textdim)' };
  return map[level] || 'var(--green)';
}

function _riskSevColor(sev) {
  const map = { critical:'var(--red)', high:'var(--amber)', medium:'#ffcc00', low:'var(--green)', info:'var(--textdim)' };
  return map[sev] || 'var(--textdim)';
}
