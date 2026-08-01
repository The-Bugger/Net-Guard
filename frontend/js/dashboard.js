/**
 * dashboard.js — Main dashboard KPIs, live updates, and SocketIO event handlers.
 *
 * Requirements: 16.1, 16.8, 16.10, 16.11
 */

// ── State ─────────────────────────────────────────────────────────────────
let recentEvents = [];
let selectedEventId = null;
let pollingInterval = null;

// ── Initialisation ────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  initTrafficChart('traffic-chart');
  initSeverityChart('severity-chart');

  await loadDashboard();
  startClock();

  // SocketIO events
  SocketManager.on('new_threat',        onNewThreat);
  SocketManager.on('ip_blocked',        onIpBlocked);
  SocketManager.on('ip_unblocked',      onIpUnblocked);
  SocketManager.on('live_stats',        onLiveStats);
  SocketManager.on('monitoring_status', onMonitoringStatus);

  SocketManager.connect();

  // Fallback polling if SocketIO unavailable
  startFallbackPolling();
});

// ── Load initial dashboard data ────────────────────────────────────────────
async function loadDashboard() {
  try {
    const data = await NetGuardAPI.getDashboard();
    updateKPIs(data);
    updateMonitoringStatus(data.monitoring, data.interface);

    recentEvents = data.recent_events || [];
    renderThreatTimeline(recentEvents);
    renderActiveBlocks(data.active_blocks || []);
    renderWhitelistPanel(data.whitelist || []);

    if (data.attack_type_counts) {
      const counts = { Low: 0, Medium: 0, High: 0, Critical: 0 };
      (data.recent_events || []).forEach(e => {
        if (counts[e.severity] !== undefined) counts[e.severity]++;
      });
      setSeverityCounts(counts);
    }
  } catch (err) {
    console.error('Failed to load dashboard:', err);
  }
}

// ── KPI Updates ────────────────────────────────────────────────────────────
function updateKPIs(data) {
  setKPI('kpi-packets',   fmtNumber(data.packets || data.packets_processed || 0));
  setKPI('kpi-alerts',    fmtNumber(data.alerts_today || data.alerts || 0));
  setKPI('kpi-blocked',   fmtNumber(data.blocked_ips || 0));
  setKPI('kpi-pps',       (data.traffic_rate || 0).toFixed(1));
}

function setKPI(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function fmtNumber(n) {
  return Number(n || 0).toLocaleString();
}

// ── Monitoring Status ──────────────────────────────────────────────────────
function updateMonitoringStatus(active, iface) {
  const badge = document.getElementById('monitoring-badge');
  const ifaceEl = document.getElementById('current-interface');
  if (badge) {
    badge.className = `status-badge ${active ? 'active' : 'inactive'}`;
    badge.innerHTML = `
      <span class="status-dot"></span>
      ${active ? 'Monitoring Active' : 'Monitoring Stopped'}
    `;
  }
  if (ifaceEl && iface) ifaceEl.textContent = iface;
}

// ── Threat Timeline ────────────────────────────────────────────────────────
function renderThreatTimeline(events) {
  const tbody = document.getElementById('threat-tbody');
  if (!tbody) return;

  if (!events.length) {
    tbody.innerHTML = `
      <tr><td colspan="6" class="empty-state">
        <p>No threats detected yet.</p>
      </td></tr>`;
    return;
  }

  tbody.innerHTML = events.slice(0, 20).map(e => `
    <tr data-event-id="${e.event_id}" onclick="toggleEvidence('${e.event_id}')">
      <td>${fmtTime(e.timestamp)}</td>
      <td>${escHtml(e.attack_type)}</td>
      <td><code>${escHtml(e.source_ip)}</code></td>
      <td><span class="severity-badge severity-${(e.severity||'').toLowerCase()}">${e.severity||''}</span></td>
      <td>
        <div class="confidence-bar">
          <div class="confidence-track"><div class="confidence-fill" style="width:${e.confidence||0}%"></div></div>
          <span>${e.confidence||0}%</span>
        </div>
      </td>
      <td><span class="badge ${e.blocked ? 'blocked' : ''}">${e.blocked ? '🔴 Blocked' : '👁 Detected'}</span></td>
    </tr>
    <tr id="evidence-row-${e.event_id}" style="display:none">
      <td colspan="6">
        <div class="evidence-panel" id="evidence-${e.event_id}">Loading…</div>
      </td>
    </tr>
  `).join('');
}

async function toggleEvidence(eventId) {
  const row = document.getElementById(`evidence-row-${eventId}`);
  if (!row) return;

  if (row.style.display !== 'none') {
    row.style.display = 'none';
    return;
  }

  row.style.display = '';
  const panel = document.getElementById(`evidence-${eventId}`);
  if (!panel || panel.textContent !== 'Loading…') return;

  try {
    const ev = await NetGuardAPI.getEvidence(eventId);
    panel.innerHTML = renderEvidencePanel(ev);
  } catch (err) {
    panel.innerHTML = `<p style="color:var(--danger)">Failed to load evidence: ${escHtml(err.message)}</p>`;
  }
}

function renderEvidencePanel(ev) {
  return `
    <div class="evidence-grid">
      <div class="evidence-field"><label>Attack</label><span>${escHtml(ev.attack_name||'')}</span></div>
      <div class="evidence-field"><label>Rule</label><span>${escHtml(ev.rule_triggered||'')}</span></div>
      <div class="evidence-field"><label>Source IP</label><span><code>${escHtml(ev.source_ip||'')}</code></span></div>
      <div class="evidence-field"><label>Severity</label>
        <span class="severity-badge severity-${(ev.severity||'').toLowerCase()}">${ev.severity||''}</span>
      </div>
      <div class="evidence-field"><label>Confidence</label><span>${ev.confidence_score||0}%</span></div>
      <div class="evidence-field"><label>Timestamp</label><span>${escHtml(ev.timestamp||'')}</span></div>
    </div>
    <div class="evidence-explanation">${escHtml(ev.plain_english_text||'')}</div>
    <div class="evidence-recommendation">
      <strong>Recommendation:</strong> ${escHtml(ev.recommendation||'')}
    </div>
  `;
}

// ── Active Blocks ──────────────────────────────────────────────────────────
function renderActiveBlocks(blocks) {
  const tbody = document.getElementById('blocks-tbody');
  if (!tbody) return;

  if (!blocks.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state"><p>No active blocks.</p></td></tr>`;
    return;
  }

  tbody.innerHTML = blocks.map(b => `
    <tr>
      <td><code>${escHtml(b.ip_address)}</code></td>
      <td>${escHtml(b.reason)}</td>
      <td>${fmtTime(b.blocked_at)}</td>
      <td>${b.expires_in !== undefined ? b.expires_in + 's' : '—'}</td>
      <td>
        <button class="btn btn-danger btn-sm" onclick="manualUnblock('${escHtml(b.ip_address)}')">
          Unblock
        </button>
      </td>
    </tr>
  `).join('');
}

async function manualUnblock(ip) {
  if (!confirm(`Unblock ${ip}?`)) return;
  try {
    await NetGuardAPI.unblockIP(ip);
    showNotification(`${ip} unblocked.`, 'success');
    await loadDashboard();
  } catch (err) {
    showNotification(`Failed to unblock ${ip}: ${err.message}`, 'error');
  }
}

// ── Whitelist Panel ────────────────────────────────────────────────────────
function renderWhitelistPanel(entries) {
  const list = document.getElementById('whitelist-list');
  if (!list) return;
  if (!entries.length) {
    list.innerHTML = '<p class="empty-state"><p>Whitelist is empty.</p></p>';
    return;
  }
  list.innerHTML = entries.map(e => `
    <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)">
      <code style="flex:1">${escHtml(e.ip_address)}</code>
      <span style="color:var(--text-muted);font-size:12px">${escHtml(e.description||'')}</span>
      <button class="btn btn-ghost btn-sm" onclick="removeWhitelist('${escHtml(e.ip_address)}')">Remove</button>
    </div>
  `).join('');
}

async function addToWhitelist() {
  const ipEl  = document.getElementById('wl-ip-input');
  const descEl = document.getElementById('wl-desc-input');
  if (!ipEl) return;
  const ip   = ipEl.value.trim();
  const desc = descEl ? descEl.value.trim() : '';
  if (!ip) return;
  try {
    await NetGuardAPI.addWhitelist(ip, desc);
    ipEl.value = '';
    if (descEl) descEl.value = '';
    showNotification(`${ip} added to whitelist.`, 'success');
    await loadDashboard();
  } catch (err) {
    showNotification(`Failed: ${err.message}`, 'error');
  }
}

async function removeWhitelist(ip) {
  try {
    await NetGuardAPI.removeWhitelist(ip);
    showNotification(`${ip} removed from whitelist.`, 'success');
    await loadDashboard();
  } catch (err) {
    showNotification(`Failed: ${err.message}`, 'error');
  }
}

// ── SocketIO Event Handlers ────────────────────────────────────────────────
function onNewThreat(event) {
  // Prepend to recent events list
  recentEvents.unshift(event);
  if (recentEvents.length > 20) recentEvents.pop();
  renderThreatTimeline(recentEvents);

  // Update severity chart
  updateSeverityChart(event.severity);

  // Show notification
  const sev = (event.severity || '').toLowerCase();
  showNotification(`${event.severity} ${event.attack_type} from ${event.source_ip}`, sev === 'critical' ? 'critical' : 'warning');

  // Refresh KPI counts
  loadDashboard();
}

function onIpBlocked(data) {
  loadDashboard();
  showNotification(`🔴 ${data.ip} blocked — ${data.reason}`, 'warning');
}

function onIpUnblocked(data) {
  loadDashboard();
  showNotification(`✅ ${data.ip} unblocked`, 'success');
}

function onLiveStats(data) {
  updateTrafficChart(data.packets_per_second || 0);
  setKPI('kpi-pps', (data.packets_per_second || 0).toFixed(1));
  setKPI('kpi-alerts', fmtNumber(data.alerts_today || 0));
  setKPI('kpi-blocked', fmtNumber(data.active_threats || 0));
}

function onMonitoringStatus(data) {
  updateMonitoringStatus(data.active, data.interface || '');
}

// ── Fallback polling ───────────────────────────────────────────────────────
function startFallbackPolling() {
  // If SocketIO connects, stop polling
  SocketManager.on('connect', () => {
    if (pollingInterval) { clearInterval(pollingInterval); pollingInterval = null; }
  });

  // Start polling after 3s in case SocketIO doesn't connect
  setTimeout(() => {
    if (!pollingInterval) {
      pollingInterval = setInterval(async () => {
        try {
          const data = await NetGuardAPI.getLiveStats();
          onLiveStats(data);
        } catch (_) {}
      }, 1000);
    }
  }, 3000);
}

// ── Monitor start/stop buttons ─────────────────────────────────────────────
async function startMonitoring() {
  const ifaceEl = document.getElementById('interface-select');
  const iface = ifaceEl ? ifaceEl.value : '';
  if (!iface) { showNotification('Select a network interface first.', 'warning'); return; }
  try {
    await NetGuardAPI.startMonitoring(iface);
    showNotification('Monitoring started.', 'success');
    updateMonitoringStatus(true, iface);
  } catch (err) {
    showNotification(`Failed: ${err.message}`, 'error');
  }
}

async function stopMonitoring() {
  try {
    await NetGuardAPI.stopMonitoring();
    showNotification('Monitoring stopped.', 'success');
    updateMonitoringStatus(false, '');
  } catch (err) {
    showNotification(`Failed: ${err.message}`, 'error');
  }
}

async function loadInterfaces() {
  const sel = document.getElementById('interface-select');
  if (!sel) return;
  try {
    const data = await NetGuardAPI.getInterfaces();
    const ifaces = data.interfaces || [];
    sel.innerHTML = ifaces.map(i => `<option value="${escHtml(i)}">${escHtml(i)}</option>`).join('');
  } catch (_) {}
}

// ── Utilities ──────────────────────────────────────────────────────────────
function fmtTime(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleTimeString();
  } catch (_) { return ts; }
}

function escHtml(str) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(String(str || '')));
  return d.innerHTML;
}

function startClock() {
  const el = document.getElementById('system-time');
  if (!el) return;
  const tick = () => { el.textContent = new Date().toLocaleTimeString(); };
  tick();
  setInterval(tick, 1000);
}

// ── Notifications ──────────────────────────────────────────────────────────
function showNotification(message, type = 'success') {
  const container = document.getElementById('notifications');
  if (!container) return;

  const el = document.createElement('div');
  el.className = `notification ${type}`;
  el.textContent = message;
  container.appendChild(el);

  const timeout = type === 'critical' ? 0 : 5000;
  if (timeout) setTimeout(() => el.remove(), timeout);
}
