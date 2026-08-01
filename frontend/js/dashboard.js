/**
 * dashboard.js — Main dashboard KPIs, live updates, and SocketIO event handlers.
 *
 * Requirements: 3.2, 3.6, 3.9, 13.3, 16.1, 16.8, 16.10, 16.11
 */

// ── State ─────────────────────────────────────────────────────────────────
let recentEvents = [];
let selectedEventId = null;
let pollingInterval = null;
let socketConnected = false;       // tracks SocketIO connection for countUp gating (Req 3.2)
let activityFeed = [];             // max 10 entries (Req 3.3)

// ── countUp animation (Req 3.2) ───────────────────────────────────────────
/**
 * Animate a numeric KPI element from `from` to `to` over `durationMs`.
 * Only animates when SocketIO is connected; skips straight to final when polling.
 * @param {HTMLElement} el
 * @param {number} from
 * @param {number} to
 * @param {number} [durationMs=600]
 */
function countUp(el, from, to, durationMs = 600) {
  if (!el) return;
  if (!socketConnected || durationMs <= 0) { el.textContent = to.toLocaleString(); return; }
  const start = performance.now();
  const delta = to - from;
  function step(now) {
    const t = Math.min((now - start) / durationMs, 1);
    el.textContent = Math.round(from + delta * t).toLocaleString();
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ── Initialisation ────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  initTrafficChart('traffic-chart');
  initSeverityChart('severity-chart');

  await loadDashboard();
  startClock();
  startHealthPolling();
  startRecentIncidentsRefresh();
  loadLanDevices();
  loadAdvisor();
  if (!_advisorTimer) _advisorTimer = setInterval(loadAdvisor, 30000);

  // Track SocketIO connection state for countUp gating
  SocketManager.on('connect',    () => { socketConnected = true;  _hideReconnectingBanner(); stopFallbackPolling(); });
  SocketManager.on('disconnect', () => { socketConnected = false; _showReconnectingBanner(); startFallbackPolling(); });

  // SocketIO events
  SocketManager.on('new_threat',        onNewThreat);
  SocketManager.on('ip_blocked',        onIpBlocked);
  SocketManager.on('ip_unblocked',      onIpUnblocked);
  SocketManager.on('live_stats',        onLiveStats);
  SocketManager.on('monitoring_status', onMonitoringStatus);

  SocketManager.connect();

  // Fallback polling if SocketIO unavailable (Req 3.6)
  startFallbackPolling();

  // Keyboard shortcuts (Req 13.3, Task 29)
  document.addEventListener('keydown', e => {
    // Ctrl+Shift+P / Cmd+Shift+P — fullscreen toggle
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'P') {
      e.preventDefault();
      if (document.fullscreenElement) {
        document.exitFullscreen();
      } else {
        document.documentElement.requestFullscreen().catch(err => {
          showToast(`Fullscreen denied: ${err.message}`, 'warning', 4000);
        });
      }
      return;
    }

    // Ctrl+/ — toggle keyboard shortcuts help modal
    if ((e.ctrlKey || e.metaKey) && e.key === '/') {
      e.preventDefault();
      const modal = document.getElementById('shortcuts-modal');
      if (modal) modal.style.display = modal.style.display === 'flex' ? 'none' : 'flex';
      return;
    }

    // Esc — close any open modal
    if (e.key === 'Escape') {
      const modal = document.getElementById('shortcuts-modal');
      if (modal) modal.style.display = 'none';
      return;
    }

    // D — focus detections search (not when typing in an input)
    if (e.key === 'd' || e.key === 'D') {
      const tag = document.activeElement?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
      e.preventDefault();
      document.getElementById('search-input')?.focus();
    }
  });
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

  // New KPI cards (Req 3.1)
  if (data.blocked_ips_total !== undefined) setKPI('kpi-blocked-total', fmtNumber(data.blocked_ips_total));
  if (data.detection_accuracy !== undefined) {
    setKPI('kpi-accuracy', Math.round(data.detection_accuracy) + '%');
    updateAccuracyRing(data.detection_accuracy);
  } else if (data.total_events && data.blocked_count !== undefined) {
    const acc = data.total_events > 0 ? Math.round((data.blocked_count / data.total_events) * 100) : 0;
    setKPI('kpi-accuracy', acc + '%');
    updateAccuracyRing(acc);
  }
  updateHealthScore(data.health_score);
}

// ── Health Score (Req 3.6) ─────────────────────────────────────────────────
function updateHealthScore(score) {
  const el = document.getElementById('kpi-health');
  if (!el) return;
  if (score === undefined || score === null || score === -1) { el.textContent = '—'; el.style.color = ''; return; }
  el.textContent = score;
  el.style.color = score < 50 ? 'var(--danger)' : score < 80 ? 'var(--warning)' : 'var(--success)';
  drawHealthGauge(score);
  // gauge label
  const gl = document.getElementById('gauge-label');
  if (gl) { gl.textContent = score; gl.style.color = el.style.color; }
}

// ── Severity Gauge — canvas arc (Req 3.6 / Task 31) ───────────────────────
function drawHealthGauge(score) {
  const canvas = document.getElementById('severity-gauge');
  if (!canvas || !canvas.getContext) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  const cx = W / 2, cy = H - 10, r = Math.min(W, H * 2) * 0.42;
  const startAngle = Math.PI, endAngle = 2 * Math.PI;

  // Track
  ctx.beginPath();
  ctx.arc(cx, cy, r, startAngle, endAngle);
  ctx.strokeStyle = 'rgba(255,255,255,0.1)';
  ctx.lineWidth = 14;
  ctx.lineCap = 'round';
  ctx.stroke();

  // Fill — colour by threshold
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const fillEnd = startAngle + pct * Math.PI;
  const color = score < 50 ? '#F87171' : score < 80 ? '#FACC15' : '#4ADE80';
  ctx.beginPath();
  ctx.arc(cx, cy, r, startAngle, fillEnd);
  ctx.strokeStyle = color;
  ctx.lineWidth = 14;
  ctx.lineCap = 'round';
  ctx.stroke();
}

// ── Detection Accuracy Ring (Req 3.1 / Task 31) ────────────────────────────
function updateAccuracyRing(pct) {
  const ring = document.getElementById('accuracy-ring');
  const label = document.getElementById('ring-value');
  if (!ring) return;
  const r = 50;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - Math.max(0, Math.min(100, pct)) / 100);
  ring.style.strokeDasharray = `${circ}`;
  ring.style.strokeDashoffset = offset;
  if (label) label.textContent = Math.round(pct) + '%';
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
      <td onclick="event.stopPropagation()">
        <button class="btn btn-ghost btn-sm" onclick="replayEvent('${escHtml(e.event_id)}')">↺ Replay</button>
      </td>
    </tr>
    <tr id="evidence-row-${e.event_id}" style="display:none">
      <td colspan="7">
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

// ── Activity Feed (Req 3.3) ────────────────────────────────────────────────
function severityColor(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical' || s === 'high') return '#F87171';
  if (s === 'medium') return '#FACC15';
  return '#4ADE80';
}

function prependActivityFeed(type, event) {
  const ts = fmtTime(event.timestamp || event.blocked_at || new Date().toISOString());
  const label = type === 'new_threat'   ? (event.attack_type || 'Threat')
              : type === 'ip_blocked'   ? `Blocked: ${event.ip || ''}`
              :                           `Unblocked: ${event.ip || ''}`;
  const sev = event.severity || (type === 'ip_blocked' ? 'High' : 'Low');
  const color = severityColor(sev);

  activityFeed.unshift({ ts, label, sev, color, type });
  if (activityFeed.length > 10) activityFeed.pop();
  renderActivityFeed();
}

function renderActivityFeed() {
  const feed = document.getElementById('activity-feed');
  if (!feed) return;
  if (!activityFeed.length) {
    feed.innerHTML = '<p style="color:var(--text-muted);font-size:13px;text-align:center;padding:20px 0">Waiting for events\u2026</p>';
    return;
  }
  feed.innerHTML = activityFeed.map(e => `
    <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid rgba(51,65,85,0.4)">
      <span style="font-size:11px;color:var(--text-muted);flex-shrink:0">${escHtml(e.ts)}</span>
      <span style="flex:1;font-size:13px">${escHtml(e.label)}</span>
      <span style="background:${e.color};color:#000;font-size:11px;font-weight:600;padding:2px 8px;border-radius:10px;flex-shrink:0">${escHtml(e.sev)}</span>
    </div>
  `).join('');
}

// ── Status Badges (Req 3.8) ────────────────────────────────────────────────
function updateStatusBadges(monitoringActive, aiAvailable) {
  _setBadge('badge-monitoring', monitoringActive, 'Monitoring Active', 'Monitoring Stopped');
  _setBadge('badge-ai',         aiAvailable,      'AI Available',      'AI Unavailable');
}

function _setBadge(id, active, labelOn, labelOff) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = `status-badge ${active ? 'active' : 'inactive'}`;
  el.innerHTML = `<span class="status-dot"></span> ${active ? labelOn : labelOff}`;
}

// ── System Health polling (Req 3.4) ────────────────────────────────────────
let _healthPollTimer = null;

function startHealthPolling() {
  if (_healthPollTimer) return;   // already running
  pollSystemHealth();             // immediate first call
  _healthPollTimer = setInterval(pollSystemHealth, 10000);  // every 10 s
}

async function pollSystemHealth() {
  try {
    const resp = await fetch('/api/v1/status');
    if (!resp.ok) return;
    const json = await resp.json();
    const d = json.data || json;

    setKPI('sys-cpu',        d.cpu_percent !== undefined ? Math.round(d.cpu_percent) + '%' : '—');
    setKPI('sys-mem',        d.memory_percent !== undefined ? Math.round(d.memory_percent) + '%' : '—');
    setKPI('sys-uptime',     d.uptime || '—');
    setKPI('sys-monitoring', d.monitoring ? '✅ Active' : '⏹ Stopped');

    const ts = document.getElementById('health-refresh-ts');
    if (ts) ts.textContent = 'Updated ' + new Date().toLocaleTimeString();

    if (d.health_score !== undefined) updateHealthScore(d.health_score);

    const monActive = !!(d.monitoring);
    updateStatusBadges(monActive, d.ai_available !== false);
  } catch (_) {}
}

// ── SocketIO Event Handlers ────────────────────────────────────────────────
function onNewThreat(event) {
  // Prepend to recent events list
  recentEvents.unshift(event);
  if (recentEvents.length > 20) recentEvents.pop();
  renderThreatTimeline(recentEvents);

  // Activity feed (Req 3.3)
  prependActivityFeed('new_threat', event);

  // Update severity chart
  updateSeverityChart(event.severity);

  // Show notification
  const sev = (event.severity || '').toLowerCase();
  showNotification(`${event.severity} ${event.attack_type} from ${event.source_ip}`, sev === 'critical' ? 'critical' : 'warning');

  // Refresh KPI counts
  loadDashboard();

  // Re-fetch advisor on new threat (Req 10.7)
  loadAdvisor();
}

function onIpBlocked(data) {
  prependActivityFeed('ip_blocked', data);
  loadDashboard();
  showNotification(`🔴 ${data.ip} blocked — ${data.reason}`, 'warning');
}

function onIpUnblocked(data) {
  prependActivityFeed('ip_unblocked', data);
  loadDashboard();
  showNotification(`✅ ${data.ip} unblocked`, 'success');
}

function onLiveStats(data) {
  updateTrafficChart(data.packets_per_second || 0);
  setKPI('kpi-pps', (data.packets_per_second || 0).toFixed(1));
  setKPI('kpi-alerts', fmtNumber(data.alerts_today || 0));
  setKPI('kpi-blocked', fmtNumber(data.active_threats || 0));
  if (data.health_score !== undefined) updateHealthScore(data.health_score);
}

function onMonitoringStatus(data) {
  updateMonitoringStatus(data.active, data.interface || '');
  _setBadge('badge-monitoring', data.active, 'Monitoring Active', 'Monitoring Stopped');
  // Start or stop the demo simulator based on mode flag
  if (data.active && data.mode === 'simulation') {
    _startDemoSimulator();
  } else if (!data.active) {
    _stopDemoSimulator();
  }
}

// ── Reconnecting banner helpers ────────────────────────────────────────────
function _showReconnectingBanner() {
  const b = document.getElementById('reconnecting-banner');
  if (b) b.classList.add('visible');
}
function _hideReconnectingBanner() {
  const b = document.getElementById('reconnecting-banner');
  if (b) b.classList.remove('visible');
}

// ── Fallback polling ───────────────────────────────────────────────────────
function startFallbackPolling() {
  // Start polling after 3s in case SocketIO doesn't connect (Req 3.9 — 2-second interval)
  setTimeout(() => {
    if (!pollingInterval) {
      pollingInterval = setInterval(async () => {
        try {
          const data = await NetGuardAPI.getLiveStats();
          onLiveStats(data);
        } catch (_) {}
      }, 2000);
    }
  }, 3000);
}

function stopFallbackPolling() {
  if (pollingInterval) { clearInterval(pollingInterval); pollingInterval = null; }
}

// ── Monitor start/stop buttons ─────────────────────────────────────────────
async function startMonitoring() {
  const ifaceEl = document.getElementById('interface-select');
  const iface = ifaceEl ? ifaceEl.value : '';
  if (!iface) { showNotification('Select a network interface first.', 'warning'); return; }
  const btn = document.querySelector('button[onclick="startMonitoring()"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Starting…'; }
  try {
    await NetGuardAPI.startMonitoring(iface);
    showNotification('Monitoring started.', 'success');
    updateMonitoringStatus(true, iface);
  } catch (err) {
    // 409 = already monitoring — that's fine, just update badge
    if (err.code === 409 || (err.message && err.message.includes('already'))) {
      updateMonitoringStatus(true, iface);
      showNotification('Monitoring is already active.', 'info');
    } else {
      showNotification(`Failed to start: ${err.message}`, 'error');
    }
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = '▶ Start Monitoring'; }
  }
}

async function stopMonitoring() {
  const btn = document.querySelector('button[onclick="stopMonitoring()"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Stopping…'; }
  try {
    // Stop simulator immediately — don't wait for the API response
    _stopDemoSimulator();
    updateMonitoringStatus(false, '');
    _setBadge('badge-monitoring', false, 'Monitoring Active', 'Monitoring Stopped');
    setKPI('kpi-pps', '0.0');

    await NetGuardAPI.stopMonitoring();
    showNotification('Monitoring stopped.', 'success');
  } catch (err) {
    if (err.code === 409 || (err.message && err.message.includes('not active'))) {
      // Was already stopped — badge already updated above, no error shown
    } else {
      showNotification(`Failed to stop: ${err.message}`, 'error');
    }
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = '⏹ Stop'; }
  }
}

async function loadInterfaces() {
  const sel = document.getElementById('interface-select');
  if (!sel) return;
  try {
    // Use /interfaces (v2) — returns [{name, is_up}, ...] from psutil directly
    const resp = await fetch('/api/v1/interfaces');
    const json = await resp.json();
    const ifaces = (json.data && json.data.interfaces) || [];

    if (!ifaces.length) {
      sel.innerHTML = '<option value="">No interfaces found</option>';
      return;
    }

    // Keep a leading placeholder, then list up-interfaces first
    const up   = ifaces.filter(i => i.is_up  && !i.name.toLowerCase().startsWith('lo'));
    const down = ifaces.filter(i => !i.is_up && !i.name.toLowerCase().startsWith('lo'));
    const sorted = [...up, ...down];

    sel.innerHTML = '<option value="">Select interface…</option>' +
      sorted.map(i => {
        const label = i.is_up ? i.name : `${i.name} (down)`;
        return `<option value="${escHtml(i.name)}" ${!i.is_up ? 'disabled' : ''}>${escHtml(label)}</option>`;
      }).join('');

    // Auto-select first active interface
    if (up.length > 0 && !sel.value) {
      sel.value = up[0].name;
    }
  } catch (err) {
    console.warn('loadInterfaces failed:', err);
    // Fallback to old endpoint
    try {
      const data = await NetGuardAPI.getInterfaces();
      const ifaces = data.interfaces || [];
      sel.innerHTML = '<option value="">Select interface…</option>' +
        ifaces.map(i => `<option value="${escHtml(i)}">${escHtml(i)}</option>`).join('');
    } catch (_) {
      sel.innerHTML = '<option value="">Unable to load interfaces</option>';
    }
  }
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

// ── Quick Actions ──────────────────────────────────────────────────────────
function exportJSON() {
  window.location.href = '/api/v1/export?format=json';
}

function viewAnalytics() {
  window.location.href = '/analytics';
}

// ── Connected Devices (LAN) — Req 11.1, 11.6 ──────────────────────────────
let _devicesTimer = null;

async function loadLanDevices() {
  const container = document.getElementById('lan-devices-list');
  if (!container) return;
  try {
    const data = await api.get('/devices');   // GET /api/v1/devices (Req 11.1)
    renderLanDevices(data.devices || []);
  } catch (_) {
    const el = document.getElementById('lan-devices-list');
    if (el) el.innerHTML = '<p style="color:var(--text-muted);font-size:13px;text-align:center;padding:16px 0">ARP scan requires root on Linux. Start monitoring first.</p>';
  }
  // 30-second auto-refresh (Req 11.6) — start once
  if (!_devicesTimer) _devicesTimer = setInterval(loadLanDevices, 30000);
}

async function refreshLanDevices() {
  const container = document.getElementById('lan-devices-list');
  if (container) container.innerHTML = '<p style="color:var(--text-muted);font-size:13px;text-align:center;padding:16px 0">Scanning…</p>';
  try {
    const data = await api.post('/lan-devices/refresh', {});
    renderLanDevices(data.devices || []);
    showToast(`Found ${data.count} device(s) on LAN.`, 'success', 3000);
  } catch (err) {
    showToast(`LAN scan failed: ${err.message}`, 'warning', 4000);
    loadLanDevices();
  }
}

function renderLanDevices(devices) {
  const container = document.getElementById('lan-devices-list');
  if (!container) return;
  if (!devices.length) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:13px;text-align:center;padding:16px 0">No devices found. Start monitoring and click Scan LAN.</p>';
    return;
  }
  container.innerHTML = `<table class="data-table" style="margin:0">
    <thead><tr><th>IP Address</th><th>MAC Address</th><th>Hostname</th><th>Vendor</th><th>Status</th><th>Last Seen</th></tr></thead>
    <tbody>${devices.map(d => `
      <tr>
        <td><code>${escHtml(d.ip)}</code></td>
        <td><code style="font-size:11px">${escHtml(d.mac || '—')}</code></td>
        <td>${escHtml(d.hostname || '—')}</td>
        <td>${escHtml(d.vendor || '—')}</td>
        <td><span style="color:${d.status === 'up' ? 'var(--success)' : 'var(--text-muted)'}">${escHtml(d.status)}</span></td>
        <td style="font-size:12px;color:var(--text-muted)">${escHtml(d.last_seen ? new Date(d.last_seen).toLocaleTimeString() : '—')}</td>
      </tr>`).join('')}
    </tbody>
  </table>`;
}

// ── AI Assistant Panel (Task 37) ───────────────────────────────────────────
function toggleAIAssistant() {
  const panel = document.getElementById('ai-assistant-panel');
  if (!panel) return;
  const isOpen = panel.style.transform === 'translateY(0)' || panel.style.transform === 'translateY(0px)';
  // ponytail: CSS transform toggle — no class juggling needed
  panel.style.transform = isOpen ? 'translateY(100%)' : 'translateY(0)';
  if (!isOpen) {
    setTimeout(() => document.getElementById('ai-question-input')?.focus(), 320);
  }
}

async function submitAIQuestion() {
  const input = document.getElementById('ai-question-input');
  if (!input) return;
  const question = input.value.trim();
  if (!question) return;

  const messages = document.getElementById('ai-chat-messages');
  if (!messages) return;

  // Show user message
  const userDiv = document.createElement('div');
  userDiv.style.cssText = 'align-self:flex-end;background:var(--accent);color:#000;padding:8px 12px;border-radius:12px 12px 2px 12px;font-size:13px;max-width:80%';
  userDiv.textContent = question;
  messages.appendChild(userDiv);
  input.value = '';
  messages.scrollTop = messages.scrollHeight;

  // Typing indicator
  const typingDiv = document.createElement('div');
  typingDiv.style.cssText = 'color:var(--text-muted);font-size:12px;font-style:italic;padding:4px 0';
  typingDiv.textContent = 'AI is thinking…';
  messages.appendChild(typingDiv);
  messages.scrollTop = messages.scrollHeight;

  try {
    const data = await api.post('/ai-assistant', { question });
    typingDiv.remove();
    const answerDiv = document.createElement('div');
    answerDiv.style.cssText = 'align-self:flex-start;background:rgba(255,255,255,0.05);border:1px solid var(--border);padding:8px 12px;border-radius:2px 12px 12px 12px;font-size:13px;max-width:90%;white-space:pre-wrap';
    answerDiv.textContent = data.answer || 'No response.';
    messages.appendChild(answerDiv);
  } catch (err) {
    typingDiv.remove();
    const errDiv = document.createElement('div');
    errDiv.style.cssText = 'color:var(--danger);font-size:12px;padding:4px 0';
    errDiv.textContent = `Error: ${err.message}`;
    messages.appendChild(errDiv);
  }
  messages.scrollTop = messages.scrollHeight;
}

// ── Replay attack (Task 38) ────────────────────────────────────────────────
async function replayEvent(eventId) {
  try {
    const data = await api.get(`/events/${eventId}/replay`);
    showToast(`✅ Replayed — new event ${data.event_id}`, 'success', 3000);
  } catch (err) {
    showToast(`❌ Replay failed: ${err.message}`, 'error', 5000);
  }
}

// ── Security Advisor (Req 10.7) ───────────────────────────────────────────
let _advisorTimer = null;

async function loadAdvisor() {
  try {
    const resp = await fetch('/api/v1/advisor');
    if (!resp.ok) return;
    const d = await resp.json();
    const badge = document.getElementById('advisor-score-badge');
    const title = document.getElementById('advisor-title');
    const msg   = document.getElementById('advisor-message');
    const list  = document.getElementById('advisor-actions');
    if (badge) {
      badge.className = `badge-${d.badge_color || 'green'}`;
      badge.textContent = (d.score !== undefined ? d.score : '—') + '%';
    }
    if (title) title.textContent = d.title || '';
    if (msg)   msg.textContent   = d.message || '';
    if (list) {
      list.innerHTML = (d.actions || []).map(a => `<li>${escHtml(a)}</li>`).join('');
    }
  } catch (_) {}
}


let _recentIncidentsTimer = null;

function startRecentIncidentsRefresh() {
  loadRecentIncidents();  // immediate
  // ponytail: setInterval at 30s; single timer, guard against double-start
  if (!_recentIncidentsTimer) {
    _recentIncidentsTimer = setInterval(loadRecentIncidents, 30000);
  }
}

async function loadRecentIncidents() {
  const list = document.getElementById('recent-incidents-list');
  if (!list) return;
  try {
    const data = await api.get('/detections?limit=5');
    const events = (data && data.events) || [];
    if (!events.length) {
      list.innerHTML = '<p style="color:var(--text-muted);font-size:13px;text-align:center;padding:12px 0">No recent incidents.</p>';
      return;
    }
    list.innerHTML = `<table class="data-table" style="margin:0">
      <thead><tr><th>Time</th><th>Attack</th><th>Source IP</th><th>Severity</th><th></th></tr></thead>
      <tbody>${events.map(e => `
        <tr>
          <td>${fmtTime(e.timestamp)}</td>
          <td>${escHtml(e.attack_type)}</td>
          <td><code>${escHtml(e.source_ip)}</code></td>
          <td><span class="severity-badge severity-${(e.severity||'').toLowerCase()}">${e.severity||''}</span></td>
          <td><button class="btn btn-ghost btn-sm" onclick="replayEvent('${escHtml(e.event_id)}')">↺ Replay</button></td>
        </tr>`).join('')}
      </tbody></table>`;
  } catch (_) {
    list.innerHTML = '<p style="color:var(--text-muted);font-size:13px;text-align:center;padding:12px 0">Unable to load recent incidents.</p>';
  }
}

// ── Demo Traffic Simulator ─────────────────────────────────────────────────
// Server: Kathmandu, Nepal. 70% Asia-region attackers, 30% global.
// Rate: 20+ attacks per 10 min = avg ~2/min, gaps vary 15-45s.
// Continent rotation: at least one from each continent every ~10 min.

let _simTimer   = null;
let _simPps     = 0;
let _simAlerts  = 0;
let _simPackets = 0;
let _bgTimer    = null;

// ── Attack pool — Asia-centric, Kathmandu as target ───────────────────────
// weight determines relative frequency; Asia combined ~70% of total weight
const _SIM_ATTACK_POOL = [

  // ── ASIA / SOUTH ASIA — heavy (nearby, ~45% of attacks) ──────────────
  { type:'SYN Flood',     sev:'High',     baseConf:88, weight:15, continent:'Asia',
    ips:['103.41.167.21','182.72.180.1','27.251.16.1','49.36.187.45',
         '103.92.45.1','39.32.100.1','202.83.24.1','202.166.196.1'] },
  { type:'Brute Force',   sev:'High',     baseConf:91, weight:14, continent:'Asia',
    ips:['115.112.82.1','49.231.100.1','14.225.196.1','103.168.206.1',
         '91.185.186.1','91.212.68.1','209.58.130.1','118.189.149.1'] },
  { type:'Port Scan',     sev:'Medium',   baseConf:79, weight:12, continent:'Asia',
    ips:['116.228.101.1','183.2.172.1','101.71.57.1','163.177.65.1',
         '203.0.113.42','221.148.18.1','180.214.232.1','194.165.16.11'] },

  // ── CHINA / EAST ASIA (~15% of attacks) ──────────────────────────────
  { type:'SQL Injection', sev:'Critical', baseConf:94, weight:10, continent:'China',
    ips:['203.0.113.99','116.228.101.1','183.2.172.1','163.177.65.1'] },
  { type:'DNS Tunneling', sev:'High',     baseConf:77, weight:6,  continent:'China',
    ips:['101.71.57.1','203.0.113.99','116.228.101.1','183.2.172.1'] },

  // ── SOUTHEAST ASIA (~10% of attacks) ─────────────────────────────────
  { type:'ICMP Flood',    sev:'Medium',   baseConf:72, weight:8,  continent:'SEAsia',
    ips:['203.0.113.200','103.77.4.82','14.225.196.1','49.231.100.1'] },
  { type:'Slow HTTP',     sev:'Medium',   baseConf:68, weight:6,  continent:'SEAsia',
    ips:['118.189.149.1','180.214.232.1','103.77.4.82','203.0.113.200'] },

  // ── MIDDLE EAST (~8% of attacks) ─────────────────────────────────────
  { type:'Brute Force',   sev:'High',     baseConf:85, weight:6,  continent:'MiddleEast',
    ips:['5.42.92.1','185.81.96.1','176.221.97.1'] },
  { type:'ARP Spoofing',  sev:'Critical', baseConf:83, weight:4,  continent:'MiddleEast',
    ips:['5.42.92.1','176.221.97.1','185.81.96.1'] },

  // ── EUROPE (~8% of attacks, lower weight) ────────────────────────────
  { type:'Port Scan',     sev:'Medium',   baseConf:76, weight:5,  continent:'Europe',
    ips:['198.51.100.7','185.220.101.45','80.82.77.33','193.32.126.163'] },
  { type:'SQL Injection', sev:'Critical', baseConf:91, weight:4,  continent:'Europe',
    ips:['85.93.93.93','194.61.24.102','185.220.101.45','198.51.100.7'] },

  // ── NORTH AMERICA (~5% of attacks) ───────────────────────────────────
  { type:'SYN Flood',     sev:'High',     baseConf:86, weight:4,  continent:'NorthAmerica',
    ips:['45.33.32.156','104.21.45.1','198.51.100.14'] },
  { type:'Brute Force',   sev:'High',     baseConf:88, weight:3,  continent:'NorthAmerica',
    ips:['104.21.45.1','45.33.32.156','198.51.100.14'] },

  // ── AFRICA (~3%) ──────────────────────────────────────────────────────
  { type:'Port Scan',     sev:'Medium',   baseConf:72, weight:3,  continent:'Africa',
    ips:['41.215.180.1','197.255.127.1','196.216.2.1'] },

  // ── SOUTH AMERICA (~2%) ───────────────────────────────────────────────
  { type:'ICMP Flood',    sev:'Medium',   baseConf:69, weight:2,  continent:'SouthAmerica',
    ips:['177.54.144.1','190.57.20.1'] },

  // ── AUSTRALIA (~1%) ───────────────────────────────────────────────────
  { type:'DNS Tunneling', sev:'High',     baseConf:74, weight:1,  continent:'Australia',
    ips:['1.0.0.1','101.0.69.1'] },
];

// Build weighted selection pool
const _SIM_WEIGHTED = [];
_SIM_ATTACK_POOL.forEach(a => {
  for (let i = 0; i < a.weight; i++) _SIM_WEIGHTED.push(a);
});

// Continent rotation tracker — ensure every continent fires at least once per 10 min
const _CONTINENT_DUE = {
  Africa: 0, SouthAmerica: 0, Australia: 0, Europe: 0, NorthAmerica: 0
};
const _CONTINENT_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes

function _pickAttack() {
  const now = Date.now();

  // Check if any under-represented continent is overdue
  for (const [cont, lastTime] of Object.entries(_CONTINENT_DUE)) {
    if (now - lastTime > _CONTINENT_INTERVAL_MS) {
      const pool = _SIM_ATTACK_POOL.filter(a => a.continent === cont);
      if (pool.length > 0) {
        _CONTINENT_DUE[cont] = now;
        const a = pool[Math.floor(Math.random() * pool.length)];
        const ip   = a.ips[Math.floor(Math.random() * a.ips.length)];
        const conf = Math.max(50, Math.min(99, a.baseConf + Math.round((Math.random() * 14) - 7)));
        return { type: a.type, sev: a.sev, conf, ip, continent: cont };
      }
    }
  }

  // Normal weighted pick
  const a = _SIM_WEIGHTED[Math.floor(Math.random() * _SIM_WEIGHTED.length)];
  const ip   = a.ips[Math.floor(Math.random() * a.ips.length)];
  const conf = Math.max(50, Math.min(99, a.baseConf + Math.round((Math.random() * 14) - 7)));
  return { type: a.type, sev: a.sev, conf, ip, continent: a.continent };
}

function _startDemoSimulator() {
  if (_simTimer || _bgTimer) return; // already running
  console.info('[NetGuard] Simulation mode — attacks begin in ~25s');
  _showSimBanner();

  // ── Phase 1: Quiet warmup (20-30s) — normal traffic only ─────────────────
  const warmupMs = (20 + Math.random() * 10) * 1000;
  _bgTimer = setInterval(_tickBackground, 1500);

  setTimeout(() => {
    // ── Phase 2: Live traffic + attack scheduler ──────────────────────────
    clearInterval(_bgTimer);
    _bgTimer = null;
    _simTimer = setInterval(_tickBackground, 1500);
    _scheduleNextAttack();
  }, warmupMs);
}

function _tickBackground() {
  // Random walk PPS — realistic idle server traffic
  const drift = (Math.random() - 0.48) * 10; // slight upward bias
  _simPps = Math.max(5, Math.min(95, _simPps + drift));
  _simPackets += Math.round(_simPps * 1.5);
  updateTrafficChart(_simPps);
  setKPI('kpi-pps', _simPps.toFixed(1));
  setKPI('kpi-packets', fmtNumber(_simPackets));
}

let _attackSchedulerTimer = null;

function _scheduleNextAttack() {
  if (!_simTimer) return; // stopped

  // Variable gap: 15-45s (avg ~25s = ~2.4 attacks/min = ~24 per 10 min)
  // Occasionally very short gaps (10s) to mimic attack bursts
  let gapMs;
  const r = Math.random();
  if (r < 0.15) {
    gapMs = (10 + Math.random() * 8) * 1000;   // 10-18s: attack burst (15% chance)
  } else if (r < 0.70) {
    gapMs = (20 + Math.random() * 15) * 1000;  // 20-35s: normal rate (55% chance)
  } else {
    gapMs = (35 + Math.random() * 10) * 1000;  // 35-45s: quiet period (30% chance)
  }

  _attackSchedulerTimer = setTimeout(() => {
    if (!_simTimer) return;
    const attack = _pickAttack();
    _simAlerts++;
    setKPI('kpi-alerts', fmtNumber(_simAlerts));

    onNewThreat({
      event_id:    'sim-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      attack_type: attack.type,
      source_ip:   attack.ip,
      severity:    attack.sev,
      confidence:  attack.conf,
      blocked:     Math.random() < 0.28,
      timestamp:   new Date().toISOString(),
      explanation: `[SIM] ${attack.type} detected from ${attack.ip} (${attack.continent || 'Unknown'}) — ${attack.conf}% confidence`,
      rule_name:   attack.type.toUpperCase().replace(/[\s/]+/g, '_') + '_001',
    });

    _scheduleNextAttack();
  }, gapMs);
}

// Keep _SIM_ATTACKS alias for settings.html Reset Data button label compatibility
const _SIM_ATTACKS = _SIM_ATTACK_POOL;

function _stopDemoSimulator() {
  if (_bgTimer)            { clearInterval(_bgTimer);                _bgTimer  = null; }
  if (_simTimer)           { clearInterval(_simTimer);               _simTimer = null; }
  if (_attackSchedulerTimer){ clearTimeout(_attackSchedulerTimer); _attackSchedulerTimer = null; }
  _simPps = 0;
  _hideSimBanner();
}

function _showSimBanner() {
  let b = document.getElementById('sim-banner');
  if (!b) {
    b = document.createElement('div');
    b.id = 'sim-banner';
    b.setAttribute('role', 'status');
    b.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
           width="14" height="14" style="flex-shrink:0;vertical-align:-2px">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      <strong>Simulation Mode</strong> — Npcap/libpcap unavailable; showing synthetic traffic.
      <a href="https://npcap.com" target="_blank" rel="noopener"
         style="color:var(--accent);margin-left:4px">Install Npcap</a> for real packet capture.
    `;
    Object.assign(b.style, {
      position: 'fixed', bottom: '60px', left: '50%', transform: 'translateX(-50%)',
      background: 'rgba(250,204,21,0.12)', border: '1px solid var(--warning)',
      color: 'var(--warning)', padding: '8px 18px', borderRadius: '8px',
      fontSize: '12px', fontWeight: '500', zIndex: '250',
      display: 'flex', alignItems: 'center', gap: '8px', whiteSpace: 'nowrap',
      boxShadow: '0 4px 16px rgba(0,0,0,0.3)',
    });
    document.body.appendChild(b);
  }
}

function _hideSimBanner() {
  const b = document.getElementById('sim-banner');
  if (b) b.remove();
}
// NOTE: monitoring_status is handled by onMonitoringStatus (registered in DOMContentLoaded)
// which now also controls the simulator — no second registration needed.
