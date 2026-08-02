/**
 * lab.js — Attack Lab simulation control page
 * Requirements: 3.1–3.9
 */

// ── Auth gate ────────────────────────────────────────────────────────────────
// Redirect viewers; only admin/analyst may use the lab (Req 3.1)
(function authGate() {
  const token = sessionStorage.getItem('ng_access_token');
  const role  = sessionStorage.getItem('ng_user_role');
  if (!token || role === 'viewer') {
    window.location.href = '/login.html';
  }
}());

// ── Helpers ──────────────────────────────────────────────────────────────────
// escHtml is provided by api.js (loaded before this script)

function elapsed(startIso) {
  const s = Math.floor((Date.now() - new Date(startIso).getTime()) / 1000);
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}m ${s % 60}s` : `${s}s`;
}

// Detection status → badge style
const STATUS_STYLE = {
  PENDING:   'color:var(--warning)',
  DETECTED:  'color:var(--info)',
  BLOCKED:   'color:var(--accent)',
  MISSED:    'color:var(--danger)',
  CANCELLED: 'color:var(--text-muted)',
};

// ── API calls ─────────────────────────────────────────────────────────────────
async function loadAttackTypes() {
  const sel = document.getElementById('attack-type');
  try {
    const data = await apiRequest('/lab/attacks');
    const attacks = Array.isArray(data) ? data : (data.attacks || []);
    sel.innerHTML = attacks.map(a =>
      `<option value="${escHtml(a.id ?? a)}">${escHtml(a.name ?? a)}</option>`
    ).join('');
    if (!attacks.length) sel.innerHTML = '<option value="">No attack types available</option>';
  } catch (err) {
    sel.innerHTML = '<option value="">Failed to load</option>';
    showToast('Could not load attack types: ' + err.message, 'error');
  }
}

async function loadSessions() {
  const tbody = document.getElementById('sessions-tbody');
  try {
    const data = await apiRequest('/lab/sessions');
    const sessions = Array.isArray(data) ? data : (data.sessions || []);
    renderSessionsTable(sessions);
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" style="color:var(--danger);padding:16px">${escHtml(err.message)}</td></tr>`;
  }
}

async function launchSession(config) {
  return apiRequest('/lab/sessions', { method: 'POST', body: config });
}

async function cancelSession(id) {
  try {
    await apiRequest(`/lab/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' });
    showToast('Session cancelled.', 'success');
    loadSessions();
    // Close detail panel if it's showing the cancelled session
    const detail = document.getElementById('session-detail');
    if (detail.dataset.sessionId === String(id)) closeDetail();
  } catch (err) {
    showToast('Cancel failed: ' + err.message, 'error');
  }
}

async function showSessionDetail(id) {
  const panel   = document.getElementById('session-detail');
  const content = document.getElementById('session-detail-content');
  panel.dataset.sessionId = String(id);
  panel.style.display = 'block';
  content.innerHTML = '<p style="color:var(--text-muted)">Loading…</p>';
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  try {
    const s = await apiRequest(`/lab/sessions/${encodeURIComponent(id)}`);
    renderDetailPanel(s);
    // Start live elapsed counter if session is still running
    if (s.status === 'running' || s.detection_status === 'PENDING') {
      startDetailClock(s);
    }
  } catch (err) {
    content.innerHTML = `<p style="color:var(--danger)">${escHtml(err.message)}</p>`;
  }
}

// ── Render helpers ────────────────────────────────────────────────────────────
function renderSessionsTable(sessions) {
  const tbody = document.getElementById('sessions-tbody');
  if (!sessions.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-state"><p>No active sessions.</p></td></tr>`;
    return;
  }
  tbody.innerHTML = sessions.map(s => {
    const det = (s.detection_status || 'PENDING').toUpperCase();
    const style = STATUS_STYLE[det] || '';
    return `
      <tr style="cursor:pointer" onclick="showSessionDetail(${JSON.stringify(s.session_id)})">
        <td><code>${escHtml(s.session_id)}</code></td>
        <td>${escHtml(s.attack_type)}</td>
        <td style="text-transform:capitalize">${escHtml(s.difficulty || '—')}</td>
        <td id="elapsed-${escHtml(s.session_id)}">${s.started_at ? elapsed(s.started_at) : '—'}</td>
        <td>${escHtml(s.packets_sent ?? 0)}</td>
        <td><span style="font-weight:600;font-size:12px;${style}">${escHtml(det)}</span></td>
        <td>
          <button class="btn btn-ghost btn-sm" style="padding:3px 8px;color:var(--danger)"
                  onclick="event.stopPropagation();cancelSession(${JSON.stringify(s.session_id)})">
            Cancel
          </button>
        </td>
      </tr>`;
  }).join('');
}

function renderDetailPanel(s) {
  const content = document.getElementById('session-detail-content');
  const det = (s.detection_status || 'PENDING').toUpperCase();
  const style = STATUS_STYLE[det] || '';
  content.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px">
      <div><div style="font-size:11px;color:var(--text-muted);margin-bottom:2px">Session ID</div><code>${escHtml(s.session_id)}</code></div>
      <div><div style="font-size:11px;color:var(--text-muted);margin-bottom:2px">Attack Type</div>${escHtml(s.attack_type)}</div>
      <div><div style="font-size:11px;color:var(--text-muted);margin-bottom:2px">Difficulty</div><span style="text-transform:capitalize">${escHtml(s.difficulty || '—')}</span></div>
      <div><div style="font-size:11px;color:var(--text-muted);margin-bottom:2px">Duration</div>${escHtml(s.duration_seconds ?? '—')}s</div>
      <div><div style="font-size:11px;color:var(--text-muted);margin-bottom:2px">Packets / sec</div>${escHtml(s.packets_per_second ?? '—')}</div>
      <div><div style="font-size:11px;color:var(--text-muted);margin-bottom:2px">Attacker Count</div>${escHtml(s.attacker_count ?? '—')}</div>
      <div><div style="font-size:11px;color:var(--text-muted);margin-bottom:2px">Packets Sent</div>${escHtml(s.packets_sent ?? 0)}</div>
      <div><div style="font-size:11px;color:var(--text-muted);margin-bottom:2px">Detection Status</div><span style="font-weight:700;${style}">${escHtml(det)}</span></div>
      <div><div style="font-size:11px;color:var(--text-muted);margin-bottom:2px">Elapsed</div><span id="detail-elapsed">${s.started_at ? elapsed(s.started_at) : '—'}</span></div>
      ${s.estimated_detection_time ? `<div><div style="font-size:11px;color:var(--text-muted);margin-bottom:2px">Est. Detection Time</div>${escHtml(s.estimated_detection_time)}s</div>` : ''}
    </div>
  `;
}

// Live elapsed counter in detail panel
let _detailTimer = null;
function startDetailClock(s) {
  clearInterval(_detailTimer);
  if (!s.started_at) return;
  _detailTimer = setInterval(() => {
    const el = document.getElementById('detail-elapsed');
    if (el) el.textContent = elapsed(s.started_at);
  }, 1000);
}

function closeDetail() {
  clearInterval(_detailTimer);
  const panel = document.getElementById('session-detail');
  panel.style.display = 'none';
  panel.dataset.sessionId = '';
}

// ── Launch flow ───────────────────────────────────────────────────────────────
async function handleLaunch(e) {
  e.preventDefault();
  const config = {
    attack_type:       document.getElementById('attack-type').value,
    difficulty:        document.getElementById('difficulty').value,
    duration_seconds:  Number(document.getElementById('duration').value),
    packets_per_second: Number(document.getElementById('packets-per-sec').value),
    attacker_count:    Number(document.getElementById('attacker-count').value),
  };

  // Pre-flight estimate before showing dialog (Req 3.4)
  let estimatedTime = null;
  try {
    // Best-effort: some backends return estimated_detection_time from a dry-run or
    // attack type metadata. Fall through silently if not available.
    const meta = await apiRequest(`/lab/attacks/${encodeURIComponent(config.attack_type)}`).catch(() => null);
    estimatedTime = meta?.estimated_detection_time ?? null;
  } catch (_) { /* ignore */ }

  // Show confirmation dialog
  const dialog = document.getElementById('confirm-dialog');
  document.getElementById('confirm-body').innerHTML =
    `<strong>Attack:</strong> ${escHtml(config.attack_type)}<br>
     <strong>Difficulty:</strong> ${escHtml(config.difficulty)}<br>
     <strong>Duration:</strong> ${escHtml(config.duration_seconds)}s &nbsp;
     <strong>Packets/s:</strong> ${escHtml(config.packets_per_second)}<br>
     <strong>Attackers:</strong> ${escHtml(config.attacker_count)}<br>
     ${estimatedTime != null ? `<strong>Estimated detection time:</strong> ${escHtml(estimatedTime)}s` : ''}`;

  // Resolve on button click
  const ok = document.getElementById('confirm-ok');
  const confirmed = await new Promise(resolve => {
    const onOk     = () => { cleanup(); resolve(true); };
    const onCancel = () => { cleanup(); resolve(false); };
    function cleanup() {
      ok.removeEventListener('click', onOk);
      dialog.removeEventListener('close', onCancel);
    }
    ok.addEventListener('click', onOk);
    dialog.addEventListener('close', onCancel, { once: true });
    dialog.showModal();
  });

  dialog.close();
  if (!confirmed) return;

  try {
    await launchSession(config);
    showToast('Simulation launched.', 'success');
    document.getElementById('launch-form').reset();
    loadSessions();
  } catch (err) {
    showToast('Launch failed: ' + err.message, 'error');
  }
}

// ── SocketIO (optional) ───────────────────────────────────────────────────────
// ponytail: no SocketManager abstraction needed here — raw socket.io, graceful degradation
(function connectSocket() {
  if (typeof io === 'undefined') return;
  try {
    const socket = io({ transports: ['websocket', 'polling'] });
    socket.on('lab_session_update', () => loadSessions());
  } catch (_) { /* socket unavailable, polling covers it */ }
}());

// ── Auto-refresh ──────────────────────────────────────────────────────────────
// ponytail: simple interval; could be replaced by SocketIO-only when backend supports it
setInterval(loadSessions, 3000);

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadAttackTypes();
  loadSessions();
});
