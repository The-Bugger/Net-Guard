/**
 * blocked.js — Active Blocks Management Page
 * Renders active IP blocks with live countdown and manual unblock support.
 * Requirements: 16.6
 */

import { api } from './api.js';

const tableBody = document.getElementById('blocks-tbody');
const refreshBtn = document.getElementById('btn-refresh');
const statusMsg = document.getElementById('status-msg');

let _countdownTimer = null;

// ---------------------------------------------------------------------------
// Load and render blocked IPs
// ---------------------------------------------------------------------------

async function loadBlocked() {
  try {
    const data = await api('/blocked');
    const blocks = data.blocked || [];
    renderTable(blocks);
    startCountdowns();
  } catch (err) {
    showStatus(`Error loading blocked IPs: ${err.message}`, 'error');
  }
}

function renderTable(blocks) {
  if (!tableBody) return;

  if (blocks.length === 0) {
    tableBody.innerHTML = `
      <tr>
        <td colspan="5" class="empty-row">No active blocks.</td>
      </tr>`;
    return;
  }

  tableBody.innerHTML = blocks.map(b => `
    <tr data-expires="${b.expires_at}" data-ip="${b.ip_address}">
      <td>${b.ip_address}</td>
      <td>${b.reason || '—'}</td>
      <td>${formatTime(b.blocked_at)}</td>
      <td class="countdown" data-expires="${b.expires_at}">
        ${formatCountdown(b.expires_in ?? 0)}
      </td>
      <td>
        <button class="btn-unblock" data-ip="${b.ip_address}">Unblock</button>
      </td>
    </tr>
  `).join('');

  // Bind unblock buttons
  tableBody.querySelectorAll('.btn-unblock').forEach(btn => {
    btn.addEventListener('click', () => handleUnblock(btn.dataset.ip, btn));
  });
}

// ---------------------------------------------------------------------------
// Countdown timer
// ---------------------------------------------------------------------------

function startCountdowns() {
  if (_countdownTimer) clearInterval(_countdownTimer);
  _countdownTimer = setInterval(tickCountdowns, 1000);
}

function tickCountdowns() {
  const cells = document.querySelectorAll('.countdown[data-expires]');
  cells.forEach(cell => {
    const expires = new Date(cell.dataset.expires + (cell.dataset.expires.endsWith('Z') ? '' : 'Z'));
    const remaining = Math.max(0, Math.floor((expires - Date.now()) / 1000));
    cell.textContent = formatCountdown(remaining);
    if (remaining === 0) {
      cell.closest('tr')?.remove();
      if (!tableBody.querySelector('tr:not(.empty-row)')) {
        tableBody.innerHTML = `<tr><td colspan="5" class="empty-row">No active blocks.</td></tr>`;
      }
    }
  });
}

function formatCountdown(seconds) {
  if (seconds <= 0) return 'Expired';
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}m ${s.toString().padStart(2, '0')}s`;
}

function formatTime(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

// ---------------------------------------------------------------------------
// Unblock action
// ---------------------------------------------------------------------------

async function handleUnblock(ip, btn) {
  if (!confirm(`Unblock ${ip}?`)) return;
  btn.disabled = true;
  btn.textContent = 'Unblocking…';

  try {
    await api('/unblock', { method: 'POST', body: { ip } });
    showStatus(`${ip} unblocked successfully.`, 'success');
    await loadBlocked();
  } catch (err) {
    showStatus(`Failed to unblock ${ip}: ${err.message}`, 'error');
    btn.disabled = false;
    btn.textContent = 'Unblock';
  }
}

// ---------------------------------------------------------------------------
// Status message
// ---------------------------------------------------------------------------

function showStatus(msg, type = 'info') {
  if (!statusMsg) return;
  statusMsg.textContent = msg;
  statusMsg.className = `status-msg status-${type}`;
  if (type !== 'error') setTimeout(() => { statusMsg.textContent = ''; }, 4000);
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

if (refreshBtn) refreshBtn.addEventListener('click', loadBlocked);
loadBlocked();
