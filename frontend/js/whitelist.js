/**
 * whitelist.js — Whitelist Management Page
 * Add/remove trusted IPs with inline form and confirmation.
 * Requirements: 16.7
 */

import { api } from './api.js';

const tableBody = document.getElementById('whitelist-tbody');
const addForm = document.getElementById('add-whitelist-form');
const ipInput = document.getElementById('wl-ip');
const descInput = document.getElementById('wl-desc');
const statusMsg = document.getElementById('status-msg');

// ---------------------------------------------------------------------------
// Load and render whitelist
// ---------------------------------------------------------------------------

async function loadWhitelist() {
  try {
    const data = await api('/whitelist');
    renderTable(data.whitelist || []);
  } catch (err) {
    showStatus(`Error loading whitelist: ${err.message}`, 'error');
  }
}

function renderTable(entries) {
  if (!tableBody) return;

  if (entries.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="4" class="empty-row">Whitelist is empty.</td></tr>`;
    return;
  }

  tableBody.innerHTML = entries.map(e => `
    <tr>
      <td>${e.ip_address}</td>
      <td>${e.description || '—'}</td>
      <td>${formatTime(e.created_at)}</td>
      <td>
        <button class="btn-remove" data-ip="${e.ip_address}">Remove</button>
      </td>
    </tr>
  `).join('');

  tableBody.querySelectorAll('.btn-remove').forEach(btn => {
    btn.addEventListener('click', () => handleRemove(btn.dataset.ip, btn));
  });
}

// ---------------------------------------------------------------------------
// Add IP
// ---------------------------------------------------------------------------

if (addForm) {
  addForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const ip = ipInput?.value.trim();
    const description = descInput?.value.trim() || undefined;

    if (!ip) {
      showStatus('IP address is required.', 'error');
      return;
    }

    const submitBtn = addForm.querySelector('[type="submit"]');
    if (submitBtn) submitBtn.disabled = true;

    try {
      await api('/whitelist', { method: 'POST', body: { ip, description } });
      showStatus(`${ip} added to whitelist.`, 'success');
      if (ipInput) ipInput.value = '';
      if (descInput) descInput.value = '';
      await loadWhitelist();
    } catch (err) {
      showStatus(`Failed to add ${ip}: ${err.message}`, 'error');
    } finally {
      if (submitBtn) submitBtn.disabled = false;
    }
  });
}

// ---------------------------------------------------------------------------
// Remove IP
// ---------------------------------------------------------------------------

async function handleRemove(ip, btn) {
  if (!confirm(`Remove ${ip} from the whitelist?`)) return;
  btn.disabled = true;
  btn.textContent = 'Removing…';

  try {
    await api(`/whitelist/${encodeURIComponent(ip)}`, { method: 'DELETE' });
    showStatus(`${ip} removed from whitelist.`, 'success');
    await loadWhitelist();
  } catch (err) {
    showStatus(`Failed to remove ${ip}: ${err.message}`, 'error');
    btn.disabled = false;
    btn.textContent = 'Remove';
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTime(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function showStatus(msg, type = 'info') {
  if (!statusMsg) return;
  statusMsg.textContent = msg;
  statusMsg.className = `status-msg status-${type}`;
  if (type !== 'error') setTimeout(() => { statusMsg.textContent = ''; }, 4000);
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

loadWhitelist();
