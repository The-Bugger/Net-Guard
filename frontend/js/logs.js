/**
 * logs.js — Log Viewer Page
 * Paginated log viewer with severity/date/module/attack_type/source_ip filters.
 * Requirements: 13.9, 15.6
 */

import { api } from './api.js';

const tableBody = document.getElementById('logs-tbody');
const filterForm = document.getElementById('filter-form');
const prevBtn = document.getElementById('btn-prev');
const nextBtn = document.getElementById('btn-next');
const pageInfo = document.getElementById('page-info');

const PAGE_SIZE = 50;
let _page = 0;
let _filters = {};
let _total = 0;

const LEVEL_COLORS = { INFO: 'info', WARNING: 'warning', ERROR: 'danger', CRITICAL: 'critical' };

// ---------------------------------------------------------------------------
// Load logs
// ---------------------------------------------------------------------------

async function loadLogs() {
  const params = new URLSearchParams({
    page_size: PAGE_SIZE,
    offset: _page * PAGE_SIZE,
    ..._filters,
  });

  try {
    const data = await api(`/logs?${params}`);
    const logs = data.logs || [];
    _total = data.total ?? logs.length;
    renderTable(logs);
    updatePagination();
  } catch (err) {
    console.error('Failed to load logs:', err);
  }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

function renderTable(logs) {
  if (!tableBody) return;

  if (logs.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="5" class="empty-row">No log entries found.</td></tr>`;
    return;
  }

  tableBody.innerHTML = logs.map(l => `
    <tr>
      <td>${formatTime(l.timestamp)}</td>
      <td><span class="badge badge-${LEVEL_COLORS[l.level] || 'info'}">${l.level}</span></td>
      <td>${l.module || '—'}</td>
      <td>${l.event || '—'}</td>
      <td class="log-message" title="${escHtml(l.message || '')}">${escHtml(l.message || '—')}</td>
    </tr>
  `).join('');
}

function updatePagination() {
  const totalPages = Math.max(1, Math.ceil(_total / PAGE_SIZE));
  if (pageInfo) pageInfo.textContent = `Page ${_page + 1} of ${totalPages}`;
  if (prevBtn) prevBtn.disabled = _page === 0;
  if (nextBtn) nextBtn.disabled = (_page + 1) * PAGE_SIZE >= _total;
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

if (filterForm) {
  filterForm.addEventListener('submit', (e) => {
    e.preventDefault();
    _filters = {};
    _page = 0;
    const fd = new FormData(filterForm);
    for (const [k, v] of fd.entries()) {
      if (v.trim()) _filters[k] = v.trim();
    }
    loadLogs();
  });

  filterForm.addEventListener('reset', () => {
    _filters = {};
    _page = 0;
    loadLogs();
  });
}

if (prevBtn) prevBtn.addEventListener('click', () => { if (_page > 0) { _page--; loadLogs(); } });
if (nextBtn) nextBtn.addEventListener('click', () => { _page++; loadLogs(); });

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTime(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

loadLogs();
