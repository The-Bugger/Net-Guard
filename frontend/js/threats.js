/**
 * threats.js — Full Threat List Page
 * Paginated threat table with column filters and inline evidence panel.
 * Requirements: 16.4, 16.5, 13.8
 */

import { api } from './api.js';

const tableBody = document.getElementById('threats-tbody');
const filterForm = document.getElementById('filter-form');
const evidencePanel = document.getElementById('evidence-panel');
const evidenceContent = document.getElementById('evidence-content');
const closeEvidence = document.getElementById('close-evidence');

const SEVERITIES = ['Low', 'Medium', 'High', 'Critical'];
const SEVERITY_COLORS = { Low: 'info', Medium: 'warning', High: 'danger', Critical: 'critical' };

let _currentFilters = {};
let _offset = 0;
const PAGE_SIZE = 50;

// ---------------------------------------------------------------------------
// Load threats
// ---------------------------------------------------------------------------

async function loadThreats(reset = false) {
  if (reset) _offset = 0;

  const params = new URLSearchParams({ limit: PAGE_SIZE, offset: _offset, ..._currentFilters });
  try {
    const data = await api(`/detections?${params}`);
    renderTable(data.events || []);
  } catch (err) {
    console.error('Failed to load threats:', err);
  }
}

// ---------------------------------------------------------------------------
// Render table
// ---------------------------------------------------------------------------

function renderTable(events) {
  if (!tableBody) return;

  if (events.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="5" class="empty-row">No threats found.</td></tr>`;
    return;
  }

  tableBody.innerHTML = events.map(e => `
    <tr class="threat-row" data-event-id="${e.event_id}" tabindex="0">
      <td>${formatTime(e.timestamp)}</td>
      <td>${e.attack_type}</td>
      <td>${e.source_ip}</td>
      <td><span class="badge badge-${SEVERITY_COLORS[e.severity] || 'info'}">${e.severity}</span></td>
      <td>${e.confidence}%</td>
    </tr>
  `).join('');

  tableBody.querySelectorAll('.threat-row').forEach(row => {
    row.addEventListener('click', () => showEvidence(row.dataset.eventId));
    row.addEventListener('keypress', (e) => { if (e.key === 'Enter') showEvidence(row.dataset.eventId); });
  });
}

// ---------------------------------------------------------------------------
// Evidence panel
// ---------------------------------------------------------------------------

async function showEvidence(eventId) {
  if (!evidencePanel || !evidenceContent) return;

  evidenceContent.innerHTML = '<p>Loading…</p>';
  evidencePanel.hidden = false;

  try {
    const data = await api(`/evidence/${eventId}`);
    evidenceContent.innerHTML = renderEvidence(data);
  } catch (err) {
    evidenceContent.innerHTML = `<p class="error">Could not load evidence: ${err.message}</p>`;
  }
}

function renderEvidence(data) {
  const ev = data.evidence || {};
  const rows = Object.entries(ev)
    .map(([k, v]) => `<tr><td>${k}</td><td>${JSON.stringify(v)}</td></tr>`)
    .join('');

  return `
    <h3>${data.attack_name || 'Security Event'}</h3>
    <p><strong>Explanation:</strong> ${data.plain_english_text || '—'}</p>
    <p><strong>Recommendation:</strong> ${data.recommendation || '—'}</p>
    <p><strong>Severity:</strong> <span class="badge badge-${SEVERITY_COLORS[data.severity] || 'info'}">${data.severity}</span>
       <strong>Confidence:</strong> ${data.confidence_score}%</p>
    ${rows ? `<table class="evidence-table"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table>` : ''}
  `;
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

if (filterForm) {
  filterForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const fd = new FormData(filterForm);
    _currentFilters = {};
    for (const [k, v] of fd.entries()) {
      if (v.trim()) _currentFilters[k] = v.trim();
    }
    loadThreats(true);
  });

  filterForm.addEventListener('reset', () => {
    _currentFilters = {};
    loadThreats(true);
  });
}

if (closeEvidence) {
  closeEvidence.addEventListener('click', () => {
    if (evidencePanel) evidencePanel.hidden = true;
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTime(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

loadThreats();
