/**
 * settings.js — System Settings Form
 * Client-side range validation + PUT /api/v1/settings.
 * Requirements: 1.3, 1.4, 1.5
 */

import { api } from './api.js';

const form = document.getElementById('settings-form');
const statusMsg = document.getElementById('status-msg');
const resetBtn = document.getElementById('btn-reset');

// Field definitions with valid ranges (mirrors config_service.py)
const FIELD_RANGES = {
  syn_flood_threshold: { min: 1, label: 'SYN Flood Threshold' },
  syn_flood_window: { min: 1, max: 60, label: 'SYN Flood Window (s)' },
  port_scan_threshold: { min: 1, label: 'Port Scan Threshold' },
  port_scan_window: { min: 1, max: 60, label: 'Port Scan Window (s)' },
  brute_force_threshold: { min: 1, label: 'Brute Force Threshold' },
  brute_force_window: { min: 1, max: 300, label: 'Brute Force Window (s)' },
  block_duration: { min: 1, max: 3600, label: 'Block Duration (s)' },
  dashboard_refresh_interval: { min: 1, max: 60, label: 'Dashboard Refresh (s)' },
};

// ---------------------------------------------------------------------------
// Load current settings
// ---------------------------------------------------------------------------

async function loadSettings() {
  try {
    const data = await api('/settings');
    populateForm(data);
  } catch (err) {
    showStatus(`Error loading settings: ${err.message}`, 'error');
  }
}

function populateForm(settings) {
  if (!form) return;
  Object.entries(settings).forEach(([key, value]) => {
    const el = form.querySelector(`[name="${key}"]`);
    if (el) el.value = value;
  });
}

// ---------------------------------------------------------------------------
// Client-side validation
// ---------------------------------------------------------------------------

function validateForm(payload) {
  const errors = [];
  for (const [key, value] of Object.entries(payload)) {
    const rule = FIELD_RANGES[key];
    if (!rule) continue;
    const num = Number(value);
    if (isNaN(num)) { errors.push(`${rule.label} must be a number.`); continue; }
    if (rule.min !== undefined && num < rule.min) errors.push(`${rule.label} must be ≥ ${rule.min}.`);
    if (rule.max !== undefined && num > rule.max) errors.push(`${rule.label} must be ≤ ${rule.max}.`);
  }
  return errors;
}

// ---------------------------------------------------------------------------
// Submit handler
// ---------------------------------------------------------------------------

if (form) {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearFieldErrors();

    const fd = new FormData(form);
    const payload = {};
    for (const [k, v] of fd.entries()) {
      const num = parseFloat(v);
      payload[k] = isNaN(num) ? v : num;
    }

    // Client-side validation first
    const errors = validateForm(payload);
    if (errors.length) {
      showStatus(errors.join(' '), 'error');
      return;
    }

    const submitBtn = form.querySelector('[type="submit"]');
    if (submitBtn) submitBtn.disabled = true;

    try {
      await api('/settings', { method: 'PUT', body: payload });
      showStatus('Settings saved successfully.', 'success');
    } catch (err) {
      // Server-side validation error — show field name if available
      const msg = err.message || 'Failed to save settings.';
      showStatus(msg, 'error');
    } finally {
      if (submitBtn) submitBtn.disabled = false;
    }
  });
}

if (resetBtn) {
  resetBtn.addEventListener('click', () => {
    clearFieldErrors();
    loadSettings();
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function showStatus(msg, type = 'info') {
  if (!statusMsg) return;
  statusMsg.textContent = msg;
  statusMsg.className = `status-msg status-${type}`;
  if (type !== 'error') setTimeout(() => { statusMsg.textContent = ''; }, 5000);
}

function clearFieldErrors() {
  document.querySelectorAll('.field-error').forEach(el => el.remove());
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

loadSettings();
