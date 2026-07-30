/**
 * rules.js — Detection Rules Configuration Page
 * Shows rule names, thresholds, and enable/disable toggles.
 * Requirements: 9.4
 */

import { api } from './api.js';

const rulesContainer = document.getElementById('rules-container');
const statusMsg = document.getElementById('status-msg');

// ---------------------------------------------------------------------------
// Load and render rules
// ---------------------------------------------------------------------------

async function loadRules() {
  try {
    const data = await api('/statistics/rules');
    renderRules(data.rules || []);
  } catch (err) {
    showStatus(`Error loading rules: ${err.message}`, 'error');
  }
}

function renderRules(rules) {
  if (!rulesContainer) return;

  if (rules.length === 0) {
    rulesContainer.innerHTML = '<p class="empty-row">No rules available.</p>';
    return;
  }

  rulesContainer.innerHTML = rules.map(r => `
    <div class="rule-card" id="rule-${r.rule_name}">
      <div class="rule-header">
        <h3>${r.attack_type || r.rule_name}</h3>
        <label class="toggle" title="${r.enabled ? 'Enabled' : 'Disabled'}">
          <input type="checkbox" class="rule-toggle"
            data-rule="${r.rule_name}"
            ${r.enabled ? 'checked' : ''}>
          <span class="toggle-slider"></span>
        </label>
      </div>
      <dl class="rule-stats">
        <dt>Rule ID</dt><dd>${r.rule_name}</dd>
        <dt>Detections</dt><dd>${r.detection_count ?? 0}</dd>
        <dt>Threshold</dt><dd>${r.threshold ?? '—'}</dd>
        <dt>Status</dt><dd class="${r.enabled ? 'status-active' : 'status-inactive'}">${r.enabled ? 'Active' : 'Disabled'}</dd>
      </dl>
    </div>
  `).join('');

  rulesContainer.querySelectorAll('.rule-toggle').forEach(toggle => {
    toggle.addEventListener('change', () => handleToggle(toggle.dataset.rule, toggle.checked, toggle));
  });
}

// ---------------------------------------------------------------------------
// Enable/disable rule
// ---------------------------------------------------------------------------

async function handleToggle(ruleName, enabled, toggle) {
  toggle.disabled = true;

  try {
    await api('/settings', {
      method: 'PUT',
      body: { rules_enabled: { [ruleName.toLowerCase().replace(/_001$/, '')]: enabled } },
    });
    showStatus(`${ruleName} ${enabled ? 'enabled' : 'disabled'}.`, 'success');
    const card = document.getElementById(`rule-${ruleName}`);
    const statusEl = card?.querySelector('.rule-stats dd:last-child');
    if (statusEl) {
      statusEl.textContent = enabled ? 'Active' : 'Disabled';
      statusEl.className = enabled ? 'status-active' : 'status-inactive';
    }
  } catch (err) {
    showStatus(`Failed to update ${ruleName}: ${err.message}`, 'error');
    toggle.checked = !enabled; // revert
  } finally {
    toggle.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// Helpers
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

loadRules();
