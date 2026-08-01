/**
 * api.js — Fetch wrapper for the NetGuard REST API.
 *
 * Enforces the standard JSON envelope:
 *   Success: { success: true, message, data }
 *   Error:   { success: false, error, code }
 *
 * Requirements: 13.3, 16.11
 */

const API_BASE = '/api/v1';

/**
 * Make an API request and return the data field on success.
 * Throws an Error with descriptive message on failure.
 *
 * @param {string} path  - API path (e.g. '/dashboard')
 * @param {object} [options] - fetch options
 * @returns {Promise<any>} - resolves to response.data
 */
async function apiRequest(path, options = {}) {
  const url = `${API_BASE}${path}`;

  const defaults = {
    headers: { 'Content-Type': 'application/json' },
  };

  const config = { ...defaults, ...options };
  if (config.body && typeof config.body === 'object') {
    config.body = JSON.stringify(config.body);
  }

  const res = await fetch(url, config);
  let json;
  try {
    json = await res.json();
  } catch (e) {
    throw new Error(`API request to ${path} returned non-JSON response (status ${res.status})`);
  }

  if (!json.success) {
    const msg = json.error || json.message || 'Unknown API error';
    const err = new Error(msg);
    err.code = json.error_code || json.code || res.status;
    throw err;
  }

  return json.data;
}

// ── Convenience methods ────────────────────────────────────────────────────

const api = {
  get:    (path)         => apiRequest(path, { method: 'GET' }),
  post:   (path, body)   => apiRequest(path, { method: 'POST',   body }),
  put:    (path, body)   => apiRequest(path, { method: 'PUT',    body }),
  delete: (path)         => apiRequest(path, { method: 'DELETE' }),
};

// ── Named API calls ────────────────────────────────────────────────────────

const NetGuardAPI = {
  // Health
  health:           () => api.get('/health'),
  status:           () => api.get('/status'),

  // Monitor
  startMonitoring:  (iface) => api.post('/monitor/start', { interface: iface }),
  stopMonitoring:   ()      => api.post('/monitor/stop', {}),
  getInterfaces:    ()      => api.get('/monitor/interfaces'),

  // Dashboard
  getDashboard:     ()      => api.get('/dashboard'),
  getLiveStats:     ()      => api.get('/dashboard/live'),

  // Detections
  getDetections:    (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return api.get(`/detections${qs ? '?' + qs : ''}`);
  },
  getDetection:     (id)    => api.get(`/detections/${id}`),
  getEvidence:      (id)    => api.get(`/evidence/${id}`),

  // Blocks
  getBlocked:       ()      => api.get('/blocked'),
  blockIP:          (ip, reason, duration) =>
    api.post('/block', { ip, reason, duration }),
  unblockIP:        (ip)    => api.post('/unblock', { ip }),

  // Whitelist
  getWhitelist:     ()      => api.get('/whitelist'),
  addWhitelist:     (ip, description) =>
    api.post('/whitelist', { ip, description }),
  removeWhitelist:  (ip)    => api.delete(`/whitelist/${ip}`),

  // Statistics
  getStatistics:    ()      => api.get('/statistics'),
  getRuleStats:     ()      => api.get('/statistics/rules'),

  // Logs
  getLogs:          (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return api.get(`/logs${qs ? '?' + qs : ''}`);
  },

  // Settings
  getSettings:      ()       => api.get('/settings'),
  updateSettings:   (body)   => api.put('/settings', body),

  // Data reset (demo utility)
  resetData:        ()       => api.post('/reset-data', {}),
};

// ── Security: HTML-escape a string for safe innerHTML assignment ─────────────
// Uses DOM textContent to derive HTML entities (& < > ") correctly without
// risk of XSS.  Does NOT escape single quotes (not needed for innerHTML);
// use data-* attributes for onclick payloads instead of string interpolation.
function escHtml(str) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(String(str ?? '')));
  return d.innerHTML;
}
