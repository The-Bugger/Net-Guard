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

  const token = sessionStorage.getItem('ng_access_token');
  const defaults = {
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    },
  };

  const config = { ...defaults, ...options };
  if (config.body && typeof config.body === 'object') {
    config.body = JSON.stringify(config.body);
  }

  let res = await fetch(url, config);

  // ── Token refresh on 401 ──────────────────────────────────────────────────
  // The access token expires after 8h; a refresh token is stored at login
  // but was never used — users were hard-dropped to login mid-session.
  // On 401 (and not already retrying), try one refresh, then replay the
  // original request with the new token.
  if (res.status === 401 && !config._isRetry && sessionStorage.getItem('ng_refresh_token')) {
    const refreshed = await tryRefreshToken();
    if (refreshed) {
      config._isRetry = true;
      config.headers['Authorization'] = `Bearer ${sessionStorage.getItem('ng_access_token')}`;
      res = await fetch(url, config);
    }
  }

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
    // Redirect to login on auth failure (refresh already attempted above)
    if (res.status === 401) {
      sessionStorage.clear();
      window.location.href = '/frontend/login.html';
      return;
    }
    throw err;
  }

  return json.data;
}

// Single-flight refresh: concurrent 401s share one refresh call.
let _refreshInFlight = null;

async function tryRefreshToken() {
  if (_refreshInFlight) return _refreshInFlight;
  _refreshInFlight = (async () => {
    try {
      const refresh = sessionStorage.getItem('ng_refresh_token');
      const res = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refresh }),
      });
      const json = await res.json();
      if (!res.ok || !json.success || !json.data?.access_token) return false;
      sessionStorage.setItem('ng_access_token', json.data.access_token);
      if (json.data.refresh_token) {
        sessionStorage.setItem('ng_refresh_token', json.data.refresh_token);
      }
      return true;
    } catch (_) {
      return false;
    } finally {
      _refreshInFlight = null;
    }
  })();
  return _refreshInFlight;
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

  // Analytics
  getAnalytics:    (period) =>
    api.get(`/analytics${period ? '?period=' + encodeURIComponent(period) : ''}`),

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

// Expose globally — the single canonical escaper for every page.
// (Previously each page defined its own copy; several had none at all.)
window.escHtml = escHtml;

// ── Logout ──────────────────────────────────────────────────────────────────
// The backend exposes POST /api/v1/auth/logout but nothing in the UI ever
// called it — tokens lived in sessionStorage until the tab closed. This
// auto-injects a Sign Out button into the page header on every
// authenticated page (headers are inline in 14 HTML files; api.js is
// loaded on all of them, so this is the one place to wire it).
async function handleLogout() {
  try {
    await api.post('/auth/logout', {});
  } catch (_) {
    // Best-effort: clear local session even if the call fails.
  }
  sessionStorage.clear();
  window.location.href = '/frontend/login.html';
}

document.addEventListener('DOMContentLoaded', () => {
  const header = document.querySelector('.header');
  if (!header || document.getElementById('btn-logout')) return;
  // Only show on authenticated pages (login/landing have no token)
  if (!sessionStorage.getItem('ng_access_token')) return;

  const btn = document.createElement('button');
  btn.id = 'btn-logout';
  btn.textContent = 'Sign Out';
  btn.title = 'Sign out';
  btn.style.cssText = 'background:none;border:1px solid var(--border,#333);'
    + 'color:inherit;border-radius:6px;padding:4px 10px;font-size:12px;'
    + 'cursor:pointer;margin-right:8px';
  btn.addEventListener('click', handleLogout);
  const timeEl = header.querySelector('.header-time');
  if (timeEl) header.insertBefore(btn, timeEl);
  else header.appendChild(btn);
});
