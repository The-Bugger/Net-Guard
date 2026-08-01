/**
 * auth.js — JWT authentication for NetGuard Enterprise IDPS
 *
 * Handles login flow with optional MFA, token storage in sessionStorage,
 * auto-redirect to index.html on success.
 *
 * Requirements: 14.1, 14.4
 */

(function() {
  'use strict';

  const API_BASE = window.location.origin + '/api/v1';
  const form = document.getElementById('login-form');
  const btnLogin = document.getElementById('btn-login');
  const totpGroup = document.getElementById('totp-group');
  const alertContainer = document.getElementById('alert-container');

  let mfaRequired = false;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearAlert();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const totpCode = document.getElementById('totp_code').value.trim();

    if (!username || !password) {
      showAlert('Username and password are required.', 'error');
      return;
    }

    btnLogin.disabled = true;
    btnLogin.textContent = 'Signing in...';

    try {
      const payload = { username, password };
      if (mfaRequired && totpCode) {
        payload.totp_code = totpCode;
      }

      const resp = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await resp.json();

      if (!resp.ok) {
        if (data.error_code === 'MFA_REQUIRED') {
          mfaRequired = true;
          totpGroup.classList.add('visible');
          document.getElementById('totp_code').focus();
          showAlert('MFA code required. Check your authenticator app.', 'error');
          btnLogin.disabled = false;
          btnLogin.textContent = 'Sign In';
          return;
        }
        if (data.error_code === 'MFA_INVALID') {
          showAlert('Invalid MFA code. Please try again.', 'error');
          btnLogin.disabled = false;
          btnLogin.textContent = 'Sign In';
          return;
        }
        showAlert(data.message || 'Login failed. Check your credentials.', 'error');
        btnLogin.disabled = false;
        btnLogin.textContent = 'Sign In';
        return;
      }

      // Store tokens in sessionStorage (not localStorage — session-only)
      sessionStorage.setItem('ng_access_token', data.data.access_token);
      sessionStorage.setItem('ng_refresh_token', data.data.refresh_token);
      sessionStorage.setItem('ng_user_role', data.data.role);

      // Redirect to dashboard
      window.location.href = '/frontend/index.html';

    } catch (err) {
      console.error('Login error:', err);
      showAlert('Network error. Please try again.', 'error');
      btnLogin.disabled = false;
      btnLogin.textContent = 'Sign In';
    }
  });

  function showAlert(message, type) {
    const cls = type === 'error' ? 'alert-error' : 'alert-info';
    alertContainer.innerHTML = `<div class="alert ${cls}">${escapeHtml(message)}</div>`;
  }

  function clearAlert() {
    alertContainer.innerHTML = '';
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // Check if already logged in — redirect to dashboard
  if (sessionStorage.getItem('ng_access_token')) {
    window.location.href = '/frontend/index.html';
  }

})();
