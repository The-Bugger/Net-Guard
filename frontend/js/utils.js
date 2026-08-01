/**
 * utils.js — Shared UI utilities for all NetGuard pages.
 *
 * showToast(message, type, durationMs)
 *   Appends a .toast div to #toast-container and auto-removes after duration.
 *   types: success (#4ADE80), error (#F87171), warning (#FACC15), info (#00E5FF)
 */

const _TOAST_COLORS = {
  success: '#4ADE80',
  error:   '#F87171',
  warning: '#FACC15',
  info:    '#00E5FF',
};

/**
 * Show a toast notification.
 * @param {string} message    - Text to display.
 * @param {string} [type]     - 'success' | 'error' | 'warning' | 'info'
 * @param {number} [durationMs] - Auto-dismiss delay in ms (default 4000).
 */
function showToast(message, type = 'info', durationMs = 4000) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const color = _TOAST_COLORS[type] || _TOAST_COLORS.info;

  const el = document.createElement('div');
  el.className = 'toast';
  el.setAttribute('role', 'status');
  el.setAttribute('aria-live', 'polite');
  el.style.cssText = `border-left-color:${color}`;
  el.textContent = message;

  container.appendChild(el);

  // Trigger fade-in on next frame
  requestAnimationFrame(() => el.classList.add('toast-visible'));

  if (durationMs > 0) {
    setTimeout(() => {
      el.classList.remove('toast-visible');
      // Remove after CSS transition completes (300ms)
      setTimeout(() => el.remove(), 300);
    }, durationMs);
  }
}
