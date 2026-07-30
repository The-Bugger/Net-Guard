/**
 * shell.js — Shared layout component for NetGuard frontend.
 * Injects header, sidebar, notifications container, and system clock.
 * Provides a single place to manage navigation, status, and branding.
 */

(function() {
  'use strict';

  const navItems = [
    { href: '/',           icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"></rect></svg>', label: 'Dashboard' },
    { href: '/threats.html', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>', label: 'Threats' },
    { href: '/blocked.html', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg>', label: 'Blocked IPs' },
    { href: '/whitelist.html', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>', label: 'Whitelist' },
    { href: '/logs.html', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>', label: 'Logs' },
    { href: '/rules.html', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>', label: 'Rules' },
    { href: '/settings.html', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>', label: 'Settings' },
    { href: '/about.html', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>', label: 'About' },
  ];

  function escHtml(str) {
    const d = document.createElement('div');
    d.appendChild(document.createTextNode(String(str ?? '')));
    return d.innerHTML;
  }

  function getCurrentPath() {
    return window.location.pathname.replace(/\/$/, '');
  }

  function renderSidebar() {
    const path = getCurrentPath();
    const navHtml = navItems.map(item => {
      const isActive = path === item.href;
      return `
        <a href="${item.href}" class="nav-item ${isActive ? 'active' : ''}">
          ${item.icon}
          ${escHtml(item.label)}
        </a>
      `;
    }).join('');
    return navHtml;
  }

  function renderHeader(monitoringActive, currentInterface) {
    return `
      <header class="header">
        <div class="header-logo">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          </svg>
          NetGuard
        </div>
        <div class="header-spacer"></div>
        <div class="header-status">
          <span id="current-interface" style="color:var(--text-muted);font-size:13px">${escHtml(currentInterface || '')}</span>
          <div id="monitoring-badge" class="status-badge ${monitoringActive ? 'active' : 'inactive'}">
            <span class="status-dot"></span>
            ${monitoringActive ? 'Monitoring Active' : 'Monitoring Stopped'}
          </div>
        </div>
        <div class="header-time" id="system-time"></div>
      </header>
    `;
  }

  function renderNotificationsContainer() {
    return '<div id="notifications"></div>';
  }

  function startClock() {
    const el = document.getElementById('system-time');
    if (!el) return;
    const tick = () => { el.textContent = new Date().toLocaleTimeString(); };
    tick();
    setInterval(tick, 1000);
  }

  function updateMonitoringStatus(active, iface) {
    const badge = document.getElementById('monitoring-badge');
    const ifaceEl = document.getElementById('current-interface');
    if (badge) {
      badge.className = `status-badge ${active ? 'active' : 'inactive'}`;
      badge.innerHTML = `
        <span class="status-dot"></span>
        ${active ? 'Monitoring Active' : 'Monitoring Stopped'}
      `;
    }
    if (ifaceEl) ifaceEl.textContent = iface || '';
  }

  function showNotification(message, type = 'success') {
    const container = document.getElementById('notifications');
    if (!container) return;

    const el = document.createElement('div');
    el.className = `notification ${type}`;
    el.textContent = message;
    container.appendChild(el);

    const timeout = type === 'critical' ? 0 : 5000;
    if (timeout) setTimeout(() => el.remove(), timeout);
  }

  // Public API
  window.Shell = {
    renderSidebar,
    renderHeader,
    renderNotificationsContainer,
    startClock,
    updateMonitoringStatus,
    showNotification,
  };

  // Auto-inject on DOMContentLoaded if not already present
  document.addEventListener('DOMContentLoaded', () => {
    const headerTarget = document.querySelector('.app-layout');
    if (!headerTarget) return;

    const headerEl = document.querySelector('.header');
    const sidebarEl = document.querySelector('.sidebar');
    const notificationsEl = document.getElementById('notifications');

    if (!headerEl) {
      // Inject header before the first element in app-layout
      const layout = document.querySelector('.app-layout');
      if (layout) {
        layout.insertAdjacentHTML('beforebegin', renderHeader(false, ''));
      }
    }

    if (!sidebarEl) {
      const layout = document.querySelector('.app-layout');
      if (layout) {
        const sidebarHtml = `
          <nav class="sidebar">
            ${renderSidebar()}
          </nav>
        `;
        layout.insertAdjacentHTML('afterbegin', sidebarHtml);
      }
    }

    if (!notificationsEl) {
      const layout = document.querySelector('.app-layout');
      if (layout) {
        layout.insertAdjacentHTML('beforeend', renderNotificationsContainer());
      }
    }

    startClock();
  });
})();