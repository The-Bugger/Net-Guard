/**
 * socket.js — Flask-SocketIO connection management.
 *
 * Handles:
 * - WebSocket connection to the backend
 * - Auto-reconnect at 5-second intervals on disconnect
 * - "Reconnecting..." banner visibility
 * - Event routing to registered handlers
 *
 * Requirements: 16.8, 16.12
 */

const SocketManager = (() => {
  let socket = null;
  let reconnectTimer = null;
  // Support multiple handlers per event (array, not single-slot dict)
  const handlers = {};

  function on(event, fn) {
    if (!handlers[event]) handlers[event] = [];
    // Avoid double-registration of the same function reference
    if (!handlers[event].includes(fn)) handlers[event].push(fn);
    if (socket) socket.on(event, fn);
  }

  function connect() {
    if (typeof io === 'undefined') {
      console.warn('SocketIO not loaded — falling back to polling.');
      return;
    }

    socket = io({
      transports: ['websocket', 'polling'],
      reconnection: false,
    });

    socket.on('connect', () => {
      _hideBanner();
      if (reconnectTimer) { clearInterval(reconnectTimer); reconnectTimer = null; }
      // Re-register all handlers on reconnect
      Object.entries(handlers).forEach(([ev, fns]) =>
        fns.forEach(fn => socket.on(ev, fn))
      );
    });

    socket.on('disconnect', () => {
      console.warn('SocketIO disconnected — scheduling reconnect.');
      _showBanner();
      _scheduleReconnect();
    });

    socket.on('connect_error', () => {
      _showBanner();
      _scheduleReconnect();
    });

    // Register handlers added before connect()
    Object.entries(handlers).forEach(([ev, fns]) =>
      fns.forEach(fn => socket.on(ev, fn))
    );
  }

  function _scheduleReconnect() {
    if (reconnectTimer) return;
    reconnectTimer = setInterval(() => {
      if (socket) socket.connect();
    }, 5000);
  }

  function _showBanner() {
    const b = document.getElementById('reconnecting-banner');
    if (b) b.classList.add('visible');
  }

  function _hideBanner() {
    const b = document.getElementById('reconnecting-banner');
    if (b) b.classList.remove('visible');
  }

  /**
   * Emit an event to the server.
   */
  function emit(event, data) {
    if (socket && socket.connected) {
      socket.emit(event, data);
    }
  }

  return { connect, on, emit };
})();
