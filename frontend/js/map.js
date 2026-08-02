/**
 * map.js — World Attack Map page logic.
 *
 * - Auth-guards the page (redirects to login if no token)
 * - Fetches /api/v1/map/events and renders pulsing attack dots + bottom strip
 * - resolveIP() calls /api/v1/map/resolve?ip=... and renders sidebar result
 * - SocketIO 'new_threat' listener adds live dots that fade after 10 s
 *
 * Requirements: 5.1–5.9
 */

// ── Auth guard ──────────────────────────────────────────────────────────────
if (!sessionStorage.getItem('ng_access_token')) {
  window.location.href = '/login.html';
}

// ── Projection helper ────────────────────────────────────────────────────────
/**
 * Equirectangular lat/lon → SVG pixel.
 * SVG viewBox is 0 0 1000 500 (width × height).
 * lon -180..180 → x 0..1000; lat 90..-90 → y 0..500
 *
 * @param {number} lat
 * @param {number} lon
 * @param {number} [svgW=1000]
 * @param {number} [svgH=500]
 * @returns {{ x: number, y: number }}
 */
function latLonToXY(lat, lon, svgW = 1000, svgH = 500) {
  const x = ((lon + 180) / 360) * svgW;
  const y = ((90 - lat) / 180) * svgH;
  return { x, y };
}

// ── Dot management ───────────────────────────────────────────────────────────
const dotsLayer = document.getElementById('map-dots');
let dotIndex = 0;

/**
 * Add an attack dot at the given lat/lon.
 * @param {number} lat
 * @param {number} lon
 * @param {string} severity  — used for fill colour
 * @param {boolean} ephemeral — if true, fades and removes after 10 s (live events)
 */
function addDot(lat, lon, severity = '', ephemeral = false) {
  if (!lat && !lon) return; // skip 0,0 (unknown coords)
  const { x, y } = latLonToXY(lat, lon);
  const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  circle.setAttribute('cx', x.toFixed(1));
  circle.setAttribute('cy', y.toFixed(1));
  circle.setAttribute('r', '6');
  circle.classList.add('attack-dot');
  circle.style.fill = _severityColor(severity);
  circle.style.animationDelay = `${(dotIndex % 10) * 0.2}s`;
  circle.setAttribute('aria-label', `Attack origin lat=${lat} lon=${lon}`);
  dotsLayer.appendChild(circle);
  dotIndex++;

  if (ephemeral) {
    // Fade out and remove after 10 s
    setTimeout(() => {
      circle.style.transition = 'opacity 1s';
      circle.style.opacity = '0';
      setTimeout(() => circle.remove(), 1000);
    }, 10000);
  }
}

function _severityColor(sev) {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return '#f87171'; // --danger
    case 'high':     return '#fb923c';
    case 'medium':   return '#facc15';
    default:         return '#00e5ff'; // --accent
  }
}

// ── Event feed (bottom strip) ─────────────────────────────────────────────────
/**
 * Severity → flag emoji subset for a quick flag column.
 * Flag emojis are derived from country code. Fallback to 🌐.
 */
function _countryFlag(countryCode) {
  if (!countryCode || countryCode.length !== 2) return '🌐';
  // Regional indicator letters: A=0x1F1E6, offset from 'A'=65
  const base = 0x1F1E6 - 65;
  return String.fromCodePoint(base + countryCode.toUpperCase().charCodeAt(0)) +
         String.fromCodePoint(base + countryCode.toUpperCase().charCodeAt(1));
}

function renderStrip(events) {
  const strip = document.getElementById('events-strip');
  if (!events.length) { strip.textContent = 'No geo-tagged events yet.'; return; }
  strip.innerHTML = events.map(ev => `
    <div class="strip-item" title="${escHtml(ev.source_ip)} — ${escHtml(ev.attack_type)}">
      <span>${_countryFlag(ev.country_code || '')}</span>
      <code style="font-size:11px">${escHtml(ev.source_ip)}</code>
      <span class="severity-badge severity-${(ev.severity || '').toLowerCase()}" style="font-size:10px">${escHtml(ev.severity || '?')}</span>
    </div>
  `).join('');
}

function renderFeed(events) {
  const feed = document.getElementById('events-feed');
  if (!events.length) {
    feed.innerHTML = '<div style="padding:12px;color:var(--text-muted);font-size:13px">No events yet.</div>';
    return;
  }
  feed.innerHTML = events.map(ev => `
    <div class="feed-item">
      <span>${_countryFlag(ev.country_code || '')}</span>
      <span class="feed-ip">${escHtml(ev.source_ip)}</span>
      <span class="feed-type">${escHtml(ev.attack_type || 'Unknown')}</span>
      <span class="severity-badge severity-${(ev.severity || '').toLowerCase()}" style="font-size:10px">${escHtml(ev.severity || '?')}</span>
    </div>
  `).join('');
}

// ── Load initial events ───────────────────────────────────────────────────────
async function loadMapEvents() {
  try {
    const data = await apiRequest('/map/events?limit=20');
    const events = data.events || [];
    events.forEach(ev => addDot(ev.lat, ev.lon, ev.severity));
    renderStrip(events);
    renderFeed(events);
  } catch (err) {
    const strip = document.getElementById('events-strip');
    strip.textContent = `Error loading events: ${err.message}`;
  }
}

// ── IP resolution ─────────────────────────────────────────────────────────────
async function resolveIP() {
  const input = document.getElementById('resolve-input');
  const resultEl = document.getElementById('resolve-result');
  const ip = (input.value || '').trim();
  if (!ip) { resultEl.innerHTML = '<span class="resolve-error">Enter an IP address.</span>'; return; }

  resultEl.innerHTML = '<span style="color:var(--text-muted)">Resolving…</span>';

  try {
    // apiRequest throws on non-success envelope; for GeoIPError the backend
    // returns HTTP 503 without the success wrapper, so catch via raw fetch.
    const res = await fetch(`/api/v1/map/resolve?ip=${encodeURIComponent(ip)}`, {
      headers: { 'Content-Type': 'application/json' },
    });
    const json = await res.json();

    if (!res.ok || !json.success) {
      // GeoIPError shape: { ip, error_code, timestamp }
      const code = json.error_code || json.error || 'Unknown error';
      resultEl.innerHTML = `<span class="resolve-error">GeoIP error: ${escHtml(code)}</span>`;
      return;
    }

    const d = json.data;
    resultEl.innerHTML = [
      ['IP',      d.ip       || ip],
      ['Country', d.country  || '—'],
      ['City',    d.city     || '—'],
      ['Lat/Lon', d.lat != null ? `${d.lat}, ${d.lon}` : '—'],
      ['ASN',     d.asn      || '—'],
      ['ISP',     d.isp      || '—'],
    ].map(([label, val]) => `
      <div class="resolve-row-item">
        <span class="resolve-label">${label}</span>
        <span>${escHtml(String(val))}</span>
      </div>
    `).join('');

    // Also highlight on map if coords available
    if (d.lat && d.lon) addDot(d.lat, d.lon, 'high', true);

  } catch (err) {
    resultEl.innerHTML = `<span class="resolve-error">Network error: ${escHtml(err.message)}</span>`;
  }
}

// Allow Enter key in input
document.getElementById('resolve-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') resolveIP();
});

// ── SocketIO live threats ─────────────────────────────────────────────────────
SocketManager.on('new_threat', (payload) => {
  const ev = payload || {};
  const lat = ev.lat ?? 0;
  const lon = ev.lon ?? 0;
  addDot(lat, lon, ev.severity, true);

  // Prepend to feed
  const feed = document.getElementById('events-feed');
  const item = document.createElement('div');
  item.className = 'feed-item';
  item.innerHTML = `
    <span>${_countryFlag(ev.country_code || '')}</span>
    <span class="feed-ip">${escHtml(ev.source_ip || '?')}</span>
    <span class="feed-type">${escHtml(ev.attack_type || 'Unknown')}</span>
    <span class="severity-badge severity-${(ev.severity || '').toLowerCase()}" style="font-size:10px">${escHtml(ev.severity || '?')}</span>
  `;
  feed.prepend(item);
  // Keep feed bounded to ~40 items
  while (feed.children.length > 40) feed.lastChild.remove();
});

// ── Clock + sidebar toggle ────────────────────────────────────────────────────
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sidebar-overlay').classList.toggle('visible');
}

function startClock() {
  const el = document.getElementById('system-time');
  if (el) setInterval(() => { el.textContent = new Date().toLocaleTimeString(); }, 1000);
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startClock();
  loadMapEvents();
  SocketManager.connect();
});
