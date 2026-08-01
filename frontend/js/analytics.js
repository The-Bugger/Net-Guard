/**
 * analytics.js — Fetches /api/v1/analytics and updates charts + KPIs.
 *
 * Requirements: 5.5, 5.6
 */

'use strict';

// Chart instances (initialised once, updated on period change)
let barChart = null;
let doughnutChart = null;
let radarChart = null;

// ── World Attack Map — Canvas renderer ─────────────────────────────────────
// Uses a canvas element sized to match its container.
// Draws: ocean background, simplified land polygons (Natural Earth-inspired),
// lat/lon grid, pulsing attack dots, arc lines from Europe "server" centroid.
// No external image dependency — fully self-contained.

// Equirectangular projection helpers (canvas is sized W×H at runtime)
function lonToXc(lon, W) { return (lon + 180) / 360 * W; }
function latToYc(lat, H) { return (90 - lat) / 180 * H; }

// Simplified land path data as arrays of [lon, lat] polygons
// Source: Natural Earth 110m simplified (public domain)
const _LAND_POLYS = [
  // North America mainland
  [[-168,72],[-140,70],[-120,60],[-84,42],[-80,25],[-90,15],[-105,20],[-117,32],[-125,48],[-140,58],[-153,60],[-165,68]],
  // Greenland
  [[-44,83],[-18,77],[-18,70],[-38,65],[-50,67],[-58,76],[-50,82]],
  // South America
  [[-80,12],[-63,12],[-50,5],[-35,-5],[-35,-20],[-50,-30],[-65,-42],[-72,-50],[-68,-55],[-55,-52],[-40,-22],[-48,-15],[-60,-5],[-70,0],[-78,8]],
  // Europe (simplified)
  [[-10,36],[5,36],[15,38],[28,37],[30,42],[24,48],[15,50],[8,55],[0,51],[-5,48],[-8,42]],
  // Scandinavia
  [[5,58],[10,63],[15,70],[28,72],[30,62],[24,58],[18,58],[12,56]],
  // UK
  [[-5,50],[2,51],[2,56],[-4,58],[-6,55],[-3,51]],
  // Africa
  [[-18,15],[0,5],[12,5],[20,15],[35,12],[42,12],[45,0],[40,-10],[35,-20],[25,-35],[18,-35],[12,-18],[8,-5],[2,5],[-5,5],[-10,5],[-18,15]],
  // Middle East
  [[28,37],[37,37],[48,30],[55,22],[45,12],[38,15],[30,28],[28,33]],
  // Russia (simplified)
  [[30,68],[60,72],[90,70],[130,68],[170,65],[175,55],[155,52],[140,50],[135,48],[120,52],[100,50],[80,52],[65,55],[60,62],[50,68],[40,68],[30,70]],
  // Central Asia / Kazakhstan
  [[52,40],[60,45],[80,50],[100,50],[105,42],[80,38],[65,38],[55,38]],
  // India
  [[68,24],[78,10],[80,8],[77,8],[72,20],[68,24]],
  // China / East Asia
  [[76,39],[88,48],[120,53],[135,48],[130,38],[120,30],[110,20],[100,22],[95,28],[85,32],[80,38],[76,39]],
  // Southeast Asia
  [[100,22],[108,20],[110,10],[108,1],[104,-2],[100,4],[96,8],[100,12],[100,22]],
  // Japan
  [[130,31],[135,34],[141,41],[143,44],[141,44],[135,35],[130,31]],
  // Australia
  [[114,-22],[122,-18],[136,-14],[140,-15],[150,-22],[152,-30],[150,-38],[143,-38],[130,-32],[120,-34],[114,-28],[114,-22]],
  // New Zealand (North)
  [[174,-37],[178,-38],[176,-40],[172,-41],[172,-38],[174,-37]],
];

let _mapCanvas = null;
let _mapCtx   = null;
let _mapW = 0;
let _mapH = 0;
let _mapInitDone = false;
let _currentTopIps = [];
let _pulseFrame = 0;
let _pulseAnim  = null;
let _mapImg     = null;   // The world map background image
let _mapImgReady = false;

function _initMap() {
  _mapCanvas = document.getElementById('attack-map-canvas');
  if (!_mapCanvas) return false;
  const wrap = _mapCanvas.parentElement;
  _mapW = wrap.clientWidth  || 800;
  _mapH = Math.round(_mapW * 0.52);
  _mapCanvas.width  = _mapW;
  _mapCanvas.height = _mapH;
  _mapCanvas.style.height = _mapH + 'px';
  _mapCtx = _mapCanvas.getContext('2d');

  // Load the world map background image
  _mapImg = new Image();
  _mapImg.crossOrigin = 'anonymous';
  _mapImg.onload = () => {
    _mapImgReady = true;
    _drawMapBase();
    // If we already have IPs, draw them now
    if (_currentTopIps.length > 0) updateAttackMap(_currentTopIps);
  };
  _mapImg.onerror = () => {
    // Fallback: draw canvas-only map
    _mapImgReady = false;
    _drawMapBase();
  };
  _mapImg.src = '/images/world-map.png';
  _mapInitDone = true;
  return true;
}

function _drawMapBase() {
  if (!_mapCtx) return;
  const ctx = _mapCtx;
  const W = _mapW, H = _mapH;
  ctx.clearRect(0, 0, W, H);

  // Dark ocean background
  ctx.fillStyle = '#071220';
  ctx.fillRect(0, 0, W, H);

  if (_mapImgReady && _mapImg) {
    // Draw the real world map image, tinted to match our dark theme
    // Draw full image stretched to canvas
    ctx.drawImage(_mapImg, 0, 0, W, H);
    // Apply dark blue tint overlay to unify with the UI color scheme
    ctx.fillStyle = 'rgba(7, 18, 32, 0.35)';
    ctx.fillRect(0, 0, W, H);
  } else {
    // Fallback: draw simplified land polygons while image loads
    _drawLandFallback(ctx, W, H);
  }

  // Lat/lon grid on top (subtle)
  ctx.strokeStyle = 'rgba(0,229,255,0.08)';
  ctx.lineWidth = 0.5;
  [-60,-30,0,30,60].forEach(lat => {
    const y = latToYc(lat, H);
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
  });
  [-120,-60,0,60,120].forEach(lon => {
    const x = lonToXc(lon, W);
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
  });

  // Subtle lat/lon labels
  ctx.fillStyle = 'rgba(0,229,255,0.18)';
  ctx.font = `${Math.max(8, W / 120)}px monospace`;
  ctx.textAlign = 'right';
  [['60°N',60],['30°N',30],['EQ',0],['30°S',-30],['60°S',-60]].forEach(([lbl,lat]) => {
    ctx.fillText(lbl, W - 4, latToYc(lat, H) - 2);
  });
}

function _drawLandFallback(ctx, W, H) {
  // Simplified polygons while the image loads
  ctx.fillStyle   = '#1a3a5c';
  ctx.strokeStyle = '#2d5a8e';
  ctx.lineWidth   = 0.8;
  _LAND_POLYS.forEach(poly => {
    if (poly.length < 3) return;
    ctx.beginPath();
    poly.forEach(([lon, lat], i) => {
      const x = lonToXc(lon, W), y = latToYc(lat, H);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
  });
}

function updateAttackMap(top_ips) {
  _currentTopIps = top_ips || [];

  const counter = document.getElementById('map-attack-count');
  if (counter) counter.textContent = _currentTopIps.length ? `${_currentTopIps.length} source(s)` : '';

  if (!_mapInitDone && !_initMap()) return;

  // Cancel existing animation before redrawing
  if (_pulseAnim) { cancelAnimationFrame(_pulseAnim); _pulseAnim = null; }

  if (_currentTopIps.length === 0) {
    _drawMapBase();
    return;
  }

  // Animate pulsing dots
  function frame() {
    _pulseFrame++;
    _drawMapBase();
    _drawAttackDots(_currentTopIps, _pulseFrame);
    _pulseAnim = requestAnimationFrame(frame);
  }
  frame();
}

// Map IPs to approximate [lon, lat] based on the known sim IP pool
// Real upgrade path: use ip-api.com or MaxMind GeoLite2
// ── IP Geo lookup: Kathmandu/Asia-centric attack simulation ──────────────────
// Server target: Kathmandu, Nepal [85, 28]
// ~70% Asia/nearby, ~30% global (1 per continent over 10 min)
// All coordinates are [lon, lat] for equirectangular projection.
const _IP_GEO = {
  // ── Asia (nearby — high frequency) ──────────────────────────────────────
  // India
  '103.41.167.21':  [77, 28],   // Delhi
  '49.36.187.45':   [80, 13],   // Chennai
  '182.72.180.1':   [72, 19],   // Mumbai
  '115.112.82.1':   [77, 13],   // Bangalore
  '27.251.16.1':    [88, 22],   // Kolkata
  // China
  '203.0.113.99':   [116, 40],  // Beijing
  '116.228.101.1':  [121, 31],  // Shanghai
  '183.2.172.1':    [113, 23],  // Guangzhou
  '101.71.57.1':    [104, 30],  // Chengdu
  '163.177.65.1':   [114, 22],  // Shenzhen
  // Bangladesh
  '103.92.45.1':    [90, 23],   // Dhaka
  '103.168.206.1':  [91, 22],   // Chittagong
  // Pakistan
  '39.32.100.1':    [67, 24],   // Karachi
  '202.83.24.1':    [73, 31],   // Lahore
  '209.58.130.1':   [69, 34],   // Islamabad
  // Southeast Asia
  '203.0.113.200':  [103, 1],   // Singapore
  '103.77.4.82':    [106, -6],  // Jakarta
  '14.225.196.1':   [106, 16],  // Hanoi
  '49.231.100.1':   [100, 14],  // Bangkok
  '180.214.232.1':  [121, 14],  // Manila
  '118.189.149.1':  [101, 3],   // Kuala Lumpur
  // Central Asia / nearby
  '194.165.16.11':  [71, 51],   // Almaty (KZ)
  '91.212.68.1':    [69, 38],   // Tashkent (UZ)
  '91.185.186.1':   [74, 42],   // Bishkek (KG)
  // Nepal / local ISP ranges (rare — insider threat)
  '202.166.196.1':  [85, 27],   // Kathmandu (local)
  // Japan / Korea
  '203.0.113.42':   [139, 36],  // Tokyo
  '221.148.18.1':   [126, 37],  // Seoul

  // ── Europe (medium frequency) ────────────────────────────────────────────
  '198.51.100.7':   [2,  48],   // Paris
  '185.220.101.45': [8,  51],   // Frankfurt (Tor)
  '80.82.77.33':    [18, 60],   // Stockholm
  '85.93.93.93':    [26, 44],   // Bucharest
  '193.32.126.163': [4,  52],   // Amsterdam
  '194.61.24.102':  [44, 53],   // Moscow

  // ── North America (low frequency) ────────────────────────────────────────
  '45.33.32.156':   [-97, 38],  // Dallas
  '104.21.45.1':    [-74, 41],  // New York
  '198.51.100.14':  [-118,34],  // Los Angeles

  // ── Africa (low frequency) ───────────────────────────────────────────────
  '41.215.180.1':   [36, -1],   // Nairobi
  '197.255.127.1':  [3,  6],    // Lagos
  '196.216.2.1':    [28, -26],  // Johannesburg

  // ── South America (low frequency) ────────────────────────────────────────
  '177.54.144.1':   [-46,-23],  // São Paulo
  '190.57.20.1':    [-58,-34],  // Buenos Aires

  // ── Australia / Oceania (low frequency) ──────────────────────────────────
  '1.0.0.1':        [151,-33],  // Sydney
  '101.0.69.1':     [144,-38],  // Melbourne

  // ── Middle East (medium frequency) ───────────────────────────────────────
  '5.42.92.1':      [46, 24],   // Riyadh
  '185.81.96.1':    [51, 25],   // Tehran
  '176.221.97.1':   [35, 32],   // Beirut
};

function _geoOf(ip) {
  if (_IP_GEO[ip]) return _IP_GEO[ip];
  // Fallback: hash-distribute unknown IPs around the globe
  let h = 0;
  for (let i = 0; i < ip.length; i++) h = (h * 31 + ip.charCodeAt(i)) & 0xffffffff;
  const lon = ((h & 0x1ff) - 180);
  const lat = (((h >> 9) & 0xff) - 90) * 0.7;
  return [lon, lat];
}

function _drawAttackDots(top_ips, frame) {
  if (!_mapCtx) return;
  const ctx = _mapCtx;
  const W = _mapW, H = _mapH;

  // "Server" target — Kathmandu, Nepal (our monitored system)
  const srvX = lonToXc(85, W);
  const srvY = latToYc(28, H);

  // Draw server marker
  ctx.beginPath();
  ctx.arc(srvX, srvY, 5, 0, Math.PI * 2);
  ctx.fillStyle = '#00E5FF';
  ctx.fill();
  ctx.strokeStyle = 'rgba(0,229,255,0.4)';
  ctx.lineWidth = 2;
  const serverPulse = 5 + 4 * Math.abs(Math.sin(frame * 0.05));
  ctx.beginPath();
  ctx.arc(srvX, srvY, serverPulse, 0, Math.PI * 2);
  ctx.stroke();

  top_ips.forEach((row, i) => {
    const [lon, lat] = _geoOf(row.source_ip);
    const cx = lonToXc(lon, W);
    const cy = latToYc(lat, H);
    const countR = Math.min(3 + Math.log2(row.count + 1) * 1.5, 10);

    // Arc line — animated dashes
    const dashOffset = (frame * 1.5) % 20;
    ctx.save();
    ctx.setLineDash([4, 3]);
    ctx.lineDashOffset = -dashOffset;
    ctx.strokeStyle = 'rgba(248,113,113,0.35)';
    ctx.lineWidth = 0.8;
    ctx.beginPath();
    // Bezier curve for arc effect
    const mx = (cx + srvX) / 2;
    const my = Math.min(cy, srvY) - Math.abs(cx - srvX) * 0.18;
    ctx.moveTo(cx, cy);
    ctx.quadraticCurveTo(mx, my, srvX, srvY);
    ctx.stroke();
    ctx.restore();

    // Pulsing outer ring
    const pulse = countR + 3 * Math.abs(Math.sin(frame * 0.06 + i * 1.2));
    ctx.beginPath();
    ctx.arc(cx, cy, pulse, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(248,113,113,0.12)';
    ctx.fill();
    ctx.strokeStyle = 'rgba(248,113,113,0.4)';
    ctx.lineWidth = 1;
    ctx.stroke();

    // Solid dot
    ctx.beginPath();
    ctx.arc(cx, cy, countR, 0, Math.PI * 2);
    ctx.fillStyle = '#F87171';
    ctx.globalAlpha = 0.9;
    ctx.fill();
    ctx.globalAlpha = 1;

    // IP label
    ctx.fillStyle = '#94A3B8';
    ctx.font = `${Math.max(8, W / 110)}px monospace`;
    ctx.textAlign = 'left';
    ctx.fillText(row.source_ip + (row.count > 1 ? ` ×${row.count}` : ''), cx + countR + 3, cy + 4);
  });
}

// Handle window resize
window.addEventListener('resize', () => {
  if (!_mapInitDone) return;
  _mapInitDone = false; // force re-init
  if (_pulseAnim) { cancelAnimationFrame(_pulseAnim); _pulseAnim = null; }
  setTimeout(() => updateAttackMap(_currentTopIps), 100);
});

const ATTACK_TYPES = [
  'SQL Injection', 'Brute Force', 'Port Scan', 'SYN Flood',
  'ARP Spoofing', 'ICMP Flood', 'DNS Tunneling', 'Slow HTTP',
];

const SEVERITY_COLORS = {
  Critical: '#F87171',
  High:     '#FB923C',
  Medium:   '#FACC15',
  Low:      '#4ADE80',
  Unknown:  '#94A3B8',
};

function initCharts() {
  const barCtx = document.getElementById('bar-chart').getContext('2d');
  barChart = new Chart(barCtx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Events',
        data: [],
        backgroundColor: 'rgba(0, 229, 255, 0.6)',
        borderColor: '#00E5FF',
        borderWidth: 1,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#94A3B8', maxRotation: 45 }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { ticks: { color: '#94A3B8' }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true },
      }
    }
  });

  const donutCtx = document.getElementById('doughnut-chart').getContext('2d');
  doughnutChart = new Chart(donutCtx, {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: { position: 'bottom', labels: { color: '#94A3B8', padding: 12, boxWidth: 12 } }
      }
    }
  });

  const radarCtx = document.getElementById('threat-radar').getContext('2d');
  radarChart = new Chart(radarCtx, {
    type: 'radar',
    data: {
      labels: ATTACK_TYPES,
      datasets: [{
        label: 'Event Count',
        data: new Array(ATTACK_TYPES.length).fill(0),
        backgroundColor: 'rgba(0, 229, 255, 0.15)',
        borderColor: '#00E5FF',
        pointBackgroundColor: '#00E5FF',
        borderWidth: 1.5,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      scales: {
        r: {
          ticks: { color: '#94A3B8', backdropColor: 'transparent' },
          grid: { color: 'rgba(255,255,255,0.08)' },
          pointLabels: { color: '#94A3B8', font: { size: 10 } },
          beginAtZero: true,
        }
      },
      plugins: { legend: { display: false } }
    }
  });
}

function updateAll(data) {
  // Bar chart — events over time
  const labels = data.buckets.map(b => b.bucket);
  const counts = data.buckets.map(b => b.count);
  barChart.data.labels = labels;
  barChart.data.datasets[0].data = counts;
  barChart.update();

  // Doughnut chart — severity distribution
  const sevLabels = Object.keys(data.severity_counts);
  const sevData   = Object.values(data.severity_counts);
  const sevColors = sevLabels.map(l => SEVERITY_COLORS[l] || SEVERITY_COLORS.Unknown);
  doughnutChart.data.labels = sevLabels;
  doughnutChart.data.datasets[0].data = sevData;
  doughnutChart.data.datasets[0].backgroundColor = sevColors;
  doughnutChart.update();

  // KPI cards
  document.getElementById('kpi-total').textContent    = data.total_events;
  document.getElementById('kpi-blocked').textContent  = data.blocked_count;
  document.getElementById('kpi-detected').textContent = data.detected_count;

  // Top attacker IPs table
  const tbody = document.getElementById('top-ips-tbody');
  if (!data.top_ips || data.top_ips.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" class="empty-state"><p>No data for this period.</p></td></tr>';
    updateAttackMap([]);
    radarChart.data.datasets[0].data = new Array(ATTACK_TYPES.length).fill(0);
    radarChart.update();
    return;
  }
  tbody.innerHTML = data.top_ips.map((row, i) =>
    `<tr>
      <td>${i + 1}</td>
      <td style="font-family:monospace">${row.source_ip}</td>
      <td>${row.count}</td>
    </tr>`
  ).join('');

  // Attack map — cycle top IPs through region centroids
  updateAttackMap(data.top_ips);

  // Radar chart — sum breakdown counts per attack type across all buckets
  const typeTotals = new Array(ATTACK_TYPES.length).fill(0);
  (data.buckets || []).forEach(bucket => {
    const bd = bucket.breakdown || {};
    ATTACK_TYPES.forEach((t, idx) => { typeTotals[idx] += (bd[t] || 0); });
  });
  radarChart.data.datasets[0].data = typeTotals;
  radarChart.update();
}

async function loadAnalytics(period) {
  try {
    const res  = await fetch(`/api/v1/analytics?period=${encodeURIComponent(period)}`);
    const json = await res.json();
    if (!json.success) throw new Error(json.message || 'API error');
    updateAll(json.data);
  } catch (err) {
    showToast('Failed to load analytics: ' + err.message, 'error');
  }
}

// Kick off on page load
document.addEventListener('DOMContentLoaded', () => {
  initCharts();

  // Initialize and draw the base world map immediately
  if (_initMap()) _drawMapBase();

  const sel = document.getElementById('period-select');
  loadAnalytics(sel.value);
  sel.addEventListener('change', () => loadAnalytics(sel.value));

  setInterval(() => {
    const el = document.getElementById('system-time');
    if (el) el.textContent = new Date().toLocaleTimeString();
  }, 1000);
});
