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

// Hardcoded region centroids [lon, lat] for attack-map projection
// ponytail: index-based assignment since we have no real geo-IP; ceiling: IP geolocation API
const REGION_CENTROIDS = [
  [-100, 40],  // NA
  [15,   50],  // EU
  [100,  35],  // Asia
  [60,   60],  // RU
  [45,   25],  // ME
  [-60, -15],  // SA
  [20,    5],  // AF
  [135, -25],  // AU
];

const ATTACK_TYPES = [
  'SQL Injection', 'Brute Force', 'Port Scan', 'DDoS/SYN Flood', 'XSS',
  'SSH Login', 'Suspicious DNS', 'Malware Download', 'Privilege Escalation',
];

const SEVERITY_COLORS = {
  Critical: '#F87171',
  High:     '#FB923C',
  Medium:   '#FACC15',
  Low:      '#4ADE80',
  Unknown:  '#94A3B8',
};

// Project lon/lat → SVG pixel coords for viewBox="0 0 800 400"
function lonToX(lon) { return (lon + 180) / 360 * 800; }
function latToY(lat) { return (90 - lat) / 180 * 400; }

function updateAttackMap(top_ips) {
  const g = document.getElementById('map-dots');
  if (!g) return;
  g.innerHTML = '';
  if (!top_ips || top_ips.length === 0) return;
  top_ips.forEach((row, i) => {
    const [lon, lat] = REGION_CENTROIDS[i % REGION_CENTROIDS.length];
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', lonToX(lon).toFixed(1));
    circle.setAttribute('cy', latToY(lat).toFixed(1));
    circle.setAttribute('r', '6');
    circle.setAttribute('fill', '#F87171');
    circle.setAttribute('opacity', '0.8');
    const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    title.textContent = `${row.source_ip} (${row.count} events)`;
    circle.appendChild(title);
    g.appendChild(circle);
  });
}

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

  const sel = document.getElementById('period-select');
  // Initialise with daily (already selected in HTML)
  loadAnalytics(sel.value);

  // Update on period change — no page reload
  sel.addEventListener('change', () => loadAnalytics(sel.value));
});
