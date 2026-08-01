/**
 * charts.js — Chart.js chart initialisation and update helpers.
 *
 * - trafficChart: Real-time line chart (packets/second over last 60s)
 * - severityChart: Severity distribution doughnut
 *
 * Requirements: 16.2, 16.3
 */

// ── Shared Chart.js defaults ──────────────────────────────────────────────
Chart.defaults.color = '#94A3B8';
Chart.defaults.borderColor = '#334155';
Chart.defaults.font.family = "'Inter', Arial, sans-serif";

// ── Traffic Rate Line Chart ────────────────────────────────────────────────
let trafficChart = null;
const TRAFFIC_MAX_POINTS = 60;
const trafficLabels = [];
const trafficData = [];

function initTrafficChart(canvasId) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;

  trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: trafficLabels,
      datasets: [{
        label: 'Packets/sec',
        data: trafficData,
        borderColor: '#3B82F6',
        backgroundColor: 'rgba(59,130,246,0.1)',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 0,
        pointHoverRadius: 4,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 300 },
      scales: {
        x: {
          display: true,
          grid: { color: 'rgba(51,65,85,0.5)' },
          ticks: { maxTicksLimit: 8, font: { size: 11 } },
        },
        y: {
          display: true,
          beginAtZero: true,
          grid: { color: 'rgba(51,65,85,0.5)' },
          ticks: { font: { size: 11 } },
        },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#1E293B',
          borderColor: '#334155',
          borderWidth: 1,
        },
      },
    },
  });
}

function updateTrafficChart(pps) {
  if (!trafficChart) return;

  const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  trafficLabels.push(now);
  trafficData.push(Number(pps) || 0);

  if (trafficLabels.length > TRAFFIC_MAX_POINTS) {
    trafficLabels.shift();
    trafficData.shift();
  }

  trafficChart.update('none'); // 'none' = no animation for smooth live updates
}

// ── Severity Distribution Doughnut ────────────────────────────────────────
let severityChart = null;
const severityCounts = { Low: 0, Medium: 0, High: 0, Critical: 0 };

function initSeverityChart(canvasId) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;

  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Low', 'Medium', 'High', 'Critical'],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: [
          'rgba(34,197,94,0.7)',
          'rgba(250,204,21,0.7)',
          'rgba(239,68,68,0.7)',
          'rgba(220,38,38,0.9)',
        ],
        borderColor: ['#22C55E', '#FACC15', '#EF4444', '#DC2626'],
        borderWidth: 1,
        hoverOffset: 4,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '65%',
      animation: { duration: 400 },
      plugins: {
        legend: {
          position: 'bottom',
          labels: { padding: 12, font: { size: 12 } },
        },
        tooltip: {
          backgroundColor: '#1E293B',
          borderColor: '#334155',
          borderWidth: 1,
        },
      },
    },
  });
}

function updateSeverityChart(severity) {
  if (!severityChart) return;
  if (severityCounts[severity] !== undefined) {
    severityCounts[severity]++;
    severityChart.data.datasets[0].data = [
      severityCounts.Low,
      severityCounts.Medium,
      severityCounts.High,
      severityCounts.Critical,
    ];
    severityChart.update();
  }
}

function setSeverityCounts(counts) {
  if (!severityChart) return;
  severityCounts.Low      = counts.Low      || 0;
  severityCounts.Medium   = counts.Medium   || 0;
  severityCounts.High     = counts.High     || 0;
  severityCounts.Critical = counts.Critical || 0;
  severityChart.data.datasets[0].data = [
    severityCounts.Low, severityCounts.Medium,
    severityCounts.High, severityCounts.Critical,
  ];
  severityChart.update();
}
