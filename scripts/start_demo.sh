#!/bin/bash
# =============================================================================
# start_demo.sh — NetGuard IDPS Demo Launcher
#
# Starts the NetGuard backend, opens the dashboard, and runs the attack
# demo scripts in sequence.
#
# Requirements: 1.7
# Usage:  sudo ./scripts/start_demo.sh [interface]
#         Default interface is eth0
# =============================================================================

set -euo pipefail

INTERFACE="${1:-eth0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEMO_DIR="${PROJECT_DIR}/demo"

echo "============================================"
echo "  NetGuard IDPS — Demo"
echo "============================================"
echo ""

# ── Run setup if needed ──────────────────────────────────────────────────────
if [ ! -f "${PROJECT_DIR}/database/netguard.db" ]; then
    echo "[*] Running setup..."
    bash "${SCRIPT_DIR}/setup.sh"
fi

# ── Start backend ────────────────────────────────────────────────────────────
echo "[*] Starting NetGuard backend..."
cd "${PROJECT_DIR}"
python3 backend/main.py &
NG_PID=$!
echo "  PID: ${NG_PID}"
cd "${SCRIPT_DIR}"

# Give it time to start
sleep 3

# ── Open dashboard ───────────────────────────────────────────────────────────
echo "[*] Opening dashboard at http://localhost:5000"
if command -v xdg-open &>/dev/null; then
    xdg-open "http://localhost:5000" 2>/dev/null || true
elif command -v open &>/dev/null; then
    open "http://localhost:5000" 2>/dev/null || true
fi

# ── Start monitoring ─────────────────────────────────────────────────────────
echo "[*] Starting packet capture on ${INTERFACE}..."
curl -s -X POST "http://localhost:5000/api/v1/monitor/start" \
  -H "Content-Type: application/json" \
  -d "{\"interface\": \"${INTERFACE}\"}" 2>&1 || echo "  [!] Monitor start failed (expected if not running as root)"

echo ""
echo "============================================"
echo "  Running attack sequence..."
echo "============================================"
echo ""

# ── Attack sequence ──────────────────────────────────────────────────────────
echo "[1/5] SYN Flood attack..."
bash "${DEMO_DIR}/attack_syn.sh" 2>&1 || true
echo "  Waiting for detection…"; sleep 5

echo ""
echo "[2/5] Port Scan attack..."
bash "${DEMO_DIR}/attack_scan.sh" 2>&1 || true
echo "  Waiting for detection…"; sleep 5

echo ""
echo "[3/5] SQL Injection attack..."
bash "${DEMO_DIR}/attack_sql.sh" 2>&1 || true
echo "  Waiting for detection…"; sleep 5

echo ""
echo "[4/5] Brute Force attack..."
bash "${DEMO_DIR}/attack_bruteforce.sh" 2>&1 || true
echo "  Waiting for detection…"; sleep 5

echo ""
echo "[5/5] ARP Spoofing attack..."
bash "${DEMO_DIR}/attack_arp.sh" 2>&1 || true
echo "  Waiting for detection…"; sleep 3

echo ""
echo "============================================"
echo "  Demo sequence complete!"
echo "============================================"
echo ""
echo "  Dashboard: http://localhost:5000"
echo ""
echo "  Press Ctrl+C to stop the backend."
echo ""

# Wait for backend
wait "${NG_PID}"
