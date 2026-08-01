#!/bin/bash
# =============================================================================
# setup.sh — NetGuard IDPS Setup Script
#
# Installs dependencies, creates directories, initialises the database,
# and verifies prerequisites.
#
# Requirements: 1.1, 14.1
# Usage:  sudo ./scripts/setup.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "============================================"
echo "  NetGuard IDPS — Setup"
echo "============================================"
echo ""

# ── Prerequisites ────────────────────────────────────────────────────────────
echo "[1/5] Checking prerequisites..."
echo "  Python: $(python3 --version 2>&1 || echo 'NOT FOUND')"
echo "  Pip:    $(pip3 --version 2>&1 || echo 'NOT FOUND')"

if ! command -v python3 &>/dev/null; then
    echo "[!] Python 3.11+ is required. Install it and re-run."
    exit 1
fi

# Check iptables availability
if command -v iptables &>/dev/null; then
    echo "  iptables: $(iptables --version 2>&1)"
else
    echo "  iptables: NOT FOUND (optional — prevention engine requires it)"
fi

# ── Install Python dependencies ──────────────────────────────────────────────
echo ""
echo "[2/5] Installing Python dependencies..."
pip3 install -r "${PROJECT_DIR}/requirements.txt" -q 2>&1 | tail -3
echo "  Done."

# ── Create directory structure ───────────────────────────────────────────────
echo ""
echo "[3/5] Creating directory structure..."

mkdir -p "${PROJECT_DIR}"/{backend/{api,services,models,routes,utils},frontend/{css,js,assets},detection/{rules,parsers,capture},database/migrations,config,logs,scripts,tests/integration,demo,docs}

echo "  Done."

# ── Initialise database ──────────────────────────────────────────────────────
echo ""
echo "[4/5] Initialising database..."
cd "${PROJECT_DIR}"
python3 -c "
from database.init_db import initialize_db
initialize_db()
print('  Database initialised: database/netguard.db')
" 2>&1 || echo "  [!] Database initialisation failed — check database/schema.py"
cd "${SCRIPT_DIR}"

# ── Verify iptables ──────────────────────────────────────────────────────────
echo ""
echo "[5/5] Verifying iptables..."
if command -v iptables &>/dev/null; then
    if iptables -L -n &>/dev/null; then
        echo "  iptables is accessible."
    else
        echo "  iptables requires root privileges. Run setup with sudo for prevention features."
    fi
else
    echo "  iptables not found — prevention engine will be unavailable."
fi

echo ""
echo "============================================"
echo "  Setup complete!"
echo "============================================"
echo ""
echo "  Start the system:  python backend/main.py"
echo "  Open dashboard:    http://localhost:5000"
echo "  Run tests:         pytest tests/ -v"
echo ""
