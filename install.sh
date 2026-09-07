#!/usr/bin/env bash
# =============================================================================
# install.sh — NetGuard IDPS cross-platform installer (macOS / Linux / Windows)
#
# Detects the OS, installs system prerequisites, creates a virtualenv,
# installs Python dependencies, initialises the database, and prints
# platform-specific next steps.
#
# Usage:
#   ./install.sh              # normal install (venv at .venv/)
#   ./install.sh --system      # install into system Python (not recommended)
#
# Windows: run from Git Bash, WSL, or MSYS2. A native PowerShell variant is
# at install.ps1 (run: powershell -ExecutionPolicy Bypass -File install.ps1)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}"

USE_SYSTEM=0
[[ "${1:-}" == "--system" ]] && USE_SYSTEM=1

# ── OS detection ────────────────────────────────────────────────────────────
OS="$(uname -s)"
case "${OS}" in
    Linux*)  PLATFORM="linux" ;;
    Darwin*) PLATFORM="macos" ;;
    MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
    *) echo "[!] Unsupported OS: ${OS}"; exit 1 ;;
esac

echo "============================================"
echo "  NetGuard IDPS — Installer (${PLATFORM})"
echo "============================================"
echo ""

# ── Python detection ─────────────────────────────────────────────────────────
find_python() {
    for cand in python3.14 python3.13 python3.12 python3.11 python3 python; do
        if command -v "${cand}" &>/dev/null; then
            echo "${cand}"
            return 0
        fi
    done
    return 1
}

PY="$(find_python)" || { echo "[!] Python 3.11+ not found. Install it and re-run."; exit 1; }

if ! "${PY}" -c 'import sys; exit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "[!] Python 3.11+ required (found $(${PY} --version))."
    exit 1
fi
echo "[1/6] Python OK: $(${PY} --version)"

# ── System prerequisites ─────────────────────────────────────────────────────
echo ""
echo "[2/6] Checking system prerequisites..."

case "${PLATFORM}" in
    linux)
        MISSING=()
        for pkg in python3-venv libpcap-dev; do
            dpkg -s "${pkg}" &>/dev/null || MISSING+=("${pkg}")
        done
        if [[ ${#MISSING[@]} -gt 0 ]]; then
            echo "  Missing: ${MISSING[*]}"
            echo "  Installing via apt (needs sudo)..."
            sudo apt-get update -qq
            sudo apt-get install -y -qq "${MISSING[@]}" || {
                echo "[!] apt install failed. Install manually: sudo apt install ${MISSING[*]}"
                exit 1
            }
        fi
        command -v iptables &>/dev/null \
            && echo "  iptables: OK" \
            || echo "  iptables: not found (prevention engine unavailable — install: sudo apt install iptables)"
        ;;
    macos)
        if ! command -v brew &>/dev/null; then
            echo "  Homebrew not found — install from https://brew.sh if system deps fail."
        else
            brew list libpcap &>/dev/null || brew install libpcap || true
        fi
        echo "  Note: full prevention (PF rules) is Linux-only; detection/API work on macOS."
        ;;
    windows)
        echo "  Note: run under Git Bash/WSL/MSYS2. Packet capture needs Npcap:"
        echo "        https://npcap.com/  (prevention engine is Linux-only)"
        ;;
esac
echo "  Prerequisites OK."

# ── Virtual environment ──────────────────────────────────────────────────────
echo ""
echo "[3/6] Setting up Python environment..."

if [[ ${USE_SYSTEM} -eq 1 ]]; then
    echo "  --system: skipping venv (using system Python)"
else
    if [[ ! -d "${PROJECT_DIR}/.venv" ]]; then
        "${PY}" -m venv "${PROJECT_DIR}/.venv"
    fi
    # shellcheck disable=SC1091
    source "${PROJECT_DIR}/.venv/bin/activate"
    echo "  venv active: ${VIRTUAL_ENV}"
fi

"${PY}" -m pip install --upgrade pip -q

# ── Python dependencies ──────────────────────────────────────────────────────
echo ""
echo "[4/6] Installing Python dependencies..."
pip install -r "${PROJECT_DIR}/requirements.txt" -q
echo "  Installed: $(pip list --format=freeze 2>/dev/null | wc -l | tr -d ' ') packages"

# ── Environment config ───────────────────────────────────────────────────────
echo ""
echo "[5/6] Preparing environment config..."
if [[ ! -f "${PROJECT_DIR}/.env" ]]; then
    cp "${PROJECT_DIR}/.env.example" "${PROJECT_DIR}/.env"
    echo "  Created .env from template — edit SECRET_KEY before production."
else
    echo "  .env exists — keeping it."
fi

# ── Database ─────────────────────────────────────────────────────────────────
echo ""
echo "[6/6] Initialising database..."
cd "${PROJECT_DIR}"
python -c "
from database.init_db import initialize_db
initialize_db()
print('  Database ready: database/netguard.db')
"

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo "  Install complete!"
echo "============================================"
echo ""
case "${PLATFORM}" in
    linux)
        echo "  Start (full features, needs root):"
        echo "    source .venv/bin/activate"
        echo "    sudo \$(which python) backend/main.py"
        ;;
    macos|windows)
        echo "  Start (dev mode — detection/API, no firewall blocking):"
        echo "    source .venv/bin/activate   # Git Bash/WSL on Windows"
        echo "    python backend/main.py"
        ;;
esac
echo ""
echo "  Dashboard:  http://localhost:5000"
echo "  Login:      admin / Admin@NetGuard1  (change immediately)"
echo "  Tests:      pytest tests/ -q"
echo ""
