#!/bin/bash
# NetGuard Setup Script
# Installs all dependencies and initializes the database
# Usage: sudo ./scripts/setup.sh

set -e

echo "============================================"
echo " NetGuard IDPS — Setup"
echo "============================================"

# Check Python version
python3 --version || { echo "[ERROR] Python 3 is required."; exit 1; }
PYTHON_VER=$(python3 -c "import sys; print(sys.version_info.minor)")
if [ "$PYTHON_VER" -lt 11 ]; then
  echo "[ERROR] Python 3.11+ is required. Found Python 3.$PYTHON_VER"
  exit 1
fi

# Install Python dependencies
echo "[1/4] Installing Python dependencies..."
pip3 install -r requirements.txt

# Create required directories
echo "[2/4] Creating directories..."
mkdir -p logs database/migrations

# Initialize database
echo "[3/4] Initializing database..."
python3 database/init_db.py

# Verify iptables
echo "[4/4] Checking iptables..."
if ! command -v iptables &>/dev/null; then
  echo "[WARNING] iptables not found. Blocking features will be disabled."
else
  echo "[OK] iptables found."
fi

echo ""
echo "============================================"
echo " Setup complete!"
echo " Start NetGuard: sudo python3 backend/main.py"
echo " Dashboard:      http://localhost:5000"
echo "============================================"
