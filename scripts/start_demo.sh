#!/bin/bash
# NetGuard Demo Startup Script
# Starts the complete NetGuard system and opens the dashboard
# Usage: sudo ./scripts/start_demo.sh

set -e

echo "============================================"
echo " NetGuard IDPS — Demo Mode"
echo "============================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Initialize database if needed
echo "[1/3] Initializing database..."
python3 database/init_db.py

# Start backend in background
echo "[2/3] Starting NetGuard backend..."
python3 backend/main.py &
BACKEND_PID=$!

# Wait for backend to be ready
echo "      Waiting for backend to start..."
for i in $(seq 1 20); do
  if curl -s http://localhost:5000/api/v1/health > /dev/null 2>&1; then
    echo "      Backend ready!"
    break
  fi
  sleep 1
done

# Open dashboard in browser
echo "[3/3] Opening dashboard..."
if command -v xdg-open &>/dev/null; then
  xdg-open http://localhost:5000
elif command -v open &>/dev/null; then
  open http://localhost:5000
else
  echo "      Open http://localhost:5000 in your browser."
fi

echo ""
echo "============================================"
echo " NetGuard is running!"
echo " Dashboard:  http://localhost:5000"
echo " API:        http://localhost:5000/api/v1"
echo " Press Ctrl+C to stop."
echo "============================================"

# Wait for backend process
wait $BACKEND_PID
