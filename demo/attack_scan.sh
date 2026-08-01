#!/bin/bash
# =============================================================================
# attack_scan.sh — Nmap Port Scan Demo
#
# Performs a TCP SYN scan against localhost covering a wide range of ports
# (1–65535) to trigger the PortScanRule. The default threshold is 20 unique
# ports within a 10-second window, so scanning all 65535 ports will easily
# exceed this.
#
# Requirements: 5.1
# Tools: nmap
# Usage:  ./demo/attack_scan.sh [target_ip]
#         Default target is 127.0.0.1
# =============================================================================

set -euo pipefail

TARGET="${1:-127.0.0.1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/attack_scan.log"

echo "[*] Port Scan Attack against ${TARGET}" | tee "${LOG_FILE}"
echo "[*] Starting nmap SYN scan of ports 1-10000..." | tee -a "${LOG_FILE}"

nmap -sS -p 1-10000 --min-rate=500 -T5 "${TARGET}" -oN "${LOG_FILE}.nmap" 2>&1 | tee -a "${LOG_FILE}"

echo "[*] Scan complete. Results saved to ${LOG_FILE}.nmap" | tee -a "${LOG_FILE}"
