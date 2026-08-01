#!/bin/bash
# NetGuard Demo — Port Scan Attack
# Scans 80+ ports to trigger PORT_SCAN_001 (threshold: 20 unique ports / 10s)
# Usage: ./attack_scan.sh [TARGET_IP]
# Requires: nmap

TARGET="${1:-127.0.0.1}"
echo "[*] Launching port scan against $TARGET..."
nmap -Pn --max-rate 500 -p 1-100 "$TARGET"
echo "[+] Port scan complete."
