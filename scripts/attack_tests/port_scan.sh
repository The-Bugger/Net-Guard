#!/usr/bin/env bash
# port_scan.sh — Port scan attack test script for NetGuard IDPS demonstration
#
# Prerequisites: nmap
#   Install: sudo apt-get install nmap
#
# Usage:
#   TARGET_IP=<victim-ip> bash port_scan.sh
#   Example: TARGET_IP=192.168.1.100 bash port_scan.sh
#
# Expected detection in NetGuard:
#   Attack type : Port Scan
#   Rule        : PORT_SCAN_001
#   Severity    : Critical (nmap top-1000 scan contacts >> 80 ports within 10 s window)
#   Appears on dashboard within ~15 seconds of script start
#
# Safe-use warning:
#   Run ONLY in an isolated lab/hackathon network.
#   SYN scans (-sS) require root privileges on the attacker machine.
#   Never run against systems you do not own or have explicit permission to scan.

TARGET_IP="${TARGET_IP:-}"

if [ -z "$TARGET_IP" ]; then
    echo "ERROR: TARGET_IP is not set." >&2
    echo "Usage: TARGET_IP=<victim-ip> bash $0" >&2
    exit 1
fi

echo "[*] Starting port scan → $TARGET_IP (top 1000 ports, aggressive timing)..."
nmap -sS -T4 "$TARGET_IP"
echo "[*] Done. Check NetGuard dashboard for Port Scan alert."
