#!/usr/bin/env bash
# sql_injection.sh — SQL Injection attack test script for NetGuard IDPS demonstration
#
# Prerequisites: curl
#   Install: sudo apt-get install curl   (usually pre-installed)
#
# Usage:
#   TARGET_IP=<victim-ip> bash sql_injection.sh
#   Example: TARGET_IP=192.168.1.100 bash sql_injection.sh
#
# Payload sent (URL-decoded):
#   GET /search?q=' OR 1=1 -- UNION SELECT 1
# Encoded form: %27%20OR%201%3D1%20--%20UNION%20SELECT%201
#
# Expected detection in NetGuard:
#   Attack type : SQL Injection
#   Rule        : matched patterns "' OR" and "UNION SELECT"
#   Severity    : High (first event from this IP in 300 s window)
#   Confidence  : 100
#   Appears on dashboard within ~3 seconds of curl completing
#
# Safe-use warning:
#   Run ONLY in an isolated lab/hackathon network.
#   Sending SQL injection payloads to production systems is illegal without
#   explicit written authorisation from the system owner.

TARGET_IP="${TARGET_IP:-}"

if [ -z "$TARGET_IP" ]; then
    echo "ERROR: TARGET_IP is not set." >&2
    echo "Usage: TARGET_IP=<victim-ip> bash $0" >&2
    exit 1
fi

echo "[*] Sending SQL injection payload → http://$TARGET_IP/search"
curl -s "http://$TARGET_IP/search?q=%27%20OR%201%3D1%20--%20UNION%20SELECT%201"
echo ""
echo "[*] Done. Check NetGuard dashboard for SQL Injection alert."
