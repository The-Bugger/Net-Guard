#!/usr/bin/env bash
# attack_sql.sh — SQL Injection payloads via HTTP against the NetGuard target
#
# Requirements: curl (pre-installed on Kali)
#
# Usage: bash attack_sql.sh <TARGET_IP> [PORT]
# Example: bash attack_sql.sh 192.168.1.50 5000
#
# What it triggers: SqlInjectionRule inspects TCP payloads on HTTP ports
# (80, 443, 8080, 8443). Each request containing a SQL pattern triggers
# an alert immediately (confidence = 100).
#
# NetGuard must be capturing packets on the interface facing this attacker.

set -euo pipefail

TARGET="${1:-}"
PORT="${2:-5000}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: bash attack_sql.sh <TARGET_IP> [PORT]"
  exit 1
fi

BASE="http://${TARGET}:${PORT}"

echo "[*] Sending SQL injection payloads to $BASE"

# Pattern 1: ' OR
echo "  [1] ' OR 1=1 --"
curl -s -o /dev/null "$BASE/search?q=%27+OR+1%3D1+--"

sleep 0.5

# Pattern 2: UNION SELECT
echo "  [2] UNION SELECT"
curl -s -o /dev/null "$BASE/items?id=1+UNION+SELECT+username%2Cpassword+FROM+users--"

sleep 0.5

# Pattern 3: DROP TABLE
echo "  [3] DROP TABLE"
curl -s -o /dev/null -X POST "$BASE/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user=admin%27%3B+DROP+TABLE+users%3B--&pass=x"

sleep 0.5

# Pattern 4: -- comment
echo "  [4] -- (comment injection)"
curl -s -o /dev/null "$BASE/profile?id=1--"

sleep 0.5

# Pattern 5: xp_cmdshell
echo "  [5] xp_cmdshell"
curl -s -o /dev/null "$BASE/exec?cmd=1%3B+EXEC+xp_cmdshell%28%27whoami%27%29"

echo "[✓] SQL injection payloads sent. Check the NetGuard dashboard for alerts."
echo "    NOTE: NetGuard must be actively monitoring the network interface."
echo "    Traffic must flow through the monitored interface (not loopback)."
