#!/usr/bin/env bash
# backup.sh — SQLite dump + gzip + SHA-256 checksum
#
# Usage: ./scripts/backup.sh [output_dir]
#   output_dir defaults to ./backups
#
# Exit code 1 on any failure (Req 12.5)
#
# Requirements: 12.5

set -euo pipefail

DB_PATH="${DB_PATH:-database/netguard.db}"
OUT_DIR="${1:-backups}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
DUMP_FILE="${OUT_DIR}/netguard_${TIMESTAMP}.sql"
GZ_FILE="${DUMP_FILE}.gz"
SHA_FILE="${GZ_FILE}.sha256"

# Validate DB exists
if [[ ! -f "${DB_PATH}" ]]; then
  echo "ERROR: database not found at ${DB_PATH}" >&2
  exit 1
fi

# Create output directory
mkdir -p "${OUT_DIR}" || { echo "ERROR: cannot create ${OUT_DIR}" >&2; exit 1; }

echo "[backup] Dumping ${DB_PATH} → ${DUMP_FILE}"
sqlite3 "${DB_PATH}" .dump > "${DUMP_FILE}" || {
  echo "ERROR: sqlite3 dump failed" >&2
  exit 1
}

echo "[backup] Compressing → ${GZ_FILE}"
gzip -9 "${DUMP_FILE}" || {
  echo "ERROR: gzip failed" >&2
  exit 1
}

echo "[backup] Computing SHA-256 → ${SHA_FILE}"
if command -v sha256sum &>/dev/null; then
  sha256sum "${GZ_FILE}" > "${SHA_FILE}"
else
  # macOS / BSD fallback
  shasum -a 256 "${GZ_FILE}" > "${SHA_FILE}"
fi || {
  echo "ERROR: checksum failed" >&2
  exit 1
}

echo "[backup] Done: ${GZ_FILE}"
echo "[backup] Checksum: $(cat "${SHA_FILE}")"
