#!/usr/bin/env bash
# attack_scan.sh — Port scan attack against the NetGuard target
#
# Requirements: nmap
#   sudo apt install nmap
#
# Usage: bash attack_scan.sh <TARGET_IP>
# Example: bash attack_scan.sh 192.168.1.50
#
# What it triggers: PortScanRule fires when >=20 unique ports are probed
# from this source IP within a 10-second window.

set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
  echo "Usage: bash attack_scan.sh <TARGET_IP>"
  exit 1
fi

echo "[*] Running TCP SYN scan of top 1000 ports on $TARGET"
echo "[*] NetGuard should alert after ~20 unique port attempts."

# -sS  SYN scan (stealth) — requires root
# -T4  aggressive timing (faster, triggers detection quicker)
# --top-ports 200  scan top 200 ports — well above the 20-port threshold
sudo nmap -sS -T4 --top-ports 200 "$TARGET"

echo "[✓] Port scan complete. Check the NetGuard dashboard for the alert."
