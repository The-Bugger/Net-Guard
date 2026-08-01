#!/usr/bin/env bash
# attack_dns_tunnel.sh — DNS Tunneling heuristic test script for NetGuard IDPS demonstration
#
# Prerequisites: dig (from dnsutils/bind-utils)
#   Install: sudo apt-get install dnsutils
#   Optional (full tunnel): iodine — sudo apt-get install iodine
#
# Usage:
#   TARGET_IP=<victim-ip> bash attack_dns_tunnel.sh
#   Example: TARGET_IP=192.168.1.100 bash attack_dns_tunnel.sh
#
# Expected detection in NetGuard:
#   Attack type : DNS Tunneling
#   Rule        : DNS_TUNNEL_001
#   Severity    : Medium (long labels or high entropy; single indicator)
#                 High   (two or more indicators firing simultaneously)
#   Confidence  : capped at 80 (heuristic rule — see note below)
#   Appears on dashboard within ~20 seconds of script start
#
# Heuristic false-positive warning:
#   DNS_TUNNEL_001 is a heuristic rule. Confidence is intentionally capped at 80.
#   Legitimate high-volume DNS traffic (CDN resolvers, internal nameservers) may trigger
#   the TXT-rate or entropy indicators. Treat alerts from this rule as "investigate further"
#   rather than "confirmed malicious". In a noisy environment, consider raising
#   dns_tunnel_txt_rate_threshold in config/config.yaml before running this script.
#
# Safe-use warning:
#   Run ONLY in an isolated lab/hackathon network you own or have explicit permission to test.
#   Never run against production DNS servers.

TARGET_IP="${TARGET_IP:-}"

if [ -z "$TARGET_IP" ]; then
    echo "ERROR: TARGET_IP is not set." >&2
    echo "Usage: TARGET_IP=<victim-ip> bash $0" >&2
    exit 1
fi

# High-entropy base32-style labels that mimic DNS tunnel payloads (iodine/dnscat2 style).
# Each label is >50 characters and consists of high-entropy alphanumeric sequences.
LABELS=(
    "aGVsbG93b3JsZHRoaXNpc2Fkbm10dW5uZWx0ZXN0cGF5bG9hZA"
    "dGVzdHBheWxvYWRmb3JuZXRndWFyZGRuc3R1bm5lbGRldGVjdA"
    "c3VwZXJsb25nbGFiZWxmb3JlbnRyb3B5dGVzdGluZ25ldGd1YXI"
    "aW9kaW5lc3R5bGVkbnN0dW5uZWxkYXRhZXhmaWx0cmF0aW9udA"
    "ZG5zY2F0MnN0eWxlcGF5bG9hZGZvcmRldGVjdGlvbnRlc3Rpbmc"
    "bmV0Z3VhcmR0dW5uZWxkZXRlY3Rpb250ZXN0bG9uZ2xhYmVsbHM"
    "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA"
    "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWI"
)

echo "[*] Sending DNS TXT queries with long high-entropy labels → $TARGET_IP ..."
echo "[*] This triggers the label-length (a) and entropy (c) indicators in DNS_TUNNEL_001."

for i in $(seq 1 8); do
    for label in "${LABELS[@]}"; do
        # Send TXT query: long label + .example.com routed to TARGET_IP as resolver
        dig TXT "${label}.example.com" "@${TARGET_IP}" +time=1 +tries=1 >/dev/null 2>&1
    done
    echo "[*] Round $i/8 complete (${#LABELS[@]} TXT queries sent)..."
    sleep 1
done

echo "[*] Done. Check NetGuard dashboard for DNS Tunneling alert (DNS_TUNNEL_001)."
echo "[*] Note: confidence will be ≤ 80 (heuristic rule). This is expected."
