#!/bin/bash
# NetGuard Demo — Brute Force Attack
# Sends rapid SSH connection attempts to trigger BRUTE_FORCE_001
# Usage: ./attack_bruteforce.sh [TARGET_IP]
# Requires: hydra (or nmap for simulation)

TARGET="${1:-127.0.0.1}"
echo "[*] Launching brute force simulation against $TARGET:22..."

# Use nmap to generate repeated SSH connection attempts
# (simulates auth failures visible to packet capture)
for i in $(seq 1 15); do
  timeout 1 nc -z -w1 "$TARGET" 22 2>/dev/null &
done
wait

echo "[+] Brute force simulation complete."
echo "    Note: For a real demo, use: hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://$TARGET"
