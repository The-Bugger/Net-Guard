# NetGuard Attack Test Scripts

Scripts for triggering each detection rule from a second device on the same LAN.
Run these on an **attacker laptop** while NetGuard monitors on a separate machine.

> **Legal warning:** Run only in an isolated lab or hackathon network you own or have
> explicit written permission to test. These scripts perform real attacks.

---

## Network Topology

```
┌─────────────────┐        ┌──────────────┐        ┌──────────────────────┐
│  Attacker Laptop│        │   Switch /   │        │  NetGuard Laptop     │
│  (runs scripts) │◄──────►│   Router     │◄──────►│  (captures on eth0)  │
│  TARGET_IP=...  │        │  GATEWAY_IP  │        │  flask + scapy       │
└─────────────────┘        └──────────────┘        └──────────────────────┘
```

- **Attacker laptop** — Kali/Parrot/Ubuntu with the tools below installed.
- **NetGuard laptop** — running `python backend/main.py` with CaptureEngine active on the shared interface.
- Both devices must be on the **same Layer-2 segment** (same VLAN/subnet).

---

## Prerequisites

Install all tools on the attacker laptop before running any script.

| Tool | Package | Install |
|------|---------|---------|
| `hping3` | `hping3` | `sudo apt-get install hping3` |
| `nmap` | `nmap` | `sudo apt-get install nmap` |
| `hydra` | `hydra` | `sudo apt-get install hydra` |
| `arpspoof` | `dsniff` | `sudo apt-get install dsniff` |
| `curl` | `curl` | `sudo apt-get install curl` (usually pre-installed) |
| `slowhttptest` | `slowhttptest` | `sudo apt-get install slowhttptest` |
| `dig` | `dnsutils` | `sudo apt-get install dnsutils` |

rockyou wordlist (needed by brute_force.sh):

```bash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz   # Kali ships it compressed
```

Most scripts require **root** (`sudo`) on the attacker machine.

---

## Environment Variables

| Variable | Used by | Description |
|----------|---------|-------------|
| `TARGET_IP` | all scripts | IP address of the machine being attacked |
| `IFACE` | `arp_spoof.sh` only | Network interface on the attacker (e.g. `eth0`, `wlan0`) |
| `GATEWAY_IP` | `arp_spoof.sh` only | Default gateway IP on the LAN |

---

## Scripts

---

## Scripts

### 1. `syn_flood.sh` — SYN Flood

**Prerequisites:** `hping3`

**Usage:**
```bash
TARGET_IP=192.168.1.100 bash syn_flood.sh
```

**What it does:** Sends TCP SYN packets at flood rate to port 80 for 5 seconds
(`timeout 5 hping3 -S -p 80 --flood`), producing well over 150 SYN packets/second.

**Expected NetGuard alert:**

| Field | Value |
|-------|-------|
| Attack type | `SYN Flood` |
| Rule | `SYN_FLOOD_001` |
| Severity | `High` or `Critical` (≥ 200 SYN packets in 3 s window) |
| Confidence | `100` |
| Dashboard delay | ~5 seconds from script start |

---

### 2. `port_scan.sh` — Port Scan

**Prerequisites:** `nmap`

**Usage:**
```bash
TARGET_IP=192.168.1.100 bash port_scan.sh
```

**What it does:** Runs `nmap -sS -T4 <TARGET_IP>` (TCP SYN scan, top 1000 ports,
aggressive timing). Contacts 80+ unique ports within the 10-second detection window.
Requires root on the attacker.

**Expected NetGuard alert:**

| Field | Value |
|-------|-------|
| Attack type | `Port Scan` |
| Rule | `PORT_SCAN_001` |
| Severity | `Critical` (≥ 80 unique ports in 10 s window) |
| Dashboard delay | ~15 seconds from script start |

---

### 3. `sql_injection.sh` — SQL Injection

**Prerequisites:** `curl`

**Usage:**
```bash
TARGET_IP=192.168.1.100 bash sql_injection.sh
```

**What it does:** Sends one HTTP GET request to `http://<TARGET_IP>/search` with the
URL-encoded payload `' OR 1=1 -- UNION SELECT 1`. The raw payload matches both the
`' OR` and `UNION SELECT` patterns that `SqlInjectionRule` monitors on port 80.

**Expected NetGuard alert:**

| Field | Value |
|-------|-------|
| Attack type | `SQL Injection` |
| Rule | matches `' OR`, `UNION SELECT` patterns |
| Severity | `High` (first event from this IP in 300 s) |
| Confidence | `100` |
| Dashboard delay | ~3 seconds after curl completes |

---

### 4. `brute_force.sh` — SSH Brute Force

**Prerequisites:** `hydra`, rockyou wordlist at `/usr/share/wordlists/rockyou.txt`

**Usage:**
```bash
TARGET_IP=192.168.1.100 bash brute_force.sh
```

**What it does:** Runs `hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh://<TARGET_IP>`.
Sends ≥ 15 SSH authentication attempts (4 parallel threads) within the 60-second detection window.

**Expected NetGuard alert:**

| Field | Value |
|-------|-------|
| Attack type | `Brute Force` |
| Rule | `BRUTE_FORCE_001` |
| Severity | `Medium` → `High` (escalates as attempt count grows past 20) |
| Target service | `SSH` (port 22) |
| Dashboard delay | ~10 seconds from hydra starting |

---

### 5. `arp_spoof.sh` — ARP Spoofing

**Prerequisites:** `arpspoof` (from `dsniff`)

**Usage:**
```bash
IFACE=eth0 TARGET_IP=192.168.1.100 GATEWAY_IP=192.168.1.1 bash arp_spoof.sh
```

**What it does:** Runs `timeout 10 arpspoof -i <IFACE> -t <TARGET_IP> <GATEWAY_IP>` for
10 seconds. Sends repeated ARP replies claiming the attacker's MAC owns `GATEWAY_IP`,
creating conflicting MAC-to-IP mappings that `ArpSpoofRule` detects.

**Expected NetGuard alert:**

| Field | Value |
|-------|-------|
| Attack type | `ARP Spoofing` |
| Rule | `ARP_SPOOF_001` |
| Severity | `High` |
| Confidence | `97` (2 distinct MACs) → `100` (≥ 3 distinct MACs) |
| Dashboard delay | ~5 seconds from script start |

---

### 6. `attack_icmp_flood.sh` — ICMP Flood

**Prerequisites:** `hping3` (preferred) or root-capable `ping -f`

**Usage:**
```bash
TARGET_IP=192.168.1.100 bash attack_icmp_flood.sh
```

**What it does:** Sends 500 ICMP Echo Request packets at flood rate using
`hping3 --icmp --flood -c 500` (falls back to `ping -f -c 500` if hping3 is absent).
Exceeds the 100-packet/3-second threshold for ICMP_FLOOD_001.

**Expected NetGuard alert:**

| Field | Value |
|-------|-------|
| Attack type | `ICMP Flood` |
| Rule | `ICMP_FLOOD_001` |
| Severity | `Medium` (≥ 100), `High` (≥ 200), `Critical` (≥ 400 or broadcast dst) |
| Confidence | `100` |
| Dashboard delay | ~5 seconds from script start |

---

### 7. `attack_slow_http.sh` — Slow HTTP (Slowloris)

**Prerequisites:** `slowhttptest`

**Usage:**
```bash
TARGET_IP=192.168.1.100 bash attack_slow_http.sh
```

**What it does:** Opens 200 HTTP connections using Slowloris mode
(`slowhttptest -c 200 -H -i 10 -r 200 -t GET`). Each connection sends headers
slowly and never delivers `\r\n\r\n`, keeping connections open without completing
an HTTP request — the exact pattern `SLOW_HTTP_001` detects.

**Expected NetGuard alert:**

| Field | Value |
|-------|-------|
| Attack type | `Slow HTTP` |
| Rule | `SLOW_HTTP_001` |
| Severity | `Medium` (≥ 10 simultaneous slow connections), `High` (≥ 20) |
| Confidence | `100` |
| Dashboard delay | ~15 seconds (after connection timeout window elapses) |

---

### 8. `attack_dns_tunnel.sh` — DNS Tunneling

**Prerequisites:** `dig` (from `dnsutils`)

**Usage:**
```bash
TARGET_IP=192.168.1.100 bash attack_dns_tunnel.sh
```

**What it does:** Sends repeated DNS `TXT` queries with long (>50 character),
high-entropy base32-encoded labels to `TARGET_IP` as the resolver. This triggers
the label-length indicator (a) and entropy indicator (c) of `DNS_TUNNEL_001`.

**Expected NetGuard alert:**

| Field | Value |
|-------|-------|
| Attack type | `DNS Tunneling` |
| Rule | `DNS_TUNNEL_001` |
| Severity | `Medium` (label length or entropy alone), `High` (both indicators) |
| Confidence | `≤ 80` (heuristic rule — confidence is intentionally capped) |
| Dashboard delay | ~20 seconds from script start |

> **Note:** Confidence ≤ 80 is by design. `DNS_TUNNEL_001` is a heuristic rule with
> known false-positive risk. Treat alerts as "investigate further", not "confirmed
> malicious". See the script header for details.

---

## Expected Alert Sequence (Full Demo Run)

Running all eight scripts back-to-back produces the following sequence on the NetGuard dashboard:

```
 t+0s    syn_flood.sh starts
 t+5s    [ALERT] SYN Flood — Critical — SYN_FLOOD_001
 t+10s   port_scan.sh starts
 t+25s   [ALERT] Port Scan — Critical — PORT_SCAN_001
 t+30s   sql_injection.sh starts
 t+33s   [ALERT] SQL Injection — High — patterns matched
 t+35s   brute_force.sh starts
 t+45s   [ALERT] Brute Force — Medium/High — BRUTE_FORCE_001
 t+90s   arp_spoof.sh starts
 t+95s   [ALERT] ARP Spoofing — High — ARP_SPOOF_001
 t+110s  attack_icmp_flood.sh starts
 t+115s  [ALERT] ICMP Flood — Medium/High — ICMP_FLOOD_001
 t+120s  attack_slow_http.sh starts
 t+135s  [ALERT] Slow HTTP — Medium/High — SLOW_HTTP_001
 t+145s  attack_dns_tunnel.sh starts
 t+165s  [ALERT] DNS Tunneling — Medium/High — DNS_TUNNEL_001 (confidence ≤ 80)

Health score after all eight: well below 50/100 (eight deductions + multi-attack penalty)
```

After the run, `GET /api/v1/events` should return ≥ 8 rows each with a distinct `attack_type`.

---

## Troubleshooting

**No alert appears on dashboard**
- Confirm NetGuard's CaptureEngine is running on the correct interface (check the green
  "Monitoring Active" badge and interface name on the dashboard).
- Confirm the attacker and NetGuard laptops are on the same subnet.
- For `sql_injection.sh`: the target must have a service listening on port 80, or NetGuard
  must see the raw TCP packets in transit — run from the same L2 segment.

**hping3 / nmap needs root**
```bash
sudo TARGET_IP=192.168.1.100 bash syn_flood.sh
sudo TARGET_IP=192.168.1.100 bash port_scan.sh
sudo TARGET_IP=192.168.1.100 bash attack_icmp_flood.sh
sudo IFACE=eth0 TARGET_IP=192.168.1.100 GATEWAY_IP=192.168.1.1 bash arp_spoof.sh
```

**rockyou.txt not found**
```bash
sudo apt-get install wordlists
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```
