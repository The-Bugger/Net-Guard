# NetGuard
### Explainable Intrusion Detection & Prevention System

> **MVIC Build Nepal Hackathon 2026** — Enterprise-grade intrusion detection, running free on a student laptop.

NetGuard watches your network in real time, detects attacks, automatically blocks attackers via iptables, and **explains every single security decision in plain English** — the way a real security analyst would explain it to their manager.

---

## Architecture

```
Network Interface
       │
       ▼
Packet Capture (Scapy)  ──▶  packet_queue
       │
Packet Decoder (normalized Packet objects)
       │
Detection Engine ──▶  5 rule modules (SYN Flood, Port Scan, SQL Injection, Brute Force, ARP Spoof)
       │
Explainability Engine  ──▶  plain-English explanation + recommendation
       │
Prevention Engine  ──▶  iptables block + DB record
       │
Logging Engine  ──▶  system.log / detections.log / errors.log + SQLite
       │
Flask REST API + SocketIO  ──▶  Live Dashboard (Chart.js + vanilla JS)
```

All modules run in isolated threads connected by thread-safe queues. No business logic lives in Flask routes.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Packet Capture | Scapy 2.5 |
| Detection | Custom Python rule engine |
| Prevention | iptables (Linux) |
| Backend | Flask 3.0 + Flask-SocketIO |
| Database | SQLite + SQLAlchemy 2.0 |
| Frontend | HTML5 + CSS3 + Vanilla JS + Chart.js |
| Real-time | Flask-SocketIO (eventlet) |
| Config | PyYAML |

---

## Detection Coverage

| Attack | Rule ID | Threshold | Severity |
|--------|---------|-----------|----------|
| SYN Flood | SYN_FLOOD_001 | 100 SYN/3s | Medium → Critical |
| Port Scan | PORT_SCAN_001 | 20 ports/10s | Medium → Critical |
| SQL Injection | SQL_INJECTION_001 | 1 pattern match | High → Critical |
| Brute Force | BRUTE_FORCE_001 | 10 failures/60s | Medium → Critical |
| ARP Spoofing | ARP_SPOOF_001 | 2+ conflicting MACs | High |

---

## Prerequisites

- **OS:** Ubuntu 24.04 LTS or Kali Linux
- **Python:** 3.11+
- **Root/sudo** (for iptables and Scapy packet capture)
- **iptables** installed

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-team/netguard.git
cd netguard

# Install dependencies
pip install -r requirements.txt

# Initialize database
python3 database/init_db.py
```

---

## Running NetGuard

```bash
# Start with sudo (required for iptables + raw packet capture)
sudo python3 backend/main.py
```

Dashboard will be available at: **http://localhost:5000**

Or use the demo startup script:

```bash
sudo ./scripts/start_demo.sh
```

---

## Configuration

Edit `config/config.yaml` to adjust detection thresholds:

```yaml
network_interface: eth0
syn_flood_threshold: 100    # packets per 3s window
port_scan_threshold: 20     # unique ports per 10s window
brute_force_threshold: 10   # failures per 60s window
block_duration: 120         # seconds to block attackers
```

Or update settings live via the dashboard Settings page without restarting.

---

## Project Structure

```
NetGuard/
├── backend/
│   ├── api/            Flask app factory + SocketIO
│   ├── routes/         10 route blueprints (thin — no business logic)
│   ├── services/       Business logic (DetectionEngine, PreventionEngine, etc.)
│   ├── repositories/   Database CRUD (EventRepo, BlockRepo, etc.)
│   ├── utils/          IP validators, response helpers
│   └── main.py         Application entry point
├── detection/
│   ├── capture/        Scapy CaptureEngine
│   ├── parsers/        PacketDecoder
│   └── rules/          5 detection rule modules + BaseRule
├── frontend/           HTML pages + CSS + JS (Chart.js, Socket.IO)
├── database/
│   ├── schema.py       SQLAlchemy ORM models
│   └── init_db.py      Database initialisation
├── config/config.yaml  Runtime configuration
├── logs/               system.log, detections.log, errors.log
├── demo/               Attack simulation scripts
├── scripts/            Setup + startup scripts
└── tests/              Unit + integration tests
```

---

## API Reference

Base URL: `http://localhost:5000/api/v1`

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Liveness check |
| GET | /status | Monitoring status |
| POST | /monitor/start | Start packet capture |
| POST | /monitor/stop | Stop packet capture |
| GET | /monitor/interfaces | List network interfaces |
| GET | /detections | List all detections (filterable) |
| GET | /detections/{id} | Get single detection |
| GET | /evidence/{id} | Get explanation for event |
| POST | /block | Manually block an IP |
| POST | /unblock | Unblock an IP |
| GET | /blocked | List active blocks |
| GET | /whitelist | List whitelist |
| POST | /whitelist | Add to whitelist |
| DELETE | /whitelist/{ip} | Remove from whitelist |
| GET | /dashboard | Full dashboard snapshot |
| GET | /dashboard/live | Live stats (PPS, threats) |
| GET | /statistics | Aggregate statistics |
| GET | /statistics/rules | Per-rule counts |
| GET | /logs | System logs (paginated) |
| PUT | /settings | Update configuration |

All responses use the standard envelope:
```json
{ "success": true, "message": "OK", "data": {} }
```

---

## Demo — 90-Second Walkthrough

```bash
# Terminal 1: Start NetGuard
sudo python3 backend/main.py

# Terminal 2: Launch attacks (from Kali VM or same machine)
./demo/attack_syn.sh 192.168.1.10        # SYN flood
./demo/attack_scan.sh 192.168.1.10       # Port scan
./demo/attack_sql.sh 192.168.1.10 80     # SQL injection
./demo/attack_bruteforce.sh 192.168.1.10 # Brute force
./demo/attack_arp.sh 192.168.1.1 eth0    # ARP spoofing
```

Watch the dashboard at **http://localhost:5000** — attacks appear in the threat timeline within seconds, with full explanations.

---

## Why NetGuard?

Unlike Snort/Suricata (powerful but black-box), NetGuard **explains every decision**:

> *"Detected 231 SYN packets from 192.168.1.20 within 3 seconds. The threshold of 100 was exceeded. Blocked for 120 seconds. Recommendation: Investigate the source host and verify whether the traffic is legitimate."*

Every alert answers four questions:
1. What happened?
2. Why was it detected?
3. How confident is the system?
4. What should the administrator do next?

---

## Team

Built for **MVIC Build Nepal Hackathon 2026** by Team NetGuard.

---

## License

MIT License — Build Today, Transform Tomorrow.
