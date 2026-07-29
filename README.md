# NetGuard — Explainable Intrusion Detection & Prevention System

NetGuard is an explainable, real-time Intrusion Detection and Prevention System (IDPS) that captures live network traffic, detects five common attack types using configurable detection rules, generates plain-English explanations for every alert, and optionally blocks malicious IPs via iptables.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Frontend (Vanilla JS + Chart.js)        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │Dashboard │ │ Threats  │ │ Blocks   │ │ Whitelist    │  │
│  │  KPI +   │ │ Timeline │ │  Table   │ │   + Add IP   │  │
│  │  Charts  │ │+Evidence │ │+Unblock  │ │              │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └──────┬───────┘  │
│       └────────────┴────────────┴───────────────┘          │
│                      │ HTTP REST + SocketIO                 │
└──────────────────────┼──────────────────────────────────────┘
                       │
┌──────────────────────┼──────────────────────────────────────┐
│              Flask API + Flask-SocketIO                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │  Health  │ │ Monitor  │ │Detection │ │ Block/Unblock │  │
│  │  Routes  │ │ Routes   │ │ Routes   │ │   Routes     │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │
│                      │                                      │
│  ┌────────────────────────────────────────────────────┐     │
│  │  Services Layer                                    │     │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────┐  │     │
│  │  │Detection │ │Explain   │ │Prevention│ │Stats │  │     │
│  │  │ Engine   │ │ Engine   │ │ Engine   │ │Svc   │  │     │
│  │  └────┬─────┘ └──────────┘ └────┬─────┘ └──────┘  │     │
│  │  ┌────┴─────┐ ┌──────────┐ ┌───┴──────┐           │     │
│  │  │Whitelist │ │Monitor   │ │ Expiry   │           │     │
│  │  │Manager   │ │Service   │ │ Thread   │           │     │
│  │  └──────────┘ └──────────┘ └──────────┘           │     │
│  └────────────────────────────────────────────────────┘     │
│                      │                                      │
│  ┌────────────────────────────────────────────────────┐     │
│  │  Detection Engine                                  │     │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │     │
│  │  │ Capture  │ │ Packet   │ │ Detection Rules  │   │     │
│  │  │ Engine   │→│ Decoder  │→│ SYN Flood        │   │     │
│  │  │(Scapy)   │ │          │ │ Port Scan        │   │     │
│  │  │          │ │          │ │ SQL Injection    │   │     │
│  │  │          │ │          │ │ Brute Force      │   │     │
│  │  │          │ │          │ │ ARP Spoofing     │   │     │
│  │  └──────────┘ └──────────┘ └──────────────────┘   │     │
│  └────────────────────────────────────────────────────┘     │
│                      │                                      │
│  ┌──────────┐ ┌──────┴───────┐ ┌──────────────────────┐    │
│  │ SQLite   │ │ iptables     │ │ Logging (rotating)   │    │
│  │ DB (ORM) │ │ (subprocess) │ │ system/detections/   │    │
│  │          │ │              │ │ errors.log           │    │
│  └──────────┘ └──────────────┘ └──────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Features

- **Real-time Packet Capture** — lives packet capture via Scapy with support for TCP, UDP, ICMP, and ARP
- **Five Detection Rules** — SYN Flood, Port Scan, SQL Injection, Brute Force, ARP Spoofing
- **Explainable Alerts** — every detection includes plain-English explanation, severity, confidence score (0–100), and concrete recommendation
- **Automatic Blocking** — iptables-based IP blocking with configurable duration and whitelist bypass
- **Auto-Expiry** — background thread that automatically removes expired blocks
- **REST API** — 20+ endpoints for monitoring, detections, blocks, whitelist, statistics, logs, and settings
- **Real-time Dashboard** — WebSocket-powered live KPI cards, traffic rate chart, severity distribution chart, and threat timeline with expandable evidence
- **SQLite Persistence** — events, blocks, whitelist, settings, and logs stored in SQLite via SQLAlchemy ORM
- **Comprehensive Testing** — 296 passing tests including unit tests, property-based tests (Hypothesis), and integration tests

## Prerequisites

- **Python 3.11+**
- **iptables** (Linux only, for the prevention/blocking engine)
- **Network interface** (for packet capture)
- **Root/sudo** (for packet capture and iptables operations)

### Optional (for demo attacks)

- `hping3` — SYN flood attacks
- `nmap` — port scans
- `hydra` — brute force attacks
- `arpspoof` (dsniff) — ARP spoofing

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/netguard.git
cd netguard

# 2. Run the setup script (recommended)
sudo bash scripts/setup.sh

# Or manually:
pip install -r requirements.txt
python -c "from database.init_db import initialize_db; initialize_db()"
```

## Usage

```bash
# Start the NetGuard backend
sudo python backend/main.py

# The dashboard is available at:
# http://localhost:5000

# Start monitoring via the dashboard:
# 1. Select a network interface
# 2. Click "Start Monitoring"
```

### Running Attacks

Each attack type has a demo script:

```bash
# SYN Flood
sudo bash demo/attack_syn.sh

# Port Scan
bash demo/attack_scan.sh

# SQL Injection
bash demo/attack_sql.sh

# Brute Force
bash demo/attack_bruteforce.sh

# ARP Spoofing (requires root)
sudo bash demo/attack_arp.sh
```

### Running the Full Demo

```bash
sudo bash scripts/start_demo.sh [interface]
```

### Running Tests

```bash
# Unit + property tests (no root required)
pytest tests/ -v --ignore=tests/integration

# With coverage
pytest tests/ --ignore=tests/integration --cov=backend --cov=detection --cov-report=term-missing

# Integration tests (requires root + iptables)
sudo pytest tests/integration/ -v
```

## Directory Structure

```
netguard/
├── backend/           # Flask API + services
│   ├── api/           # App factory, dependencies
│   ├── repositories/  # Database access layer
│   ├── routes/        # REST API route handlers
│   ├── services/      # Business logic (detection, prevention, etc.)
│   └── utils/         # Validators, response helpers
├── database/          # SQLAlchemy schema + init
├── detection/         # Packet capture + detection rules
│   ├── capture/       # Sniffer engine
│   ├── parsers/       # Packet decoder
│   └── rules/         # Five detection rules
├── frontend/          # Web dashboard
│   ├── css/           # Dark theme styles
│   └── js/            # Dashboard JS (API client, SocketIO, charts)
├── config/            # Configuration YAML
├── demo/              # Attack simulation scripts
├── docs/              # API documentation
├── logs/              # Rotating log files
├── scripts/           # Setup and demo launcher
├── tests/             # Unit, property, and integration tests
└── requirements.txt   # Python dependencies
```

## API Reference

Full REST API documentation is available in [`docs/API.md`](docs/API.md).

### Quick Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/status` | System status |
| POST | `/api/v1/monitor/start` | Start packet capture |
| POST | `/api/v1/monitor/stop` | Stop packet capture |
| GET | `/api/v1/monitor/interfaces` | List network interfaces |
| GET | `/api/v1/dashboard` | Full dashboard snapshot |
| GET | `/api/v1/dashboard/live` | Lightweight live stats |
| GET | `/api/v1/detections` | List detections (filterable) |
| GET | `/api/v1/detections/{id}` | Single detection |
| POST | `/api/v1/detect` | Manual detection trigger |
| GET | `/api/v1/evidence/{id}` | Evidence/explanation |
| POST | `/api/v1/block` | Block an IP manually |
| POST | `/api/v1/unblock` | Unblock an IP |
| GET | `/api/v1/blocked` | List active blocks |
| GET | `/api/v1/whitelist` | List whitelist |
| POST | `/api/v1/whitelist` | Add to whitelist |
| DELETE | `/api/v1/whitelist/{ip}` | Remove from whitelist |
| GET | `/api/v1/statistics` | Detection statistics |
| GET | `/api/v1/statistics/rules` | Per-rule statistics |
| GET | `/api/v1/logs` | System logs (paginated) |
| PUT | `/api/v1/settings` | Update configuration |

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Runtime | Python 3.11+ |
| Packet Capture | Scapy |
| Web Framework | Flask + Flask-SocketIO (eventlet) |
| Database | SQLite via SQLAlchemy ORM |
| Firewall | iptables (subprocess) |
| Frontend | Vanilla JS ES6 + Chart.js |
| Testing | pytest 7+ + Hypothesis (property-based) |

## License

MIT License — see LICENSE for details.
