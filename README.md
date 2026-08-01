# NetGuard — Explainable Intrusion Detection & Prevention System

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-678%20passing-brightgreen.svg)](#testing)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Flask](https://img.shields.io/badge/flask-3.0.3-lightgrey.svg)](https://flask.palletsprojects.com)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0-orange.svg)](https://sqlalchemy.org)

NetGuard is a real-time, explainable Intrusion Detection and Prevention System (IDPS) that
captures live network traffic, detects eight attack categories, generates plain-English
explanations for every alert, and automatically blocks attackers via iptables — all visible
through a live SOC-style dashboard.

Built for the **MVIC Build Nepal Hackathon 2026**. Runs entirely offline on a single Linux
machine. No cloud, no proprietary hardware, no agents.

---

## Table of Contents

1. [Features](#features)
2. [Quick Start](#quick-start)
3. [Architecture](#architecture)
4. [Directory Structure](#directory-structure)
5. [Prerequisites](#prerequisites)
6. [Installation](#installation)
7. [Configuration](#configuration)
8. [Environment Variables](#environment-variables)
9. [Running NetGuard](#running-netguard)
10. [API Reference](#api-reference)
11. [Detection Rules](#detection-rules)
12. [Service Layer](#service-layer)
13. [Database Schema](#database-schema)
14. [Testing](#testing)
15. [Demo Attack Scripts](#demo-attack-scripts)
16. [Technology Stack](#technology-stack)
17. [Judges Mode](#judges-mode)

---

## Features

| Feature | Detail |
|---------|--------|
| Live packet capture | Scapy-based; TCP, UDP, ICMP, ARP on any OS interface |
| 8 detection rules | SYN Flood, Port Scan, SQL Injection, Brute Force, ARP Spoofing, ICMP Flood, Slow HTTP, DNS Tunneling |
| Explainable alerts | Plain-English text, severity, confidence 0–100, actionable recommendation |
| Auto-blocking | iptables DROP rule applied within seconds of detection |
| Auto-expiry | Background thread removes expired blocks every 5 seconds |
| Whitelist | Trusted IPs bypass blocking; O(1) in-memory set lookup |
| API key auth | `X-API-Key` header enforcement on all mutating endpoints; constant-time comparison |
| Rate limiting | 120 req/60s per client IP with `Retry-After` header |
| Security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| REST API | 28+ endpoints — monitor, detect, block, whitelist, stats, logs, analytics, export, AI assistant |
| Live dashboard | WebSocket KPIs, traffic chart, severity chart, threat timeline, analytics, AI chat |
| SQLite persistence | Events, blocks, whitelist, settings, logs via SQLAlchemy ORM |
| 678 tests | Unit + property-based (Hypothesis) + integration |
| Rotating log files | system.log, detections.log, errors.log — max 10 MB each, 5 backups |
| Export | JSON, CSV, Markdown, and PDF (optional) detection export |
| Analytics | Hourly / daily / weekly detection charts with attack breakdown |
| AI assistant | Per-event Markdown report and chat panel (stub / Gemini / OpenAI) |
| Demo mode | Continuous synthetic attack generation using RFC 5737 TEST-NET IPs |

---

## Quick Start

```bash
pip install -r requirements.txt
python -c "from database.init_db import initialize_db; initialize_db()"
sudo python backend/main.py
```

Open **http://localhost:5000**. Add `?judges=1` for presentation mode.

---

## Architecture

### System Overview

```mermaid
graph TB
    NIC["Network Interface (eth0 / wlan0)"]
    CE["CaptureEngine\nsniffer.py\nPacket_Capture_Thread"]
    PD["PacketDecoder\npacket_decoder.py"]
    PQ["packet_queue\nqueue.Queue maxsize=10000"]
    DE["DetectionEngine\ndetection_service.py\nDetection_Thread"]
    R1["SynFloodRule"] R2["PortScanRule"] R3["SqlInjectionRule"]
    R4["BruteForceRule"] R5["ArpSpoofRule"]
    R6["IcmpFloodRule"] R7["SlowHttpRule"] R8["DnsTunnelRule"]
    EE["ExplainabilityEngine\nexplain_service.py"]
    PE["PreventionEngine\nprevention_service.py"]
    LE["LoggingEngine\nlog_service.py\nLogging_Thread"]
    ET["ExpiryThread\nexpiry_service.py"]
    DB[(SQLite\nnetguard.db)]
    API["Flask REST API\n+ Flask-SocketIO"]
    DASH["Frontend Dashboard\nVanilla JS + Chart.js"]

    NIC -->|raw packets| CE
    CE -->|decode| PD
    PD -->|Packet objects| PQ
    PQ -->|consume| DE
    DE --> R1 & R2 & R3 & R4 & R5 & R6 & R7 & R8
    DE -->|ThreatEvent| EE
    EE -->|Explanation| PE
    EE -->|Explanation| LE
    PE -->|iptables -I| NIC
    LE -->|INSERT| DB
    ET -->|poll 5s| DB
    ET -->|iptables -D| NIC
    DE -->|SocketIO emit| API
    PE -->|SocketIO emit| API
    API <-->|HTTP + WS| DASH
    DB <-->|SQLAlchemy| API
```

### Threading Model

| Thread | Module | Role |
|--------|--------|------|
| `Packet_Capture_Thread` | `detection/capture/sniffer.py` | Scapy `sniff()` → decodes packets → puts onto `packet_queue` |
| `Detection_Thread` | `backend/services/detection_service.py` | Consumes `packet_queue` → runs all 8 rules → emits `ThreatEvent` via callback |
| `Logging_Thread` | `backend/services/log_service.py` | Consumes `event_queue` → persists to SQLite and log files |
| `Expiry_Thread` | `backend/services/expiry_service.py` | Polls DB every 5 s → removes expired iptables rules |
| `API_Thread` | Flask + eventlet | Serves HTTP REST + WebSocket |

> **Python 3.14 note:** eventlet is incompatible with Python 3.14 threading changes.
> Set `SOCKETIO_ASYNC_MODE=threading` in your `.env` when running under Python 3.14.
> The app factory reads this variable and falls back to threading mode automatically.

---

## Directory Structure

```
NetGuard/
├── backend/
│   ├── api/
│   │   ├── __init__.py          # Flask app factory + SocketIO init
│   │   └── dependencies.py      # Service registry (populated by main.py)
│   ├── middleware/
│   │   ├── auth.py              # X-API-Key authentication hook
│   │   ├── rate_limiter.py      # Sliding-window rate limiter
│   │   └── security_headers.py  # CSP / HSTS / Permissions-Policy headers
│   ├── repositories/
│   │   ├── event_repository.py
│   │   ├── block_repository.py
│   │   ├── whitelist_repository.py
│   │   ├── log_repository.py
│   │   └── settings_repository.py
│   ├── routes/
│   │   ├── health_routes.py        # GET /health, GET /status
│   │   ├── monitor_routes.py       # POST /monitor/start|stop, GET /interfaces
│   │   ├── detection_routes.py     # GET /detections, GET /detections/{id}, POST /detect
│   │   ├── block_routes.py         # POST /block|/unblock, GET /blocked
│   │   ├── whitelist_routes.py     # GET|POST /whitelist, DELETE /whitelist/{ip}
│   │   ├── dashboard_routes.py     # GET /dashboard, GET /dashboard/live
│   │   ├── stats_routes.py         # GET /statistics, GET /statistics/rules
│   │   ├── evidence_routes.py      # GET /evidence/{id}
│   │   ├── logs_routes.py          # GET /logs
│   │   ├── settings_routes.py      # GET|PUT /settings
│   │   ├── analytics_routes.py     # GET /analytics
│   │   ├── export_routes.py        # GET /export
│   │   ├── timeline_routes.py      # GET /timeline/{event_id}
│   │   ├── ai_assistant_routes.py  # POST /ai-assistant
│   │   ├── advisor_routes.py       # GET /advisor
│   │   ├── lan_devices_routes.py   # GET /lan-devices, POST /lan-devices/refresh
│   │   └── reset_routes.py         # POST /reset (dev only)
│   ├── services/
│   │   ├── config_service.py       # ConfigurationManager — loads/validates config.yaml
│   │   ├── detection_service.py    # DetectionEngine — packet→rule→event pipeline
│   │   ├── explain_service.py      # ExplainabilityEngine — ThreatEvent→Explanation
│   │   ├── ai_explain_service.py   # AIExplainService — Gemini/OpenAI/stub enrichment
│   │   ├── prevention_service.py   # PreventionEngine — iptables block/unblock
│   │   ├── expiry_service.py       # ExpiryThread — auto-removes expired blocks
│   │   ├── whitelist_service.py    # WhitelistManager — O(1) in-memory lookup
│   │   ├── monitor_service.py      # MonitorService — start/stop/interface management
│   │   ├── log_service.py          # LoggingEngine — async DB + file logging
│   │   ├── stats_service.py        # StatsService — aggregation for dashboard
│   │   ├── lan_scan_service.py     # LanScanService — ARP-based LAN device discovery
│   │   └── security_advisor.py     # SecurityAdvisor — health score and advice
│   ├── utils/
│   │   ├── validators.py           # IP + numeric range validation
│   │   └── response.py             # Standard JSON envelope helpers
│   └── main.py                     # Application entry point + startup sequence
├── database/
│   ├── schema.py                   # SQLAlchemy ORM models (6 tables)
│   └── init_db.py                  # initialize_db() — creates tables + seeds defaults
├── detection/
│   ├── capture/
│   │   └── sniffer.py              # CaptureEngine — Scapy sniff() wrapper
│   ├── parsers/
│   │   └── packet_decoder.py       # PacketDecoder — raw Scapy → normalized Packet
│   └── rules/
│       ├── base_rule.py            # BaseRule ABC + ThreatEvent + Explanation dataclasses
│       ├── syn_flood.py            # SynFloodRule      (SYN_FLOOD_001)
│       ├── port_scan.py            # PortScanRule      (PORT_SCAN_001)
│       ├── sql_injection.py        # SqlInjectionRule  (SQL_INJECT_001)
│       ├── brute_force.py          # BruteForceRule    (BRUTE_FORCE_001)
│       ├── arp_spoof.py            # ArpSpoofRule      (ARP_SPOOF_001)
│       ├── icmp_flood.py           # IcmpFloodRule     (ICMP_FLOOD_001)
│       ├── slow_http.py            # SlowHttpRule      (SLOW_HTTP_001)
│       └── dns_tunnel.py           # DnsTunnelRule     (DNS_TUNNEL_001)
├── frontend/
│   ├── css/dark-theme.css
│   ├── js/                         # socket.js, api.js, dashboard.js, charts.js, shell.js, …
│   ├── index.html                  # Main dashboard (KPIs, charts, threat timeline)
│   ├── blocked.html                # Active blocks management
│   ├── whitelist.html              # Whitelist management
│   ├── threats.html                # Full threat list with filters
│   ├── logs.html                   # Log viewer
│   ├── rules.html                  # Detection rule configuration
│   ├── settings.html               # System settings form
│   ├── analytics.html              # Charts and attack distribution
│   ├── timeline.html               # Per-event incident timeline
│   ├── about.html / architecture.html
│   └── 404.html / 500.html
├── config/
│   └── config.yaml                 # Runtime configuration (thresholds, interface, etc.)
├── demo/
│   ├── attack_syn.sh               # hping3 SYN flood demo
│   ├── attack_scan.sh              # nmap port scan demo
│   ├── attack_sql.sh               # curl SQL injection demo
│   ├── attack_bruteforce.sh        # hydra brute force demo
│   └── attack_arp.sh               # arpspoof ARP spoofing demo
├── docs/
│   ├── API.md                      # Full REST API reference
│   ├── ARCHITECTURE.md             # Detailed architecture with Mermaid diagrams
│   ├── DATABASE.md                 # Database schema reference
│   ├── DEPLOYMENT.md               # Production deployment guide
│   ├── TROUBLESHOOTING.md          # Common problems and solutions
│   └── ROADMAP.md                  # Feature roadmap
├── logs/                           # Rotating log files (auto-created)
├── scripts/
│   └── setup.sh                    # One-shot setup script
├── tests/                          # 678+ unit + property-based + integration tests
├── .env                            # Environment variables (not committed)
├── .env.example                    # Environment variable documentation
├── requirements.txt                # Pinned Python dependencies
├── CHANGELOG.md                    # Version history
├── CONTRIBUTING.md                 # Contributor guide
├── SECURITY.md                     # Security policy and threat model
├── INSTALL.md                      # Installation guide
└── DEPLOYMENT.md                   # Proxy trust model and deployment notes
```

---

## Prerequisites

- **Python 3.11+** (tested on 3.11, 3.12, 3.14)
- **Linux** (required for iptables-based blocking; detection and API work on Windows/macOS in mock mode)
- **Root / sudo** (required for Scapy raw socket capture and iptables)
- **iptables** (pre-installed on most Linux distributions)

### Optional tools (demo scripts only)

| Tool | Script | Install |
|------|--------|---------|
| `hping3` | `demo/attack_syn.sh` | `sudo apt install hping3` |
| `nmap` | `demo/attack_scan.sh` | `sudo apt install nmap` |
| `hydra` | `demo/attack_bruteforce.sh` | `sudo apt install hydra` |
| `arpspoof` | `demo/attack_arp.sh` | `sudo apt install dsniff` |
| `curl` | `demo/attack_sql.sh` | usually pre-installed |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/The-Bugger/Net-Guard.git
cd Net-Guard

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows

# 3. Automated setup (Linux, requires sudo)
sudo bash scripts/setup.sh

# ── OR install manually ────────────────────────────────────────────────────
pip install -r requirements.txt
python -c "from database.init_db import initialize_db; initialize_db()"

# 4. Copy and edit environment variables
cp .env.example .env
# Edit .env — at minimum set SECRET_KEY and optionally NETGUARD_API_KEY
```

See [INSTALL.md](INSTALL.md) for full platform-specific installation instructions.

---

## Configuration

All runtime settings live in **`config/config.yaml`**. Edit this file to tune
thresholds without touching source code. Changes submitted via
`PUT /api/v1/settings` take effect immediately without restart.

```yaml
# config/config.yaml

network_interface: ""           # Interface to capture on (e.g. eth0, wlan0)

syn_flood_threshold: 150        # SYN packets per source IP to trigger detection
syn_flood_window: 3             # Sliding window in seconds

port_scan_threshold: 20         # Unique ports per source IP to trigger detection
port_scan_window: 10

brute_force_threshold: 10       # Auth failures per source IP to trigger detection
brute_force_window: 60

icmp_flood_threshold: 100       # ICMP echo requests per source IP to trigger detection
icmp_flood_window: 3

slow_http_threshold: 10         # Concurrent slow connections to trigger detection
slow_http_window: 10

block_duration: 120             # Auto-block duration in seconds

dashboard_refresh_interval: 1   # Dashboard polling interval in seconds

rules_enabled:
  syn_flood: true
  port_scan: true
  sql_injection: true
  brute_force: true
  arp_spoof: true
  icmp_flood: true
  slow_http: true
  dns_tunnel: true

debug: false
```

---

## Environment Variables

See [`.env.example`](.env.example) for full documentation of every variable.

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `change-me-before-production` | Flask session secret — **must be set in production** or app refuses to start |
| `DATABASE_URL` | `sqlite:///database/netguard.db` | SQLAlchemy DB URL |
| `LOG_LEVEL` | `INFO` | Python logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `FLASK_HOST` | `0.0.0.0` | Bind address; use `127.0.0.1` behind a reverse proxy |
| `FLASK_PORT` | `5000` | Listen port |
| `FLASK_ENV` | `development` | Flask environment; set to `production` for production |
| `ALLOWED_ORIGINS` | `*` | Comma-separated CORS origins; restrict in production |
| `NETGUARD_API_KEY` | _(unset)_ | Shared API key required in `X-API-Key` header for mutating endpoints; when unset, app runs in dev no-auth mode |
| `TRUST_PROXY_HEADERS` | `false` | When `true`, rate limiter reads client IP from `X-Forwarded-For`; only enable behind a trusted reverse proxy |
| `REQUIRE_AUTH_FOR_READS` | `false` | When `true`, `X-API-Key` is also enforced on `GET` endpoints; SocketIO paths are always exempt |
| `AI_PROVIDER` | `stub` | AI explanation provider: `stub`, `gemini`, or `openai` |
| `GEMINI_API_KEY` | _(unset)_ | Required when `AI_PROVIDER=gemini` |
| `OPENAI_API_KEY` | _(unset)_ | Required when `AI_PROVIDER=openai` |
| `SOCKETIO_ASYNC_MODE` | _(auto)_ | Force `threading` on Python 3.14+ (set automatically) |

---

## Running NetGuard

```bash
# Requires root for packet capture + iptables
sudo python backend/main.py

# Dashboard: http://localhost:5000
# API base:  http://localhost:5000/api/v1
```

### Startup Sequence (`backend/main.py`)

1. Eventlet monkey-patch (must be first import)
2. Load `config/config.yaml` via `ConfigurationManager`
3. Configure rotating log handlers via `setup_logging()`
4. Initialize SQLite database (`initialize_db()`)
5. Build repositories (EventRepository, BlockRepository, etc.)
6. Build services (LoggingEngine, WhitelistManager, PreventionEngine, etc.)
7. Verify iptables privileges (`PreventionEngine.verify_privileges()`)
8. Register all services in the dependency container
9. Create Flask app + register all route blueprints
10. Start `LoggingEngine` thread
11. Start `ExpiryThread`
12. Start `DetectionEngine` thread
13. Start live-stats SocketIO background task
14. `socketio.run()` — serves HTTP + WebSocket on configured host:port

---

## API Reference

All endpoints are under `http://localhost:5000/api/v1`.

**Response envelope** (every response):
```json
{ "success": true, "message": "OK", "data": { ... } }
{ "success": false, "error": "Description", "error_code": "VALIDATION_ERROR" }
```

**Authentication:** When `NETGUARD_API_KEY` is set, all `POST`, `PUT`, `DELETE`, and `PATCH`
requests must include an `X-API-Key: <key>` header. `GET` requests are open by default
(set `REQUIRE_AUTH_FOR_READS=true` to protect them). SocketIO paths are always exempt.

### Core Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness check |
| `GET` | `/status` | Monitoring state, thread states, packet/block counts |
| `POST` | `/monitor/start` | Start capture: `{"interface":"eth0"}` |
| `POST` | `/monitor/stop` | Stop capture |
| `GET` | `/monitor/interfaces` | List available network interfaces |
| `GET` | `/dashboard` | Full snapshot: KPIs + recent events + active blocks |
| `GET` | `/dashboard/live` | Lightweight: `packets_per_second`, `active_threats`, `alerts_today` |
| `GET` | `/detections` | Paginated list; filter by `severity`, `attack_type`, `source_ip`, `date` |
| `GET` | `/detections/<event_id>` | Single detection by UUID |
| `POST` | `/detect` | Submit detection event manually |
| `GET` | `/evidence/<event_id>` | Full `Explanation` object for a detection |
| `POST` | `/block` | Block an IP: `{"ip":"10.0.0.1","reason":"manual","duration":120}` |
| `POST` | `/unblock` | Unblock: `{"ip":"10.0.0.1"}` |
| `GET` | `/blocked` | All active blocks with `expires_in` countdown |
| `GET` | `/whitelist` | List all trusted IPs |
| `POST` | `/whitelist` | Add trusted IP: `{"ip":"192.168.1.1","description":"gateway"}` |
| `DELETE` | `/whitelist/<ip>` | Remove IP from whitelist |
| `GET` | `/statistics` | Aggregate counts by attack type and severity |
| `GET` | `/statistics/rules` | Per-rule detection counts (all 8 rules) |
| `GET` | `/logs` | Paginated system logs; filter by `severity`, `date`, `module` |
| `GET` | `/settings` | Return current configuration |
| `PUT` | `/settings` | Update thresholds; out-of-range → 422 VALIDATION_ERROR |
| `GET` | `/timeline/<event_id>` | Step-by-step incident timeline |
| `GET` | `/analytics` | Hourly/daily/weekly chart data, severity and attack distribution |
| `GET` | `/export` | Export events: `?format=json\|csv\|markdown\|pdf` |
| `GET` | `/lan-devices` | LAN devices from most recent ARP scan |
| `POST` | `/lan-devices/refresh` | Trigger a fresh ARP scan |
| `GET` | `/advisor` | Security advice and health score |
| `POST` | `/ai-assistant` | Chat with AI security assistant: `{"question":"..."}` |

### Demo Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/demo/start` | Start continuous synthetic attack generation |
| `POST` | `/demo/stop` | Stop the demo emit loop |
| `POST` | `/demo/trigger` | Emit one synthetic event: `{"attack_type":"SQL Injection"}` |
| `GET` | `/demo/status` | Current demo session state |

Full API documentation with request/response schemas: [`docs/API.md`](docs/API.md)

### Socket.IO Events

| Event | Payload | Description |
|-------|---------|-------------|
| `new_threat` | `{event_id, attack_type, source_ip, severity, confidence, timestamp, blocked}` | New threat detected |
| `ip_blocked` | `{ip, reason, expires_at}` | IP blocked |
| `ip_unblocked` | `{ip}` | IP unblocked (manual or expired) |
| `live_stats` | `{packets_per_second, active_threats, alerts_today}` | Emitted every second during monitoring |
| `monitoring_status` | `{active: bool, interface: string}` | Monitoring started or stopped |

---
