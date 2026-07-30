# Changelog

All notable changes to NetGuard IDPS are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project uses [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2025-07-01

Initial release for the MVIC Build Nepal Hackathon 2026.

### Added

#### Core Detection Pipeline
- `CaptureEngine` (`detection/capture/sniffer.py`) — Scapy-based raw packet
  capture with daemon thread and clean stop via `threading.Event`
- `PacketDecoder` (`detection/parsers/packet_decoder.py`) — normalises raw
  Scapy packets into a typed `Packet` dataclass; handles TCP, UDP, ICMP, ARP,
  IPv4, IPv6; returns `None` on decode failure (never raises to caller)
- `BaseRule` abstract class (`detection/rules/base_rule.py`) — enforces
  `initialize / process_packet / evaluate / explain / cleanup` interface;
  defines `ThreatEvent`, `Explanation`, and `FlowData` shared dataclasses

#### Detection Rules
- `SynFloodRule` — TCP SYN flood detection; sliding window; three severity
  tiers (Medium ≥100, High ≥200, Critical ≥400); confidence formula based on
  count/threshold ratio
- `PortScanRule` — unique destination port count per source IP; tiers
  (Medium ≥20, High ≥40, Critical ≥80); efficient `_PortScanFlow` tracker
  with deque + set
- `SqlInjectionRule` — HTTP payload pattern matching on ports 80/443/8080/8443;
  five patterns (`' OR`, `UNION SELECT`, `DROP TABLE`, `--`, `xp_cmdshell`);
  High on first hit, Critical on repeat; confidence always 100
- `BruteForceRule` — TCP connection tracking to auth ports (SSH 22, HTTP 80/443,
  FTP 21); sliding window; service name from port; tiers (Medium ≥10, High ≥20,
  Critical ≥40)
- `ArpSpoofRule` — IP-to-MAC conflict detection via ARP packets; confidence 97
  for 2 MACs, 100 for ≥3 MACs; severity always High

#### Services
- `DetectionEngine` — multi-rule pipeline with 10-second cooldown per
  (source_ip, rule_name); severity escalation within cooldown window;
  per-rule exception isolation (faulty rule disabled, others continue);
  `reload_rules()` for live config changes
- `ExplainabilityEngine` — attack-type templates for all five rule types;
  whitelist annotation; 500-character limit; fallback explanation on error;
  never raises to caller
- `PreventionEngine` — iptables block/unblock via `subprocess.run`;
  duplicate-block extension; privilege check at startup; 5-second timeout
  on all iptables commands
- `ExpiryThread` — 5-second poll interval; automatic expiry of `blocked_ips`
  records; iptables `-D` + DB `set_inactive` + SocketIO emit per expiry
- `WhitelistManager` — O(1) in-memory set backed by SQLite; thread-safe with
  `RLock`; `sync_from_db()` on startup
- `LoggingEngine` — async Logging_Thread consuming event_queue; three rotating
  log files (system.log, detections.log, errors.log); sensitive key redaction;
  max 10 MB per file, 5 backups
- `ConfigurationManager` — YAML config load with built-in defaults fallback;
  range validation for all integer settings; thread-safe in-memory store;
  `update()` persists to YAML without restart
- `MonitorService` — interface validation via `psutil`; start/stop coordination;
  SocketIO `monitoring_status` events
- `StatsService` — rolling packets-per-second counter; dashboard and live stats
  aggregation

#### REST API (Flask + Flask-SocketIO)
- Flask application factory (`backend/api/__init__.py`) with CORS and eventlet
- Service registry pattern (`backend/api/dependencies.py`) for blueprint DI
- 21 REST endpoints across 10 route blueprints under `/api/v1`
- Standard JSON envelope: `{"success": bool, "message": str, "data": any}`
  for all responses
- IP validation (`validate_ip_address`, `require_valid_ip`) on all IP inputs
- SocketIO events: `new_threat`, `ip_blocked`, `ip_unblocked`, `live_stats`,
  `monitoring_status`

#### Database
- SQLAlchemy 2.x ORM with six tables: `events`, `blocked_ips`, `whitelist`,
  `detection_rules`, `settings`, `system_logs`
- WAL mode + foreign keys enabled at init
- `initialize_db()` — idempotent; creates tables and seeds five default rules
  and eleven default settings

#### Frontend Dashboard
- Dark SOC-style theme in Vanilla JS ES6 + Chart.js
- Live KPI cards (packets/sec, active threats, alerts today)
- Traffic rate chart and severity distribution chart via WebSocket
- Threat timeline with evidence panel
- Active blocks page with `expires_in` countdown and manual unblock
- Whitelist management CRUD
- Log viewer with pagination and filters
- Detection rule toggle controls
- Settings form with client-side validation

#### Testing
- 511 tests: unit, property-based (Hypothesis), and integration
- Property-based tests for IP validation, severity tiers, confidence formulas,
  config validation ranges
- Flask test client integration tests for all route blueprints

#### Developer Experience
- `scripts/setup.sh` — one-shot setup (pip install + DB init)
- `scripts/start_demo.sh` — full demo launcher
- Five demo attack scripts in `demo/` (hping3, nmap, curl, hydra, arpspoof)
- `config/config.yaml` with fully documented parameters and valid ranges
- `.env.example` with documentation for every environment variable
- `docs/` — ARCHITECTURE.md, DATABASE.md, DEPLOYMENT.md, TROUBLESHOOTING.md, ROADMAP.md

### Known Limitations

- Blocking requires Linux + root; detection and API run on all platforms
- SQL injection detection uses pattern matching, not full HTTP stream reassembly
- Brute force detection uses connection counting as an auth-failure proxy
  (TCP-level; does not inspect HTTP 401 or SSH banner responses)
- No IPv6 blocking support (iptables IPv6 requires `ip6tables`)
- ARP spoofing detection has no MAC aging / cache eviction — restart clears state
