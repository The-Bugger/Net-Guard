# Changelog

All notable changes to NetGuard IDPS are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project uses [Semantic Versioning](https://semver.org/).

---

## [1.1.0] — 2026-08-01

### Added

#### Security Hardening
- `backend/middleware/auth.py` — API key authentication via `check_api_key()` before-request
  hook; constant-time `hmac.compare_digest` comparison; dev pass-through when
  `NETGUARD_API_KEY` is unset; SocketIO paths excluded from auth requirement
- `backend/middleware/security_headers.py` — `Content-Security-Policy`,
  `Strict-Transport-Security` (HTTPS-only), and `Permissions-Policy` response headers
- Rate limiter `_client_ip()` now respects `TRUST_PROXY_HEADERS` env var (default `false`);
  `X-Forwarded-For` header ignored unless explicitly opted in
- `SECRET_KEY` now read from `os.environ`; raises `RuntimeError` in production when unset
- `.env.example` updated with `NETGUARD_API_KEY`, `TRUST_PROXY_HEADERS`,
  `REQUIRE_AUTH_FOR_READS`; `SECURITY.md` expanded; `DEPLOYMENT.md` created

#### New Detection Rules
- `IcmpFloodRule` (`ICMP_FLOOD_001`) — ICMP Echo Request flood and Smurf attack detection;
  severity tiers Medium / High / Critical based on count vs threshold; 27 unit tests
- `SlowHttpRule` (`SLOW_HTTP_001`) — Slowloris / slow HTTP connection exhaustion detection;
  TCP state tracking for ports 80/443; severity Medium / High; 29 unit tests
- `DnsTunnelRule` (`DNS_TUNNEL_001`) — DNS tunneling heuristic via label length, TXT query
  rate, and Shannon entropy; confidence capped at 80; 46 unit tests
- All three rules registered in `DetectionEngine` and `config/config.yaml`
- Attack test scripts added to `scripts/attack_tests/` for all new rule types

#### Analytics and Export
- `analytics_routes` — traffic and threat analytics endpoints with time-range filtering
- `export_routes` — CSV and JSON export for detections and blocked-IP history
- `timeline_routes` — chronological event timeline endpoint
- `ai_assistant_routes` — AI-backed chat assistant for threat investigation
- `demo_service` — synthetic attack replay for demonstration purposes
- Frontend: `analytics.html`, `landing.html`, `timeline.html`, `architecture.html` pages

#### AI Explain Service
- `backend/services/ai_explain_service.py` — Gemini-backed natural-language threat
  explanation with deterministic fallback template when API is unavailable
- `POST /api/v1/detections/{id}/explain` endpoint

#### Frontend
- `frontend/js/shell.js` — shared sidebar, top-bar, and notification drawer component
  consumed by all dashboard pages
- `frontend/js/analytics.js`, `timeline.js`, `topology.js`, `utils.js` — new JS modules
- HTML-escaped all dynamic content in `blocked.html`, `logs.html`, `rules.html`,
  `threats.html`, `whitelist.html` to prevent reflected XSS; `escapeHtml()` added to `api.js`
- `404.html`, `500.html` error pages

#### Testing
- API integration tests for block, detections, monitor, settings, and whitelist endpoints
- Threading, logging, database, prevention engine, rate-limiter, and security-headers tests
- 678 property-based tests covering hackathon upgrade requirements

### Changed

- SQL injection `--` pattern tightened to `(?:'\s*--|[^-\w]--)` — reduces false positives
  on date strings while preserving detection of genuine injection payloads
- `prevention_service.py` — private-IP safety guard: RFC 1918, loopback, link-local, and
  multicast addresses refused by `block_ip()` unless `allow_private_block=True`
- `stats_service.py` — expose blocked-IP count in dashboard stats
- `config/config.yaml` — added threshold and window config keys for all three new rules
- `requirements.txt` — all dependencies pinned to exact versions

### Fixed

- `backend/api/__init__.py` — dead `ai_routes` blueprint removed (was never registered)
- `backend/api/.gitkeep` placeholder removed (directory non-empty)
- Rate limiter `_client_ip()` proxy header handling
- Brute-force and SQL injection test assertions narrowed to avoid false failures on benign
  double-dash patterns (e.g. SQL date literals)

### Documentation

- `README.md` — updated with new env vars, new detection rules, and API auth reference
- `docs/API.md` — `X-API-Key` requirement documented; new endpoints added
- `docs/ARCHITECTURE.md` — updated with new rules and API auth pipeline
- `SECURITY.md` — expanded: API key auth, SocketIO exclusion, proxy trust model
- `CONTRIBUTING.md` — prominent warning added for `.env` secret handling

---

## [1.0.0] — 2026-08-01

Initial release for the MVIC Build Nepal Hackathon 2026.

### Added

#### Core Detection Pipeline
- `CaptureEngine` (`detection/capture/sniffer.py`) — Scapy-based raw packet capture with
  daemon thread and clean stop via `threading.Event`
- `PacketDecoder` (`detection/parsers/packet_decoder.py`) — normalises raw Scapy packets
  into a typed `Packet` dataclass; handles TCP, UDP, ICMP, ARP, IPv4, IPv6; returns `None`
  on decode failure
- `BaseRule` abstract class (`detection/rules/base_rule.py`) — enforces
  `initialize / process_packet / evaluate / explain / cleanup` interface; defines
  `ThreatEvent`, `Explanation`, and `FlowData` shared dataclasses

#### Detection Rules
- `SynFloodRule` — TCP SYN flood; sliding window; severity tiers Medium / High / Critical
- `PortScanRule` — unique destination port count per source IP; tiers Medium / High / Critical
- `SqlInjectionRule` — HTTP payload pattern matching on ports 80/443/8080/8443; five patterns
- `BruteForceRule` — TCP connection tracking to auth ports (SSH 22, HTTP 80/443, FTP 21)
- `ArpSpoofRule` — IP-to-MAC conflict detection via ARP; confidence 97 for 2 MACs, 100 for ≥3

#### Services
- `DetectionEngine` — multi-rule pipeline; 10-second cooldown per (source_ip, rule_name);
  per-rule exception isolation; `reload_rules()` for live config changes
- `ExplainabilityEngine` — attack-type templates; 500-character limit; fallback on error
- `PreventionEngine` — iptables block/unblock; duplicate-block protection; privilege check
- `ExpiryThread` — automatic expiry of blocked IPs with iptables cleanup
- `WhitelistManager` — O(1) in-memory set backed by SQLite; thread-safe with `RLock`
- `LoggingEngine` — async log thread; three rotating log files; sensitive key redaction
- `ConfigurationManager` — YAML config with built-in defaults; range validation; thread-safe
- `MonitorService` — interface validation via psutil; start/stop coordination
- `StatsService` — rolling packets-per-second counter; dashboard stats aggregation

#### REST API
- Flask application factory with CORS and eventlet
- Service registry pattern for blueprint dependency injection
- 21 REST endpoints across 10 route blueprints under `/api/v1`
- Standard JSON envelope `{"success": bool, "message": str, "data": any}` on all responses
- IP validation on all IP inputs
- SocketIO events: `new_threat`, `ip_blocked`, `ip_unblocked`, `live_stats`,
  `monitoring_status`

#### Database
- SQLAlchemy 2.x ORM; six tables: `events`, `blocked_ips`, `whitelist`,
  `detection_rules`, `settings`, `system_logs`
- WAL mode and foreign keys enabled at init
- `initialize_db()` — idempotent; seeds five default rules and eleven default settings

#### Frontend
- Dark SOC-style theme in Vanilla JS ES6 + Chart.js
- Live KPI cards, traffic rate chart, severity distribution chart via WebSocket
- Threat timeline with evidence panel; active blocks with countdown and manual unblock
- Whitelist CRUD; log viewer with pagination; detection rule toggles; settings form

#### Testing
- 511 tests: unit, property-based (Hypothesis), and integration
- Property-based tests for IP validation, severity tiers, confidence formulas, config ranges
- Flask test client integration tests for all route blueprints

#### Developer Experience
- `scripts/setup.sh` and `scripts/start_demo.sh`
- Demo attack scripts in `demo/`
- Fully documented `config/config.yaml` and `.env.example`
- `docs/` — ARCHITECTURE.md, DATABASE.md, DEPLOYMENT.md, TROUBLESHOOTING.md, ROADMAP.md

### Known Limitations

- Blocking requires Linux + root; detection and API run on all platforms
- SQL injection detection uses pattern matching, not full HTTP stream reassembly
- Brute force detection counts connections as auth-failure proxy (no HTTP 401 / SSH banner
  inspection)
- No IPv6 blocking support (`ip6tables` required)
- ARP spoofing state is in-process only — restart clears MAC cache
