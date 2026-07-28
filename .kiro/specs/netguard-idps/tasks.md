# Implementation Plan: NetGuard IDPS

## Overview

Implement NetGuard — an Explainable Intrusion Detection and Prevention System — in six sequential phases:
project scaffolding → detection engine → prevention layer → REST API → frontend dashboard → tests and documentation.
Each phase builds on the previous; no orphaned code is left unintegrated. All code is Python 3.11+ (backend/detection) and vanilla JavaScript ES6 (frontend).

---

## Tasks

### Phase 1: Project Structure, Configuration, Dependencies, Database, Logging

- [x] 1. Create directory structure and dependency manifest
  - Create all required directories: `backend/api/`, `backend/services/`, `backend/models/`, `backend/routes/`, `backend/utils/`, `frontend/css/`, `frontend/js/`, `frontend/assets/`, `detection/rules/`, `detection/parsers/`, `detection/capture/`, `database/migrations/`, `config/`, `logs/`, `scripts/`, `tests/integration/`, `demo/`, `docs/`
  - Place a `.gitkeep` in each empty leaf directory so git tracks them
  - Create `requirements.txt` pinning exact versions for: flask, flask-socketio, flask-cors, eventlet, scapy, sqlalchemy, pyyaml, hypothesis, pytest, pytest-cov, ipaddress (stdlib note)
  - _Requirements: 1.1, 1.7_

- [x] 2. Implement Configuration_Manager
  - [x] 2.1 Create `config/config.yaml` with all settings and documented defaults (interface, syn_flood_threshold=100, syn_flood_window=3, port_scan_threshold=20, port_scan_window=10, brute_force_threshold=10, brute_force_window=60, block_duration=120, dashboard_refresh_interval=1, rules_enabled dict all true)
  - Create `backend/services/config_service.py` with `Settings` dataclass and `ConfigurationManager` class implementing `load()`, `get()`, `update()`, `validate_settings()` methods
  - Implement fallback-to-defaults when `config/config.yaml` is missing or malformed with CRITICAL log to `logs/errors.log`
  - Implement in-memory apply plus YAML file persist on `update()` without restart
  - _Requirements: 1.2, 1.3, 1.4, 1.5, 1.6_

  - [x] 2.2 Write property test for ConfigurationManager (Property 1)
    - **Property 1: Settings Validation and Persistence** — for any numeric setting within range, accepted and persisted; outside range, rejected with 422; absent config.yaml, defaults applied
    - **Validates: Requirements 1.3, 1.4, 1.5, 1.6**
    - Annotate with `# Feature: netguard-idps, Property 1`
    - File: `tests/test_properties_config.py`


- [x] 3. Create database schema and initialization
  - [x] 3.1 Create `database/schema.py` with six SQLAlchemy ORM models: `Event`, `BlockedIP`, `WhitelistEntry`, `DetectionRule`, `Setting`, `SystemLog` using all fields specified in design
    - Include CHECK constraint on `Event.confidence BETWEEN 0 AND 100`
    - Include UNIQUE constraint on `Event.event_id`
    - _Requirements: 14.1, 14.3, 14.4_

  - [x] 3.2 Create `database/init_db.py` with `initialize_db()` function that creates all tables on first startup if `database/netguard.db` does not exist
    - _Requirements: 14.1_

  - [x] 3.3 Write property tests for database constraints (Properties 39–40)
    - **Property 39: Database Confidence Constraint** — INSERT with confidence outside [0,100] rejected
    - **Property 40: Database Event ID Uniqueness Constraint** — duplicate event_id rejected
    - **Validates: Requirements 14.3, 14.4**
    - Annotate with `# Feature: netguard-idps, Property 39` and `# Feature: netguard-idps, Property 40`
    - File: `tests/test_properties_db.py`

- [x] 4. Implement logging system
  - Create `backend/services/log_service.py` with `LoggingEngine` class implementing `start()`, `stop()`, `_logging_loop()`, `log_event()`, `log_system()` methods
  - Configure Python logging with three file handlers: `logs/system.log` (INFO), `logs/detections.log` (INFO + detection events), `logs/errors.log` (WARNING+)
  - Use rotating log files with max size 10 MB and 5 backups
  - Implement Logging_Thread that consumes `event_queue` (thread-safe `queue.Queue`)
  - Never log passwords, secrets, or tokens
  - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5_

- [x] 5. Create utility modules
  - Create `backend/utils/validators.py` with IP validation using `ipaddress.ip_address()`, numeric range checks, raises ValueError on invalid
  - Create `backend/utils/response.py` with `success_response(data, message)` and `error_response(error, code)` helpers returning standard JSON envelope
  - _Requirements: 13.3, 13.6_


- [ ] 6. Checkpoint — Phase 1 complete
  - Ensure all tests pass, ask the user if questions arise.

---

### Phase 2: Packet Capture, Parsing, Detection Engine, Evidence Generation

- [x] 7. Implement Packet_Decoder
  - [x] 7.1 Create `detection/parsers/packet_decoder.py` with `Packet` dataclass (src_ip, dst_ip, src_port, dst_port, protocol, flags, timestamp, length, payload) and `PacketDecoder` class with `decode()` method
    - Extract all required fields; set src_port/dst_port to None for non-TCP/UDP; set protocol to "UNKNOWN" for unrecognized protocols; set flags to None for non-TCP
    - Return None and log WARNING on failure; never raise to caller; complete within 10 ms
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

  - [x] 7.2 Write unit tests for PacketDecoder
    - Test each protocol (TCP, UDP, ICMP, ARP, UNKNOWN), null fields for non-TCP/UDP, edge cases, decode failure returns None
    - _Requirements: 3.1, 3.2, 3.3, 3.4_
    - File: `tests/test_packet_decoder.py`

  - [x] 7.3 Write property tests for Packet_Decoder (Properties 2–3)
    - **Property 2: Malformed Input Resilience** — any undecodeable raw input returns None without exception
    - **Property 3: Packet Decoding Correctness** — all required fields present on valid packet
    - **Validates: Requirements 2.4, 3.1, 3.2, 3.4, 9.7**
    - Annotate with `# Feature: netguard-idps, Property 2` and `# Feature: netguard-idps, Property 3`
    - File: `tests/test_properties_capture.py`

- [x] 8. Implement Capture_Engine
  - [x] 8.1 Create `detection/capture/sniffer.py` with `CaptureEngine` class implementing `start(interface)`, `stop()`, `_capture_loop()`, `_on_packet(raw_pkt)` methods
    - Use Scapy `sniff()` in daemon thread with `threading.Event` for clean stop
    - On each packet call `PacketDecoder.decode()` and put result on `packet_queue`
    - Log WARNING to `logs/system.log` on decode failure; discard malformed packet; continue
    - Start within 2 seconds; stop within 2 seconds
    - _Requirements: 2.1, 2.3, 2.4, 2.6_


- [ ] 9. Implement detection rule base and all five rules
  - [x] 9.1 Create `detection/rules/base_rule.py` with abstract `BaseRule` class defining `initialize()`, `process_packet()`, `evaluate()`, `generate_event()`, `explain()`, `cleanup()` abstract methods; define `FlowData` dataclass with timestamps deque, ports set, macs dict
    - _Requirements: 9.3, 9.4, 9.7_

  - [x] 9.2 Create `detection/rules/syn_flood.py` — `SynFloodRule`
    - Track TCP SYN packets per source IP using deque of timestamps; evict entries older than `syn_flood_window` seconds
    - Emit ThreatEvent when count ≥ configured threshold; assign severity Medium/High/Critical per tiers (100–199/200–399/≥400)
    - Confidence formula: `round(min(count/threshold, 2.0)/2.0*100)` capped at 100
    - Include evidence: source_ip, syn_packet_count, time_window_seconds, destination_ips, sample_timestamps (≤5)
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7_

  - [ ] 9.3 Write unit tests for SynFloodRule
    - Test threshold boundary, severity tiers, confidence formula, evidence fields, cooldown behavior
    - File: `tests/test_syn_flood.py`
    - _Requirements: 4.1–4.7_

  - [ ] 9.4 Write property tests for SYN Flood (Properties 4–7)
    - **Property 4:** count ≥ threshold → ThreatEvent emitted with correct attack_type
    - **Property 5:** Severity tiers for Medium/High/Critical
    - **Property 6:** Confidence formula result always in [0, 100]
    - **Property 7:** Evidence dict contains all required fields
    - **Validates: Requirements 4.1–4.6**
    - Annotate `# Feature: netguard-idps, Property 4` through `# Feature: netguard-idps, Property 7`
    - File: `tests/test_properties_detection.py`

  - [x] 9.5 Create `detection/rules/port_scan.py` — `PortScanRule`
    - Track unique destination ports per source IP using set of (dst_ip, dst_port) tuples within sliding window
    - Emit ThreatEvent when unique port count ≥ configured threshold; assign severity Medium/High/Critical per tiers (20–39/40–79/≥80)
    - Confidence formula: `round(min(unique_count/threshold, 2.0)/2.0*100)` capped at 100
    - Include evidence: source_ip, scanned_ports, unique_port_count, time_window_seconds, confidence_score
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_

  - [ ] 9.6 Write unit tests for PortScanRule
    - Test threshold boundary, severity tiers, confidence formula, evidence, cooldown
    - File: `tests/test_port_scan.py`
    - _Requirements: 5.1–5.6_

  - [ ] 9.7 Write property tests for Port Scan (Properties 8–11)
    - **Property 8:** unique_count ≥ threshold → ThreatEvent with "Port Scan" and "PORT_SCAN_001"
    - **Property 9:** Severity tiers for Medium/High/Critical
    - **Property 10:** Confidence formula always in [0, 100]
    - **Property 11:** Evidence dict contains all required fields
    - **Validates: Requirements 5.1–5.5**
    - Annotate `# Feature: netguard-idps, Property 8` through `# Feature: netguard-idps, Property 11`
    - File: `tests/test_properties_detection.py`


  - [x] 9.8 Create `detection/rules/sql_injection.py` — `SqlInjectionRule`
    - Inspect TCP payload of HTTP packets (dst_port 80 or 443) with case-insensitive regex for patterns: `' OR`, `UNION SELECT`, `DROP TABLE`, `--`, `xp_cmdshell`
    - First detection from IP → severity High; repeated detection → severity Critical; confidence always 100
    - Include evidence: source_ip, destination_ip, http_method, request_url, matched_pattern
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_

  - [ ] 9.9 Write unit tests for SqlInjectionRule
    - Test each pattern (case-insensitive), severity escalation on repeated IP, confidence=100, evidence fields
    - File: `tests/test_sql_injection.py`
    - _Requirements: 6.1–6.6_

  - [ ] 9.10 Write property tests for SQL Injection (Properties 12–14)
    - **Property 12:** Any matching payload → ThreatEvent with "SQL Injection" and "SQL_INJECTION_001"
    - **Property 13:** First occurrence → High; repeat from same IP → Critical
    - **Property 14:** Confidence always 100; evidence contains all required fields
    - **Validates: Requirements 6.1–6.6**
    - Annotate `# Feature: netguard-idps, Property 12` through `# Feature: netguard-idps, Property 14`
    - File: `tests/test_properties_detection_sqli.py`

  - [x] 9.11 Create `detection/rules/brute_force.py` — `BruteForceRule`
    - Track auth-failure indicators per source IP: SSH (port 22), HTTP 401 responses (port 80/443), FTP (port 21)
    - Emit ThreatEvent when failure count ≥ configured threshold within sliding window; assign severity Medium/High/Critical per tiers (10–19/20–39/≥40)
    - Confidence formula: `round(min(failure_count/threshold, 2.0)/2.0*100)` capped at 100
    - Include evidence: source_ip, failure_count, time_window_seconds, target_service (identified from dst_port or "Unknown")
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

  - [ ] 9.12 Write unit tests for BruteForceRule
    - Test threshold boundary, severity tiers, confidence formula, service identification (SSH/HTTP/FTP/Unknown), evidence
    - File: `tests/test_brute_force.py`
    - _Requirements: 7.1–7.6_

  - [ ] 9.13 Write property tests for Brute Force (Properties 15–18)
    - **Property 15:** failure_count ≥ threshold → ThreatEvent with "Brute Force" and "BRUTE_FORCE_001"
    - **Property 16:** Severity tiers for Medium/High/Critical
    - **Property 17:** Confidence formula result always in [0, 100]
    - **Property 18:** Evidence dict contains all required fields including target_service
    - **Validates: Requirements 7.1–7.6**
    - Annotate `# Feature: netguard-idps, Property 15` through `# Feature: netguard-idps, Property 18`
    - File: `tests/test_properties_detection_bruteforce.py`

  - [x] 9.14 Create `detection/rules/arp_spoof.py` — `ArpSpoofRule`
    - Maintain `ip_to_macs: dict[str, set[str]]` mapping each IP to observed MAC addresses from ARP replies
    - Emit ThreatEvent when `len(macs_for_ip) >= 2`; severity always High
    - Confidence: 97 for exactly 2 MACs, 100 for ≥3 MACs
    - Include evidence: conflicting_ip, conflicting_macs (complete list), first_observed_timestamp, most_recent_timestamp
    - _Requirements: 8.1, 8.2, 8.3, 8.4_

  - [ ] 9.15 Write unit tests for ArpSpoofRule
    - Test trigger on 2 MACs, confidence tiers (97 vs 100), evidence fields, severity always High
    - File: `tests/test_arp_spoof.py`
    - _Requirements: 8.1–8.4_

  - [ ] 9.16 Write property tests for ARP Spoofing (Properties 19–22)
    - **Property 19:** 2+ MACs for same IP → ThreatEvent with "ARP Spoofing" and "ARP_SPOOF_001"
    - **Property 20:** Severity always "High" regardless of MAC count
    - **Property 21:** Confidence 97 for exactly 2 MACs, 100 for ≥3 MACs
    - **Property 22:** Evidence contains conflicting_ip, conflicting_macs, first_observed_timestamp, most_recent_timestamp
    - **Validates: Requirements 8.1–8.4**
    - Annotate `# Feature: netguard-idps, Property 19` through `# Feature: netguard-idps, Property 22`
    - File: `tests/test_properties_detection_arp.py`


- [ ] 10. Implement Detection_Engine
  - [ ] 10.1 Create `backend/services/detection_service.py` with `DetectionEngine` class implementing `start()`, `stop()`, `_detection_loop()`, `_dispatch()`, `reload_rules()` methods
    - Consume `packet_queue`; run all enabled rules via `process_packet()` and `evaluate()` for each packet
    - Enforce cooldown: dict[(source_ip, rule_name)] → (last_severity, emit_time); suppress if same or lower severity within 10 s
    - Assign UUID4 event_id to every ThreatEvent; complete all rule evaluation within 100 ms per packet
    - Expire Flow_Tracker counters for IPs inactive longer than the longest configured window
    - On rule exception: log to `logs/errors.log`, disable that rule for session, continue other rules
    - Wire to Explainability_Engine then forward ThreatEvent to `event_queue`
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7_

  - [ ] 10.2 Write property tests for Detection_Engine general rules (Properties 23–25)
    - **Property 23:** All ThreatEvents have unique UUID4 event_id
    - **Property 24:** Cooldown enforcement — no duplicate event within 10 s unless higher severity
    - **Property 25:** Rule exception → rule disabled; other rules continue
    - **Validates: Requirements 9.1, 9.2, 4.7, 5.6, 9.5**
    - Annotate `# Feature: netguard-idps, Property 23` through `# Feature: netguard-idps, Property 25`
    - File: `tests/test_properties_engine.py`

  - [ ] 10.3 Write unit tests for threading behavior
    - Test queue communication between threads, graceful shutdown via threading.Event, single auto-restart on thread crash
    - File: `tests/test_threading.py`
    - _Requirements: 9.3, 9.7_

- [ ] 11. Implement Explainability_Engine
  - [ ] 11.1 Create `backend/services/explain_service.py` with `ExplainabilityEngine` class implementing `explain()`, `_build_text()`, `_get_recommendation()`, `_fallback_explanation()` methods
    - Use attack-type-specific templates to produce `plain_english_text` (≤500 chars, non-empty)
    - Map recommendation strings exactly per design for all five attack types
    - Append "Whitelisted device — monitoring only, no block applied." if source IP is whitelisted
    - Return fallback Explanation on exception; log error to `logs/errors.log`; complete within 50 ms
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8, 10.9, 10.10_

  - [ ] 11.2 Write unit tests for ExplainabilityEngine
    - Test each attack type template, fallback explanation, recommendation mapping, whitelist annotation, severity/confidence passthrough
    - File: `tests/test_explainability.py`
    - _Requirements: 10.1–10.10_

  - [ ] 11.3 Write property tests for Explainability_Engine (Properties 26–30)
    - **Property 26:** plain_english_text always non-null, non-empty, ≤500 chars
    - **Property 27:** confidence_score always integer in [0, 100]
    - **Property 28:** severity always one of "Low", "Medium", "High", "Critical"
    - **Property 29:** recommendation exactly matches attack-type string from requirements
    - **Property 30:** whitelisted source IP → whitelist phrase appended to plain_english_text
    - **Validates: Requirements 10.1–10.9**
    - Annotate `# Feature: netguard-idps, Property 26` through `# Feature: netguard-idps, Property 30`
    - File: `tests/test_properties_explain.py`

- [ ] 12. Checkpoint — Phase 2 complete
  - Ensure all tests pass, ask the user if questions arise.


---

### Phase 3: Firewall Integration, Blocking, Auto-Unblock, Whitelist

- [ ] 13. Implement database repositories
  - [x] 13.1 Create `backend/repositories/event_repository.py` with CRUD methods for `events` table: `insert(event)`, `get_by_id(event_id)`, `get_all(filters)` using SQLAlchemy ORM; use parameterized queries only
    - Implement in-memory queue (thread-safe deque) for retry on DB unavailability up to 60 s
    - _Requirements: 14.2, 14.5, 14.6, 14.7_

  - [x] 13.2 Create `backend/repositories/block_repository.py` with CRUD for `blocked_ips` table: `insert(record)`, `get_active(ip)`, `get_all_active()`, `set_inactive(ip)`, `extend_expiry(ip, new_expires_at)`, `get_expired()`
    - _Requirements: 11.2, 11.3, 11.6_

  - [x] 13.3 Create `backend/repositories/whitelist_repository.py` with CRUD for `whitelist` table: `insert(entry)`, `delete(ip)`, `get_all()`, `exists(ip)` within single DB transactions
    - _Requirements: 12.2, 12.3_

  - [x] 13.4 Create `backend/repositories/log_repository.py` with `insert(log_entry)` for `system_logs` table; complete each insert in under 20 ms
    - _Requirements: 14.5_

  - [x] 13.5 Create `backend/repositories/settings_repository.py` with `get(key)`, `set(key, value)`, `get_all()` for `settings` table
    - _Requirements: 1.4_

  - [ ] 13.6 Write unit tests for database schema and repositories
    - Test DB initialization creates all 6 tables, constraint enforcement, ORM model insert/query, no raw SQL strings
    - File: `tests/test_database.py`
    - _Requirements: 14.1–14.7_

- [ ] 14. Implement Whitelist_Manager
  - [ ] 14.1 Create `backend/services/whitelist_service.py` with `WhitelistManager` implementing `is_whitelisted(ip)` (O(1) in-memory set lookup), `add(ip, description, created_by)`, `remove(ip)`, `get_all()`, `_sync_from_db()` methods
    - Sync in-memory set from DB on startup and after every mutation
    - Validate IP using `validators.py` before any DB operation
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7_

  - [ ]14.2 Write unit tests for WhitelistManager
    - Test add/remove/list, in-memory sync, invalid IP rejection, DB transaction atomicity
    - File: `tests/test_whitelist.py`
    - _Requirements: 12.1–12.7_

  - [ ] 14.3 Write property tests for Whitelist (Properties 31, 35–36)
    - **Property 31:** Whitelisted IP → Prevention_Engine never calls iptables block
    - **Property 35:** GET /whitelist returns all entries with all required fields
    - **Property 36:** Malformed IP in any API request → HTTP 422 INVALID_IP without DB/firewall op
    - **Validates: Requirements 11.1, 12.1, 12.5, 12.6, 12.7, 13.6**
    - Annotate `# Feature: netguard-idps, Property 31`, `Property 35`, `Property 36`
    - File: `tests/test_properties_prevention.py` (Properties 31) and `tests/test_properties_api.py` (Properties 35–36)


- [ ] 15. Implement Prevention_Engine
  - [ ] 15.1 Create `backend/services/prevention_service.py` with `PreventionEngine` implementing `handle_event(event, explanation)`, `block_ip(ip, reason, event_id)`, `unblock_ip(ip)`, `_run_iptables(cmd)`, `verify_privileges()` methods
    - Use `subprocess.run(shlex.split(cmd), capture_output=True, timeout=5)` for all iptables calls
    - Check WhitelistManager before any block; if whitelisted, skip iptables and log
    - Execute `iptables -I INPUT -s <ip> -j DROP` within 3 s of ThreatEvent timestamp
    - Detect duplicate active block; extend expires_at by block_duration instead of issuing duplicate rule
    - Log iptables failures to `logs/errors.log`; set blocked=False in events record; continue
    - Verify iptables privileges on startup; raise RuntimeError and log CRITICAL if insufficient
    - _Requirements: 11.1, 11.2, 11.4, 11.5, 11.6, 11.7, 11.8_

  - [ ] 15.2 Write unit tests for PreventionEngine
    - Test block/unblock with mocked subprocess, whitelist bypass, duplicate block extension, iptables failure handling, privilege check
    - File: `tests/test_prevention.py`
    - _Requirements: 11.1–11.8_

  - [ ] 15.3 Write property tests for Prevention_Engine (Properties 32–34)
    - **Property 32:** Every successful block → blocked_ips record with all required fields
    - **Property 33:** Block expiry at expires_at → iptables -D rule executed, active set to False within 5 s
    - **Property 34:** Active block exists → no duplicate iptables rule; expires_at extended
    - **Validates: Requirements 11.2, 11.3, 11.6**
    - Annotate `# Feature: netguard-idps, Property 32` through `# Feature: netguard-idps, Property 34`
    - File: `tests/test_properties_prevention.py`

- [ ] 16. Implement Expiry_Thread
  - Create `backend/services/expiry_service.py` with `ExpiryThread` that polls `blocked_ips` for records where `expires_at <= now()` and `active = TRUE`
  - For each expired record: execute `iptables -D INPUT -s <ip> -j DROP`, set `active = FALSE` in DB
  - Poll interval: 5 seconds; run as daemon thread with `threading.Event` stop signal
  - _Requirements: 11.3_

- [ ] 17. Checkpoint — Phase 3 complete
  - Ensure all tests pass, ask the user if questions arise.


---

### Phase 4: REST API, Backend, Database Integration

- [ ] 18. Create Flask application factory and services
  - [ ] 18.1 Create `backend/api/__init__.py` with Flask app factory `create_app()`, Flask-SocketIO initialization with eventlet backend, eventlet monkey-patch applied before any other imports; register all blueprints
    - _Requirements: 13.1, 13.2_

  - [ ] 18.2 Create `backend/services/monitor_service.py` with `MonitorService` that coordinates `CaptureEngine.start(interface)` / `stop()`, validates interface against OS list, manages shared `MonitoringState`, emits `monitoring_status` SocketIO events
    - Return HTTP 409 ALREADY_MONITORING if already active; HTTP 409 NOT_MONITORING if stop called when inactive; HTTP 422 INVALID_INTERFACE for unknown interface
    - _Requirements: 2.1, 2.2, 2.6, 2.7, 2.8, 2.9_

  - [ ] 18.3 Create `backend/services/stats_service.py` with `StatsService` that aggregates detection counts by attack_type, severity, rule, packets-per-second, active threats, alerts today from DB + in-memory counters
    - _Requirements: 13.2, 16.1_

- [ ] 19. Implement all REST API route handlers
  - [ ] 19.1 Create `backend/routes/health_routes.py` — `GET /api/v1/health` returns `{"status":"ok"}`, `GET /api/v1/status` returns monitoring status, uptime, thread states; delegate to MonitorService
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5_

  - [ ] 19.2 Create `backend/routes/monitor_routes.py` — `POST /api/v1/monitor/start`, `POST /api/v1/monitor/stop`, `GET /api/v1/monitor/interfaces`; delegate to MonitorService; validate interface name
    - _Requirements: 2.1, 2.2, 2.5, 2.6, 2.7, 2.8, 2.9, 13.3, 13.4_

  - [ ] 19.3 Create `backend/routes/detection_routes.py` — `GET /api/v1/detections` with filters (severity, attack_type, source_ip, date), `GET /api/v1/detections/{event_id}`, `POST /api/v1/detect`; delegate to EventRepository/DetectionEngine
    - _Requirements: 13.2, 13.3, 13.4, 13.8_

  - [ ] 19.4 Create `backend/routes/block_routes.py` — `POST /api/v1/block`, `POST /api/v1/unblock`, `GET /api/v1/blocked`; delegate to PreventionEngine/BlockRepository; validate IP
    - _Requirements: 11.7, 13.2, 13.3, 13.4, 13.6_

  - [ ] 19.5 Create `backend/routes/whitelist_routes.py` — `GET /api/v1/whitelist`, `POST /api/v1/whitelist`, `DELETE /api/v1/whitelist/{ip}`; delegate to WhitelistManager; validate IP
    - _Requirements: 12.2, 12.3, 12.4, 12.5, 12.6, 13.2, 13.3, 13.4_

  - [ ] 19.6 Create `backend/routes/dashboard_routes.py` — `GET /api/v1/dashboard` (full snapshot: KPIs + recent 20 events + active blocks + whitelist), `GET /api/v1/dashboard/live` (lightweight: packets/s, active_threats, alerts_today); delegate to StatsService
    - _Requirements: 13.2, 13.3, 16.1, 16.2_

  - [ ] 19.7 Create `backend/routes/stats_routes.py` — `GET /api/v1/statistics`, `GET /api/v1/statistics/rules`; delegate to StatsService
    - _Requirements: 13.2, 13.3_

  - [ ] 19.8 Create `backend/routes/evidence_routes.py` — `GET /api/v1/evidence/{event_id}` returns full Explanation for event; delegate to EventRepository + ExplainabilityEngine
    - _Requirements: 13.2, 13.3, 13.4_

  - [ ] 19.9 Create `backend/routes/logs_routes.py` — `GET /api/v1/logs` with pagination (default page_size=50) and filters (severity, date, module, attack_type, source_ip); delegate to LogRepository
    - _Requirements: 13.2, 13.3, 13.9, 15.6_

  - [ ] 19.10 Create `backend/routes/settings_routes.py` — `PUT /api/v1/settings` validates all fields against Settings schema, returns HTTP 422 VALIDATION_ERROR with invalid field name on out-of-range value; delegate to ConfigurationManager
    - _Requirements: 1.4, 1.5, 13.2, 13.3, 13.4_


- [ ] 20. Create application entry point
  - Create `backend/main.py` implementing the full startup sequence: monkey-patch eventlet → load ConfigurationManager → initialize_db() → verify_privileges() (PreventionEngine) → create_app() + register blueprints → start LoggingEngine thread → start ExpiryThread → start DetectionEngine thread → socketio.run()
  - Entire startup must complete within 10 seconds
  - Emit `monitoring_status: {active: false}` SocketIO event on clean shutdown
  - _Requirements: 1.7, 11.8_

- [ ] 21. Wire REST API tests
  - [ ] 21.1 Write REST API tests for `/monitor` endpoints
    - Test start/stop happy paths, ALREADY_MONITORING, NOT_MONITORING, INVALID_INTERFACE, interfaces list
    - File: `tests/test_api_monitor.py`
    - _Requirements: 2.1–2.9_

  - [ ] 21.2 Write REST API tests for `/detections` endpoints
    - Test paginated list, filter by severity/type/source_ip/date, single event by id, 404 for unknown id
    - File: `tests/test_api_detections.py`
    - _Requirements: 13.3, 13.4, 13.8_

  - [ ] 21.3 Write REST API tests for `/block` and `/unblock` endpoints
    - Test manual block, unblock, blocked list, duplicate block, invalid IP rejection
    - File: `tests/test_api_block.py`
    - _Requirements: 11.7, 13.3, 13.4, 13.6_

  - [ ] 21.4 Write REST API tests for `/whitelist` endpoints
    - Test add valid IP, delete existing IP, delete non-existent IP (404), invalid IP (422), list all
    - File: `tests/test_api_whitelist.py`
    - _Requirements: 12.2–12.6_

  - [ ] 21.5 Write REST API tests for `PUT /settings`
    - Test valid update applied in memory, invalid range returns 422 VALIDATION_ERROR with field name, config.yaml persisted
    - File: `tests/test_api_settings.py`
    - _Requirements: 1.4, 1.5_

  - [ ] 21.6 Write property tests for API envelope and filtering (Properties 37–38)
    - **Property 37:** Every API response uses standard JSON envelope shape
    - **Property 38:** GET /detections with filters returns only matching events
    - **Validates: Requirements 13.3, 13.8**
    - Annotate `# Feature: netguard-idps, Property 37` and `# Feature: netguard-idps, Property 38`
    - File: `tests/test_properties_api.py`

  - [ ] 21.7 Write unit tests for LogService
    - Test event persistence timing (≤50 ms), log routing (system.log/detections.log/errors.log), async behavior, no secret logging
    - File: `tests/test_logging.py`
    - _Requirements: 14.2, 14.5, 15.1–15.5_

- [ ] 22. Checkpoint — Phase 4 complete
  - Ensure all tests pass, ask the user if questions arise.


---

### Phase 5: Frontend, Dashboard, Charts, Threat Timeline, Evidence Panel

- [ ] 23. Build dark-theme CSS
  - Create `frontend/css/dark-theme.css` with CSS custom properties for the full color palette: `--bg: #0F172A`, `--card-bg: #1E293B`, `--border: #334155`, `--success: #22C55E`, `--warning: #FACC15`, `--danger: #EF4444`, `--critical: #DC2626`, `--info: #3B82F6`
  - Include styles for KPI cards, severity badges (Low/Medium/High/Critical), threat timeline table, evidence panel (expandable inline), active blocks panel, charts container, log viewer, reconnecting status indicator
  - _Requirements: 16.9_

- [ ] 24. Build JavaScript foundation modules
  - [ ] 24.1 Create `frontend/js/socket.js` — Socket.IO connection management with automatic reconnect at 5-second intervals, emit `reconnecting` status indicator on disconnect, emit `monitoring_status` handler
    - _Requirements: 16.8, 16.12_

  - [ ] 24.2 Create `frontend/js/api.js` — fetch wrapper that enforces standard envelope, extracts `data` field on success, throws structured error on `success: false`, handles HTTP 4xx/5xx
    - _Requirements: 13.3, 16.11_

- [ ] 25. Build dashboard page
  - [ ] 25.1 Create `frontend/index.html` — main dashboard HTML skeleton with four KPI card slots, traffic rate chart canvas, severity doughnut chart canvas, threat timeline table, evidence panel div, active blocks panel, whitelist panel, SocketIO script tag, Chart.js script tag
    - _Requirements: 16.1–16.12_

  - [ ] 25.2 Create `frontend/js/dashboard.js` — KPI cards (total packets, active threats, blocked IPs, detection rate), SocketIO listeners for `new_threat`/`ip_blocked`/`ip_unblocked`/`live_stats`/`monitoring_status`, updates all KPI values within 1 s of SocketIO event, fallback polling GET /dashboard/live at 1-second intervals when WebSocket unavailable
    - _Requirements: 16.1, 16.8, 16.10, 16.11_

  - [ ] 25.3 Create `frontend/js/charts.js` — Chart.js initialization for traffic rate line chart (updates every 1 s from `live_stats` event) and severity distribution doughnut chart (updated on each `new_threat` event)
    - _Requirements: 16.2, 16.3_

  - [ ] 25.4 Create `frontend/js/threats.js` — threat timeline table displaying 20 most recent ThreatEvents in reverse-chronological order with columns (timestamp, attack_type, source_ip, severity badge, confidence %); expand inline evidence panel on row click showing full Explanation fields
    - _Requirements: 16.4, 16.5_

- [ ] 26. Build management pages
  - [ ] 26.1 Create `frontend/blocked.html` and `frontend/js/blocked.js` — active blocks table with ip_address, reason, blocked_at, live countdown to expiry, Manual Unblock button that calls POST /api/v1/unblock
    - _Requirements: 16.6_

  - [ ] 26.2 Create `frontend/whitelist.html` and `frontend/js/whitelist.js` — whitelist table with current entries, inline Add IP form with optional description, Remove button per entry; calls GET/POST/DELETE /api/v1/whitelist endpoints
    - _Requirements: 16.7_

  - [ ] 26.3 Create `frontend/threats.html` — full threat list page with column filters (severity, attack_type, source_ip, date) calling GET /api/v1/detections with query params
    - _Requirements: 13.8_

  - [ ] 26.4 Create `frontend/logs.html` and `frontend/js/logs.js` — log viewer with filters (severity, date, module, attack_type, source_ip), paginated entries from GET /api/v1/logs
    - _Requirements: 13.9, 15.6_

  - [ ] 26.5 Create `frontend/rules.html` and `frontend/js/rules.js` — detection rules configuration toggles (enable/disable per rule), threshold displays; reads from GET /api/v1/statistics/rules
    - _Requirements: 9.4_

  - [ ] 26.6 Create `frontend/settings.html` and `frontend/js/settings.js` — settings form for all configurable fields with client-side range validation before submission; calls PUT /api/v1/settings; shows validation errors from HTTP 422 response
    - _Requirements: 1.3, 1.4, 1.5_

  - [ ] 26.7 Create `frontend/about.html` — about page with architecture overview, component descriptions, and link to docs/API.md
    - _Requirements: 16.1_

- [ ] 27. Checkpoint — Phase 5 complete
  - Ensure all tests pass and the dashboard loads correctly in a browser, ask the user if questions arise.


---

### Phase 6: Testing, Bug Fixing, Optimization, Documentation

- [ ] 28. Complete remaining unit test files
  - [ ] 28.1 Write unit tests for `ConfigurationManager`
    - Test load with valid YAML, load with missing file (defaults), load with malformed YAML (defaults + CRITICAL log), validate_settings with in-range and out-of-range values
    - File: `tests/test_config.py`
    - _Requirements: 1.2, 1.3, 1.5, 1.6_

- [ ] 29. Implement integration tests
  - [ ] 29.1 Create `tests/integration/test_integration_capture.py` — end-to-end packet capture on loopback interface; verify packets flow from sniffer → decoder → packet_queue
    - _Requirements: 2.1, 2.3, 3.1_

  - [ ] 29.2 Create `tests/integration/test_integration_block.py` — full flow: ThreatEvent → PreventionEngine → iptables rule applied → blocked_ips record created with all required fields
    - _Requirements: 11.1, 11.2_

  - [ ] 29.3 Create `tests/integration/test_integration_expiry.py` — block with short duration (e.g., 3 s), verify ExpiryThread removes iptables rule and sets active=False within 5 s of expiry
    - _Requirements: 11.3_

  - [ ] 29.4 Create `tests/integration/test_integration_demo.py` — verify each attack demo script triggers a corresponding detection ThreatEvent within the timeout window
    - _Requirements: All detection requirements 4–8_

- [ ] 30. Create demo attack scripts
  - [ ] 30.1 Create `demo/attack_syn.sh` — hping3 SYN flood targeting loopback or specified interface at rate exceeding syn_flood_threshold within syn_flood_window
    - _Requirements: 4.1_

  - [ ] 30.2 Create `demo/attack_scan.sh` — nmap port scan targeting localhost covering at least 80 ports within port_scan_window
    - _Requirements: 5.1_

  - [ ] 30.3 Create `demo/attack_sql.sh` — curl HTTP requests with SQL injection payloads (`' OR`, `UNION SELECT`, `DROP TABLE`, `--`, `xp_cmdshell`) to localhost:80
    - _Requirements: 6.1_

  - [ ] 30.4 Create `demo/attack_bruteforce.sh` — hydra brute force against localhost SSH (port 22) exceeding brute_force_threshold within brute_force_window
    - _Requirements: 7.1_

  - [ ] 30.5 Create `demo/attack_arp.sh` — arpspoof command generating gratuitous ARP replies with conflicting MAC addresses for the gateway IP
    - _Requirements: 8.1_

- [ ] 31. Create setup and startup scripts
  - [ ] 31.1 Create `scripts/setup.sh` — install all requirements.txt dependencies (pip install -r requirements.txt), create all required directories, initialize database via `python database/init_db.py`, verify iptables available
    - _Requirements: 1.1, 14.1_

  - [ ] 31.2 Create `scripts/start_demo.sh` — complete startup script: run setup.sh if needed, start NetGuard backend in background, open browser to http://localhost:5000, wait for all five attack scripts in sequence
    - _Requirements: 1.7_

- [ ] 32. Write documentation
  - [ ] 32.1 Create `README.md` with: project description, architecture diagram (Mermaid), prerequisites (Python 3.11+, iptables, Linux), installation steps, usage instructions, directory structure table
    - _Requirements: 1.1_

  - [ ] 32.2 Create `docs/API.md` — full REST API documentation: all 21 endpoints with method, path, request body schema, response envelope examples, all HTTP status codes and error codes
    - _Requirements: 13.1–13.10_

- [ ] 33. Final checkpoint — all tests pass
  - Ensure all unit tests, property-based tests, and integration tests pass. Run `pytest tests/ --ignore=tests/integration --cov=backend --cov=detection --cov-report=term-missing` and confirm coverage targets are met. Ask the user if questions arise.


---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP delivery
- All implementation language is Python 3.11+ (backend/detection) and vanilla JavaScript ES6 (frontend)
- Each task references specific requirements for traceability
- Checkpoints at phases 1–6 ensure incremental validation before proceeding
- Property-based tests use Hypothesis; each test annotated with `# Feature: netguard-idps, Property N`
- Unit tests use pytest 7+; integration tests require Linux root + iptables
- The design document's Correctness Properties section defines all 40 PBT properties
- No task implements business logic in route handlers; all logic is in the service layer
- Run tests: `pytest tests/ -v --ignore=tests/integration` for unit + property tests
- Run with coverage: `pytest tests/ --ignore=tests/integration --cov=backend --cov=detection --cov-report=term-missing`
- Integration tests (Linux root required): `sudo pytest tests/integration/ -v`


## Task Dependency Graph

```json
{
  "waves": [
    {
      "id": 0,
      "tasks": ["1"]
    },
    {
      "id": 1,
      "tasks": ["2.1", "3.1", "5"]
    },
    {
      "id": 2,
      "tasks": ["2.2", "3.2", "4", "7.1"]
    },
    {
      "id": 3,
      "tasks": ["3.3", "7.2", "7.3", "8.1", "9.1"]
    },
    {
      "id": 4,
      "tasks": ["9.2", "9.5", "9.8", "9.11", "9.14", "13.1", "13.2", "13.3", "13.4", "13.5"]
    },
    {
      "id": 5,
      "tasks": ["9.3", "9.4", "9.6", "9.7", "9.9", "9.10", "9.12", "9.13", "9.15", "9.16", "13.6", "14.1"]
    },
    {
      "id": 6,
      "tasks": ["10.1", "14.2", "14.3"]
    },
    {
      "id": 7,
      "tasks": ["10.2", "10.3", "11.1", "15.1"]
    },
    {
      "id": 8,
      "tasks": ["11.2", "11.3", "15.2", "15.3", "16"]
    },
    {
      "id": 9,
      "tasks": ["18.1", "18.2", "18.3"]
    },
    {
      "id": 10,
      "tasks": ["19.1", "19.2", "19.3", "19.4", "19.5", "19.6", "19.7", "19.8", "19.9", "19.10"]
    },
    {
      "id": 11,
      "tasks": ["20"]
    },
    {
      "id": 12,
      "tasks": ["21.1", "21.2", "21.3", "21.4", "21.5"]
    },
    {
      "id": 13,
      "tasks": ["21.6", "21.7", "23"]
    },
    {
      "id": 14,
      "tasks": ["24.1", "24.2"]
    },
    {
      "id": 15,
      "tasks": ["25.1"]
    },
    {
      "id": 16,
      "tasks": ["25.2", "25.3", "25.4"]
    },
    {
      "id": 17,
      "tasks": ["26.1", "26.2", "26.3", "26.4", "26.5", "26.6", "26.7"]
    },
    {
      "id": 18,
      "tasks": ["28.1"]
    },
    {
      "id": 19,
      "tasks": ["29.1", "29.2", "29.3", "29.4", "30.1", "30.2", "30.3", "30.4", "30.5"]
    },
    {
      "id": 20,
      "tasks": ["31.1", "31.2", "32.1", "32.2"]
    }
  ]
}
```
