# Implementation Plan: Net-Guard Enterprise IDPS

## Overview

Incremental build-out of the enterprise IDPS on top of the existing Flask +
SQLite + Scapy + vanilla-JS stack. Every task targets a concrete file or class
and produces working, integrated code — no hanging code is left unregistered.
Services follow the `PreventionEngine` constructor-injection pattern; all new
tables land in `database/migrate.py`; tests extend the existing `tests/`
structure.

Foundation first: DB migrations → auth/RBAC → core services → routes →
detection extensions → frontend → integrations/compliance.

---

## Tasks

- [x] 1. Database migrations and extended schema
  - [x] 1.1 Write `database/migrate.py` with `ALTER TABLE` / `CREATE TABLE IF NOT EXISTS` statements for all new columns and tables
    - Add columns to `blocked_ips`: `block_type`, `threat_score`, `operator_id`, `audit_entry_id`
    - Add columns to `events`: `ioc_match`, `risk_score`, `mitre_tactic`, `mitre_technique`, `enrichment_status`, `false_positive`
    - Create tables: `scheduled_jobs`, `user_accounts`, `audit_log`, `enrichment_results`, `compliance_reports`, `ioc_store`
    - Call `migrate()` from `database/init_db.py` `initialize_db()` so it runs at every startup
    - _Requirements: 1.1, 1.3, 2.1, 10.1, 13.1, 14.1, 14.5_
  - [x] 1.2 Add ORM model classes for all six new tables to `database/schema.py`
    - `ScheduledJob`, `UserAccount`, `AuditLog`, `EnrichmentResult`, `ComplianceReport`, `IOCStore`
    - Match field names exactly as specified in the design data-model section
    - _Requirements: 2.1, 14.1, 14.5, 10.1, 13.1, 1.3_


- [ ] 2. Authentication service and RBAC middleware
  - [-] 2.1 Implement `backend/services/auth_service.py` (`AuthService`)
    - `login(username, password, totp_code)` → `{access_token, refresh_token}` using `PyJWT` (HS256, 8 h / 30 d expiry)
    - `refresh(refresh_token)` → new access token
    - `create_user(username, password, role)` with password policy enforcement (12 chars, uppercase, digit, punctuation)
    - `validate_token(token)` → decoded payload, raises on invalid/expired
    - TOTP via `pyotp`; password hashing via `werkzeug.security` (already installed)
    - Constructor: `AuthService(settings_repo, audit_service)`; register as `auth_service` in `main.py`
    - _Requirements: 14.1, 14.4, 14.6_
  - [~] 2.2 Write property test for password policy (Property 12)
    - **Property 12: Password policy enforced consistently**
    - **Validates: Requirements 14.6**
    - File: `tests/test_properties_enterprise.py`; use `@given(st.text())` from Hypothesis
  - [~] 2.3 Write property test for JWT gate (Property 13)
    - **Property 13: JWT authentication blocks all non-public endpoints without valid token**
    - **Validates: Requirements 14.1**
    - Iterate all registered Flask URL rules; assert 401 for missing/malformed/expired token on every non-public route
  - [-] 2.4 Implement `backend/middleware/auth_middleware.py`
    - `before_request` hook: read `Authorization: Bearer` header, call `auth_service.validate_token()`, store result in `flask.g.current_user`
    - `@require_role(*roles)` decorator used by route blueprints
    - Return HTTP 401 / 403 with correct error codes; log 403 attempts via `audit_service.log()`
    - _Requirements: 14.1, 14.2, 14.3_
  - [ ] 2.5 Implement `backend/services/audit_service.py` (`AuditService`) and `backend/routes/audit_routes.py` (`audit_bp`)
    - `AuditService.log(username, action, resource_path, detail)` → append-only insert to `audit_log`
    - `GET /api/v1/audit` — paginated, admin-only; no DELETE/UPDATE endpoints
    - Register `audit_service` and `audit_bp` in `main.py`
    - _Requirements: 14.5, 1.3, 14.3_
  - [~] 2.6 Implement `backend/routes/auth_routes.py` (`auth_bp`)
    - `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`, `POST /api/v1/auth/logout`
    - `POST /api/v1/auth/users` (admin only — create user)
    - Register `auth_bp` in `main.py`
    - _Requirements: 14.1, 14.2, 14.4, 14.6_


- [ ] 3. Block Manager — enterprise IP blocking
  - [~] 3.1 Extend `backend/repositories/block_repository.py` with new query methods
    - `get_history(ip, page, per_page)`, `get_by_type(block_type)`, `get_paginated(page, per_page, filters)`
    - Support filtering by IP, type, status, date range (for `GET /api/v1/blocks`)
    - _Requirements: 1.10, 1.12_
  - [~] 3.2 Implement `backend/services/block_manager.py` (`BlockManager`)
    - Constructor: `BlockManager(block_repo, whitelist_manager, log_engine, socketio_emit)` — mirror `PreventionEngine` signature
    - `block(target, target_type, reason, duration, operator, severity, confidence)` — atomically applies iptables rule then inserts DB record; on DB failure rolls back iptables (Req 1.14); delegates IPv6 to `ip6tables` when address family is IPv6
    - `unblock(block_id, operator)`, `restore_on_startup()`, `get_history(ip, page, per_page)`
    - `compute_threat_score(severity, confidence, hit_count)` → `min(100, round(severity/10*40 + confidence*0.30 + min(hit_count,100)*0.30))`
    - Duplicate-block logic: extend expiry instead of inserting second record (Req 1.5)
    - Whitelist rejection: return `WHITELISTED_IP` error code without touching firewall (Req 1.7)
    - `block_type` ∈ `{"ip","cidr","country","asn"}` stored in extended `BlockedIP` column
    - Register as `block_manager` in `main.py`; keep existing `prevention_engine` wired unchanged
    - _Requirements: 1.1, 1.2, 1.4, 1.5, 1.6, 1.7, 1.8, 1.13, 1.14, 1.15_
  - [~] 3.3 Write property test for threat score formula (Property 4)
    - **Property 4: Threat score is bounded and formula-correct**
    - **Validates: Requirements 1.8**
    - File: `tests/test_properties_enterprise.py`; `@given(st.integers(0,10), st.integers(0,100), st.integers(0,10000))`
  - [~] 3.4 Write property test for block atomicity (Property 1)
    - **Property 1: Block atomicity — no partial state on failure**
    - **Validates: Requirements 1.1, 1.14**
    - Mock iptables to fail after DB write; assert DB record absent; mock DB to fail; assert no iptables call
  - [~] 3.5 Write property test for whitelisted-IP rejection (Property 3)
    - **Property 3: Whitelisted IPs are always rejected from blocking**
    - **Validates: Requirements 1.7**
    - `@given(st.ip_addresses())` filtered through a generated whitelist set
  - [~] 3.6 Write property test for duplicate-block expiry extension (Property 2)
    - **Property 2: Duplicate block extends expiry, never duplicates**
    - **Validates: Requirements 1.5**
  - [~] 3.7 Implement `backend/routes/blocks_v2_routes.py` (`blocks_v2_bp`)
    - `POST /api/v1/blocks`, `DELETE /api/v1/blocks/{id}`, `GET /api/v1/blocks`, `GET /api/v1/blocks/{id}`, `GET /api/v1/blocks/{ip}/history`
    - Confirmation dialog data returned in POST response for UI (Req 1.11)
    - Register `blocks_v2_bp` in `main.py`
    - _Requirements: 1.10, 1.11, 1.12_


- [ ] 4. Threat Simulator
  - [~] 4.1 Implement `backend/services/threat_simulator.py` (`ThreatSimulator`)
    - `generate_profile(source_category=None)` → dict with `ip, country, asn, isp, lat, lon, city, actor_name, risk_score, reputation_score, malware_family, campaign_name`
    - `generate_session(count, source_category=None)` → list of profiles, each IP unique within the session
    - IP generation: use `ipaddress` stdlib; exclude RFC 1918, loopback, link-local, multicast
    - Source categories (Req 4.4): embedded CIDR datasets for AWS/Azure/GCP/DO/OVH/Hetzner/Oracle/Tencent/Alibaba, TOR exit nodes, botnet ranges, VPN egress, residential proxy, compromised servers, CDN edge
    - Whitelist guard: up to 10 retries per slot; emit `whitelist_exhaustion` warning event on exhaustion (Req 4.7)
    - `generate_session` exposes profiles via the `new_threat` WebSocket payload format
    - Register as `threat_simulator` in `main.py`
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7_
  - [~] 4.2 Write property test for public-IP exclusion (Property 5)
    - **Property 5: Simulator generates only public routable IPs**
    - **Validates: Requirements 4.2**
    - `@given(st.sampled_from([None,"aws","tor","botnet",...]))` — call `generate_profile()`, assert not private/loopback/link-local/multicast
  - [~] 4.3 Write property test for whitelist non-injection (Property 6)
    - **Property 6: Simulator never injects whitelisted IPs**
    - **Validates: Requirements 4.7**


- [ ] 5. GeoIP Engine
  - [~] 5.1 Implement `backend/services/geoip_engine.py` (`GeoIPEngine`)
    - `resolve(ip)` → `{ip, country, lat, lon, city, asn, isp}` or `GeoIPError`
    - Provider chain: MaxMind GeoLite2 (`geoip2`) → ip-api.com → IPinfo; chain configurable via `settings_repo` key `geoip.provider_chain`
    - LRU cache via `functools.lru_cache` (stdlib) wrapping internal `_resolve_uncached()`; cap 10 000 entries; TTL 24 h via parallel `_cache_times` dict with lazy eviction on access
    - `set_provider(provider)` re-configures chain at runtime without restart
    - On full-chain failure: return `GeoIPError(ip, code, timestamp)` — never raise to caller
    - Register as `geoip_engine` in `main.py`
    - _Requirements: 5.1, 5.2, 5.8, 5.9_
  - [~] 5.2 Write property test for GeoIP cache deduplication (Property 7)
    - **Property 7: GeoIP cache prevents redundant API calls**
    - **Validates: Requirements 5.9**
    - `@given(st.lists(st.ip_addresses(), min_size=2))` with repeated IPs; assert external call count == distinct IP count
  - [~] 5.3 Implement `backend/routes/map_routes.py` (`map_bp`)
    - `GET /api/v1/map/resolve?ip=...` — single IP resolution
    - `GET /api/v1/map/events` — recent events with geo coordinates for map initialisation
    - Register `map_bp` in `main.py`
    - _Requirements: 5.1, 5.8_


- [~] 6. Checkpoint — foundation services integrated
  - Ensure all tests pass, ask the user if questions arise.
  - Verify `GET /api/v1/health` returns HTTP 200 with auth middleware applied.
  - Verify DB migration runs cleanly on a fresh `database/netguard.db`.

- [ ] 7. Anomaly Engine (AI detection)
  - [~] 7.1 Implement `backend/services/anomaly_engine.py` (`AnomalyEngine`)
    - Per-IP rolling stats using Welford online algorithm; 5-minute sliding window (`baseline_window_seconds=300`)
    - `ingest(ip, pps, conn_freq, entropy)` → `AnomalyEvent | None`; flag when `|v - mean| > 3 * std`
    - `is_warming_up()` → `True` if less than 5 minutes of data; suppress flagging and emit `baseline_warming_up` log during warm-up
    - `calibration_data()` → per-IP mean, std, window start, warm-up status
    - `override_calibration(ip, values)` → replace stored baseline, tag as manually overridden
    - Register as `anomaly_engine` in `main.py`; wire into `_on_threat_event` callback
    - _Requirements: 9.1, 9.8_
  - [~] 7.2 Write property test for anomaly threshold (Property 8)
    - **Property 8: Anomaly detection fires iff deviation exceeds threshold**
    - **Validates: Requirements 9.1**
    - `@given(st.lists(st.floats(0,1000), min_size=30), st.floats(0,2000))` — feed baseline samples then probe; assert flag iff `|v-mean|>3*std`; assert no flag during warm-up
  - [~] 7.3 Implement `backend/routes/ai_routes.py` (`ai_bp`)
    - `GET /api/v1/ai/calibration`, `PUT /api/v1/ai/calibration`
    - Register `ai_bp` in `main.py`
    - _Requirements: 9.8_


- [ ] 8. Threat Intel Service & enrichment
  - [~] 8.1 Implement `backend/services/threat_intel_service.py` (`ThreatIntelService`)
    - Constructor: `ThreatIntelService(event_repo, settings_repo, log_engine)`
    - `enqueue_enrichment(event_id, source_ip)` → push to `threading.Queue`; background worker thread calls VirusTotal/AbuseIPDB/Shodan/Censys via `requests` (already installed); update `EnrichmentResult` row and `Event.enrichment_status`; on all-sources failure mark `enrichment_failed` and log (Req 10.1)
    - `compute_risk_score(severity, reputation, ioc_match, recurrence)` → `min(100, round(severity*40 + reputation*0.30 + ioc_match*20 + min(recurrence,10)*1.0))`
    - `hunt(ioc_value, page, per_page)` → combined events/blocks/enrichment for an IOC (Req 10.6)
    - `feedback(event_id, is_false_positive, operator)` — persist feedback; decrease confidence for matching rule+subnet /24 by configurable step (default 5, floor 1) (Req 10.5)
    - IOC correlation: compare source IP, domain, file hash against `ioc_store`; set `Event.ioc_match` and `ioc_identifiers` (Req 10.2)
    - Register as `threat_intel_service` in `main.py`; call `enqueue_enrichment` from `_on_threat_event` callback
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6_
  - [~] 8.2 Write property test for composite risk score (Property 9)
    - **Property 9: Composite risk score is bounded and weights sum to 100%**
    - **Validates: Requirements 10.3**
    - `@given(st.floats(0,1), st.floats(0,100), st.booleans(), st.integers(0,1000))`
  - [~] 8.3 Implement `backend/routes/hunt_routes.py` (`hunt_bp`)
    - `GET /api/v1/hunt?ioc={value}`, `POST /api/v1/events/{id}/feedback`
    - Register `hunt_bp` in `main.py`
    - _Requirements: 10.5, 10.6_


- [ ] 9. SOAR Engine & external alerting
  - [~] 9.1 Implement `backend/services/soar_engine.py` (`SOAREngine`)
    - Constructor: `SOAREngine(settings_repo, log_engine, socketio_emit, geoip_engine)`
    - `trigger(event, enrichment)` → iterate enabled channels; per-channel severity threshold gate (Req 15.3)
    - Channels: Email (`smtplib` stdlib), Slack webhook, Discord webhook, Telegram Bot API, generic HTTP webhook, Syslog (`logging.handlers.SysLogHandler` stdlib) — all via `requests` or stdlib only
    - Retry loop: up to 3 attempts with `time.sleep(2**attempt)` backoff; on exhaustion mark channel `degraded` in `settings_repo` and emit `channel_degraded` WebSocket event (Req 15.5)
    - Notification body: attack type, source IP, GeoIP country, severity, confidence, timestamp, event detail link (Req 15.4)
    - `test_integration(channel)` → send synthetic event, return target's HTTP status and body within 15 s (Req 15.7)
    - SIEM forwarding: ECS JSON over HTTPS, Splunk HEC, Wazuh TCP socket, OpenSearch Bulk API — each independently selectable (Req 15.6)
    - Register as `soar_engine` in `main.py`; call `trigger` from `_on_threat_event` callback
    - _Requirements: 9.6, 9.7, 15.1, 15.2, 15.3, 15.4, 15.5, 15.6, 15.7_
  - [~] 9.2 Write property test for per-channel severity gating (Property 14)
    - **Property 14: Per-channel severity threshold correctly gates notifications**
    - **Validates: Requirements 15.3**
    - `@given(st.sampled_from(["Low","Medium","High","Critical"]), st.sampled_from(["Low","Medium","High","Critical"]))` — assert dispatch iff `severity_order[event] >= severity_order[threshold]`
  - [~] 9.3 Implement SIEM integration routes in `backend/routes/settings_routes.py` (extend existing file)
    - `POST /api/v1/settings/integrations/test` — delegates to `soar_engine.test_integration()`
    - _Requirements: 15.7_


- [ ] 10. Attack Scheduler
  - [~] 10.1 Implement `backend/services/scheduler_service.py` (`SchedulerService`)
    - Wrap `APScheduler` `BackgroundScheduler` with `SQLAlchemyJobStore` on existing engine
    - `create_job(config)`: validate target datetime (reject past), attack type, cron/interval rule (Req 2.1); mirror to `ScheduledJob` ORM row; concurrency cap via `threading.Semaphore(10)` (Req 2.8)
    - `create_batch(configs)`: reject if `len > 50` with `BATCH_LIMIT_EXCEEDED` (Req 2.6); sets `campaign_id` on all jobs
    - `cancel_job(job_id)`: mark `CANCELLED`, stop in-progress within 1 s, return `False` if not found (Req 2.10)
    - `list_jobs(page, per_page, status, attack_type)` → paginated (max 100)
    - On job execution: mark `RUNNING`, call `attack_lab_service.launch()`, then `DONE` or `FAILED`; on failure emit notification event (Req 2.9)
    - On startup: skip past occurrences, log at INFO, schedule only next future occurrence (Req 2.4)
    - `_schedule_next(job_id)`: create next occurrence respecting recurrence rule, cap at 365 total occurrences (Req 2.5)
    - Register as `scheduler_service` in `main.py`; start scheduler in `if __name__ == "__main__"` block
    - _Requirements: 2.1, 2.2, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10_
  - [~] 10.2 Implement `backend/routes/scheduler_routes.py` (`scheduler_bp`)
    - `POST /api/v1/scheduler/jobs`, `POST /api/v1/scheduler/jobs/batch`, `GET /api/v1/scheduler/jobs`, `DELETE /api/v1/scheduler/jobs/{id}`
    - Register `scheduler_bp` in `main.py`
    - _Requirements: 2.1, 2.6, 2.7, 2.10_


- [ ] 11. Attack Lab Service
  - [~] 11.1 Implement `backend/services/attack_lab_service.py` (`AttackLabService`)
    - `ATTACK_TYPES`: full list of 17 types from Req 3.2 as a class attribute
    - `launch(config, operator)` → `session_id`; config includes difficulty, duration, pps, concurrent attackers, payload template, MITRE mapping; validate concurrency limit (Req 3.9); confirm config before executing (Req 3.4)
    - Each session runs in a daemon thread pushing synthetic Scapy packets directly into existing `packet_queue`; uses `ThreatSimulator.generate_session()` for attacker profiles
    - Session status: `PENDING → DETECTED / BLOCKED / MISSED / CANCELLED`; updated via event callback from `DetectionEngine`
    - `cancel(session_id)` → stop packet generation within 1 s, set status `CANCELLED` (Req 3.8)
    - `status(session_id)` → `{elapsed, packets_sent, detection_status, detection_latency_ms, mitre_coverage}`
    - `list_active()` → all running sessions
    - Register as `attack_lab_service` in `main.py`
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9_
  - [~] 11.2 Implement `backend/routes/lab_routes.py` (`lab_bp`)
    - `GET /api/v1/lab/attacks` (list available types), `POST /api/v1/lab/sessions`, `DELETE /api/v1/lab/sessions/{id}`, `GET /api/v1/lab/sessions/{id}`
    - Register `lab_bp` in `main.py`
    - _Requirements: 3.1, 3.2, 3.5, 3.6, 3.8, 3.9_


- [~] 12. Checkpoint — all backend services wired
  - Ensure all tests pass, ask the user if questions arise.
  - Smoke: `GET /api/v1/lab/attacks` returns the 17 attack types.
  - Smoke: `POST /api/v1/auth/login` with seeded admin credentials returns tokens.

- [ ] 13. Detection Engine extensions — Sigma, YARA, MITRE annotations, PacketDecoder hardening
  - [~] 13.1 Add Sigma rule loading to `backend/services/detection_service.py`
    - Load Sigma YAML files from configurable directory (`settings_repo` key `ai.sigma_rules_dir`)
    - Convert to internal rule objects at startup using `pySigma`; hot-reload via `watchdog` observer (Req 9.3)
    - On parse failure: skip file, log error with filename + line number, continue (Req 9.3)
    - _Requirements: 9.3_
  - [~] 13.2 Add YARA rule loading and evaluation to `backend/services/detection_service.py`
    - Load YARA rules from configurable directory (`settings_repo` key `ai.yara_rules_dir`)
    - Evaluate against HTTP payload bytes captured by `detection/parsers/packet_decoder.py` (Req 9.4)
    - On compile failure: skip file, log error, continue (Req 9.4)
    - _Requirements: 9.4_
  - [~] 13.3 Add MITRE ATT&CK tactic/technique annotation to `DetectionEngine`
    - Populate `Event.mitre_tactic` and `Event.mitre_technique` for every detected event (Req 9.8)
    - Extend `ThreatEvent` dataclass with `mitre_tactic` and `mitre_technique` fields
    - _Requirements: 9.8_
  - [~] 13.4 Harden `detection/parsers/packet_decoder.py` `decode()` method
    - Wrap all parsing logic in a blanket `try/except Exception`; return `None` on any error; never raise to caller (Req 12.4)
    - _Requirements: 12.4_
  - [~] 13.5 Write property test for PacketDecoder fuzz robustness (Property 10)
    - **Property 10: PacketDecoder never propagates unhandled exceptions**
    - **Validates: Requirements 12.4**
    - `@given(st.binary())` — assert `decode(data)` is either a valid object or `None`, never raises
  - [~] 13.6 Add Suricata export endpoint to `backend/routes/detection_routes.py` (extend existing file)
    - `GET /api/v1/rules/export?format=suricata` — convert active rules to Suricata syntax; return `[]` with HTTP 200 if no active rules (Req 9.5)
    - _Requirements: 9.5_
  - [~] 13.7 Add thread pool to `DetectionEngine` for parallel rule evaluation
    - Configurable worker count via `settings_repo` key `performance.rule_workers` (default 4, min 1, max 32) (Req 11.1)
    - _Requirements: 11.1_


- [ ] 14. ConfigurationManager hardening and enterprise settings
  - [~] 14.1 Harden `backend/services/config_service.py` `ConfigurationManager.load()` and `update()`
    - Wrap all dict access in `try/except`; raise only `ValueError` for invalid ranges; never let any other exception propagate (Req 12.4)
    - _Requirements: 12.4_
  - [~] 14.2 Write property test for ConfigurationManager fuzz robustness (Property 11)
    - **Property 11: ConfigurationManager never propagates unhandled exceptions**
    - **Validates: Requirements 12.4**
    - `@given(st.dictionaries(st.text(), st.one_of(st.none(), st.text(), st.integers(), st.booleans())))` — assert only `ValueError` or valid `Settings` returned
  - [~] 14.3 Extend enterprise settings sections in `backend/routes/settings_routes.py` (extend existing file)
    - Ensure all 29 setting sections from Req 6.1 are served as namespaced keys
    - RBAC enforcement: admin-only write for Security/Firewall/AI/Roles/Licensing sections; HTTP 403 + audit log on violation (Req 6.5)
    - `PUT /api/v1/settings` applies within 2 s; mark restart-required keys in response (Req 6.2)
    - Persist all settings to DB; YAML acts only as initial seed (Req 6.3)
    - API key masking: last 4 chars visible, rest masked; `POST /api/v1/settings/apikeys/rotate` returns new key exactly once (Req 6.9)
    - _Requirements: 6.1, 6.2, 6.3, 6.5, 6.9_


- [ ] 15. Compliance Reporter and Plugin Registry
  - [~] 15.1 Implement `backend/services/compliance_reporter.py` (`ComplianceReporter`)
    - `SUPPORTED_FRAMEWORKS = ["nist_csf","cis_v8","iso27001","mitre_attack"]`
    - `generate(framework)` → dict with framework name, assessment date, total controls, % compliant (1 decimal), per-control findings (Pass/Fail/Partial + evidence reference)
    - `to_pdf(report)` → bytes using `reportlab` (lazy import with `importlib` — only pulled in when called) (Req 13.2)
    - `to_json(report)` → dict; cache in `ComplianceReport` table; `regenerate=True` bypasses cache
    - On unrecognised framework: raise `ValueError` with list of supported names → HTTP 400 at route layer
    - Register as `compliance_reporter` in `main.py`
    - _Requirements: 13.1, 13.2, 13.4_
  - [~] 15.2 Implement `backend/routes/reports_routes.py` (`reports_bp`)
    - `GET /api/v1/reports/compliance?framework={name}&regenerate={bool}` (Req 13.4)
    - Serve PDF via `Content-Type: application/pdf` when `format=pdf` query param present
    - Register `reports_bp` in `main.py`
    - _Requirements: 13.1, 13.2, 13.4_
  - [~] 15.3 Implement `backend/services/plugin_registry.py` (`PluginRegistry`) and `backend/routes/plugins_routes.py` (`plugins_bp`)
    - `discover()`, `enable(name)`, `disable(name)`, `load(name)` — use `importlib`; plugins in `plugins/` directory expose `PLUGIN_META` dict and `register(app)` function
    - `GET /api/v1/plugins` — name, version, description, enabled status (Req 6.8)
    - Create `plugins/example_widget/` as the one example plugin (Req 13.6)
    - Register `plugin_registry` and `plugins_bp` in `main.py`
    - _Requirements: 6.8, 13.6_


- [ ] 16. Backup/Restore, DevSecOps artefacts, and performance
  - [~] 16.1 Implement backup/restore in `backend/routes/settings_routes.py` (extend existing file)
    - Backup: export settings + rules + block history + whitelist to a single password-protected archive; complete within 60 s for ≤1 GB (Req 6.6)
    - Restore: compute SHA-256 of uploaded archive, compare against embedded checksum file; present conflict list; require confirmation before committing (Req 6.7, 12.6); reject with `CHECKSUM_MISMATCH` on mismatch
    - _Requirements: 6.6, 6.7, 12.6_
  - [~] 16.2 Write `scripts/backup.sh`
    - Dump SQLite via `.dump`, compress with `gzip`, write SHA-256 checksum file alongside; exit code 1 on failure (Req 12.5)
    - _Requirements: 12.5_
  - [~] 16.3 Add Redis Streams publishing to `DetectionEngine`
    - When Redis is reachable, publish `ThreatEvent` to `netguard:events` stream in addition to in-process queue; on Redis unavailable log `redis_unavailable` warning and fall back (Req 11.3)
    - Shared Redis cache for GeoIP (TTL 24 h), enrichment (TTL 1 h), live stats (TTL 2 s); fall back to direct computation when Redis unavailable (Req 11.5)
    - _Requirements: 11.3, 11.5_
  - [~] 16.4 Wire queue-pressure warning into `DetectionEngine`
    - When `packet_queue.qsize() >= 8000`, emit `queue_pressure` WebSocket event and log at WARNING (Req 11.6)
    - _Requirements: 11.6_
  - [~] 16.5 Write `Dockerfile` and `docker-compose.yml`
    - `Dockerfile`: non-root user UID ≥ 1000, `python:3.12-slim` base, no secrets in layers, `HEALTHCHECK` every 30 s calling `GET /api/v1/health` with 10 s timeout (Req 12.1)
    - `docker-compose.yml`: backend + Redis + nginx reverse-proxy; starts with `docker compose up` — no manual pre-config (Req 11.2)
    - _Requirements: 11.2, 12.1_
  - [~] 16.6 Add TLS termination to Flask startup in `backend/main.py`
    - When `TLS_CERT_FILE` and `TLS_KEY_FILE` env vars are set, pass `ssl_context` to `socketio.run()` with minimum TLS 1.2 (Req 11.8)
    - _Requirements: 11.8_
  - [~] 16.7 Add rate limiting per authenticated user (extend `backend/middleware/rate_limiter.py`)
    - 300 req/min per user; HTTP 429 + `Retry-After` header on breach (Req 11.4)
    - _Requirements: 11.4_


- [~] 17. Checkpoint — all backend complete, full test suite green
  - Ensure all tests pass, ask the user if questions arise.
  - Smoke: `GET /api/v1/plugins` returns list.
  - Smoke: `GET /api/v1/reports/compliance?framework=unsupported` returns HTTP 400 with framework list.

- [ ] 18. Frontend — UI/UX redesign and new pages
  - [~] 18.1 Create design token stylesheet `frontend/css/tokens.css` and update `frontend/css/` main stylesheet
    - Glassmorphism design system: CSS custom properties for colour palette, typography scale, 8-point spacing grid, border-radius, shadow levels, dark/light themes
    - Dark/Light toggle: switch themes within 200 ms, no page reload; persist selection in `localStorage`; wire toggle to existing settings endpoint (Req 6.4, 8.10)
    - Logo `frontend/images/logooo.jpeg` displayed in header and login page (Req 8.1)
    - CSS transitions 150–300 ms `ease-out` for all interactive state changes (Req 8.4)
    - _Requirements: 8.1, 8.4, 8.10, 6.4_
  - [~] 18.2 Create `frontend/login.html` and wire `frontend/js/auth.js`
    - Login form: username, password, optional TOTP field; calls `POST /api/v1/auth/login`; stores tokens in `sessionStorage` (not `localStorage`); redirects to `index.html` on success
    - _Requirements: 14.1, 14.4_
  - [~] 18.3 Redesign `frontend/index.html` as the SOC Dashboard
    - Role-based dashboard views: Executive, SOC Analyst, Threat Hunter, Customer — sections shown/hidden per `current_user.role` from JWT (Req 13.3)
    - Data visualisations: real-time line chart (traffic rate), donut chart (severity), heatmap grid (hourly/daily attack frequency), network graph (lateral movement), attack timeline with MITRE ATT&CK swim lanes, threat score gauge (Req 8.8)
    - Skeleton placeholders → real content within 5 s of fetch (Req 8.3)
    - Resizable panels (drag dividers) and dockable widgets; layout persisted in `localStorage` with fallback to default (Req 8.7)
    - `Ctrl+K` command palette; `Tab`/`Enter`/`Space` keyboard navigation; modal focus trap (Req 8.6, 8.9)
    - _Requirements: 8.2, 8.3, 8.6, 8.7, 8.8, 8.9, 13.3_
  - [~] 18.4 Create `frontend/map.html` and `frontend/js/map.js` (World Map)
    - Render attacks on a globe/map using GeoIP coordinates from `GET /api/v1/map/events` + WebSocket `new_threat` events
    - Pulse animation within 500 ms of receiving event (Req 5.3); connection lines colour-coded by risk score (Req 5.4)
    - Heatmap clustering mode (Req 5.5); zoom/pan/country filter (Req 5.6)
    - Timeline replay control: scrubber for 24 h window, 1×/5×/10× speeds (Req 5.7)
    - Unknown-location events shown at (0.0°, 0.0°) marker (Req 5.8)
    - HQ coordinates read from `settings_manager` via existing settings endpoint (Req 5.4)
    - _Requirements: 5.3, 5.4, 5.5, 5.6, 5.7, 5.8_
  - [~] 18.5 Create `frontend/lab.html` and `frontend/js/lab.js` (Attack Lab)
    - Attack type picker; configuration panel (difficulty, duration, pps, concurrency, payload template, MITRE mapping) (Req 3.3)
    - Real-time progress indicator: elapsed time, packets sent, detection status (Req 3.5); countdown timer for scheduled attacks (Req 2.3)
    - Post-simulation summary report: detected/missed, detection latency ms, MITRE tactics covered (Req 3.6)
    - Concurrency-limit error message when limit reached (Req 3.9)
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.8, 3.9, 2.3_
  - [~] 18.6 Enhance `frontend/logs.html` as the enterprise Log Viewer
    - Resizable modal defaulting to 70% viewport, draggable to full-screen (Req 7.1)
    - Search field with 200 ms debounce, highlighting, match count (Req 7.2)
    - Filter bar: severity, module, date range, MITRE tactic, CVE ID; AND logic; combined match count (Req 7.3)
    - Export selected entries as JSON or CSV; Export button disabled with tooltip when none selected (Req 7.4)
    - Mini-timeline above log list: event density buckets (10–120); click to scroll (Req 7.5)
    - Severity badges, MITRE badges, CVE badges, IOC badges on each row (Req 7.6)
    - Pin up to 10 entries to sticky section; reject 11th with error message (Req 7.7)
    - ESC closes modal; `Ctrl+F` focuses search; `Ctrl+A` selects all visible (Req 7.8, 7.9)
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.9_


- [~] 19. Final checkpoint — full stack end-to-end
  - Ensure all tests pass, ask the user if questions arise.
  - Smoke: launch a Port Scan simulation from the Attack Lab UI; verify detection event appears in Log Viewer with MITRE annotation and GeoIP coordinates on the map.
  - WCAG 2.1 AA: run `axe-core` against `index.html` and `login.html` in headless browser.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP; all 14 Hypothesis PBT tasks are marked optional per workflow rules but are **strongly recommended** — they validate pure functions with zero infrastructure overhead
- Property test file: all property tests in `tests/test_properties_enterprise.py`; tag format `# Feature: net-guard-enterprise-idps, Property N: <text>`
- Ponytail constraint throughout: no new framework, no unnecessary abstraction; reuse `PreventionEngine` pattern, `requests` (already installed), `smtplib`/`logging.handlers`/`functools.lru_cache` (stdlib), `werkzeug.security` (Flask dep)
- New dependencies (pinned versions required in `requirements.txt`): `APScheduler`, `PyJWT`, `pyotp`, `geoip2`, `yara-python`, `pySigma`, `watchdog`, `reportlab`, `redis` (optional)
- All migrations go through `database/migrate.py` called from `init_db.py`; no Alembic
- `block_manager` complements (does not replace) `prevention_engine`; existing auto-block flow remains unchanged
- Settings persisted as namespaced DB keys (`appearance.theme`, `ai.sigma_rules_dir`, etc.); YAML is seed-only


## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2"] },
    { "id": 1, "tasks": ["2.1", "2.4", "2.5"] },
    { "id": 2, "tasks": ["2.2", "2.3", "2.6", "3.1", "4.1", "5.1"] },
    { "id": 3, "tasks": ["3.2", "4.2", "4.3", "5.2", "5.3"] },
    { "id": 4, "tasks": ["3.3", "3.4", "3.5", "3.6", "3.7", "7.1", "8.1"] },
    { "id": 5, "tasks": ["7.2", "7.3", "8.2", "8.3", "9.1", "10.1"] },
    { "id": 6, "tasks": ["9.2", "9.3", "10.2", "11.1", "13.1", "13.2", "13.3", "13.4", "14.1", "15.1"] },
    { "id": 7, "tasks": ["11.2", "13.5", "13.6", "13.7", "14.2", "14.3", "15.2", "15.3"] },
    { "id": 8, "tasks": ["16.1", "16.2", "16.3", "16.4", "16.5", "16.6", "16.7"] },
    { "id": 9, "tasks": ["18.1", "18.2"] },
    { "id": 10, "tasks": ["18.3", "18.4", "18.5", "18.6"] }
  ]
}
```
