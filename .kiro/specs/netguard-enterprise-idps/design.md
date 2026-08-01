# Design Document — Net-Guard Enterprise IDPS

## Overview

Net-Guard Enterprise IDPS extends the existing Flask + SQLite + Scapy + vanilla-JS
stack into a commercial-grade AI-powered Intrusion Detection and Prevention System.
The design follows the **ponytail constraint** throughout: every new capability reuses
the existing service/repository/route/Blueprint patterns, no new frameworks are
introduced unless strictly required, and the smallest working diff is preferred over
abstraction for its own sake.

The 15 requirement areas map to a set of new and extended services, each following
the same constructor-injection pattern as `PreventionEngine`, registered via
`dependencies.register()` in `main.py` and accessed in routes through
`dependencies.get()`.

### Research Findings

**JWT / Auth**: `PyJWT` is already a common Flask companion; TOTP is covered by
`pyotp`. Both are small, pinned-version installs with no heavy transitive deps.

**GeoIP**: MaxMind GeoLite2 via `geoip2` library (offline DB, no API cost);
ip-api.com as free online fallback (no key required for low volume);
IPinfo as the premium fallback. LRU cache via `functools.lru_cache` (stdlib).

**Property-based testing**: `hypothesis` is already installed (`.hypothesis/`
directory exists in the repo with many saved examples).

**Redis**: `redis-py` for optional queue/cache layer; falls back to in-process
queue when Redis is unreachable. Not a hard dependency for basic operation.

**Scheduling**: `APScheduler` is the lightest correct choice — cron + interval +
one-shot, persists jobs to SQLite via existing engine. No new heavy dep.

**SOAR notifications**: `smtplib` (stdlib), `requests` (already installed for
AI services) for Slack/Discord/Telegram/webhook. No new deps required.

**PDF reports**: `reportlab` for compliance PDFs; only pulled in when compliance
reporting endpoint is called (lazy import).

**YARA**: `yara-python` for YARA rule evaluation against HTTP payloads.

**Sigma**: `sigma-cli` / `pySigma` converts Sigma YAML to internal rule dicts;
hot-reload via `watchdog` file-system observer.

---

## Architecture

The architecture is layered and additive — no existing layers are removed.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Vanilla-JS Frontend                              │
│  SOC Dashboard · Attack Lab · Log Viewer · World Map · Settings · Auth  │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │ HTTP REST + WebSocket (SocketIO)
┌────────────────────────────────▼────────────────────────────────────────┐
│                      Flask API Gateway (Blueprint routes)               │
│  Rate limiter · JWT auth middleware · RBAC middleware · Security headers│
└──────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┘
       │          │          │          │          │          │
  BlockMgr   Scheduler  AttackLab  GeoIP/Map  Settings  Auth/RBAC
  Service    Service    Service    Service    Service   Service
       │          │          │          │          │          │
       └──────────┴──────────┴────┬─────┴──────────┘          │
                                  │                            │
┌─────────────────────────────────▼────────────────────────────▼──────────┐
│                     Core Detection Pipeline (unchanged)                 │
│  CaptureEngine → packet_queue → DetectionEngine → on_event callback     │
│            + AI_Engine (anomaly/behaviour analytics layer)              │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────────┐
│                     Persistence & Integration Layer                     │
│  SQLite (PostgreSQL path) · Redis (optional) · External SIEMs/Notifiers │
└─────────────────────────────────────────────────────────────────────────┘
```

### New Services (all follow PreventionEngine constructor-injection pattern)

| Service | File | Registers as |
|---|---|---|
| `BlockManager` | `services/block_manager.py` | `block_manager` |
| `SchedulerService` | `services/scheduler_service.py` | `scheduler_service` |
| `AttackLabService` | `services/attack_lab_service.py` | `attack_lab_service` |
| `ThreatSimulator` | `services/threat_simulator.py` | `threat_simulator` |
| `GeoIPEngine` | `services/geoip_engine.py` | `geoip_engine` |
| `AnomalyEngine` | `services/anomaly_engine.py` | `anomaly_engine` |
| `ThreatIntelService` | `services/threat_intel_service.py` | `threat_intel_service` |
| `SOAREngine` | `services/soar_engine.py` | `soar_engine` |
| `ComplianceReporter` | `services/compliance_reporter.py` | `compliance_reporter` |
| `AuthService` | `services/auth_service.py` | `auth_service` |
| `AuditService` | `services/audit_service.py` | `audit_service` |
| `PluginRegistry` | `services/plugin_registry.py` | `plugin_registry` |

### New Route Blueprints

| Blueprint | File | URL prefix |
|---|---|---|
| `auth_bp` | `routes/auth_routes.py` | `/api/v1/auth` |
| `blocks_v2_bp` | `routes/blocks_v2_routes.py` | `/api/v1/blocks` |
| `scheduler_bp` | `routes/scheduler_routes.py` | `/api/v1/scheduler` |
| `lab_bp` | `routes/lab_routes.py` | `/api/v1/lab` |
| `map_bp` | `routes/map_routes.py` | `/api/v1/map` |
| `hunt_bp` | `routes/hunt_routes.py` | `/api/v1/hunt` |
| `ai_bp` | `routes/ai_routes.py` | `/api/v1/ai` |
| `reports_bp` | `routes/reports_routes.py` | `/api/v1/reports` |
| `audit_bp` | `routes/audit_routes.py` | `/api/v1/audit` |
| `plugins_bp` | `routes/plugins_routes.py` | `/api/v1/plugins` |

---

## Components and Interfaces

### 1. Block Manager (`block_manager.py`)

Extends `PreventionEngine` responsibilities with: CIDR/country/ASN block targets,
threat score computation, per-IP history, `ip6tables` support, and atomic
rollback on partial failure. The existing `BlockRepository` is extended with new
query methods; the existing `BlockedIP` schema model gains new columns.

```python
class BlockManager:
    def __init__(self, block_repo, whitelist_manager, log_engine, socketio_emit): ...
    def block(self, target: str, target_type: str, reason: str,
              duration: int, operator: str, severity: int,
              confidence: int) -> dict: ...
    def unblock(self, block_id: int, operator: str) -> bool: ...
    def restore_on_startup(self) -> None: ...
    def compute_threat_score(self, severity: int, confidence: int,
                             hit_count: int) -> int: ...
    def get_history(self, ip: str, page: int, per_page: int) -> list: ...
```

**Threat score formula** (Req 1.8):
`score = min(100, round(severity/10 * 40 + confidence * 0.30 + min(hit_count, 100) * 0.30))`

`target_type` ∈ `{"ip", "cidr", "country", "asn"}` — stored as new `block_type`
column on `BlockedIP`.

### 2. Scheduler Service (`scheduler_service.py`)

Wraps `APScheduler` (BackgroundScheduler, SQLAlchemyJobStore on existing engine).
Job records are also mirrored to a new `ScheduledJob` ORM table for API queries.

```python
class SchedulerService:
    def __init__(self, attack_lab_service, log_engine, socketio_emit): ...
    def create_job(self, config: dict) -> dict: ...          # Req 2.1
    def cancel_job(self, job_id: str) -> bool: ...           # Req 2.10
    def list_jobs(self, page, per_page, status, attack_type) -> dict: ...
    def _execute_job(self, job_id: str) -> None: ...         # Req 2.2
    def _schedule_next(self, job_id: str) -> None: ...       # Req 2.5
```

Concurrency cap (Req 2.8): a `threading.Semaphore(10)` guards `_execute_job`.
Batch scheduling (Req 2.6): `create_batch(configs: list)` — rejects if
`len(configs) > 50`.

### 3. Attack Lab Service (`attack_lab_service.py`)

Manages simulated attack sessions. Each session runs in a daemon thread, pushing
synthetic packets (built with Scapy) directly into `packet_queue` to exercise
the real detection pipeline.

```python
class AttackLabService:
    ATTACK_TYPES: list[str]                                  # Req 3.2
    def launch(self, config: dict, operator: str) -> str: ... # returns session_id
    def cancel(self, session_id: str) -> bool: ...
    def status(self, session_id: str) -> dict: ...
    def list_active(self) -> list[dict]: ...
```

### 4. Threat Simulator (`threat_simulator.py`)

Pure-Python profile generator. No network calls — all data is generated from
embedded CIDR range datasets and seeded `random` / `faker` values.

```python
class ThreatSimulator:
    def generate_profile(self, source_category: str | None = None) -> dict: ...
    # Returns: {ip, country, asn, isp, lat, lon, city,
    #           actor_name, risk_score, reputation_score,
    #           malware_family, campaign_name}
    def generate_session(self, count: int,
                         source_category: str | None = None) -> list[dict]: ...
```

RFC 1918 / reserved range exclusion uses `ipaddress` stdlib — no new dep.

### 5. GeoIP Engine (`geoip_engine.py`)

```python
class GeoIPEngine:
    def __init__(self, settings_repo, cache_size=10_000, ttl_hours=24): ...
    def resolve(self, ip: str) -> dict | GeoIPError: ...
    def set_provider(self, provider: str) -> None: ...  # maxmind | ipapi | ipinfo
```

LRU cache: `functools.lru_cache` wraps the internal `_resolve_uncached()`.
Cache invalidation on TTL: timestamps stored alongside cached values in a
parallel `_cache_times` dict; stale entries evicted on next access.

ponytail: `functools.lru_cache` is stdlib and zero-cost; TTL eviction is a lazy
check (evict on access, not on timer). Ceiling: stale entries live until accessed.

### 6. Anomaly Engine (`anomaly_engine.py`)

Rolling statistics tracker. Maintains per-IP deques of packet counts over a
5-minute sliding window. Uses Welford online algorithm for mean/std updates
(one pass, O(1) per sample).

```python
class AnomalyEngine:
    def __init__(self, baseline_window_seconds=300, sigma_threshold=3.0): ...
    def ingest(self, ip: str, pps: float, conn_freq: float,
               entropy: float) -> AnomalyEvent | None: ...
    def calibration_data(self) -> dict: ...
    def override_calibration(self, ip: str, values: dict) -> None: ...
    def is_warming_up(self) -> bool: ...  # True if < 5 min of data
```

### 7. Threat Intel Service (`threat_intel_service.py`)

Async enrichment via a `threading.Thread` worker consuming an `enrichment_queue`.
Enrichment results update the `Event` record via `event_repo`. External calls use
`requests` (already installed).

```python
class ThreatIntelService:
    def __init__(self, event_repo, settings_repo, log_engine): ...
    def enqueue_enrichment(self, event_id: str, source_ip: str) -> None: ...
    def compute_risk_score(self, severity: float, reputation: float,
                           ioc_match: bool, recurrence: int) -> int: ...
    def hunt(self, ioc_value: str, page: int, per_page: int) -> dict: ...
    def feedback(self, event_id: str, is_false_positive: bool,
                 operator: str) -> None: ...
```

### 8. SOAR Engine (`soar_engine.py`)

Playbook executor. Each playbook action is a callable registered in an
`_ACTION_REGISTRY` dict. Retry with exponential backoff uses a simple loop —
no new scheduler needed.

```python
class SOAREngine:
    def __init__(self, settings_repo, log_engine, socketio_emit, geoip_engine): ...
    def trigger(self, event: ThreatEvent, enrichment: dict) -> None: ...
    def test_integration(self, channel: str) -> dict: ...
```

Notification channels: SMTP (`smtplib` stdlib), Slack/Discord/Telegram/webhook
(`requests`), Syslog (`logging.handlers.SysLogHandler` stdlib).

### 9. Auth Service (`auth_service.py`) + Middleware

```python
class AuthService:
    def __init__(self, settings_repo, audit_service): ...
    def login(self, username: str, password: str,
              totp_code: str | None) -> dict: ...   # returns {access_token, refresh_token}
    def refresh(self, refresh_token: str) -> dict: ...
    def create_user(self, username, password, role) -> dict: ...
    def validate_token(self, token: str) -> dict: ...  # raises on invalid
```

JWT via `PyJWT`; TOTP via `pyotp`. Password hashing via `werkzeug.security`
(already a Flask dependency — no new dep).

RBAC middleware: `auth_middleware.py` — a `before_request` hook that reads the
`Authorization` header, validates the JWT, and stores the user payload in
`flask.g.current_user`. Route decorators `@require_role(*roles)` wrap
blueprints as needed.

### 10. Compliance Reporter (`compliance_reporter.py`)

```python
class ComplianceReporter:
    SUPPORTED_FRAMEWORKS = ["nist_csf", "cis_v8", "iso27001", "mitre_attack"]
    def generate(self, framework: str) -> dict: ...
    def to_pdf(self, report: dict) -> bytes: ...   # lazy-imports reportlab
    def to_json(self, report: dict) -> dict: ...
```

Reports are cached in the `reports` table (new ORM model). `regenerate=true`
bypasses cache.

### 11. Plugin Registry (`plugin_registry.py`)

```python
class PluginRegistry:
    def __init__(self, plugin_dir: Path): ...
    def discover(self) -> list[dict]: ...
    def enable(self, plugin_name: str) -> bool: ...
    def disable(self, plugin_name: str) -> bool: ...
    def load(self, plugin_name: str) -> types.ModuleType: ...
```

Plugins are Python packages in `plugins/` directory. Each exposes a
`PLUGIN_META` dict and a `register(app)` function. No magic — just `importlib`.

---

## Data Models

### Extended: `BlockedIP` (existing table, new columns)

```python
block_type: Mapped[str]        # "ip" | "cidr" | "country" | "asn"
threat_score: Mapped[int]      # 0-100, computed at block time
operator_id: Mapped[str]       # username of blocking operator
audit_entry_id: Mapped[int]    # FK to audit_log.id (immutable link)
```

### New Table: `ScheduledJob`

```python
class ScheduledJob(Base):
    __tablename__ = "scheduled_jobs"
    id: str                     # UUID, maps to APScheduler job_id
    attack_type: str
    config_json: Text           # serialised attack params
    recurrence_rule: str | None # cron expression or interval descriptor
    status: str                 # PENDING | RUNNING | QUEUED | DONE | FAILED | CANCELLED
    scheduled_at: str           # ISO-8601 UTC
    executed_at: str | None
    created_by: str
    campaign_id: str | None     # links batch jobs together
    occurrence_count: int       # tracks unbounded recurrence cap (365)
```

### New Table: `UserAccount`

```python
class UserAccount(Base):
    __tablename__ = "user_accounts"
    id: int
    username: str               # UNIQUE
    password_hash: str          # werkzeug pbkdf2:sha256
    role: str                   # admin | analyst | hunter | viewer
    mfa_secret: str | None      # TOTP base32 secret
    mfa_enabled: int            # 0 | 1
    created_at: str
    last_login: str | None
    active: int                 # 0 | 1 (soft delete)
```

### New Table: `AuditLog`

```python
class AuditLog(Base):
    __tablename__ = "audit_log"
    id: int
    timestamp: str              # ISO-8601 UTC
    username: str
    action: str                 # LOGIN | LOGOUT | BLOCK | UNBLOCK | SETTINGS_WRITE | etc.
    resource_path: str
    detail_json: Text | None
    # No UPDATE/DELETE on this table — append-only enforced in AuditService
```

### New Table: `EnrichmentResult`

```python
class EnrichmentResult(Base):
    __tablename__ = "enrichment_results"
    id: int
    event_id: str               # FK events.event_id
    source: str                 # virustotal | abuseipdb | shodan | censys
    fetched_at: str
    result_json: Text
    risk_score: int             # 0-100 composite
    ioc_match: int              # 0 | 1
    ioc_identifiers: Text | None
    status: str                 # ok | enrichment_failed
```

### New Table: `ComplianceReport`

```python
class ComplianceReport(Base):
    __tablename__ = "compliance_reports"
    id: int
    framework: str              # nist_csf | cis_v8 | iso27001 | mitre_attack
    generated_at: str           # ISO-8601 UTC
    report_json: Text           # cached JSON blob
```

### Extended: `Event` (existing table, new columns)

```python
ioc_match: Mapped[int]         # 0 | 1
risk_score: Mapped[int]        # 0-100 composite from ThreatIntel
mitre_tactic: Mapped[str]      # e.g. "Reconnaissance"
mitre_technique: Mapped[str]   # e.g. "T1595"
enrichment_status: Mapped[str] # pending | ok | enrichment_failed
false_positive: Mapped[int]    # 0 | 1, set via feedback endpoint
```

### Extended: `Setting` (existing table)

The `Setting` table already supports arbitrary key-value pairs. Enterprise
settings sections (Req 6.1) are stored as namespaced keys
(`appearance.theme`, `ai.sigma_rules_dir`, `notifications.slack_webhook`, etc.).
No schema change needed — only new key namespaces.

### New Table: `IOCStore`

```python
class IOCStore(Base):
    __tablename__ = "ioc_store"
    id: int
    ioc_type: str               # ip | domain | hash
    ioc_value: str              # UNIQUE per type
    added_at: str
    source: str                 # manual | virustotal | abuseipdb
    last_seen: str
```

### DB Migration Strategy

All new columns and tables are added via `database/migrate.py` — a simple
`ALTER TABLE` / `CREATE TABLE IF NOT EXISTS` script run at startup by
`init_db.py`. No Alembic needed at this scale.

ponytail: Alembic adds migration tracking, rollback, branching. For a
single-team project this is overkill. Upgrade path: add Alembic when the team
grows past 3 contributors or needs rollback. Mark migration scripts with version
numbers so Alembic adoption is a drop-in when needed.

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid
executions of a system — essentially, a formal statement about what the system
should do. Properties serve as the bridge between human-readable specifications and
machine-verifiable correctness guarantees.*

PBT is appropriate for this feature because it contains pure functions (threat score
computation, risk score computation, IP address validation, JWT validation, password
policy enforcement, anomaly detection thresholds) whose correctness must hold across
a wide input space. The PBT library used is **Hypothesis**, which is already installed
in the project (evidenced by the `.hypothesis/` directory).

---

### Property 1: Block atomicity — no partial state on failure

*For any* valid IP address and reason string, a block attempt that fails either the
firewall step or the database step SHALL leave the system in the same state as before
the call: either both the iptables rule and the DB record exist (success), or neither
exists (failure). There is no observable intermediate state where one succeeds and the
other does not.

**Validates: Requirements 1.1, 1.14**

---

### Property 2: Duplicate block extends expiry, never duplicates

*For any* IP address that already has an active block record, submitting a second block
request SHALL result in exactly one active block record for that IP (the expiry is
extended, not a second record inserted), and the new `expires_at` SHALL be strictly
later than the original `expires_at`.

**Validates: Requirements 1.5**

---

### Property 3: Whitelisted IPs are always rejected from blocking

*For any* IP address that is present in the active whitelist, every block request
targeting that IP SHALL return a `WHITELISTED_IP` error code and SHALL NOT create a
block record or apply an iptables rule.

**Validates: Requirements 1.7**

---

### Property 4: Threat score is bounded and formula-correct

*For any* triple `(severity ∈ [0,10], confidence ∈ [0,100], hit_count ∈ [0,∞))`,
`compute_threat_score(severity, confidence, hit_count)` SHALL return an integer in
`[0, 100]` equal to
`min(100, round(severity/10 * 40 + confidence * 0.30 + min(hit_count, 100) * 0.30))`.

**Validates: Requirements 1.8**

---

### Property 5: Simulator generates only public routable IPs

*For any* call to `ThreatSimulator.generate_profile()` with any source category or
none, the returned `ip` field SHALL NOT be a private, loopback, link-local, or
multicast address as defined by `ipaddress.ip_address(ip).is_private`,
`is_loopback`, `is_link_local`, or `is_multicast`.

**Validates: Requirements 4.2**

---

### Property 6: Simulator never injects whitelisted IPs

*For any* non-empty whitelist set W and any call to
`ThreatSimulator.generate_session()`, the set of returned IPs SHALL be disjoint from
W (no generated IP appears in the whitelist), OR a `whitelist_exhaustion` event SHALL
be emitted for that attacker slot when all 10 retry attempts yield only whitelisted IPs.

**Validates: Requirements 4.7**

---

### Property 7: GeoIP cache prevents redundant API calls

*For any* sequence of IP resolution calls that includes repeated IPs, the number of
external API calls made by `GeoIPEngine` SHALL equal the number of distinct IPs in the
sequence (not the total call count), assuming no cache entries have expired.

**Validates: Requirements 5.9**

---

### Property 8: Anomaly detection fires iff deviation exceeds threshold

*For any* set of baseline samples `{x₁, …, xₙ}` (n ≥ 30, to ensure stable std) and
any probe value `v`, `AnomalyEngine.ingest()` SHALL flag `v` as anomalous if and only
if `|v - mean(x)| > 3 * std(x)`, and SHALL suppress flagging when the engine is in
warm-up mode (fewer than 5 minutes of baseline data).

**Validates: Requirements 9.1**

---

### Property 9: Composite risk score is bounded and weights sum to 100%

*For any* tuple `(severity ∈ [0,1], reputation ∈ [0,100], ioc_match ∈ {0,1},
recurrence ∈ [0,∞))`, `ThreatIntelService.compute_risk_score()` SHALL return an
integer in `[0, 100]` equal to
`min(100, round(severity * 40 + reputation * 0.30 + ioc_match * 20 + min(recurrence, 10) * 1.0))`,
confirming the four weights (40%, 30%, 20%, 10%) sum to 100%.

**Validates: Requirements 10.3**

---

### Property 10: PacketDecoder never propagates unhandled exceptions

*For any* arbitrary byte sequence (including empty, null bytes, truncated headers,
malformed layer data), `PacketDecoder.decode()` SHALL return either a valid `Packet`
object or `None` and SHALL NEVER raise an unhandled exception to the caller.

**Validates: Requirements 12.4**

---

### Property 11: ConfigurationManager never propagates unhandled exceptions

*For any* arbitrary dict (including empty, deeply nested, wrong types, unknown keys,
None values), `ConfigurationManager.load()` and `ConfigurationManager.update()` SHALL
return a valid `Settings` object (or raise only `ValueError` for invalid ranges) and
SHALL NEVER raise any other unhandled exception to the caller.

**Validates: Requirements 12.4**

---

### Property 12: Password policy enforced consistently

*For any* string `s`, the password validator SHALL accept `s` if and only if:
`len(s) >= 12` AND `any(c.isupper() for c in s)` AND `any(c.isdigit() for c in s)`
AND `any(c in string.punctuation for c in s)`. The validator result SHALL be
deterministic — calling it twice on the same input always returns the same outcome.

**Validates: Requirements 14.6**

---

### Property 13: JWT authentication blocks all non-public endpoints without valid token

*For any* non-public API endpoint path registered in the Flask app and any request
without a valid `Authorization: Bearer <token>` header (absent, expired, malformed,
or signed with wrong key), the IDPS SHALL return HTTP 401 and SHALL NOT execute the
route handler.

**Validates: Requirements 14.1**

---

### Property 14: Per-channel severity threshold correctly gates notifications

*For any* pair `(event_severity ∈ {Low, Medium, High, Critical},
channel_threshold ∈ {Low, Medium, High, Critical})`, the SOAR engine SHALL dispatch
a notification to that channel if and only if `severity_order[event_severity] >=
severity_order[channel_threshold]`, where `severity_order = {Low:0, Medium:1,
High:2, Critical:3}`.

**Validates: Requirements 15.3**

---

## Error Handling

### General Principle

All new services follow the same error handling contract as existing services:
exceptions are caught at the service boundary, logged, and surfaced via
`error_response()` to the caller. No raw stack traces reach the HTTP response.

### Partial State / Atomic Operations

**Block atomicity (Req 1.1, 1.14)**: `BlockManager.block()` applies the iptables
rule first. If iptables succeeds but the DB insert fails, a compensating iptables
`DELETE` rule is immediately issued before returning HTTP 500. If iptables fails,
the DB write is never attempted.

**Backup/Restore (Req 6.6, 12.6)**: Restore operations use a temporary session;
changes are only committed after checksum validation and operator confirmation.

### External Service Failures

**GeoIP fallback chain (Req 5.1)**: `GeoIPEngine` iterates its configured provider
list. On provider failure, it logs a warning and tries the next. On exhaustion, it
returns a structured `GeoIPError` object; the caller (World Map, SOAR) handles it by
rendering the "Unknown Location" marker or substituting `"Unknown"` for country.

**Enrichment failure (Req 10.1)**: `ThreatIntelService` marks the enrichment record
`enrichment_failed`, logs the error, and does not block event persistence.

**SOAR retries (Req 9.7, 15.5)**: Exponential backoff with `time.sleep()` in the
worker thread. Max 3 retries. On exhaustion, `channel_degraded` WebSocket event emitted.

### Startup Failures

**Block restoration failure (Req 1.15)**: If the database is unreachable during
startup block restoration, `BlockManager.restore_on_startup()` logs at CRITICAL level,
emits a `blocklist_restore_failed` WebSocket event, and returns without applying a
partial blocklist.

**Sigma/YARA parse errors (Req 9.3, 9.4)**: Parse failures are caught per-file; the
offending file is skipped, the error is logged with filename and line number, and
loading continues with the remaining files.

### Scheduler Errors

**Job execution failure (Req 2.9)**: APScheduler listener catches `EVENT_JOB_ERROR`,
marks the `ScheduledJob` record `FAILED`, and emits a notification event.

**Past-datetime skipping (Req 2.4)**: On startup, jobs whose scheduled time has
passed are logged at INFO level and skipped; only future occurrences are scheduled.

### Authentication Errors

HTTP 401 for missing/expired/invalid JWT. HTTP 403 for insufficient role. HTTP 400
for password policy violations with a machine-readable list of unmet criteria.
MFA errors distinguished by `MFA_REQUIRED` vs `MFA_INVALID` error codes.

---

## Testing Strategy

### Dual Testing Approach

Unit tests cover specific examples, edge cases, and error conditions.
Property-based tests (Hypothesis) verify universal properties across arbitrary inputs.
Both are necessary — unit tests catch concrete bugs, property tests verify general
correctness.

### Property-Based Tests

Using **Hypothesis** (already installed). Each property above maps to one
`@given(...)` test. Minimum 100 iterations per property (Hypothesis default is 100;
set `settings(max_examples=100)` explicitly for CI stability).

Tag format in comments:
`# Feature: net-guard-enterprise-idps, Property N: <property_text>`

Priority properties to implement first (highest coverage-per-test-line ratio):

1. **Property 4** — Threat score formula (pure arithmetic, zero dependencies)
2. **Property 9** — Risk score formula (pure arithmetic)
3. **Property 12** — Password policy (pure string logic)
4. **Property 10** — PacketDecoder fuzz (Req 12.4 explicitly requires this)
5. **Property 11** — ConfigManager fuzz (Req 12.4 explicitly requires this)
6. **Property 5** — Simulator public IP exclusion (ipaddress stdlib)
7. **Property 14** — SOAR severity gating (pure enum comparison)
8. **Property 8** — Anomaly detection threshold (Welford stats)
9. **Properties 1-3, 6-7, 13** — require mock infrastructure, implement after

### Unit Tests

- `BlockManager.restore_on_startup()` with mocked DB: verify iptables calls match
  active records
- `SchedulerService.create_job()` with past datetime: verify rejection
- `SchedulerService.create_batch()` with 51 items: verify `BATCH_LIMIT_EXCEEDED`
- `GeoIPEngine.resolve()` with all providers failing: verify `GeoIPError` returned
- `AuthService.login()` with MFA enabled + wrong TOTP: verify `MFA_INVALID`
- `ComplianceReporter.generate("unknown_framework")`: verify HTTP 400 + framework list
- `SOAREngine.trigger()` with channel failure: verify retry sequence and
  `channel_degraded` event after exhaustion

### Integration Tests

- Full attack simulation → detection → block pipeline (end-to-end with real SQLite,
  mocked iptables)
- Scheduler job execution timing: verify < 5s drift for 3 timed jobs
- GeoIP provider fallback: mock primary provider to fail, verify secondary used
- JWT token lifecycle: login → use token → expire → refresh → use refreshed token

### Smoke Tests

- `GET /api/v1/health` returns HTTP 200 after startup
- `GET /api/v1/plugins` returns list (even if empty)
- Compliance report endpoint available with correct framework names in error for
  unrecognised framework

### UI/UX Testing

- WCAG 2.1 AA contrast: use `axe-core` in CI via a Playwright smoke script
- Responsive layout: Playwright viewport tests at 1024px, 1440px, 1920px, 2560px
- Glassmorphism design tokens: CSS custom property snapshot test

### Performance

- Queue pressure warning (Req 11.6): fill queue to 7999 (no warning), then 8000
  (warning emitted) — single example test
- GeoIP cache hit rate: example test verifying 10 calls for 5 unique IPs = 5 API
  calls (not 10)

### Not Tested via PBT

- UI rendering and layout (snapshot/visual regression instead)
- AWS/external SIEM integration wiring (integration tests with mocked HTTP)
- Compliance report content accuracy (example-based tests against known framework
  control lists)
- Dashboard chart rendering (snapshot tests)
