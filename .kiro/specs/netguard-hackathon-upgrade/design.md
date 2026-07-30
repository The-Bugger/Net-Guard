# Design Document — NetGuard Hackathon Upgrade

## Overview

This document covers the technical design for extending the existing NetGuard IDPS into a
hackathon-ready enterprise platform. The base system (Flask/SQLAlchemy/SQLite/SocketIO +
detection/prevention/explainability engines) is fully preserved. All 14 requirements are
addressed by adding new services, routes, and frontend pages on top of the working system.

The guiding principle is YAGNI with maximum reuse: every new service follows the pattern
already established in `backend/services/`, every new route follows the blueprint pattern in
`backend/routes/`, and every new repository method extends the existing repositories.

**Research findings:**
- `google-generativeai` (Gemini SDK) and `openai` packages are not in `requirements.txt`;
  they will be optional extras guarded by try/import so the system works fully offline.
- `reportlab` and `weasyprint` are absent; PDF export is opt-in with a 501 fallback as
  specified.
- `functools.lru_cache` is insufficient for a 100-entry keyed cache with eviction; the
  standard library `collections.OrderedDict` provides an LRU cache without new dependencies.
- `csv` and `json` modules (stdlib) cover CSV/JSON export. `io.BytesIO` + `io.StringIO`
  cover in-memory file generation.
- Flask `after_request` hooks cover security headers and input sanitisation middleware cleanly.
- Flask `before_request` hooks cover rate limiting without adding `flask-limiter`.

---

## Architecture

The new components slot into the existing architecture as additive layers. The existing
packet-capture → detection → explanation → prevention pipeline is untouched.

```mermaid
graph TB
    subgraph Existing["Existing (unchanged)"]
        CE["CaptureEngine"] --> DE["DetectionEngine"]
        DE -->|ThreatEvent| EE["ExplainabilityEngine"]
        EE --> PE["PreventionEngine"]
        DE -->|_on_threat_event| DB[(SQLite)]
        DE -->|SocketIO| API["Flask API"]
    end

    subgraph New["New Components"]
        DEMO["DemoService\ndemo_service.py"]
        AI["AIExplainService\nai_explain_service.py"]
        EXP["ExportService\nexport_service.py"]
        ANA["AnalyticsService\nanalytics_service.py (thin)"]
        RL["RateLimiter\nbefore_request middleware"]
        SH["SecurityHeaders\nafter_request middleware"]
    end

    DEMO -->|_on_threat_event callback| DE
    AI -->|cached generate()| CACHE["LRU Cache (OrderedDict)"]
    EXP -->|event_repo.get_all()| DB
    ANA -->|event_repo queries| DB

    subgraph NewRoutes["New Route Blueprints"]
        DR["demo_routes.py\nPOST /demo/start,stop,trigger\nGET /demo/status"]
        AIR["ai_routes.py\nGET /ai-explanation/{event_id}"]
        EXPR["export_routes.py\nGET /export"]
        ANR["analytics_routes.py\nGET /analytics"]
        TLR["timeline_routes.py\nGET /timeline/{event_id}"]
    end

    subgraph NewPages["New Frontend Pages"]
        LAND["landing.html"]
        TIMELINE["timeline.html"]
        ANALYTICS["analytics.html"]
        IDX2["index.html (redesigned)"]
    end
```

### New File Manifest

```
backend/
  services/
    demo_service.py          # DemoService — synthetic event generation
    ai_explain_service.py    # AIExplainService — LLM-backed explanation enrichment
    export_service.py        # ExportService — PDF/CSV/JSON/MD export
  routes/
    demo_routes.py           # /api/v1/demo/*
    ai_routes.py             # /api/v1/ai-explanation/*
    export_routes.py         # /api/v1/export
    analytics_routes.py      # /api/v1/analytics
    timeline_routes.py       # /api/v1/timeline/*
  middleware/
    rate_limiter.py          # RateLimiter — before_request Flask middleware
    security_headers.py      # SecurityHeaders — after_request Flask middleware
frontend/
  landing.html
  timeline.html
  analytics.html
  js/
    landing.js
    timeline.js
    analytics.js
```

**Modified files** (minimum touch):
- `backend/api/__init__.py` — register 5 new blueprints + 2 middleware hooks
- `backend/services/stats_service.py` — add `get_health_score()`, cache `get_dashboard_data()`
- `backend/routes/health_routes.py` — add `health_score` to `/status` response
- `backend/routes/dashboard_routes.py` — add `health_score` to `/dashboard` response
- `backend/routes/detection_routes.py` — add `search`, `total`, strict pagination validation
- `backend/main.py` — register DemoService + AIExplainService in dependency container
- `database/schema.py` — no changes (existing schema is sufficient)

---

## Components and Interfaces

### 1. DemoService (`backend/services/demo_service.py`)

Generates synthetic `ThreatEvent` objects and injects them directly through the existing
`_on_threat_event` callback. No new database tables. No bypass of existing pipeline.

```python
# Requirement 1.6 — TEST-NET source IP ranges
_TEST_NET_RANGES = [
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
]

_ATTACK_TEMPLATES: list[dict] = [
    # 9 entries, one per attack type required by Req 1.1
    {"attack_type": "SQL Injection",       "rule_name": "SQL_INJECTION_001",    "severity": "High",     "confidence": 100, "destination_ip": "10.0.0.1", "destination_port": 80,   "protocol": "TCP",     "packet_count": 1},
    {"attack_type": "Brute Force",         "rule_name": "BRUTE_FORCE_001",      "severity": "Medium",   "confidence": 75,  "destination_ip": "10.0.0.1", "destination_port": 22,   "protocol": "TCP",     "packet_count": 15},
    {"attack_type": "Port Scan",           "rule_name": "PORT_SCAN_001",        "severity": "Medium",   "confidence": 80,  "destination_ip": "10.0.0.1", "destination_port": None, "protocol": "TCP",     "packet_count": 30},
    {"attack_type": "DDoS/SYN Flood",      "rule_name": "SYN_FLOOD_001",        "severity": "Critical", "confidence": 95,  "destination_ip": "10.0.0.1", "destination_port": 80,   "protocol": "TCP",     "packet_count": 500},
    {"attack_type": "XSS",                 "rule_name": "XSS_001",              "severity": "High",     "confidence": 90,  "destination_ip": "10.0.0.1", "destination_port": 443,  "protocol": "TCP",     "packet_count": 1},
    {"attack_type": "SSH Login",           "rule_name": "SSH_LOGIN_001",        "severity": "Medium",   "confidence": 70,  "destination_ip": "10.0.0.1", "destination_port": 22,   "protocol": "TCP",     "packet_count": 8},
    {"attack_type": "Suspicious DNS",      "rule_name": "SUSPICIOUS_DNS_001",   "severity": "Low",      "confidence": 60,  "destination_ip": "8.8.8.8",  "destination_port": 53,   "protocol": "UDP",     "packet_count": 20},
    {"attack_type": "Malware Download",    "rule_name": "MALWARE_DOWNLOAD_001", "severity": "Critical", "confidence": 85,  "destination_ip": "10.0.0.1", "destination_port": 80,   "protocol": "TCP",     "packet_count": 3},
    {"attack_type": "Privilege Escalation","rule_name": "PRIV_ESC_001",         "severity": "Critical", "confidence": 88,  "destination_ip": "10.0.0.1", "destination_port": None, "protocol": "UNKNOWN", "packet_count": 1},
]

class DemoService:
    def __init__(self, on_threat_event: Callable, block_repo) -> None: ...

    def start(self) -> None:
        """Start background thread emitting events at 2-5s random intervals."""

    def stop(self) -> None:
        """Signal background thread; waits up to 2 seconds for clean stop."""

    def trigger(self, attack_type: str) -> str:
        """Emit one event for the given attack_type; return event_id. Req 7.1."""

    def get_status(self) -> dict:
        """Return {"active": bool, "events_generated": int, "started_at": str|None}."""

    def _emit_loop(self) -> None:
        """Background thread. Shuffles templates, cycles through all 9 before reshuffling."""

    def _build_event(self, template: dict) -> ThreatEvent:
        """Build ThreatEvent from template; source_ip from random TEST-NET address."""

    @property
    def is_active(self) -> bool: ...
```

**Block bypass for demo IPs (Req 1.6):** The existing `PreventionEngine.handle_event()` already
checks `whitelist_manager.is_whitelisted()`. The design choice is to automatically add all three
TEST-NET ranges to the in-memory whitelist on `DemoService.start()` and remove them on `.stop()`.
This re-uses the existing mechanism without any modification to `PreventionEngine`.

```
# ponytail: whitelist approach re-uses existing PreventionEngine whitelist check.
# If the whitelist performance ever becomes O(n), upgrade to a separate demo-ip set.
```

The evidence dict for every synthetic event includes `"demo": True` per Req 1.8.

---

### 2. AIExplainService (`backend/services/ai_explain_service.py`)

Provider-abstracted LLM service. Three providers selected via `AI_PROVIDER` env var.
Uses `collections.OrderedDict` as an LRU cache (100 entries, keyed by `event_id`).

```python
@dataclass
class AIExplanation:
    attack_name: str
    severity: str
    confidence_pct: int
    description: str
    business_impact: str
    attacker_methodology: str
    immediate_actions: list[str]
    long_term_recommendations: list[str]
    mitre_attack_mapping: list[str]
    cve_references: list[str]
    markdown_report: str
    is_fallback: bool = False

class AIExplainService:
    _CACHE_SIZE = 100

    def __init__(self) -> None:
        self._provider: str = os.environ.get("AI_PROVIDER", "stub").lower()
        self._cache: OrderedDict = OrderedDict()   # LRU, max 100 entries
        self._lock = threading.Lock()

    def generate(self, threat_event, base_explanation) -> AIExplanation:
        """Entry point. Raises ValueError on None inputs. Returns cached if available."""

    def _get_cached(self, event_id: str) -> AIExplanation | None: ...
    def _put_cached(self, event_id: str, result: AIExplanation) -> None:
        """Evicts oldest when cache exceeds _CACHE_SIZE."""

    def _call_provider(self, threat_event, base_explanation) -> AIExplanation:
        """Dispatches to _call_gemini, _call_openai, or _call_stub."""

    def _call_stub(self, threat_event, base_explanation) -> AIExplanation:
        """Deterministic template-based response, no network call. < 100ms."""

    def _call_gemini(self, threat_event, base_explanation) -> AIExplanation:
        """Calls google.generativeai. Falls back to stub on any exception."""

    def _call_openai(self, threat_event, base_explanation) -> AIExplanation:
        """Calls openai.ChatCompletion. Falls back to stub on any exception."""

    def _parse_llm_response(self, raw: str, threat_event) -> AIExplanation:
        """Parses LLM JSON or text response into AIExplanation. Falls back on parse error."""

    def _stub_response(self, threat_event, base_explanation, is_fallback=False) -> AIExplanation:
        """Template builder always returns valid AIExplanation with all required sections."""
```

**LRU implementation** — stdlib only, no `functools.lru_cache` (which doesn't support key-based
lookup for cache invalidation):
```python
def _put_cached(self, event_id, result):
    with self._lock:
        if event_id in self._cache:
            self._cache.move_to_end(event_id)
        self._cache[event_id] = result
        if len(self._cache) > self._CACHE_SIZE:
            self._cache.popitem(last=False)  # evict oldest
```

The `markdown_report` in `_stub_response` is a f-string template containing all 7 required
section headers (`## Summary`, `## Business Impact`, `## How the Attacker Works`,
`## Immediate Actions`, `## Long-term Recommendations`, `## MITRE ATT&CK`, `## CVE References`).

---

### 3. ExportService (`backend/services/export_service.py`)

Thin service over the existing `EventRepository.get_all()`. All formats share a single
`_fetch_events(filters)` method to guarantee consistent record counts.

```python
class ExportService:
    def __init__(self, event_repo) -> None: ...

    def export_json(self, filters: dict) -> tuple[bytes, str]:
        """Returns (json_bytes, filename). Uses json.dumps(events, indent=2)."""

    def export_csv(self, filters: dict) -> tuple[str, str]:
        """Returns (csv_string, filename). Uses csv.DictWriter with all event fields."""

    def export_markdown(self, filters: dict) -> tuple[str, str]:
        """Returns (markdown_string, filename). Header + summary table + one section per event."""

    def export_pdf(self, filters: dict) -> tuple[bytes, str]:
        """Returns (pdf_bytes, filename). Raises ImportError if neither reportlab nor weasyprint installed."""

    def _fetch_events(self, filters: dict) -> list[dict]:
        """Single path for all formats — calls event_repo.get_all(filters, limit=10000, offset=0)."""

    def _filename(self, fmt: str) -> str:
        """netguard-export-{UTC-DATE}.{fmt}"""
```

`_fetch_events` uses `limit=10000` (a hard practical ceiling for a hackathon demo; the
requirements do not specify a pagination loop for export).

---

### 4. AnalyticsService (inline in `analytics_routes.py`)

The analytics logic is simple enough that a standalone service class would be over-engineering.
Instead, `analytics_routes.py` contains a `_compute_analytics(period)` helper that queries
`event_repo` directly — same pattern as `stats_routes.py`.

```python
def _compute_analytics(event_repo, period: str) -> dict:
    """
    Returns {"buckets": [...], "top_ips": [...], "severity_counts": {...},
             "protocol_counts": {...}, "total_events": int,
             "blocked_count": int, "detected_count": int}
    """
```

Time bucketing uses Python's `datetime` stdlib: generate the last N bucket boundaries, then
count events per bucket using a single `event_repo.get_all()` call and grouping in Python.

```
# ponytail: O(events) grouping in Python. For a hackathon dataset (<10K events) this is fine.
# Upgrade path: push GROUP BY + strftime into SQLAlchemy query if dataset grows.
```

---

### 5. Rate Limiter (`backend/middleware/rate_limiter.py`)

In-memory sliding window per client IP. Registered as a `before_request` hook.

```python
class RateLimiter:
    _WINDOW = 60      # seconds
    _MAX_REQ = 120    # requests per window
    _EXEMPT = {"/api/v1/health", "/api/v1/dashboard/live", "/api/v1/status"}

    def __init__(self) -> None:
        self._windows: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self) -> Response | None:
        """
        Flask before_request handler.
        Returns 429 Response or None (allow).
        Uses X-Forwarded-For leftmost IP per Req 10.5.
        """

    def _client_ip(self) -> str:
        """Extract leftmost IP from X-Forwarded-For or fall back to remote_addr."""
```

Registration in `create_app()`:
```python
limiter = RateLimiter()
app.before_request(limiter.check)
```

```
# ponytail: global in-process dict. If deployed behind a load balancer with multiple
# workers, rate limiting won't be shared across processes.
# Upgrade path: swap deque for Redis INCR + EXPIRE.
```

---

### 6. Security Headers (`backend/middleware/security_headers.py`)

Four headers on every response via `after_request`. Three lines.

```python
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
```

Registration in `create_app()`:
```python
app.after_request(add_security_headers)
```

---

### 7. Timeline Endpoint (`backend/routes/timeline_routes.py`)

No new service needed — reads from existing `event_repo` and `block_repo`.

```python
def _build_timeline(event: dict, block: dict | None) -> list[dict]:
    """
    Constructs ordered Timeline_Entry list from event + optional block record.
    Steps: Detected → Analyzed → Blocked (conditional) → Notified (skipped) → Reported (skipped)
    """
```

The `analyzed_at` field uses `detected_at + 500ms` fallback (Req 4.4), computed as:
```python
from datetime import datetime, timedelta, timezone
analyzed_at = datetime.fromisoformat(event["timestamp"]) + timedelta(milliseconds=500)
```

---

### 8. StatsService Additions

Two changes to the existing `StatsService`:

```python
def get_health_score(self) -> int:
    """
    score = max(0, min(100, 100 - (alerts_today * 5) - (active_blocks * 2)))
    Returns -1 on DB error.
    """

def get_dashboard_data(self) -> dict:
    """Extended with health_score. Cached for 2 seconds via _cache_time + _cache_data."""
```

Cache invalidation hook (Req 12.3): `_on_threat_event` in `main.py` already calls
`event_repo.insert()`; after that call we add `stats_service.invalidate_cache()`:

```python
def invalidate_cache(self) -> None:
    """Set _cache_time = 0 so next get_dashboard_data() queries DB."""
    with self._lock:
        self._cache_time = 0.0
```

---

### 9. Detection Routes Additions

Changes to `detection_routes.py`:

- Add `search` parameter: case-insensitive `LIKE %search%` on `source_ip`, `destination_ip`,
  `attack_type` via new `EventRepository.search()` method or an additional filter key.
- Add `total` to response: `event_repo.count(filters=filters)`.
- Strict pagination: validate `limit >= 1`, `offset >= 0`, non-integer → HTTP 422
  `INVALID_PAGINATION_PARAMS` before processing.
- Clamp `limit` to 500 silently (Req 8.6).

`EventRepository` gets two new methods:
```python
def count_filtered(self, filters: dict) -> int:
    """COUNT(*) with same filter logic as get_all()."""

def get_all(self, filters=None, limit=50, offset=0) -> list[dict]:
    # Adds support for filters["search"] as case-insensitive OR match
    # on source_ip, destination_ip, attack_type using SQLite LIKE
```

---

### 10. Input Sanitisation (Req 11.2, 11.3, 11.4)

`before_request` hook in `security_headers.py` (or a standalone `input_guard.py`):

```python
def sanitise_and_validate():
    """
    Strip whitespace from all string fields in JSON body.
    Return 422 INPUT_TOO_LONG if any post-strip field > 1024 chars.
    Never propagate raw tracebacks (Req 11.4 handled by app.errorhandler(Exception)).
    """
```

Global error handler in `create_app()`:
```python
@app.errorhandler(Exception)
def handle_unhandled(exc):
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return error_response("An internal error occurred.", 500, "INTERNAL_ERROR")
```

---

## Data Models

### No New Database Tables

All new features are served by the existing six-table schema. The only database change is
ensuring the existing indexes cover the new filter queries (see Performance section).

### New In-Memory Structures

| Structure | Location | Type | Purpose |
|---|---|---|---|
| `DemoService._stop_event` | `demo_service.py` | `threading.Event` | Clean thread shutdown |
| `DemoService._events_generated` | `demo_service.py` | `int` (atomic via lock) | Status counter |
| `AIExplainService._cache` | `ai_explain_service.py` | `OrderedDict[str, AIExplanation]` | 100-entry LRU |
| `RateLimiter._windows` | `rate_limiter.py` | `defaultdict[str, deque[float]]` | Per-IP timestamp deque |
| `StatsService._cache_data` | `stats_service.py` | `dict` | Cached dashboard snapshot |
| `StatsService._cache_time` | `stats_service.py` | `float` | monotonic timestamp of last cache fill |

### `AIExplanation` Dataclass Fields

| Field | Type | Notes |
|---|---|---|
| `attack_name` | `str` | From `threat_event.attack_type` |
| `severity` | `str` | One of Low/Medium/High/Critical |
| `confidence_pct` | `int` | 0–100 |
| `description` | `str` | Short summary |
| `business_impact` | `str` | Business context |
| `attacker_methodology` | `str` | How the attack works |
| `immediate_actions` | `list[str]` | Never None; empty list permitted |
| `long_term_recommendations` | `list[str]` | Never None; empty list permitted |
| `mitre_attack_mapping` | `list[str]` | e.g. `["T1190 - Exploit Public-Facing Application"]` |
| `cve_references` | `list[str]` | e.g. `["CVE-2021-44228"]` |
| `markdown_report` | `str` | Non-empty; contains all 7 required section headers |
| `is_fallback` | `bool` | True when stub used due to provider error |

### New API Response Shapes

**`GET /api/v1/demo/status`**
```json
{"active": false, "events_generated": 0, "started_at": null}
```

**`GET /api/v1/ai-explanation/{event_id}`**
```json
{"success": true, "data": {"attack_name": "SQL Injection", "severity": "High",
  "markdown_report": "## Summary\n...", "immediate_actions": ["..."],
  "long_term_recommendations": ["..."], "mitre_attack_mapping": ["T1190"],
  "cve_references": [], "is_fallback": false}}
```

**`GET /api/v1/analytics?period=daily`**
```json
{"success": true, "data": {
  "buckets": [{"bucket": "2025-07-01", "count": 12, "breakdown": {"SQL Injection": 5, "Port Scan": 7}}],
  "top_ips": [{"source_ip": "192.0.2.1", "count": 8}],
  "severity_counts": {"High": 10, "Critical": 2},
  "protocol_counts": {"TCP": 11, "UDP": 1},
  "total_events": 12,
  "blocked_count": 9,
  "detected_count": 3
}}
```

**`GET /api/v1/timeline/{event_id}`**
```json
{"success": true, "data": {"timeline": [
  {"step_name": "Detected",  "timestamp": "2025-07-01T12:00:00Z", "description": "Attack detected by SQL_INJECTION_001", "status": "completed"},
  {"step_name": "Analyzed",  "timestamp": "2025-07-01T12:00:00.5Z","description": "Explanation generated", "status": "completed"},
  {"step_name": "Blocked",   "timestamp": "2025-07-01T12:00:01Z", "description": "Source IP blocked", "status": "completed"},
  {"step_name": "Notified",  "timestamp": null, "description": "No notification sent", "status": "skipped"},
  {"step_name": "Reported",  "timestamp": null, "description": "No report generated", "status": "skipped"}
]}}
```

**`GET /api/v1/detections` (enhanced)**
```json
{"success": true, "data": {"events": [...], "count": 20, "total": 347, "limit": 20, "offset": 0}}
```

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions
of a system — essentially, a formal statement about what the system should do. Properties
serve as the bridge between human-readable specifications and machine-verifiable correctness
guarantees.*

### Property 1: Demo Source IP in TEST-NET

*For any* synthetic `ThreatEvent` generated by `DemoService`, the `source_ip` field SHALL
fall within one of the three RFC 5737 TEST-NET ranges: `192.0.2.0/24`, `198.51.100.0/24`,
or `203.0.113.0/24`.

**Validates: Requirements 1.6**

---

### Property 2: Demo Event Schema Invariant

*For any* synthetic `ThreatEvent` generated by `DemoService` and persisted via
`_on_threat_event`, the event stored in the `events` table SHALL contain non-null,
non-empty values for: `event_id`, `timestamp`, `attack_type`, `source_ip`, `rule_name`,
`severity`, `confidence`, `explanation`, and `recommendation`. The `evidence` dict SHALL
contain `demo: True`.

**Validates: Requirements 1.8, 14.1 (Property A)**

---

### Property 3: AI Explanation Fields Invariant

*For any* non-null `threat_event` and `base_explanation` passed to
`AIExplainService.generate()`, the returned `AIExplanation` SHALL satisfy:
`markdown_report` is a non-empty string; `immediate_actions`, `long_term_recommendations`,
`mitre_attack_mapping`, and `cve_references` are Python `list` instances (never `None`);
and `markdown_report` contains all seven required section headers.

**Validates: Requirements 2.4, 2.9, 14.2 (Property B)**

---

### Property 4: AI Explanation Rejects Null Inputs

*For any* call to `AIExplainService.generate()` where either argument is `None`, a
`ValueError` SHALL be raised before any provider network call is attempted.

**Validates: Requirements 2.1, 2.10**

---

### Property 5: Health Score Bounds

*For any* non-negative integer values of `alerts_today` and `active_blocks`,
`StatsService.get_health_score()` SHALL return an integer in the closed range [0, 100].

**Validates: Requirements 9.1, 9.5, 14.3 (Property C)**

---

### Property 6: Analytics Bucket Sum Equals Total Events

*For any* database state and any period ∈ {"hourly", "daily", "weekly"}, the sum of all
bucket `count` values in the response from `GET /api/v1/analytics?period=X` SHALL equal
the `total_events` field in the same response.

**Validates: Requirements 5.4, 14.4 (Property D)**

---

### Property 7: Export Count Parity

*For any* combination of valid filter parameters from {severity, attack_type, source_ip,
date, search}, the record count in the JSON response from `GET /api/v1/export?format=json`
SHALL equal the `total` field returned by `GET /api/v1/detections` with the same filters.

**Validates: Requirements 6.5, 14.5 (Property E)**

---

### Property 8: Pagination Non-Overlap

*For any* N ∈ [1, 500] and any database state with ≥ 2N records, the two result sets
returned by `GET /api/v1/detections?limit=N&offset=0` and
`GET /api/v1/detections?limit=N&offset=N` SHALL share no common `event_id` values.

**Validates: Requirements 14.6 (Property F)**

---

### Property 9: Rate Limit Enforcement

*For any* client IP and any sequence of 121 or more requests to rate-limited `/api/v1`
endpoints within a 60-second sliding window, the REST API SHALL return HTTP 429 for every
request from the 121st onward, and requests 1 through 120 inclusive SHALL be processed
normally.

**Validates: Requirements 10.1, 14.7 (Property G)**

---

### Property 10: Security Headers on All Responses

*For any* request to any `/api/v1` endpoint (regardless of HTTP method, path, or status
code), the response SHALL contain all four security headers: `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and
`Referrer-Policy: strict-origin-when-cross-origin`.

**Validates: Requirements 11.1**

---

### Property 11: Detections Search Correctness

*For any* non-empty search string S and any database state, every event returned by
`GET /api/v1/detections?search=S` SHALL contain S (case-insensitive) as a substring in at
least one of: `source_ip`, `destination_ip`, or `attack_type`. No event that does not
match this predicate SHALL appear in the results.

**Validates: Requirements 8.1**

---

### Property 12: AND Filter Correctness

*For any* combination of active filter parameters (severity, attack_type, source_ip, date,
search), every event in the `GET /api/v1/detections` response SHALL satisfy ALL active
filter conditions simultaneously.

**Validates: Requirements 8.3**

---

### Property 13: Timeline Chronological Order

*For any* existing `event_id`, the `Timeline_Entry` list returned by
`GET /api/v1/timeline/{event_id}` SHALL be ordered such that the timestamp of each entry is
greater than or equal to the timestamp of all preceding entries (ascending chronological
order), and the first entry SHALL always have `step_name = "Detected"` and
`status = "completed"`.

**Validates: Requirements 4.1, 4.2**

---

**Property Reflection — Redundancy Analysis:**

- Properties 2 and 1 are kept separate: Property 1 tests `source_ip` range specifically;
  Property 2 tests the full schema invariant including all other required fields and the
  `demo: True` marker. Different assertions, both add value.
- Properties 5 (Health Score) subsumes Req 9.5 — the property already covers bounds for ALL
  non-negative inputs, making 9.5 redundant as a separate property.
- Properties 3 and 4 cover distinct behaviors of `generate()`: valid inputs produce correct
  output vs. null inputs raise errors. Not redundant.
- Property 12 subsumes Property 11: AND filter correctness covers the single-filter search
  case. However Property 11 is kept because the search substring logic (OR across three
  fields) is distinct from the AND combination logic and warrants its own generator strategy.


---

## Error Handling

### Service-Level Error Handling

| Component | Error | Handling |
|---|---|---|
| `DemoService._emit_loop` | Any exception during event generation | Log ERROR, continue loop (don't crash demo) |
| `DemoService.trigger` | Unknown `attack_type` | Return HTTP 422 `INVALID_ATTACK_TYPE` |
| `AIExplainService.generate` | Null inputs | Raise `ValueError` immediately |
| `AIExplainService._call_gemini/_call_openai` | Network error / bad response | Log WARNING to `errors.log`; return `_stub_response(is_fallback=True)` |
| `AIExplainService._parse_llm_response` | JSON parse error | Fall back to stub; log WARNING |
| `ExportService.export_pdf` | `ImportError` (no reportlab/weasyprint) | Return HTTP 501 `PDF_NOT_SUPPORTED` |
| `ExportService` | Invalid format param | Return HTTP 400 `INVALID_EXPORT_FORMAT` |
| `RateLimiter.check` | Any exception in rate-limit logic | Log ERROR; allow request (fail open to preserve availability) |
| `StatsService.get_health_score` | DB exception | Return -1; log ERROR |
| Timeline endpoint | `event_id` not found | Return HTTP 404 `NOT_FOUND` |
| All endpoints | Unhandled exception | Global `@app.errorhandler(Exception)` returns 500 `INTERNAL_ERROR` (no traceback) |

### Input Validation Pipeline

```
Request arrives
  → RateLimiter.check() [before_request]
      → 429 if exceeded (non-exempt endpoints)
  → sanitise_and_validate() [before_request]
      → strip whitespace from all string fields in JSON body
      → 422 INPUT_TOO_LONG if any post-strip string > 1024 chars
  → Route handler validates domain-specific params
      → 422 VALIDATION_ERROR / INVALID_ATTACK_TYPE / INVALID_PAGINATION_PARAMS
  → Service performs operation
  → Response returned
  → add_security_headers() [after_request]
```

---

## Testing Strategy

### Dual Approach

Unit/example tests verify specific behaviors; property-based tests (Hypothesis) verify
universal invariants. Both are necessary.

**Library:** `hypothesis` is already installed (`hypothesis==6.115.6`). No new dependency.

### Property-Based Tests

Each of the 13 correctness properties maps to one Hypothesis `@given` test in
`tests/test_properties_hackathon.py`. Minimum 100 iterations per test (Hypothesis default
is 100; set `settings(max_examples=100)` explicitly).

Tag format (comment above each test):
```python
# Feature: netguard-hackathon-upgrade, Property N: <property_text>
@given(...)
@settings(max_examples=100)
def test_property_N_short_name(...)
```

| Property | Hypothesis Strategy |
|---|---|
| P1 — Demo IP in TEST-NET | `st.integers(0, 2)` (range index) → build IP, verify `ipaddress.ip_address(ip) in network` |
| P2 — Demo Schema Invariant | `st.sampled_from(_ATTACK_TEMPLATES)` → build event, verify all fields non-null |
| P3 — AI Explanation Fields | `st.builds(ThreatEvent, ...)` with random fields → `generate()` → verify field invariants |
| P4 — AI ValueError on None | `st.just(None)` for either arg → assert raises `ValueError` |
| P5 — Health Score Bounds | `st.integers(min_value=0)` × 2 → verify result ∈ [0, 100] |
| P6 — Analytics Bucket Sum | Seed DB with `st.lists(st.builds(event_dict))` → call analytics helper → verify sum |
| P7 — Export Count Parity | `st.fixed_dictionaries({"severity": st.one_of(...)})` → compare export vs detections count |
| P8 — Pagination Non-Overlap | `st.integers(1, 500)` for N → call two pages → assert disjoint `event_id` sets |
| P9 — Rate Limit Enforcement | 121 mock requests to RateLimiter.check() → verify 121st returns 429 |
| P10 — Security Headers | `st.sampled_from(endpoints)` → verify all 4 headers present |
| P11 — Search Correctness | `st.text(min_size=1, max_size=50)` for search string → verify all results match |
| P12 — AND Filter Correctness | `st.fixed_dictionaries(filter_combo)` → verify all results satisfy all filters |
| P13 — Timeline Order | `st.uuids()` for event_id after seeding DB → verify ascending timestamps |

### Unit / Example Tests

Location: `tests/test_hackathon_upgrade.py`

Key example tests to write (beyond the property tests):

- `test_demo_start_stop` — start/stop lifecycle, HTTP 200 both ways
- `test_demo_double_start_409` — Req 1.2
- `test_demo_trigger_all_9_types` — one per attack type
- `test_ai_provider_stub_default` — no `AI_PROVIDER` set → stub used
- `test_ai_fallback_on_provider_error` — mock provider raises, is_fallback=True returned
- `test_ai_lru_eviction` — 101 entries, oldest evicted
- `test_export_json_csv_markdown_headers` — verify Content-Disposition filename pattern
- `test_export_pdf_501_without_library` — mock import failure
- `test_export_invalid_format_400`
- `test_timeline_404_nonexistent`
- `test_timeline_detected_step_always_first`
- `test_health_score_in_status_and_dashboard`
- `test_rate_limit_retry_after_header`
- `test_rate_limiter_exempted_endpoints_not_blocked`
- `test_pagination_clamp_to_500`
- `test_pagination_invalid_422`
- `test_security_headers_on_error_response`
- `test_input_too_long_422`
- `test_no_traceback_in_response`
- `test_dashboard_cache_hit`
- `test_dashboard_cache_invalidated_on_new_event`

### Integration Tests

- `test_demo_full_pipeline` — start demo, wait for 1 event, verify in `events` table
- `test_analytics_period_counts` — seed 10K events, verify <200ms response
- `test_export_count_matches_detections_integration` — real SQLite, filters applied

### Frontend / Smoke Tests

- Verify `landing.html`, `timeline.html`, `analytics.html` files exist and Flask serves them
- Verify `landing.html` contains no `src=` or `href=` pointing to external domains

---

## Route Registration Summary

Changes to `backend/api/__init__.py` — `_register_blueprints()`:

```python
from backend.routes.demo_routes import demo_bp
from backend.routes.ai_routes import ai_bp
from backend.routes.export_routes import export_bp
from backend.routes.analytics_routes import analytics_bp
from backend.routes.timeline_routes import timeline_bp

app.register_blueprint(demo_bp,      url_prefix=prefix)
app.register_blueprint(ai_bp,        url_prefix=prefix)
app.register_blueprint(export_bp,    url_prefix=prefix)
app.register_blueprint(analytics_bp, url_prefix=prefix)
app.register_blueprint(timeline_bp,  url_prefix=prefix)
```

And `_register_frontend_routes()` adds routes for the three new HTML pages
(`/landing`, `/timeline`, `/analytics`) using the same `send_from_directory(frontend_dir, ...)` pattern.

---

## Frontend Design

### Dashboard Redesign (`frontend/index.html`)

The existing dashboard structure is preserved and extended. Changes are additive CSS + JS only.

**New KPI cards added to `.kpi-grid`:**
- Blocked IPs (total historical) — from `dashboard.blocked_ips_total`
- Detection Accuracy % — `(blocked_count / total_events) * 100`
- Security Health Score — from `dashboard.health_score`, coloured by threshold

**New panels added below existing charts:**
- System Health panel (CPU, memory, uptime, monitoring status) — polls `/api/v1/status`
- Attack Simulator panel — 9 buttons, one per attack type — calls `POST /api/v1/demo/trigger`
- Live Status Badges bar — Monitoring Active/Stopped, Demo Active/Stopped, AI Available/Unavailable

**SOC colour palette** — added CSS variables to `dark-theme.css`:
```css
--accent:   #00E5FF;
--success:  #4ADE80;
--warning:  #FACC15;
--danger:   #F87171;
--bg:       #0F172A;
```

**Glassmorphism card style** — added `.card-glass` class:
```css
.card-glass {
  backdrop-filter: blur(12px);
  background: rgba(15, 23, 42, 0.6);
  border: 1px solid rgba(255,255,255,0.08);
}
```

**Animation** — `countUp(el, from, to, durationMs)` in `dashboard.js`:
```javascript
// Only animates when SocketIO connected; skips to final value when polling
function countUp(el, from, to, durationMs = 600) { ... }
```

**Fullscreen** (Req 13.3): single 4-line event listener in `dashboard.js`:
```javascript
document.addEventListener("keydown", e => {
  if (e.ctrlKey && e.shiftKey && e.key === "P") { /* Cmd on Mac */
    document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen().catch(showToast);
  }
});
```

**External dependency removal** — `index.html` currently loads Socket.IO and Chart.js from CDNs.
For `landing.html` (Req 13.4), both libraries are copied to `frontend/js/vendor/` and served
locally. The existing `index.html` CDN references are left unchanged (not in scope for Req 13.4
which only specifies `landing.html`).

### `landing.html`

Static page — no JS framework. Inline SVG icons. Uses same `dark-theme.css`. No external URLs.
All scripts and fonts served from `/js/` and `/css/` routes.

Structure:
```html
<header> NetGuard logo + tagline </header>
<section class="features"> 5 feature cards with inline SVG icons </section>
<section class="cta">
  <a href="/" class="btn btn-primary">Launch Dashboard</a>
  <button onclick="startDemo()" class="btn btn-secondary">Start Demo</button>
</section>
<div id="error-msg" hidden></div>
<script src="/js/landing.js"></script>
```

`landing.js` — 20 lines:
```javascript
async function startDemo() {
  const r = await fetch("/api/v1/demo/start", {method:"POST"});
  if (r.ok) { window.location.href = "/"; }
  else { document.getElementById("error-msg").textContent = "Demo start failed"; document.getElementById("error-msg").hidden = false; }
}
```

### `timeline.html`

Reads `?event_id=<uuid>` from URL, calls `GET /api/v1/timeline/{event_id}`, renders vertical
timeline using CSS `::before` border trick (no new library). Each step shows a circle icon,
step name, timestamp, description, and a coloured status badge.

### `analytics.html`

- Period selector (`<select>` with hourly/daily/weekly options)
- Bar chart (Chart.js — loaded from existing CDN) for attack counts over time
- Doughnut chart for severity distribution
- Top-attacker-IPs `<table>`
- KPI cards for `total_events`, `blocked_count`, `detected_count`
- All chart data reloaded on period change via `fetch("/api/v1/analytics?period=" + period)`
  without page reload

```
# ponytail: Chart.js already loaded in index.html via CDN. analytics.html loads the same CDN
# URL. If offline use is required, copy to /js/vendor/ like landing.html.
```
