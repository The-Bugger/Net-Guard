# Design Document

## Overview

This document describes the technical design for the `netguard-production-hardening` spec.
The goal is to bring NetGuard from "functional demo" to "production-ready, still-in-active-
development grade" without restructuring the existing architecture.

**Preserved unchanged:**
- `BaseRule` / `ThreatEvent` / `Explanation` contract in `detection/rules/base_rule.py`
- Repository → service → route layering
- Dependency-injection registry in `backend/api/dependencies.py`
- All existing API response shapes (`success_response` / `error_response` envelope)
- All 511 existing passing tests

**Design principles:**
- Smallest possible diff that achieves each requirement
- No new runtime dependencies unless strictly unavoidable
- One change at a time, verified before the next
- Standard library (`ipaddress`, `hmac`, `os`) over third-party where it covers the need

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  HTTP/SocketIO Clients                                          │
│  (dashboard browser, curl, attack scripts)                      │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                ┌───────────────▼───────────────┐
                │   Flask + Flask-SocketIO       │
                │   backend/api/__init__.py      │
                │                               │
                │  before_request chain:         │
                │  1. sanitise_and_validate()    │
                │  2. RateLimiter.check()        │  ← MODIFIED: TRUST_PROXY_HEADERS
                │  3. ApiKeyAuth.check()         │  ← NEW: Phase A Req 1
                │                               │
                │  after_request:                │
                │  4. add_security_headers()     │  ← MODIFIED: +CSP,HSTS,Permissions
                └───────────────┬───────────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
    ┌─────▼──────┐       ┌──────▼─────┐       ┌──────▼──────┐
    │  Route     │       │  Route     │       │  Route      │
    │  Blueprints│       │  Blueprints│       │  Blueprints │
    │  (GET)     │       │  (POST/    │       │  (SocketIO) │
    │  open*     │       │  PUT/DEL)  │       │  no auth    │
    │            │       │  ← auth    │       │             │
    └─────┬──────┘       └──────┬─────┘       └─────────────┘
          │                     │
          └──────────┬──────────┘
                     │
          ┌──────────▼──────────┐
          │  Service Layer      │
          │  detection_service  │
          │  prevention_service │  ← MODIFIED: private-IP guard
          │  stats_service      │
          │  monitor_service    │
          └──────────┬──────────┘
                     │
          ┌──────────▼──────────┐
          │  Detection Layer    │
          │  5 existing rules   │
          │  + IcmpFloodRule    │  ← NEW: Phase B Req 6
          │  + SlowHttpRule     │  ← NEW: Phase B Req 7
          │  + DnsTunnelRule    │  ← NEW: Phase B Req 8
          └──────────┬──────────┘
                     │
          ┌──────────▼──────────┐
          │  Repository Layer   │
          │  SQLite/SQLAlchemy  │
          └─────────────────────┘

* GET endpoints obey REQUIRE_AUTH_FOR_READS flag when set
```

---

## Phase A: Security Hardening Design


### A1 — API Key Authentication (Req 1)

**Placement:** A new `before_request` hook registered in `create_app()` in
`backend/api/__init__.py`, after the existing `sanitise_and_validate` and `RateLimiter.check`
hooks. Alternatively extracted to `backend/middleware/auth.py` for testability — preferred.

**Why `before_request` over a decorator:** The five existing mutating blueprints
(block, whitelist, settings, monitor, whitelist) are already registered. Decorating each
route individually would scatter the policy. A single `before_request` hook centralises it.

**Key comparison:** Use `hmac.compare_digest` from the standard library to prevent
timing-oracle attacks. Direct string equality (`==`) must not be used.

```python
# backend/middleware/auth.py  (new file)
import hmac, os
from flask import request
from backend.utils.response import error_response

_MUTATING = {"POST", "PUT", "DELETE", "PATCH"}

def check_api_key() -> "Response | None":
    key = os.environ.get("NETGUARD_API_KEY", "")
    require_reads = os.environ.get("REQUIRE_AUTH_FOR_READS", "false").lower() == "true"

    method_needs_auth = request.method in _MUTATING
    read_needs_auth = require_reads and request.method == "GET"

    if not (method_needs_auth or read_needs_auth):
        return None                      # SocketIO, OPTIONS, HEAD — skip

    if not key:
        return None                      # no key configured → dev mode, pass through

    provided = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(provided, key):
        return error_response("UNAUTHORIZED", "Valid X-API-Key header required."), 401

    return None
```

**SocketIO exclusion:** SocketIO upgrades arrive as GET requests to `/socket.io/`. Since
`REQUIRE_AUTH_FOR_READS` defaults to `False`, GET requests pass through. Even when
`REQUIRE_AUTH_FOR_READS=true`, the path `/socket.io/` can be explicitly exempted with a
`request.path.startswith("/socket.io/")` guard, documented in `SECURITY.md`.

**SECRET_KEY hardening:** In `create_app()`, replace:
```python
app.config["SECRET_KEY"] = "netguard-dev-secret-change-in-production"
```
with:
```python
secret = os.environ.get("SECRET_KEY", "")
if not secret and os.environ.get("FLASK_ENV") == "production":
    logger.critical("CRITICAL: SECRET_KEY must be set in production. Refusing to start.")
    raise RuntimeError("SECRET_KEY not set in production environment.")
app.config["SECRET_KEY"] = secret or "netguard-dev-secret-change-in-production"
```

**No new dependency.** `hmac` and `os` are standard library.

---

### A2 — Rate Limiter Proxy Trust Fix (Req 2)

**Change:** One method, `_client_ip()`, in `backend/middleware/rate_limiter.py`.

Current code unconditionally reads `X-Forwarded-For`. New code gates on a config flag:

```python
def _client_ip(self) -> str:
    trust = os.environ.get("TRUST_PROXY_HEADERS", "false").lower() == "true"
    if trust:
        forwarded_for = request.headers.get("X-Forwarded-For", "").strip()
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"
```

**Config flag reading:** Read at call time (not at `__init__` time) so that tests can set
`os.environ` between calls without restarting the app. The cost of one `os.environ.get`
per request is negligible.

**No class-level state change.** `RateLimiter.__init__` is unchanged.

---

### A3 — Prevention Engine Private-IP Safety Guard (Req 3)

**Change:** Add a pre-check at the top of `block_ip()` in
`backend/services/prevention_service.py` using `ipaddress` (stdlib, already available in
Python 3.3+).

**Design:**

```python
import ipaddress, psutil

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]

def _is_private(ip: str) -> tuple[bool, str]:
    """Return (True, range_name) if ip is private/special, else (False, '')."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, ""
    for net in _PRIVATE_NETS:
        if addr in net:
            return True, str(net)
    return False, ""

def _is_own_address(ip: str) -> bool:
    """Return True if ip matches any address on the server's own interfaces."""
    try:
        target = ipaddress.ip_address(ip)
        for iface_addrs in psutil.net_if_addrs().values():
            for snic in iface_addrs:
                try:
                    if ipaddress.ip_address(snic.address) == target:
                        return True
                except ValueError:
                    pass
    except Exception:
        pass
    return False
```

`block_ip()` signature change:
```python
def block_ip(self, ip: str, reason: str, event_id: str,
             allow_private_block: bool = False) -> bool:
```

Pre-check inserted **before** the existing whitelist check:
```python
if not allow_private_block:
    private, net_name = _is_private(ip)
    if private:
        logger.warning("PreventionEngine: refusing to block private/special IP %s — reason: %s", ip, net_name)
        return False
    if _is_own_address(ip):
        logger.warning("PreventionEngine: refusing to block own interface address %s", ip)
        return False
# existing whitelist check follows here
```

**`psutil` is already in `requirements.txt`** (version `psutil==6.1.0`). No new dependency.

---

### A4 — Security Headers Completeness (Req 4)

**Change:** Extend `add_security_headers()` in `backend/middleware/security_headers.py`.

**CSP for existing frontend:** The dashboard uses vanilla JS loaded from `frontend/js/*.js`
(no inline scripts in the route layer). However, SocketIO injects a small inline client
bootstrap. Until a nonce-based approach is implemented, `'unsafe-inline'` is required for
scripts. This is documented in a code comment as a known limitation.

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'unsafe-inline';
  style-src 'self' 'unsafe-inline';
  connect-src 'self' ws: wss:;
  img-src 'self' data:;
  font-src 'self';
  object-src 'none';
  frame-ancestors 'none'
```

`connect-src ws: wss:` permits SocketIO WebSocket connections without hardcoding a host.

**HSTS:** Only when `request.is_secure` — prevents breaking local HTTP dev:
```python
if request.is_secure:
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
```

**Permissions-Policy:**
```python
response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
```

**X-XSS-Protection:** Kept with a comment noting it's a legacy header.

---

### A5 — SQL Injection False Positive Reduction (Req 5)

**Root cause:** `re.compile(r"--")` matches any double dash anywhere in the payload,
including date strings like `2026--07-31`, path segments, comment delimiters in other
languages, etc.

**Chosen approach (option b — minimal diff):** Keep the broad pattern but require it to
appear after a quote character or whitespace followed by a non-word boundary, reflecting the
SQL comment syntax `<expression> -- comment`. The tightened regex:

```python
("--", re.compile(r"(?:'\s*--|[^-\w]--)", re.IGNORECASE)),
```

This matches `' --`, `1=1 --`, `;--` but NOT `2026--07-31` (digits before `--`) or
`/articles--latest` (letters before `--`).

**Trade-off documented in module docstring:** "The `--` pattern requires a preceding quote
or non-word, non-dash character to avoid matching date strings and path components. This
may miss obfuscated payloads where the injector omits the preceding space, but reduces
false positives on routine URLs. The other four patterns provide overlapping coverage of
common SQL injection forms."

**Test to add in `tests/test_properties_detection_sqli.py`:**
```python
def test_double_dash_date_string_no_high_critical():
    rule = SqlInjectionRule()
    rule.initialize()
    pkt = make_packet(payload=b"GET /articles?date=2026--07-31 HTTP/1.1\r\n\r\n")
    rule.process_packet(pkt)
    event = rule.evaluate()
    # Either no event, or event with severity not High/Critical
    if event is not None:
        assert event.severity not in ("High", "Critical")
```


---

## Phase B: New Detection Rules Design

All three new rules follow the exact same structural pattern as `arp_spoof.py` and
`port_scan.py`. The design below specifies the internal state and algorithm for each.

### Common Rule Pattern

Every new rule file follows this structure:

```
module docstring (Module purpose / Detection logic / Architecture role /
                  Dependencies / Requirements: N.N)
imports
_RECOMMENDATION string
_CONFIG constants (read from config at initialize() time)
class XxxRule(BaseRule):
    rule_name = "XXX_001"
    attack_type = "Xxx Attack"
    def __init__(self) → None
    def initialize(self) → None        # reset state, read config
    def process_packet(self, pkt) → None   # never raises
    def evaluate(self) → Optional[ThreatEvent]  # never raises
    def generate_event(self) → ThreatEvent  # raises NotImplementedError
    def explain(self, event) → Explanation
    def cleanup(self) → None
helpers (_utc_now, etc.)
```

Config is read at `initialize()` time (not module import) so tests can inject values.

---

### B1 — IcmpFloodRule (Req 6)

**File:** `detection/rules/icmp_flood.py`

**State:**
```
_flow: dict[str_src_ip, deque[float]]   # monotonic timestamps of ICMP Echo Requests
_first_seen: dict[str, str]             # wall-clock ISO-8601 of first packet per IP
_pending: list[ThreatEvent]
_emitted: set[str]                      # IPs already emitted (suppress duplicates)
_threshold: int                         # from config, default 100
_window: float                          # from config, default 3.0
```

**Algorithm (`process_packet`):**
1. Skip non-ICMP packets. Skip if `packet.icmp_type != 8` (Echo Request).
2. Evict timestamps older than `_window` from deque for `src_ip`.
3. Append current monotonic time.
4. Determine `dst_ip`; set `is_smurf = dst_ip.endswith(".255") or dst_ip == "255.255.255.255"`.
5. If `len(deque) >= _threshold` OR `is_smurf`:
   - Compute severity tier; if `is_smurf` → force `"Critical"`.
   - Build evidence; append to `_pending`.

**Severity tiers (non-smurf):**
- `count < 2 × threshold` → `"Medium"`
- `count < 4 × threshold` → `"High"`
- `count ≥ 4 × threshold` → `"Critical"`

**Duplicate suppression:** Use `_emitted` set per IP; clear the set in `cleanup()` and on
each `initialize()`. This mirrors the pattern in `ArpSpoofRule`.

**Packet field used:** `packet.icmp_type` — must be present in `Packet` dataclass. Check
`detection/parsers/packet_decoder.py`; if `icmp_type` is not yet a field, add it with
default `None` (Scapy provides `pkt[ICMP].type` for ICMP packets).

---

### B2 — SlowHttpRule (Req 7)

**File:** `detection/rules/slow_http.py`

**The key distinction from SynFloodRule:** SYN Flood counts SYN-flagged packets per window.
Slow HTTP tracks long-lived, low-data-rate *established* connections — connections that stay
open without completing an HTTP request header block (`\r\n\r\n`).

**State:**
```
_connections: dict[conn_key, ConnState]
  conn_key = (src_ip, src_port, dst_port)  — unique TCP stream identifier
  ConnState = {
    "opened_at": float,       # monotonic
    "last_data_at": float,    # monotonic — last payload-bearing packet
    "completed": bool,        # True once \r\n\r\n seen
    "bytes_seen": int,
  }
_pending: list[ThreatEvent]
_threshold: int               # concurrent slow connections to trigger
_timeout: int                 # seconds a connection must be open without completing
```

**Algorithm (`process_packet`):**
1. Skip non-TCP packets. Skip if `dst_port not in {80, 443}`.
2. `conn_key = (src_ip, src_port, dst_port)`.
3. On SYN flag (new connection): create `ConnState` entry.
4. On payload (`len(packet.payload) > 0`): update `last_data_at`, `bytes_seen`. If
   `\r\n\r\n` in payload → mark `completed = True`.
5. On FIN or RST: delete `conn_key` from `_connections`.
6. Periodically (every `_timeout` seconds, tracked via a `_last_check` monotonic float)
   scan `_connections` for entries where:
   - `not completed`
   - `(now - opened_at) > _timeout`
   - `bytes_seen < 1024` (low data rate heuristic)
   Group by `src_ip`. If count ≥ `_threshold`, add to `_pending`.

**Limitation (`ponytail:` comment):** Connection state is in-process; not shared across
workers. Ceiling: upgrade to per-flow tracking in a shared store for multi-worker deployments.

**Packet fields used:** `packet.tcp_flags` (SYN, FIN, RST), `packet.src_port`,
`packet.dst_port`, `packet.payload`. All should be present in existing `Packet` dataclass
(used by `SynFloodRule` and `SqlInjectionRule` respectively).

---

### B3 — DnsTunnelRule (Req 8)

**File:** `detection/rules/dns_tunnel.py`

**Algorithm:** Three independent indicators evaluated per source IP within a sliding window.

**State:**
```
_queries: dict[src_ip, deque[(monotonic, query_name, record_type)]]
_threshold_label_len: int   # default 50
_txt_rate_threshold: int    # default 5
_entropy_threshold: float   # default 3.5
_window: int                # default 60
_pending: list[ThreatEvent]
_emitted: set[str]
```

**Shannon entropy helper:**
```python
from math import log2
from collections import Counter

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s.lower())
    total = len(s)
    return -sum((c/total) * log2(c/total) for c in counts.values())
```

**Algorithm (`process_packet`):**
1. Skip non-UDP packets. Skip if `dst_port != 53`.
2. Parse DNS query name from `packet.payload` using a minimal DNS name parser (no external
   library — parse the question section from raw bytes per RFC 1035 §3.1).
3. Parse record type (QTYPE) from the question section: `TXT=16`, `NULL=10`.
4. Append `(monotonic, query_name, qtype)` to `_queries[src_ip]`.
5. Evict entries older than `_window`.
6. Evaluate indicators for `src_ip`:
   - **(a)** max label length across all query names in window > `_threshold_label_len`
   - **(b)** count of TXT/NULL queries > `_txt_rate_threshold`
   - **(c)** mean Shannon entropy across all query labels > `_entropy_threshold`
7. If any indicator fires and `src_ip not in _emitted`, build `ThreatEvent` and append to
   `_pending`.

**DNS parsing note:** Implement a minimal `_parse_dns_qname(payload: bytes) -> tuple[str, int]`
helper that walks the label-length encoding. On any parsing error, return `("", 0)` and skip.
Never raise. This avoids adding a DNS library as a dependency.

**Confidence cap:** Always `min(confidence, 80)`. Evidence includes which indicators fired.

**Severity:**
- Only (b) fired → `"Low"`
- Only (a) or only (c) fired → `"Medium"`
- Two or more fired → `"High"`

---

### B4 — Rule Registration (Req 9)

**File touched:** `backend/services/detection_service.py` (add three imports and three
instantiations in the same block as the existing five rules), and `config/config.yaml`
(add six new keys + three `rules_enabled` entries).

No changes to `backend/api/dependencies.py` — `DetectionEngine` is already registered there
and its constructor accepts the rule list.

**config/config.yaml additions** (follow exact comment-block style):
```yaml
# ----------------------------------------------------------
# ICMP Flood Detection
# ----------------------------------------------------------
icmp_flood_threshold: 100
icmp_flood_window: 3

# ----------------------------------------------------------
# Slow HTTP / Slowloris Detection
# ----------------------------------------------------------
slow_http_threshold: 10
slow_http_connection_timeout: 10

# ----------------------------------------------------------
# DNS Tunneling Detection
# ----------------------------------------------------------
dns_tunnel_window: 60
dns_tunnel_label_max_len: 50
dns_tunnel_txt_rate_threshold: 5
dns_tunnel_entropy_threshold: 3.5

# rules_enabled additions:
  icmp_flood: true      # ICMP_FLOOD_001 — ICMP Echo Request flood / Smurf detection
  slow_http: true       # SLOW_HTTP_001  — Slowloris / slow HTTP connection detection
  dns_tunnel: true      # DNS_TUNNEL_001 — DNS tunneling heuristic detection
```


---

## Phase C: Cleanup Design

### C1 — Dead Code Removal (Req 10)

**`backend/routes/ai_routes.py`** — delete the file. Remove two lines from
`backend/api/__init__.py`:
```python
# remove:
from backend.routes.ai_routes import ai_bp
# and:
app.register_blueprint(ai_bp, url_prefix=prefix)
```
`ai_assistant_bp` (from `ai_assistant_routes.py`) remains — it is the live, registered
version of the same endpoint.

**`docs.zip`, `m.zip`** — simple file deletion at repo root. Confirm presence first.

**`.gitkeep` files** — check each:
- `backend/models/.gitkeep`: `backend/models/` contains no `.py` files (schema is in
  `database/schema.py`). If the directory is empty after all Phase A/B changes, keep the
  `.gitkeep`; if it has content, delete it.
- `backend/api/.gitkeep`: `backend/api/` is non-empty (contains `__init__.py`,
  `dependencies.py`). Delete the `.gitkeep`.

### C2 — __pycache__ Cleanup (Req 11)

```powershell
Get-ChildItem -Recurse -Force -Filter "__pycache__" | Remove-Item -Recurse -Force
Get-ChildItem -Recurse -Force -Filter "*.pyc" | Remove-Item -Force
```

Check for tracked files first: `git ls-files "**/__pycache__"` and
`git ls-files "**/*.pyc"` — if any, `git rm --cached` before deletion.

### C3 — .hypothesis/tmp/ (Req 12)

```powershell
Remove-Item -Recurse -Force ".hypothesis\tmp\*"
```

The `examples/` sibling directory is left untouched.

### C4 — Database Artifact Check (Req 13)

```bash
git ls-files --error-unmatch database/netguard.db
git ls-files --error-unmatch netguard.db-shm
git ls-files --error-unmatch netguard.db-wal
```

Non-zero exit = not tracked = correct. If tracked, `git rm --cached` each.

### C5 — .env Untrack (Req 14)

```bash
git ls-files --error-unmatch .env
```

If tracked (exit 0), run `git rm --cached .env`. File stays on disk. Add to `CONTRIBUTING.md`.

### C6 — TODO/FIXME Sweep (Req 15)

```powershell
Select-String -Recurse -Path "backend\","detection\","frontend\js\" `
  -Pattern "TODO|FIXME|XXX|HACK" -Include "*.py","*.js"
```

`ponytail:` comments are preserved. Any `TODO` introduced by Phase A/B work is either
resolved or converted to a comment with a dated note.

---

## Phase D: Verification & Documentation Design

### Documentation File Changes

| File | Change |
|---|---|
| `README.md` | Add `NETGUARD_API_KEY`, `TRUST_PROXY_HEADERS`, new rules to feature list |
| `docs/API.md` | Add `X-API-Key` header docs; confirm endpoint list matches implementation |
| `docs/ARCHITECTURE.md` | Add three new rules to detection layer description |
| `SECURITY.md` | Add sections: auth model, SocketIO exclusion, proxy trust, private-IP guard |
| `CHANGELOG.md` | Add dated phase-by-phase entry |
| `.env.example` | Add three new variables with documentation comments |
| `CONTRIBUTING.md` | Add `.env` never-commit note |
| `DEPLOYMENT.md` | Create: proxy trust model, `TRUST_PROXY_HEADERS` deployment guide |
| `VERIFICATION.md` | Create: what was changed, tested, and what still needs human review |

### VERIFICATION.md Structure

```
# Verification Report — netguard-production-hardening
Date: <completion date>
Baseline: 511 passing tests, commit <sha>

## Phase A — Security Hardening
[table: change | verification method | status]

## Phase B — New Detection Rules
[table: rule | unit test | property test | smoke test]

## Phase C — Cleanup
[table: item | verification method]

## Still Development-Grade (Not Production-Ready Without Further Work)
- in-process rate limiter (ponytail: not shared across workers)
- SQLite persistence
- iptables requires root
- single-secret API key (no rotation)
- TLS not provided by application

## Human Review Required Before Production Deployment
- Secrets manager integration for NETGUARD_API_KEY
- Redis backend for rate limiter
- TLS configuration at reverse proxy
- CAP_NET_ADMIN capability for iptables privilege reduction
- IPv6 blocking support (currently IPv4 only)
```

---

## Data Flow: Authentication Check

```
Incoming request
      │
      ▼
sanitise_and_validate()  ─── invalid JSON field length ──► 422
      │
      ▼
RateLimiter.check()  ─── rate exceeded on non-exempt path ──► 429
      │
      ▼
ApiKeyAuth.check()
      ├── method not in {POST, PUT, DELETE, PATCH}
      │   AND (not REQUIRE_AUTH_FOR_READS or method != GET)  ──► pass through
      ├── NETGUARD_API_KEY not set  ──► pass through (dev mode)
      ├── path starts with /socket.io/  ──► pass through
      ├── X-API-Key matches  ──► pass through
      └── X-API-Key missing or wrong  ──► 401 error_response
      │
      ▼
Route handler
```

---

## Data Flow: block_ip() with Safety Guard

```
block_ip(ip, reason, event_id, allow_private_block=False)
      │
      ▼  (unless allow_private_block=True)
_is_private(ip)?  ──► True ──► log WARNING, return False
      │
      ▼
_is_own_address(ip)?  ──► True ──► log WARNING, return False
      │
      ▼
whitelist_manager.is_whitelisted(ip)?  ──► True ──► log INFO, return (no-op)
      │
      ▼
existing active block?  ──► True ──► extend expiry, return True
      │
      ▼
iptables -I INPUT -s <ip> -j DROP
      │
      ▼
block_repo.insert(record)
      │
      ▼
socketio_emit("ip_blocked", {...})
      │
      ▼
return True
```

---

## New Files Summary

| File | Type | Purpose |
|---|---|---|
| `backend/middleware/auth.py` | New | API key authentication `before_request` hook |
| `detection/rules/icmp_flood.py` | New | ICMP Flood / Smurf detection rule |
| `detection/rules/slow_http.py` | New | Slow HTTP / Slowloris detection rule |
| `detection/rules/dns_tunnel.py` | New | DNS tunneling heuristic rule |
| `scripts/attack_tests/attack_icmp_flood.sh` | New | ICMP flood attack test script |
| `scripts/attack_tests/attack_slow_http.sh` | New | Slow HTTP attack test script |
| `scripts/attack_tests/attack_dns_tunnel.sh` | New | DNS tunnel attack test script |
| `DEPLOYMENT.md` | New | Proxy trust model and deployment guide |
| `VERIFICATION.md` | New | Change log and production-readiness assessment |

## Modified Files Summary

| File | Change |
|---|---|
| `backend/api/__init__.py` | Register `check_api_key` hook; fix `SECRET_KEY` loading; remove dead `ai_bp` |
| `backend/middleware/rate_limiter.py` | `_client_ip()` gated on `TRUST_PROXY_HEADERS` |
| `backend/middleware/security_headers.py` | Add CSP, HSTS (when secure), Permissions-Policy |
| `backend/services/prevention_service.py` | Add private-IP safety guard in `block_ip()` |
| `detection/rules/sql_injection.py` | Tighten `--` pattern; update module docstring |
| `backend/services/detection_service.py` | Register three new rules |
| `config/config.yaml` | Add nine new config keys and three `rules_enabled` entries |
| `.env.example` | Add `NETGUARD_API_KEY`, `TRUST_PROXY_HEADERS`, `REQUIRE_AUTH_FOR_READS` |
| `README.md` | Document new env vars and rules |
| `docs/API.md` | Document auth header; confirm endpoints |
| `docs/ARCHITECTURE.md` | Add three new rules |
| `SECURITY.md` | Add auth, proxy, private-IP sections |
| `CHANGELOG.md` | Add dated Phase A–D entry |
| `CONTRIBUTING.md` | Add `.env` never-commit note |
| `tests/test_properties_detection_sqli.py` | Add `--` false-positive test |

## Deleted Files Summary

| File | Reason |
|---|---|
| `backend/routes/ai_routes.py` | Confirmed dead code (AUDIT_REPORT.md §1) |
| `docs.zip` | Leftover artifact (AUDIT_REPORT.md §2) |
| `m.zip` | Leftover artifact (AUDIT_REPORT.md §2) |
| `backend/api/.gitkeep` | Directory is non-empty |
| `backend/models/.gitkeep` | Only if directory becomes non-empty; else keep |
| `__pycache__/`, `*.pyc` | Build artifacts |
| `.hypothesis/tmp/*` | Transient test artifacts |

