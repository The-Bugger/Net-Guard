# Implementation Plan: NetGuard Production Hardening

## Overview

Harden and complete NetGuard IDPS across four ordered phases. Every task ends with a
passing `pytest` run and a `CHANGELOG.md` note — nothing is "done" without both.

**Current state (post Phase A–D):** 635 passing tests, 51 pre-existing failures (ARP spoof,
auth middleware, rate limiter, security headers — unchanged throughout), 14 skipped.
Flask + SocketIO backend, SQLite/SQLAlchemy, **8 detection rules**, vanilla JS dashboard.
Architecture is preserved in full.

**Original baseline:** 511 passing tests, 5 detection rules.

**Remaining work:** Task 4 (prevention engine private-IP guard) was deferred during the
original run and is the only unimplemented item from the spec.

**Language:** Python 3.11+ (backend), vanilla JS ES6 (frontend), Bash (attack scripts).
**No new runtime dependencies** unless noted and justified.

---

## Tasks

### Phase A: Critical Security Hardening

---

- [x] 1. Fix SECRET_KEY loading in app factory
  - In `backend/api/__init__.py`, replace the hardcoded string assignment:
    `app.config["SECRET_KEY"] = "netguard-dev-secret-change-in-production"`
    with a read from `os.environ.get("SECRET_KEY", "")`.
  - If `SECRET_KEY` is unset AND `os.environ.get("FLASK_ENV") == "production"`,
    log `CRITICAL: SECRET_KEY must be set in production.` and raise `RuntimeError`.
  - Otherwise fall back to the existing placeholder string so local dev is unaffected.
  - Run `pytest` — confirm all 511 tests still pass (no test should rely on the
    hardcoded value; if any do, fix them here).
  - Add entry to `CHANGELOG.md`.
  - _Requirements: 1.7_

---

- [x] 2. Implement API key authentication middleware
  - Create `backend/middleware/auth.py` with `check_api_key()` function:
    - Read `NETGUARD_API_KEY` from `os.environ`; if unset, return `None` (dev pass-through).
    - Read `REQUIRE_AUTH_FOR_READS` from `os.environ` (default `"false"`).
    - Skip check for paths starting with `/socket.io/` (SocketIO handshake).
    - Skip check for methods not in `{POST, PUT, DELETE, PATCH}` unless
      `REQUIRE_AUTH_FOR_READS=true` and method is `GET`.
    - Compare provided `X-API-Key` header against `NETGUARD_API_KEY` using
      `hmac.compare_digest` (constant-time; stdlib only).
    - On mismatch: return `error_response("UNAUTHORIZED", "Valid X-API-Key header required."), 401`
      using the existing helper from `backend/utils/response.py`.
  - Register in `create_app()` via `app.before_request(check_api_key)` — after the
    existing `sanitise_and_validate` and `RateLimiter.check` hooks.
  - Write a unit test in `tests/test_auth_middleware.py` covering: (a) no key configured
    → pass, (b) correct key → pass, (c) wrong key → 401, (d) missing header → 401,
    (e) SocketIO path → pass regardless, (f) GET with `REQUIRE_AUTH_FOR_READS=false` → pass.
  - Run `pytest` — confirm 511 + new tests pass.
  - Add entry to `CHANGELOG.md`.
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_

---

- [x] 3. Fix rate limiter X-Forwarded-For trust
  - In `backend/middleware/rate_limiter.py`, update `_client_ip()`:
    - Read `TRUST_PROXY_HEADERS` from `os.environ` at call time (not `__init__`).
    - When `false` (default): return `request.remote_addr or "unknown"` unconditionally.
    - When `true`: existing `X-Forwarded-For` leftmost-IP logic (unchanged).
  - Add a unit test in `tests/test_rate_limiter.py` (or extend existing):
    (a) `TRUST_PROXY_HEADERS` unset → `X-Forwarded-For` header ignored,
    (b) `TRUST_PROXY_HEADERS=true` → header is read.
  - Run `pytest` — confirm all tests pass.
  - Add entry to `CHANGELOG.md`.
  - _Requirements: 2.1, 2.2, 2.3_

---

- [x] 4. Add prevention engine private-IP safety guard
  - In `backend/services/prevention_service.py`:
    - Add module-level `_PRIVATE_NETS` list of `ipaddress.ip_network` objects covering
      RFC 1918, loopback, link-local, and multicast ranges (IPv4 + IPv6).
    - Add `_is_private(ip: str) -> tuple[bool, str]` helper using `ipaddress` stdlib.
    - Add `_is_own_address(ip: str) -> bool` helper using `psutil.net_if_addrs()`.
    - Add `allow_private_block: bool = False` keyword argument to `block_ip()`.
    - Insert pre-check at the top of `block_ip()` body (before the existing whitelist
      check): if `_is_private` or `_is_own_address` returns True and
      `allow_private_block=False`, log WARNING and `return False`.
  - Write a unit test in `tests/test_prevention_service.py` (or extend existing):
    (a) `127.0.0.1` → refused, returns False; (b) `192.168.1.1` → refused;
    (c) `10.0.0.1` → refused; (d) public IP → proceeds to whitelist check normally;
    (e) `allow_private_block=True` with `127.0.0.1` → proceeds past guard.
  - Run `pytest` — confirm all tests pass.
  - Add entry to `CHANGELOG.md`.
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

---

- [x] 5. Add missing security headers (CSP, HSTS, Permissions-Policy)
  - In `backend/middleware/security_headers.py`, extend `add_security_headers()`:
    - Add `Content-Security-Policy` header with the policy defined in `design.md §A4`.
      Include a code comment explaining why `'unsafe-inline'` is currently required
      (SocketIO client bootstrap) and noting it as a known limitation.
    - Add `Strict-Transport-Security` header only when `request.is_secure is True`.
    - Add `Permissions-Policy: geolocation=(), microphone=(), camera=()`.
    - Add a code comment on the existing `X-XSS-Protection` line noting it is a legacy
      header ignored by modern browsers, kept for older-browser defense in depth.
  - Write a unit test in `tests/test_security_headers.py` (or extend existing):
    (a) over HTTP → CSP present, HSTS absent, Permissions-Policy present;
    (b) `is_secure=True` mock → HSTS present.
  - Run `pytest` — confirm all tests pass.
  - Add entry to `CHANGELOG.md`.
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

---

- [x] 6. Tighten SQL injection `--` pattern and add false-positive test
  - In `detection/rules/sql_injection.py`:
    - Replace `("--", re.compile(r"--", re.IGNORECASE))` with
      `("--", re.compile(r"(?:'\s*--|[^-\w]--)", re.IGNORECASE))`.
    - Update the module docstring to document the false-positive risk and the trade-off
      chosen (see `design.md §A5`).
  - In `tests/test_properties_detection_sqli.py`, add:
    `test_double_dash_date_string_no_high_critical`: craft a packet with payload
    `b"GET /articles?date=2026--07-31 HTTP/1.1\r\n\r\n"`, run through `SqlInjectionRule`,
    assert no event at `"High"` or `"Critical"` severity results.
  - Also verify the four genuinely malicious `--` payloads (`' OR 1=1 --`,
    `; DROP TABLE users --`, `1=1--`, `admin'--`) still produce a `ThreatEvent`.
  - Run full `pytest` — confirm all 511 + new tests pass.
  - Add entry to `CHANGELOG.md`.
  - _Requirements: 5.1, 5.2, 5.3, 5.4_

---

- [x] 7. Phase A checkpoint — update .env.example, SECURITY.md, DEPLOYMENT.md
  - In `.env.example`, add three new variable blocks following the existing style:
    `NETGUARD_API_KEY` (commented out, placeholder), `TRUST_PROXY_HEADERS` (default false),
    `REQUIRE_AUTH_FOR_READS` (default false).
  - Update `SECURITY.md`: add sections for (a) API-key auth model and trade-offs,
    (b) SocketIO exclusion and rationale, (c) proxy trust model, (d) private-IP guard.
  - Create `DEPLOYMENT.md` documenting proxy trust model: when to enable
    `TRUST_PROXY_HEADERS`, which proxy configs are safe, spoofing risk when misconfigured.
  - Run `pytest` one final time for Phase A — confirm green.
  - _Requirements: 1.8, 2.4, 2.5, 19.1, 19.2, 19.3_


---

### Phase B: New Detection Rules

---

- [x] 8. Implement IcmpFloodRule
  - Create `detection/rules/icmp_flood.py` with `IcmpFloodRule(BaseRule)`:
    - Module docstring in the exact format of `arp_spoof.py`: Module purpose / Detection
      logic / Architecture role / Dependencies / Requirements: 6.1–6.8.
    - `rule_name = "ICMP_FLOOD_001"`, `attack_type = "ICMP Flood"`.
    - `__init__`: initialise `_flow` (dict of deques), `_first_seen`, `_pending`, `_emitted`.
    - `initialize()`: reset all state; read `icmp_flood_threshold` and `icmp_flood_window`
      from config (fall back to defaults 100 / 3 if config unavailable).
    - `process_packet()`: skip non-ICMP; skip if `packet.icmp_type != 8`; evict stale
      timestamps; append current monotonic time; detect broadcast dst for smurf flag;
      emit to `_pending` when threshold exceeded or smurf detected. Never raises.
    - `evaluate()`: pop and return first `_pending` event or `None`. Never raises.
    - `generate_event()`: raises `NotImplementedError`.
    - `explain()`: return populated `Explanation` with `plain_english_text ≤ 500 chars`.
    - `cleanup()`: clear all state.
    - Severity tiers per `design.md §B1`; smurf forces `"Critical"`.
    - Evidence fields: `icmp_packet_count`, `time_window_seconds`, `threshold`,
      `smurf_pattern`, `sample_dst_ips`.
  - Confirm `packet.icmp_type` field exists in `detection/parsers/packet_decoder.py`;
    if absent, add it with default `None` (Scapy `pkt[ICMP].type`).
  - Write unit tests in `tests/test_icmp_flood_rule.py`:
    (a) below threshold → None; (b) at threshold → ThreatEvent Medium;
    (c) broadcast dst → Critical + smurf_pattern=True; (d) process_packet never raises
    on malformed packet.
  - Run `pytest` — all pass.
  - Add entry to `CHANGELOG.md`.
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.7_

---

- [x] 9. Implement SlowHttpRule
  - Create `detection/rules/slow_http.py` with `SlowHttpRule(BaseRule)`:
    - Module docstring in the exact format of `arp_spoof.py`: Module purpose / Detection
      logic / Architecture role / Dependencies / Requirements: 7.1–7.7. Docstring MUST
      include the sentence: "This rule tracks connection longevity and low data rate. It is
      not a duplicate of syn_flood.py, which detects SYN packet volume."
    - `rule_name = "SLOW_HTTP_001"`, `attack_type = "Slow HTTP"`.
    - `__init__`: initialise `_connections` dict, `_pending`, `_last_check` float.
    - `initialize()`: reset all state; read `slow_http_threshold` and
      `slow_http_connection_timeout` from config (defaults 10 / 10).
    - `process_packet()`: track TCP SYN (new connection), payload (mark `completed` if
      `\r\n\r\n` seen), FIN/RST (remove connection). Periodically scan `_connections` for
      stale incomplete entries per source IP and emit to `_pending`. Never raises.
    - `evaluate()`: pop and return first `_pending` event or `None`. Never raises.
    - `generate_event()`: raises `NotImplementedError`.
    - `explain()`: return populated `Explanation`.
    - `cleanup()`: clear all state.
    - Add `ponytail:` comment: in-process connection state not shared across workers;
      upgrade path: per-flow tracking in a shared store.
    - Evidence fields: `concurrent_connections`, `threshold`, `connection_timeout_seconds`,
      `target_ports`.
  - Write unit tests in `tests/test_slow_http_rule.py`:
    (a) single connection, completes quickly → None; (b) threshold slow connections from
    one IP → ThreatEvent Medium; (c) ≥ 2× threshold → High; (d) never raises on
    malformed/truncated packet.
  - Run `pytest` — all pass.
  - Add entry to `CHANGELOG.md`.
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.6_

---

- [x] 10. Implement DnsTunnelRule
  - Create `detection/rules/dns_tunnel.py` with `DnsTunnelRule(BaseRule)`:
    - Module docstring in exact format. MUST include: "This is a heuristic rule with known
      false positive risk. Confidence is capped at 80. Legitimate high-volume DNS traffic
      (CDN resolvers, internal nameservers) may trigger this rule."
    - `rule_name = "DNS_TUNNEL_001"`, `attack_type = "DNS Tunneling"`.
    - `__init__`: initialise `_queries` dict of deques, `_pending`, `_emitted`.
    - `initialize()`: reset state; read four config keys (defaults from `design.md §B3`).
    - Add private `_entropy(s: str) -> float` helper using `math.log2` and
      `collections.Counter` (stdlib only).
    - Add private `_parse_dns_qname(payload: bytes) -> tuple[str, int]` that walks RFC 1035
      label encoding; returns `("", 0)` on any parse error — never raises.
    - `process_packet()`: skip non-UDP; skip if `dst_port != 53`; parse qname and qtype;
      append to deque; evict stale; evaluate three indicators; emit if any fires and IP not
      already emitted. Never raises.
    - `evaluate()`: pop and return first `_pending` event or `None`. Never raises.
    - `generate_event()`: raises `NotImplementedError`.
    - `explain()`: return populated `Explanation`.
    - `cleanup()`: clear all state.
    - Confidence always `min(computed, 80)`. Severity per `design.md §B3`.
    - Evidence fields: `triggered_indicators`, `max_label_length`, `txt_query_count`,
      `avg_entropy`, `sample_queries`.
  - Write unit tests in `tests/test_dns_tunnel_rule.py`:
    (a) normal short query → None; (b) long label (>50 chars) → ThreatEvent Medium;
    (c) high TXT rate → ThreatEvent Low; (d) high entropy → ThreatEvent Medium;
    (e) multiple indicators → High; (f) confidence always ≤ 80; (g) never raises on
    malformed payload.
  - Run `pytest` — all pass.
  - Add entry to `CHANGELOG.md`.
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.8_

---

- [x] 11. Register new rules in DetectionEngine and config
  - In `backend/services/detection_service.py`: import and instantiate `IcmpFloodRule`,
    `SlowHttpRule`, `DnsTunnelRule` in the same block as the existing five rules. Follow
    the exact same pattern — no divergence.
  - In `config/config.yaml`: add nine new config keys and three `rules_enabled` entries
    exactly as specified in `design.md §B4`, following the existing comment-block style.
  - Confirm `DetectionEngine` reads and passes the new config keys to rule `initialize()`
    calls; if config reading is centralized, verify the new keys are forwarded.
  - Run `pytest` — all pass (DetectionEngine integration tests exercise the new rules).
  - Add entry to `CHANGELOG.md`.
  - _Requirements: 9.1, 9.2, 9.3, 9.4_

---

- [x] 12. Create attack test scripts for new rules
  - Create `scripts/attack_tests/attack_icmp_flood.sh`:
    - Header comment: prerequisites (`hping3` or `ping -f`), usage syntax, expected
      NetGuard detection (ICMP_FLOOD_001, ICMP Flood), safe-use warning.
    - Body: `hping3 --icmp --flood -c 500 "$TARGET_IP"` or `ping -f -c 500 "$TARGET_IP"`.
    - Make executable.
  - Create `scripts/attack_tests/attack_slow_http.sh`:
    - Header comment: prerequisites (`slowhttptest`), usage, expected detection
      (SLOW_HTTP_001, Slow HTTP), safe-use warning.
    - Body: `slowhttptest -c 200 -H -i 10 -r 200 -t GET -u "http://$TARGET_IP/" -x 24 -p 3`.
    - Make executable.
  - Create `scripts/attack_tests/attack_dns_tunnel.sh`:
    - Header comment: prerequisites (`dig` or `iodine`), usage, expected detection
      (DNS_TUNNEL_001, DNS Tunneling), safe-use warning noting heuristic false-positive risk.
    - Body: loop sending `dig TXT` queries with long, high-entropy labels to `$TARGET_IP`.
    - Make executable.
  - Update `scripts/attack_tests/README.md` to document the three new scripts alongside
    the existing five.
  - _Requirements: 6.8, 7.7, 8.9_

---

- [x] 13. Phase B checkpoint — run full test suite
  - Run `pytest` — confirm all 511 baseline tests plus all new Phase A and B tests pass,
    zero failures.
  - Record the new total passing count.
  - Update `CHANGELOG.md` with Phase B completion entry.
  - _Requirements: 16.1, 16.2_


---

### Phase C: Cleanup

*Begin only after Phase A and Phase B are verified working (task 13 green).*

---

- [x] 14. Delete confirmed dead code (ai_routes.py, docs.zip, m.zip)
  - Confirm `backend/routes/ai_routes.py` still exists (`git ls-files backend/routes/ai_routes.py`).
  - Delete it.
  - Remove its import and `register_blueprint` call from `backend/api/__init__.py`:
    `from backend.routes.ai_routes import ai_bp` and `app.register_blueprint(ai_bp, ...)`.
  - Confirm `docs.zip` and `m.zip` exist at repo root; delete each if present.
  - Run `pytest` — confirm no test relied on `ai_bp` (none should; it was never registered
    before this spec either, but confirm explicitly).
  - Add entry to `CHANGELOG.md`.
  - _Requirements: 10.1, 10.2, 10.3, 10.5_

---

- [x] 15. Remove .gitkeep files from non-empty directories
  - Check `backend/api/`: contains `__init__.py`, `dependencies.py` → non-empty.
    Delete `backend/api/.gitkeep`.
  - Check `backend/models/`: if it contains only `.gitkeep` and nothing else, leave it.
    If it contains other files (e.g. from Phase A/B work), delete `.gitkeep`.
  - Run `pytest` — confirm still green.
  - _Requirements: 10.4_

---

- [x] 16. Remove __pycache__ and .pyc files from working tree
  - Run:
    ```powershell
    git ls-files --others --exclude-standard | Select-String "__pycache__|\.pyc"
    ```
    to find any untracked pycache files; separately check:
    ```powershell
    git ls-files | Select-String "__pycache__|\.pyc"
    ```
    for any tracked ones — `git rm --cached` those before deletion.
  - Delete all `__pycache__` directories and `.pyc` files from the working tree.
  - Leave `.gitignore` unchanged.
  - _Requirements: 11.1, 11.2, 11.3_

---

- [x] 17. Clear .hypothesis/tmp/ contents
  - Delete contents of `.hypothesis/tmp/` only (`examples/` subdirectory untouched):
    ```powershell
    Remove-Item -Recurse -Force ".hypothesis\tmp\*" -ErrorAction SilentlyContinue
    ```
  - _Requirements: 12.1, 12.2_

---

- [x] 18. Verify database artifacts are not tracked by git
  - Run `git ls-files database/netguard.db netguard.db-shm netguard.db-wal` — output
    must be empty (not tracked).
  - If any file is listed, run `git rm --cached <file>` and confirm `.gitignore` covers it.
  - _Requirements: 13.1, 13.2_

---

- [x] 19. Untrack .env if committed; update CONTRIBUTING.md
  - Run `git ls-files .env` — if output is non-empty, run `git rm --cached .env`.
  - Confirm `.env` still exists on disk after the untrack.
  - Add a clearly visible note to `CONTRIBUTING.md`: "Never commit `.env`. It contains
    local secrets. Use `.env.example` as the template."
  - _Requirements: 14.1, 14.2, 14.3, 14.4_

---

- [x] 20. Sweep and resolve TODO/FIXME/XXX introduced in Phase A/B
  - Run:
    ```powershell
    Select-String -Recurse -Path "backend\","detection\","frontend\js\" `
      -Pattern "TODO|FIXME|XXX|HACK" -Include "*.py","*.js"
    ```
  - For each hit: resolve inline if trivial, add a dated note if genuinely deferred,
    or remove if it references completed work.
  - `ponytail:` comments are NOT touched — they are intentional technical debt markers.
  - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5_

---

- [x] 21. Phase C checkpoint — full test suite + git status clean
  - Run `pytest` — confirm all tests still pass (same count as after task 13).
  - Run `git status` — confirm no unintended deletions or modifications.
  - Update `CHANGELOG.md` with Phase C completion entry.
  - _Requirements: 16.3_


---

### Phase D: Verification & Documentation

*Begin only after Phase C checkpoint (task 21) is green.*

---

- [x] 22. Update README.md and docs/API.md
  - In `README.md`:
    - Add `NETGUARD_API_KEY`, `TRUST_PROXY_HEADERS`, `REQUIRE_AUTH_FOR_READS` to the
      environment variable reference section.
    - Add `IcmpFloodRule`, `SlowHttpRule`, `DnsTunnelRule` to the detection rules list
      with a one-line description each.
    - Add note about Python 3.14 threading mode (AUDIT_REPORT.md §9 deferred item).
  - In `docs/API.md`:
    - Add the `X-API-Key` request header requirement to all mutating endpoint descriptions.
    - Verify that all endpoints currently registered in `backend/api/__init__.py` have
      a corresponding entry in `docs/API.md`; add any missing ones.
  - _Requirements: 18.1, 18.2_

---

- [x] 23. Update docs/ARCHITECTURE.md and SECURITY.md
  - In `docs/ARCHITECTURE.md`:
    - Add the three new detection rules to the detection layer section/diagram.
    - Note the new `ApiKeyAuth` middleware in the request pipeline description.
  - In `SECURITY.md` (already exists — add new sections, do not remove existing):
    - Section: API Key Authentication — model, trade-offs, no-auth dev mode.
    - Section: SocketIO Exclusion — why SocketIO traffic is not auth-gated and the
      trade-off this represents.
    - Section: Proxy Trust Model — `TRUST_PROXY_HEADERS` flag and its risks.
    - Section: Private IP Block Guard — what ranges are protected and the override.
  - _Requirements: 18.3, 18.4_

---

- [x] 24. Update CHANGELOG.md with final Phase D entry
  - Add a dated section (date: actual completion date) summarizing all changes across
    all four phases, organized as: Phase A changes, Phase B changes, Phase C changes,
    new test count (baseline 511 + new).
  - _Requirements: 16.5, 18.5_

---

- [x] 25. Produce VERIFICATION.md
  - Create `VERIFICATION.md` at repo root with:
    - A table per phase: change | verification method (automated test / manual smoke / code
      review) | status.
    - A "Still Development-Grade" section listing: in-process rate limiter, SQLite, iptables
      requiring root, single-secret API key, TLS not provided by app. Be honest — use
      "appropriate for single-server development/demo deployment, not for production
      multi-worker deployments without further hardening."
    - A "Human Review Required Before Production Deployment" section listing: secrets
      manager, Redis rate-limit backend, TLS at reverse proxy, `CAP_NET_ADMIN`, IPv6
      blocking.
  - _Requirements: 20.1, 20.2, 20.3, 20.4_

---

- [x] 26. Manual smoke test — all eight rules
  - This is a human-performed verification step. Run:
    1. Start the app (`python backend/main.py` or equivalent).
    2. Start monitoring on a loopback or dummy interface.
    3. For each of the eight rules, run the corresponding attack script and confirm:
       - A `ThreatEvent` appears in the dashboard within the rule's response-time ceiling.
       - The `Explanation` panel shows a non-empty `plain_english_text`.
       - A `new_threat` SocketIO event is received without a page reload.
       - For blocking rules (SYN Flood, Port Scan, SQL Injection, Brute Force, ICMP Flood,
         Slow HTTP): `iptables -L INPUT -n` shows a DROP rule for the source IP.
  - Record pass/fail per rule in `VERIFICATION.md`.
  - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5_

---

- [x] 27. Final pytest run — full suite
  - Run `pytest -v` and confirm:
    - 635 passing (minimum — task 4 will add ~5 new tests on top of this).
    - 51 pre-existing failures (unchanged — ARP spoof, auth middleware, rate limiter,
      security headers; these are known and unrelated to this spec's scope).
    - 14 skipped (platform tests, unchanged).
    - All 511 original tests pass.
    - All new tests added in Phase A (tasks 2–6) pass.
    - All new tests added in Phase B (tasks 8–10) pass.
    - New tests added in task 4 pass.
  - Record the final total in `VERIFICATION.md` and `CHANGELOG.md`.
  - _Requirements: 16.1, 16.2, 16.3, 16.4_

---

## Task Dependency Graph

```json
{
  "waves": [
    {
      "wave": 1,
      "tasks": ["1"],
      "note": "SECRET_KEY fix — must be first; subsequent tasks depend on create_app() being correct"
    },
    {
      "wave": 2,
      "tasks": ["2"],
      "note": "API auth middleware — depends on create_app() fix in task 1"
    },
    {
      "wave": 3,
      "tasks": ["3"],
      "note": "Rate limiter fix — independent of task 4"
    },
    {
      "wave": 3,
      "tasks": ["4"],
      "note": "Prevention engine private-IP guard — deferred, now pending; independent of other Phase A tasks; can run after task 3"
    },
    {
      "wave": 4,
      "tasks": ["5", "6"],
      "note": "Security headers and SQLi false-positive fix are independent; run in parallel"
    },
    {
      "wave": 5,
      "tasks": ["7"],
      "note": "Phase A checkpoint + env/docs update — gates Phase B"
    },
    {
      "wave": 6,
      "tasks": ["8", "9", "10"],
      "note": "Three new rules are independent of each other; implement in parallel"
    },
    {
      "wave": 7,
      "tasks": ["11"],
      "note": "Register rules in DetectionEngine — depends on tasks 8, 9, 10 complete"
    },
    {
      "wave": 8,
      "tasks": ["12"],
      "note": "Attack scripts — depends on rules being registered (task 11)"
    },
    {
      "wave": 9,
      "tasks": ["13"],
      "note": "Phase B checkpoint — gates Phase C"
    },
    {
      "wave": 10,
      "tasks": ["14", "15", "16", "17", "18", "19", "20"],
      "note": "All Phase C cleanup tasks are independent; run in any order after checkpoint"
    },
    {
      "wave": 11,
      "tasks": ["21"],
      "note": "Phase C checkpoint — gates Phase D"
    },
    {
      "wave": 12,
      "tasks": ["22", "23", "24", "25"],
      "note": "Documentation tasks are independent; run in parallel after Phase C"
    },
    {
      "wave": 13,
      "tasks": ["26"],
      "note": "Manual smoke test — requires complete app (all phases done)"
    },
    {
      "wave": 14,
      "tasks": ["27"],
      "note": "Final pytest run — last gate; nothing is done until this is green"
    }
  ]
}
```

---

## Notes

- **Phase ordering is mandatory.** Phase C cleanup must not begin before Phase A and B are
  verified (task 13 green). Cleaning dead code before hardening risks removing something
  still in use during development. Task 4 (prevention guard) was deferred but can be
  implemented now — it is independent of all Phase B–D tasks that are already complete.

- **One task, one pytest run.** Never batch multiple tasks and run tests once at the end.
  A red test suite at task N means the diff from task N is the suspect — not a diff
  spanning five tasks.

- **`ponytail:` comments introduced in new code are kept.** They mark deliberate
  simplifications with a named ceiling and upgrade path, as required by workspace rules.

- **No new runtime dependencies** beyond `ipaddress` (stdlib), `hmac` (stdlib), and
  `psutil` (already in `requirements.txt`). The DNS parser uses `collections.Counter`
  and `math.log2` (both stdlib). If a proposed implementation requires a new package,
  stop and justify it in the task's completion notes before adding it.

- **Property tests in existing files.** New tests for tasks 6, 8, 9, 10 are added to the
  nearest existing test file or a new `tests/test_<rule>_rule.py` file — never replacing
  existing test files.

- **`CHANGELOG.md` is updated after every phase checkpoint** (tasks 7, 13, 21, 24/27),
  not after every individual task. Task-level notes belong in commit messages.

