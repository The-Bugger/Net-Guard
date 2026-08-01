# Implementation Plan: NetGuard Hackathon Upgrade

## Overview

Extend the existing NetGuard IDPS into a hackathon-ready SOC platform. All changes are
additive — no rewrites, no new dependencies beyond what's already in `requirements.txt`.
The guiding principle is minimum code: reuse existing patterns in `backend/services/`,
`backend/routes/`, and `database/` at every step.

Language: Python 3.11+ (backend), vanilla JavaScript ES6 (frontend).

---

## Tasks

### Phase 1: Backend Infrastructure — Middleware, StatsService additions, Detection routes

- [x] 1. Add security headers middleware and input sanitisation
  - Create `backend/middleware/` directory with `__init__.py`
  - Create `backend/middleware/security_headers.py` — `add_security_headers(response)` after_request hook (4 headers) and `sanitise_and_validate()` before_request hook (strip whitespace + 1024-char check → 422 INPUT_TOO_LONG)
  - Register both hooks in `backend/api/__init__.py` `create_app()`; add global `@app.errorhandler(Exception)` returning 500 INTERNAL_ERROR (no traceback)
  - _Requirements: 11.1, 11.2, 11.3, 11.4_

  - [ ] 1.1 Write property test for security headers (Property 10)
    - **Property 10: Security Headers on All Responses** — for any sampled `/api/v1` endpoint, all 4 headers present regardless of status code
    - **Validates: Requirements 11.1**
    - `# Feature: netguard-hackathon-upgrade, Property 10`
    - File: `tests/test_properties_hackathon.py`

- [ ] 2. Add rate limiter middleware
  - Create `backend/middleware/rate_limiter.py` — `RateLimiter` class with `before_request` sliding-window check; 120 req/60 s per IP; exempt set `{"/api/v1/health", "/api/v1/dashboard/live", "/api/v1/status"}`; `X-Forwarded-For` leftmost IP; returns 429 with `Retry-After` header
  - Register `RateLimiter` in `create_app()` via `app.before_request(limiter.check)`
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

  - [ ] 2.1 Write property test for rate limiter (Property 9)
    - **Property 9: Rate Limit Enforcement** — 121 mock requests within window → 121st returns 429; first 120 pass normally
    - **Validates: Requirements 10.1, 14.7**
    - `# Feature: netguard-hackathon-upgrade, Property 9`
    - File: `tests/test_properties_hackathon.py`

- [ ] 3. Extend StatsService with health score and 2-second cache
  - Add `get_health_score() -> int` to `backend/services/stats_service.py` using formula `max(0, min(100, 100 - alerts_today*5 - active_blocks*2))`; return -1 on DB error
  - Add `_cache_data`, `_cache_time`, `_lock` to `StatsService.__init__`; wrap `get_dashboard_data()` with 2-second in-process cache
  - Add `invalidate_cache()` method (sets `_cache_time = 0` under lock)
  - Wire `stats_service.invalidate_cache()` call in `backend/main.py` `_on_threat_event` after `event_repo.insert()`
  - Add `health_score` to `GET /api/v1/status` response in `health_routes.py`
  - Add `health_score` to `GET /api/v1/dashboard` response in `dashboard_routes.py`
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 12.2, 12.3_

  - [ ] 3.1 Write property test for health score bounds (Property 5)
    - **Property 5: Health Score Bounds** — for any non-negative integers `alerts_today`, `active_blocks`, `get_health_score()` ∈ [0, 100]
    - **Validates: Requirements 9.1, 9.5, 14.3**
    - `# Feature: netguard-hackathon-upgrade, Property 5`
    - File: `tests/test_properties_hackathon.py`

- [ ] 4. Extend detection routes with search, total, and strict pagination
  - Add `count_filtered(filters)` method to `backend/repositories/event_repository.py`
  - Extend `get_all()` to support `filters["search"]` as case-insensitive LIKE OR match on `source_ip`, `destination_ip`, `attack_type`
  - Update `backend/routes/detection_routes.py`: parse `search` param; validate `limit >= 1`, `offset >= 0`, non-integer → HTTP 422 INVALID_PAGINATION_PARAMS; clamp `limit` to 500 silently; add `total` and `offset` to response
  - _Requirements: 8.1, 8.3, 8.5, 8.6, 8.7_

  - [ ] 4.1 Write property tests for search and AND filter correctness (Properties 11, 12)
    - **Property 11: Detections Search Correctness** — every result contains search string in source_ip, destination_ip, or attack_type
    - **Property 12: AND Filter Correctness** — every result satisfies ALL active filter conditions simultaneously
    - **Validates: Requirements 8.1, 8.3**
    - `# Feature: netguard-hackathon-upgrade, Property 11` and `Property 12`
    - File: `tests/test_properties_hackathon.py`

  - [ ] 4.2 Write property test for pagination non-overlap (Property 8)
    - **Property 8: Pagination Non-Overlap** — for any N ∈ [1, 500], offset=0 and offset=N result sets share no `event_id` values
    - **Validates: Requirements 14.6**
    - `# Feature: netguard-hackathon-upgrade, Property 8`
    - File: `tests/test_properties_hackathon.py`

- [x] 5. Add DB indexes for filter query performance
  - In `database/schema.py`, add SQLAlchemy `Index` entries on `Event`: `(attack_type)`, `(severity)`, `(source_ip)`, `(timestamp)`
  - Call `Base.metadata.create_all()` (already wired) to apply indexes on next startup; no migration needed for SQLite
  - _Requirements: 12.1_

- [~] 6. Checkpoint — middleware and detection enhancements complete
  - Ensure all tests pass, ask the user if questions arise.

---

### Phase 2: New Backend Services — DemoService, AIExplainService, ExportService

- [ ] 7. Implement DemoService
  - Create `backend/services/demo_service.py` with `DemoService` class: `__init__(on_threat_event, block_repo)`, `start()`, `stop()`, `trigger(attack_type) -> str`, `get_status() -> dict`, `_emit_loop()`, `_build_event(template) -> ThreatEvent`, `is_active` property
  - Define `_TEST_NET_RANGES` (3 × RFC 5737 networks) and `_ATTACK_TEMPLATES` (9 entries per design)
  - Use `threading.Event` for clean stop; random TEST-NET source IP per event; include `demo: True` in evidence dict
  - On `start()`: add all TEST-NET ranges to `whitelist_manager`; on `stop()`: remove them
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8_

  - [ ] 7.1 Write property test for demo source IP in TEST-NET (Property 1)
    - **Property 1: Demo Source IP in TEST-NET** — for any generated event, `source_ip` falls within one of the three RFC 5737 ranges
    - **Validates: Requirements 1.6**
    - `# Feature: netguard-hackathon-upgrade, Property 1`
    - File: `tests/test_properties_hackathon.py`

  - [ ] 7.2 Write property test for demo event schema invariant (Property 2)
    - **Property 2: Demo Event Schema Invariant** — for any sampled Attack_Template, built event has non-null/non-empty: event_id, timestamp, attack_type, source_ip, rule_name, severity, confidence, explanation, recommendation; evidence contains `demo: True`
    - **Validates: Requirements 1.8, 14.1**
    - `# Feature: netguard-hackathon-upgrade, Property 2`
    - File: `tests/test_properties_hackathon.py`

- [ ] 8. Implement AIExplainService
  - Create `backend/services/ai_explain_service.py` with `AIExplanation` dataclass (11 fields) and `AIExplainService` class: `generate()`, `_get_cached()`, `_put_cached()` (OrderedDict LRU, 100 entries), `_call_provider()`, `_call_stub()`, `_call_gemini()`, `_call_openai()`, `_parse_llm_response()`, `_stub_response()`
  - `generate()` raises `ValueError` on None inputs; dispatches via `AI_PROVIDER` env var (default `"stub"`); provider errors fall back to stub with `is_fallback=True` and WARNING log to `logs/errors.log`
  - `_stub_response()` f-string template contains all 7 required markdown section headers
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10_

  - [ ] 8.1 Write property test for AI explanation fields invariant (Property 3)
    - **Property 3: AI Explanation Fields Invariant** — for any valid (non-None) inputs, returned `AIExplanation` has non-empty `markdown_report` with all 7 section headers; list fields are `list` (not None)
    - **Validates: Requirements 2.4, 2.9, 14.2**
    - `# Feature: netguard-hackathon-upgrade, Property 3`
    - File: `tests/test_properties_hackathon.py`

  - [ ] 8.2 Write property test for AI ValueError on None inputs (Property 4)
    - **Property 4: AI Explanation Rejects Null Inputs** — `generate(None, x)` and `generate(x, None)` both raise `ValueError` before any provider call
    - **Validates: Requirements 2.1, 2.10**
    - `# Feature: netguard-hackathon-upgrade, Property 4`
    - File: `tests/test_properties_hackathon.py`

- [ ] 9. Implement ExportService
  - Create `backend/services/export_service.py` with `ExportService` class: `export_json()`, `export_csv()`, `export_markdown()`, `export_pdf()`, `_fetch_events(filters)`, `_filename(fmt)`
  - `_fetch_events()` calls `event_repo.get_all(filters, limit=10000, offset=0)` — single code path for all formats
  - `export_pdf()` raises `ImportError` → caller returns HTTP 501 PDF_NOT_SUPPORTED
  - All formats ordered by timestamp descending; filename pattern `netguard-export-{YYYY-MM-DD}.{fmt}` (UTC)
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7_

  - [ ] 9.1 Write property test for export count parity (Property 7)
    - **Property 7: Export Count Parity** — for any valid filter combo, JSON export record count equals `total` from `GET /api/v1/detections` with same filters
    - **Validates: Requirements 6.5, 14.5**
    - `# Feature: netguard-hackathon-upgrade, Property 7`
    - File: `tests/test_properties_hackathon.py`

- [~] 10. Checkpoint — new services complete
  - Ensure all tests pass, ask the user if questions arise.

---

### Phase 3: New Route Blueprints

- [~] 11. Implement demo routes blueprint
  - Create `backend/routes/demo_routes.py` with `demo_bp`: `POST /demo/start` (409 DEMO_ALREADY_RUNNING if active), `POST /demo/stop` (409 DEMO_NOT_RUNNING if inactive), `POST /demo/trigger` (422 INVALID_ATTACK_TYPE on unknown type; returns `{"event_id": ...}`), `GET /demo/status`
  - Register DemoService in `backend/main.py` dependency container (pass `_on_threat_event` callback and `block_repo`)
  - Register `demo_bp` in `backend/api/__init__.py`
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.7, 7.1, 7.2, 7.5_

- [~] 12. Implement AI explanation routes blueprint
  - Create `backend/routes/ai_routes.py` with `ai_bp`: `GET /ai-explanation/<event_id>` — looks up event via `event_repo.get_by_id()` (404 NOT_FOUND if absent), calls `AIExplainService.generate()`; wraps response in standard envelope
  - Register AIExplainService in `backend/main.py`; register `ai_bp` in `backend/api/__init__.py`
  - _Requirements: 2.6_

- [ ] 13. Implement timeline routes blueprint
  - Create `backend/routes/timeline_routes.py` with `timeline_bp`: `GET /timeline/<event_id>` — 404 if event absent; build ordered Timeline_Entry list using `_build_timeline(event, block)` helper; `analyzed_at` fallback = `detected_at + 500ms`; Notified/Reported always included as `"skipped"` unless records exist
  - Register `timeline_bp` in `backend/api/__init__.py`
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.7_

  - [ ] 13.1 Write property test for timeline chronological order (Property 13)
    - **Property 13: Timeline Chronological Order** — for any existing event_id, Timeline_Entry timestamps are non-decreasing; first entry has `step_name = "Detected"` and `status = "completed"`
    - **Validates: Requirements 4.1, 4.2**
    - `# Feature: netguard-hackathon-upgrade, Property 13`
    - File: `tests/test_properties_hackathon.py`

- [ ] 14. Implement analytics routes blueprint
  - Create `backend/routes/analytics_routes.py` with `analytics_bp`: `GET /analytics` accepting `period` param (default `"daily"`); inline `_compute_analytics(event_repo, period) -> dict` helper; returns buckets, top_ips, severity_counts, protocol_counts, total_events, blocked_count, detected_count
  - Register `analytics_bp` in `backend/api/__init__.py`
  - _Requirements: 5.1, 5.2, 5.3, 5.4_

  - [ ] 14.1 Write property test for analytics bucket sum (Property 6)
    - **Property 6: Analytics Bucket Sum Equals Total Events** — for any DB state and any period, sum of bucket counts equals `total_events` in same response
    - **Validates: Requirements 5.4, 14.4**
    - `# Feature: netguard-hackathon-upgrade, Property 6`
    - File: `tests/test_properties_hackathon.py`

- [~] 15. Implement export routes blueprint
  - Create `backend/routes/export_routes.py` with `export_bp`: `GET /export` — dispatch on `format` param to `ExportService`; set correct `Content-Type` and `Content-Disposition` headers; 400 INVALID_EXPORT_FORMAT on unknown format; 501 PDF_NOT_SUPPORTED on ImportError
  - Register `export_bp` in `backend/api/__init__.py`
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.6, 6.7_

- [~] 16. Checkpoint — all route blueprints registered and responding
  - Ensure all tests pass, ask the user if questions arise.

---

### Phase 4: Frontend — Dashboard Redesign, New Pages

- [~] 17. Update `frontend/css/dark-theme.css` with SOC palette and glassmorphism
  - Add CSS variables: `--accent: #00E5FF`, `--success: #4ADE80`, `--warning: #FACC15`, `--danger: #F87171`, `--bg: #0F172A`
  - Add `.card-glass` class (backdrop-filter, semi-transparent background, border)
  - Add severity badge colour rules for `#F87171` (Critical/High), `#FACC15` (Medium), `#4ADE80` (Low)
  - _Requirements: 3.7_

- [~] 18. Redesign `frontend/index.html` — SOC dashboard
  - Add three new KPI cards to `.kpi-grid`: Blocked IPs Total, Detection Accuracy %, Security Health Score (coloured by threshold: <50 danger, 50–79 warning, ≥80 success)
  - Add System Health panel (CPU, memory, uptime, monitoring status) — polling `GET /api/v1/status`
  - Add Live Status Badges bar (Monitoring Active/Stopped, Demo Active/Stopped, AI Available/Unavailable) with pulsing dot
  - Add Attack Simulator panel: 9 buttons (one per attack type); on click POST `/api/v1/demo/trigger`; success toast (3 s auto-dismiss) showing event_id; error toast (5 s) on failure
  - Add activity feed panel (last 10 SocketIO events: `new_threat`, `ip_blocked`, `ip_unblocked`) with severity badge colours
  - _Requirements: 3.1, 3.3, 3.4, 3.5, 3.8, 7.3, 7.4_

- [~] 19. Update `frontend/js/dashboard.js` (or equivalent) — animation, SocketIO, fullscreen
  - Implement `countUp(el, from, to, durationMs=600)` — animates only when SocketIO connected; skips to final on polling
  - Wire SocketIO `new_threat`, `ip_blocked`, `ip_unblocked` handlers to update KPIs and prepend to activity feed (keep last 10)
  - Add `GET /api/v1/dashboard/live` polling at 2-second intervals when SocketIO disconnected; show/hide reconnecting indicator
  - Add `Ctrl+Shift+P` / `Cmd+Shift+P` fullscreen toggle; show toast if browser denies
  - _Requirements: 3.2, 3.6, 3.9, 13.3_

- [~] 20. Create `frontend/landing.html` and `frontend/js/landing.js`
  - `landing.html`: static — header (logo + tagline), 5 feature cards with inline SVG icons, CTA section with "Launch Dashboard" `<a href="/">` button and "Start Demo" button; hidden `#error-msg` div; no external URL references
  - `landing.js` (~20 lines): `startDemo()` POSTs `/api/v1/demo/start`; on 200 redirect to `/`; on error show inline message
  - Copy Chart.js and Socket.IO to `frontend/js/vendor/` if not already present (for offline use by `landing.html`)
  - Register `/landing` route in `backend/api/__init__.py` using existing `send_from_directory` pattern
  - _Requirements: 13.1, 13.2, 13.4_

- [~] 21. Create `frontend/timeline.html` and `frontend/js/timeline.js`
  - `timeline.html`: reads `?event_id=<uuid>` from URL; calls `GET /api/v1/timeline/{event_id}`; renders vertical timeline using CSS `::before` border trick (no new library); each step shows circle icon, step name, timestamp, description, status badge; 404 case shows error message
  - Register `/timeline` route in `backend/api/__init__.py`
  - _Requirements: 4.6_

- [~] 22. Create `frontend/analytics.html` and `frontend/js/analytics.js`
  - `analytics.html`: period `<select>` (hourly/daily/weekly); bar chart (Chart.js CDN, same URL as index.html); doughnut chart for severity; top-attacker-IPs `<table>`; KPI cards for total_events, blocked_count, detected_count
  - `analytics.js`: on period change, fetch `/api/v1/analytics?period=<selected>` and update all charts + KPIs without page reload
  - Register `/analytics` route in `backend/api/__init__.py`
  - _Requirements: 5.5, 5.6_

- [~] 23. Checkpoint — frontend complete, all pages render
  - Ensure all tests pass, ask the user if questions arise.

---

### Phase 5: Unit and Example Tests

- [~] 24. Write unit tests for new backend components
  - Create `tests/test_hackathon_upgrade.py` with example-based tests covering:
    - `test_demo_start_stop` — start/stop lifecycle, HTTP 200 both ways (Req 1.1, 1.4)
    - `test_demo_double_start_409` — DEMO_ALREADY_RUNNING (Req 1.2)
    - `test_demo_stop_when_inactive_409` — DEMO_NOT_RUNNING (Req 1.5)
    - `test_demo_trigger_all_9_types` — one per attack type, returns event_id (Req 7.1)
    - `test_demo_trigger_unknown_422` — INVALID_ATTACK_TYPE (Req 7.2)
    - `test_ai_provider_stub_default` — no AI_PROVIDER set → stub used (Req 2.3)
    - `test_ai_fallback_on_provider_error` — mock provider raises → is_fallback=True (Req 2.5)
    - `test_ai_lru_eviction` — insert 101 entries → oldest evicted (Req 2.7)
    - `test_export_json_csv_markdown_headers` — Content-Disposition filename format (Req 6.1–6.3)
    - `test_export_pdf_501_without_library` — mock importlib failure → 501 (Req 6.4)
    - `test_export_invalid_format_400` (Req 6.7)
    - `test_timeline_404_nonexistent` (Req 4.5)
    - `test_timeline_detected_step_always_first` (Req 4.2)
    - `test_health_score_in_status_and_dashboard` (Req 9.2, 9.3)
    - `test_rate_limit_retry_after_header` (Req 10.2)
    - `test_rate_limiter_exempted_endpoints_not_blocked` (Req 10.3, 10.4)
    - `test_pagination_clamp_to_500` (Req 8.6)
    - `test_pagination_invalid_422` (Req 8.7)
    - `test_security_headers_on_error_response` (Req 11.1)
    - `test_input_too_long_422` (Req 11.3)
    - `test_no_traceback_in_response` (Req 11.4)
    - `test_dashboard_cache_hit` (Req 12.2)
    - `test_dashboard_cache_invalidated_on_new_event` (Req 12.3)
  - _Requirements: 1.1–1.8, 2.1–2.10, 6.1–6.7, 4.5, 7.1–7.2, 8.6–8.7, 9.2–9.3, 10.2–10.4, 11.1–11.4, 12.2–12.3_

- [~] 25. Final checkpoint — all unit and property tests pass
  - Ensure all tests pass, ask the user if questions arise.

---

### Phase 6: UX Polish — Skeletons, Toasts, Empty States, Keyboard Shortcuts

- [~] 26. Add loading skeleton animations to detections list
  - In `frontend/js/detections.js` (or equivalent), show a `.skeleton-row` placeholder grid while a fetch is in-flight; remove it and render results (or empty-state message) on response
  - Define `.skeleton-row` CSS with animated `background: linear-gradient` shimmer in `dark-theme.css`
  - _Priority 2 — loading skeletons (Req 8.2)_

- [~] 27. Implement toast notification system
  - Add `showToast(message, type, durationMs)` utility in `frontend/js/utils.js` — appends a `.toast` div to `#toast-container`, auto-removes after duration; types: `success` (#4ADE80), `error` (#F87171), `warning` (#FACC15), `info` (#00E5FF)
  - Add `#toast-container` fixed overlay div to `index.html` (and other pages that need it)
  - Replace any existing `alert()` calls with `showToast()`
  - _Priority 2 — toast notifications_

- [~] 28. Add empty states and error pages
  - In detections list: when API returns 0 results, render an `.empty-state` div with an icon and "No detections found" message
  - Create `frontend/404.html` served by Flask `@app.errorhandler(404)` — branded 404 with "Return to Dashboard" link
  - Create `frontend/500.html` served by Flask `@app.errorhandler(500)` — branded 500 with support info
  - _Priority 2 — empty states, error pages_

- [~] 29. Add keyboard shortcuts
  - In `frontend/js/dashboard.js`, register `keydown` listener: `D` → focus detections search, `Ctrl+/` → open keyboard shortcut help modal, `Ctrl+Shift+P` → fullscreen toggle (already in task 19, wire help modal here), `Esc` → close any open modal
  - Add `#shortcuts-modal` hidden div to `index.html` listing all shortcuts; toggle visibility on `Ctrl+/`
  - _Priority 2 — keyboard shortcuts_

- [~] 30. Checkpoint — UX polish complete
  - Ensure all pages render correctly, toasts fire, skeletons show, empty states display.

---

### Phase 7: Visualizations — World Map, Topology, Charts

- [~] 31. Add severity gauge and security score ring to dashboard
  - In `index.html`, add a `<canvas id="severity-gauge">` SVG arc drawn with vanilla JS (no new library) that fills from green→yellow→red based on `health_score`; update on each `live_stats` SocketIO event
  - Add a progress-ring SVG `<circle>` for Detection Accuracy % — CSS `stroke-dashoffset` animation
  - `ponytail:` vanilla SVG/canvas arc; no Chart.js gauge plugin needed for two arcs
  - _Priority 3 — severity gauge, security score ring_

- [~] 32. Add animated network topology panel
  - Add `<canvas id="network-topology">` to `index.html`; in `frontend/js/topology.js`, draw a simple star topology (attacker node → gateway → server nodes) using Canvas 2D API; on each `new_threat` event, animate a red pulse along the attacker→gateway edge
  - `ponytail:` Canvas 2D only; no D3 or new dependency; ceiling: static layout, upgrade path is D3 force simulation
  - _Priority 3 — animated network topology_

- [~] 33. Add world attack map panel
  - Add `<div id="attack-map">` to `analytics.html`; use a freely licensed SVG world map (inline in the page, no CDN) and place coloured dot markers at hardcoded lat/lon centroids for the top attacker IPs returned by `GET /api/v1/analytics`; update on period change
  - `ponytail:` static SVG map with JS-positioned `<circle>` overlays; no Leaflet/Mapbox; ceiling: not geo-accurate, upgrade path is Leaflet + IP geolocation API
  - _Priority 3 — world attack map_

- [~] 34. Add live traffic graph to dashboard
  - In `index.html`, add a `<canvas id="traffic-chart">` Chart.js line chart (Chart.js already loaded) tracking packets/sec over the last 60 seconds; push a new data point on each `live_stats` SocketIO event; shift oldest point off when length > 60
  - _Priority 3 — live traffic graph (reuses existing Chart.js)_

- [~] 35. Add threat radar chart to analytics page
  - In `analytics.html`, add a `<canvas id="threat-radar">` Chart.js radar chart with axes for each of the 9 attack types; data sourced from `GET /api/v1/analytics` severity_counts; update on period change
  - `ponytail:` Chart.js radar type is already available if Chart.js is loaded — zero new dependency
  - _Priority 3 — threat radar_

- [~] 36. Checkpoint — all visualizations render without errors
  - Verify canvas/SVG elements initialise on page load and update on live events.

---

### Phase 8: Hackathon Features — AI Assistant, Incident Replay, Onboarding Tour

- [~] 37. Add AI Security Assistant chat panel
  - Add `<div id="ai-assistant-panel">` slide-in drawer to `index.html` with a text input and submit button; `POST /api/v1/ai-assistant` endpoint in a new `backend/routes/ai_assistant_routes.py` accepts `{"question": "..."}` and returns `{"answer": "..."}` using AIExplainService stub (format: "You asked about X. Based on current detections: ...")
  - Toggle panel open/close with a floating action button (💬) in the bottom-right corner
  - `ponytail:` the assistant route re-uses AIExplainService._stub_response() with a question-answering template — no new service needed
  - _Priority 7 — AI Security Assistant_

- [~] 38. Add incident replay feature
  - Add `GET /api/v1/events/{event_id}/replay` endpoint in `demo_routes.py` (no new file): look up event by id, call `demo_service.trigger(event.attack_type)` — this re-emits an identical synthetic event through the existing pipeline and returns the new `event_id`
  - Add a "Replay" button to each row in the detections table that calls this endpoint; show success/error toast
  - _Priority 7 — Attack Replay (reuses DemoService.trigger)_

- [~] 39. Add first-time onboarding tour
  - On first page load (localStorage key `ng_toured` absent), show a 5-step guided tour using a lightweight inline tour implementation (vanilla JS, no Shepherd.js): sequential `.tour-highlight` CSS overlay on target elements with a tooltip div showing step text and Next/Skip buttons; steps: (1) Live Metrics, (2) Activity Feed, (3) Attack Simulator, (4) Demo Mode, (5) Analytics link
  - Set `localStorage.ng_toured = "1"` after tour completes or is skipped
  - `ponytail:` ~80-line vanilla JS tour; no Shepherd or Intro.js dependency
  - _Priority 7 — first-time onboarding_

- [~] 40. Add quick actions bar and recent incidents widget
  - Add a `.quick-actions` bar to `index.html` with icon buttons: Start Demo, Stop Demo, Export JSON, View Analytics, Open AI Assistant; wire each to the existing JS functions already implemented
  - Add a `.recent-incidents` card showing the 5 most recent events from `GET /api/v1/detections?limit=5`; auto-refresh every 30 seconds
  - _Priority 7 — quick actions, recent incidents_

- [~] 41. Checkpoint — hackathon features complete
  - Ensure AI assistant responds, replay works, onboarding tour displays on fresh localStorage.

---

### Phase 9: Presentation Pages

- [~] 42. Create `frontend/about.html` — landing/about page
  - Static page served at `/about`: NetGuard logo, tagline, feature highlights (5 cards with SVG icons matching landing.html), architecture summary (Mermaid diagram rendered client-side via CDN-less Mermaid.js inline build or a static SVG export), team section placeholder, link back to dashboard
  - Register `/about` route in `backend/api/__init__.py`
  - No external CDN requests — all assets self-hosted per Req 13.4 pattern
  - _Priority 8 — feature overview, about page_

- [~] 43. Create `frontend/architecture.html` — architecture page
  - Static page served at `/architecture`: embedded SVG architecture diagram (the Mermaid graph from design.md exported as static SVG), component descriptions for each layer (CaptureEngine → DetectionEngine → ExplainabilityEngine → PreventionEngine → Flask API → Frontend), and a "How It Works" numbered walkthrough
  - Register `/architecture` route in `backend/api/__init__.py`
  - _Priority 8 — architecture page, how it works_

- [~] 44. Add judges/presentation mode
  - In `index.html`, add a `#judges-banner` div (hidden by default) with text "🏆 JUDGES MODE — MVIC Build Nepal Hackathon 2026"; show it when URL contains `?judges=1` or `?presentation=1`
  - When judges mode is active: auto-start demo if not already running (call `POST /api/v1/demo/start`), hide navigation links that are not relevant to the demo flow, add a floating "Next Feature →" button cycling through a predefined demo script array (Demo Mode → AI Explanation → Analytics → Export → Timeline)
  - `ponytail:` URL query param check at page load; ~30 lines; no new route needed
  - _Priority 8 — judges mode, presentation mode_

- [~] 45. Checkpoint — presentation pages complete
  - Verify all static pages load, no external domain requests, judges mode activates correctly.

---

### Phase 10: Code Quality and Documentation

- [~] 46. Improve logging and CORS configuration
  - In `backend/api/__init__.py`, ensure `flask-cors` CORS config restricts allowed origins to `ALLOWED_ORIGINS` env var (default `*` for dev, documented in `.env.example`); add the env var to `.env.example` with a comment
  - Audit `backend/services/` and `backend/routes/` for bare `except:` clauses; replace with `except Exception as e:` + `logger.error(...)` using the existing `logger` pattern
  - _Priority 4 — CORS, logging_

- [~] 47. Add type annotations and docstrings to new files
  - Add `-> None / -> dict / -> str` return type annotations to all public methods in `demo_service.py`, `ai_explain_service.py`, `export_service.py`, `rate_limiter.py`, `security_headers.py`
  - Add one-line docstrings to all public methods that lack them (Google style: first line summary only)
  - _Priority 6 — typing, documentation_

- [~] 48. Update README
  - Add sections to `README.md`: Quick Start (includes demo mode instructions), New Features (list of all added capabilities with one-line descriptions), Environment Variables table (AI_PROVIDER, ALLOWED_ORIGINS), API Reference additions (new endpoints), Screenshots placeholder
  - _Priority 6 — README updates_

- [~] 49. Final end-to-end checkpoint
  - Run full test suite (`pytest tests/` with `--tb=short`); confirm 0 failures
  - Manually verify: demo mode starts/stops, AI explanation loads, analytics charts render, export downloads work, rate limiter returns 429 on 121st request, security headers present on all responses
  - Ensure all tests pass, ask the user if questions arise.

---

## Notes

- Tasks marked `*` are optional and can be skipped for a faster MVP
- Property tests live in `tests/test_properties_hackathon.py`; unit/example tests in `tests/test_hackathon_upgrade.py`
- All new backend files follow existing patterns: service in `backend/services/`, blueprint in `backend/routes/`, middleware in `backend/middleware/`
- `ponytail:` the AnalyticsService is an inline helper in `analytics_routes.py` — no separate class (ceiling: O(events) Python grouping fine for <10K events; upgrade path: push GROUP BY into SQLAlchemy)
- `ponytail:` RateLimiter uses a global in-process defaultdict — not shared across workers (upgrade path: Redis INCR + EXPIRE)
- `ponytail:` AIExplainService LRU uses stdlib `collections.OrderedDict` — no `functools.lru_cache` because keyed eviction is needed
- `ponytail:` ExportService uses `limit=10000` hard ceiling for demo dataset; no pagination loop

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1", "2", "3", "5"] },
    { "id": 1, "tasks": ["1.1", "2.1", "3.1", "4"] },
    { "id": 2, "tasks": ["4.1", "4.2", "7", "8", "9"] },
    { "id": 3, "tasks": ["7.1", "7.2", "8.1", "8.2", "9.1", "11", "12", "13", "14", "15"] },
    { "id": 4, "tasks": ["13.1", "14.1", "17"] },
    { "id": 5, "tasks": ["18", "19", "20", "21", "22"] },
    { "id": 6, "tasks": ["24", "26", "27", "28", "29"] },
    { "id": 7, "tasks": ["31", "32", "33", "34", "35"] },
    { "id": 8, "tasks": ["37", "38", "39", "40"] },
    { "id": 9, "tasks": ["42", "43", "44"] },
    { "id": 10, "tasks": ["46", "47", "48"] },
    { "id": 11, "tasks": ["49"] }
  ]
}
```
