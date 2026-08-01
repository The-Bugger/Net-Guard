# Requirements Document

## Introduction

This document specifies the enhancements needed to transform the existing NetGuard IDPS into a
hackathon-winning enterprise cybersecurity platform for the MVIC Build Nepal Hackathon 2026.

The existing Flask/SQLAlchemy/SQLite/SocketIO/Detection Engine architecture is preserved in full.
No rewrite. All new capabilities are added on top of the working system described in
`.kiro/specs/netguard-idps/requirements.md`. Where a requirement extends an existing component,
the component name from the netguard-idps Glossary is used without re-definition.

---

## Glossary

- **Demo_Engine**: The new backend service (`backend/services/demo_service.py`) that generates
  synthetic Threat_Events and pushes them through the existing `_on_threat_event` pipeline
  without requiring live network traffic.
- **Attack_Template**: A pre-defined data structure describing one simulated attack type;
  contains attack_type, rule_name, severity, confidence, source_ip, destination_ip,
  protocol, evidence, and packet_count.
- **AI_Explanation_Service**: The new provider-abstracted service
  (`backend/services/ai_explain_service.py`) that generates enriched threat explanations using
  a configurable LLM backend (Gemini, OpenAI, or a local stub).
- **AI_Explanation**: The structured object produced by AI_Explanation_Service; contains
  attack_name, severity, confidence_pct, description, business_impact, attacker_methodology,
  immediate_actions (list), long_term_recommendations (list), mitre_attack_mapping (list),
  cve_references (list), and markdown_report (string).
- **Health_Score**: An integer in the range [0, 100] computed from active blocks, alerts_today,
  and blocked-IP ratio, used to represent the overall security posture of the monitored network.
- **Analytics_Endpoint**: The new `GET /api/v1/analytics` endpoint that returns time-bucketed
  detection counts alongside top-N aggregations used by the analytics dashboard page.
- **Export_Service**: The new service (`backend/services/export_service.py`) that serialises
  detection event records into PDF, CSV, JSON, and Markdown formats.
- **Timeline_Entry**: A structured object representing one step in an incident's lifecycle;
  contains step_name, timestamp, description, and status.
- **Incident_Timeline**: The ordered list of Timeline_Entry objects for a given event_id,
  covering the steps: Detected, Analyzed, Blocked, Notified, Reported.
- **Rate_Limiter**: A per-IP, per-endpoint request counter enforcing a configurable maximum
  requests per minute; implemented as Flask middleware using an in-memory sliding window.
- **Security_Health_Score**: Synonym for Health_Score used in the dashboard UI context.
- **Demo_Session**: The active state of the Demo_Engine between a "start" and "stop" call;
  exactly one Demo_Session may be active at a time.

---

## Requirements

### Requirement 1: Demo Mode

**User Story:** As a hackathon judge, I want to see NetGuard detect and respond to realistic
attacks immediately upon clicking "Start Demo", without needing real network traffic, so that
I can evaluate the full detection-to-block pipeline in under 90 seconds.

#### Acceptance Criteria

1. WHEN the REST_API receives `POST /api/v1/demo/start` and no Demo_Session is active,
   THE Demo_Engine SHALL begin emitting synthetic Threat_Events at random intervals between
   2 and 5 seconds, cycling continuously through all nine Attack_Templates (SQL Injection,
   Brute Force, Port Scan, DDoS/SYN Flood, XSS, SSH Login, Suspicious DNS, Malware Download,
   Privilege Escalation) in a randomised order (repeating the cycle after all nine have been
   emitted once), until explicitly stopped, and SHALL return HTTP 200.
2. WHEN the REST_API receives `POST /api/v1/demo/start` while a Demo_Session is already
   active, THE REST_API SHALL return HTTP 409 with error code "DEMO_ALREADY_RUNNING".
3. WHEN the Demo_Engine emits a synthetic Threat_Event, THE Demo_Engine SHALL pass it
   through the existing `_on_threat_event` callback so that the event is persisted to
   the `events` table, triggers the ExplainabilityEngine, triggers the Prevention_Engine,
   and is broadcast via SocketIO — identical to a real detected event.
4. WHEN the REST_API receives `POST /api/v1/demo/stop` while a Demo_Session is active,
   THE Demo_Engine SHALL cease emitting synthetic events within 2 seconds and SHALL
   return HTTP 200.
5. WHEN the REST_API receives `POST /api/v1/demo/stop` while no Demo_Session is active,
   THE REST_API SHALL return HTTP 409 with error code "DEMO_NOT_RUNNING".
6. THE Demo_Engine SHALL generate source IPs exclusively from the RFC 5737 TEST-NET ranges
   (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and SHALL NOT persist blocks for these
   IPs to the permanent `blocked_ips` table, to avoid blocking real infrastructure.
7. WHEN `GET /api/v1/demo/status` is called, THE REST_API SHALL return the current
   Demo_Session state: `{ "active": bool, "events_generated": int, "started_at": ISO-8601 or null }`,
   where `events_generated` resets to 0 on each new Demo_Session start.
8. THE Demo_Engine SHALL include a `demo: true` field in each synthetic event's evidence dict
   so that demo events are distinguishable from real detections in the UI.

---

### Requirement 2: AI Threat Explanation Service

**User Story:** As a security analyst, I want every detected attack to automatically produce an
enriched AI-generated explanation covering business impact, attacker methodology, MITRE ATT&CK
mapping, and remediation steps, so that I can respond to incidents without needing deep
security expertise.

#### Acceptance Criteria

1. THE AI_Explanation_Service SHALL expose a `generate(threat_event, base_explanation)` method
   that accepts a Threat_Event and the existing Explanation from the ExplainabilityEngine,
   and returns an AI_Explanation object. IF either `threat_event` or `base_explanation` is
   null/None, THE AI_Explanation_Service SHALL raise a ValueError and SHALL NOT attempt
   provider calls.
2. THE AI_Explanation_Service SHALL support three configurable providers selected via the
   `AI_PROVIDER` environment variable: `"gemini"` (Google Gemini API), `"openai"` (OpenAI
   Chat Completions API), and `"stub"` (deterministic local template, no network call).
3. WHERE `AI_PROVIDER` is not set or set to an unrecognised value, THE AI_Explanation_Service
   SHALL use the `"stub"` provider so that the system functions fully offline.
4. THE AI_Explanation_Service SHALL produce an AI_Explanation whose `markdown_report` field is
   a non-empty string containing at minimum the sections: ## Summary, ## Business Impact,
   ## How the Attacker Works, ## Immediate Actions, ## Long-term Recommendations,
   ## MITRE ATT&CK, ## CVE References.
5. IF the configured AI provider (`"gemini"` or `"openai"`) raises a network error or returns
   an invalid response, THEN THE AI_Explanation_Service SHALL return a fallback AI_Explanation
   generated by the `"stub"` provider with `is_fallback: true` set in the response, log a
   WARNING to `logs/errors.log`, and SHALL NOT propagate the exception to the caller.
6. WHEN the REST_API receives `GET /api/v1/ai-explanation/{event_id}`, THE REST_API SHALL
   return the AI_Explanation for that event, calling AI_Explanation_Service.generate() if the
   result is not already cached (keyed by `event_id`), and return HTTP 404 if the event_id
   does not exist.
7. THE AI_Explanation_Service SHALL cache the most recent 100 AI_Explanation results in
   memory (LRU order, keyed by `event_id`) to avoid repeated API calls for the same event_id.
8. THE AI_Explanation_Service SHALL complete the `generate()` call within 30 seconds for
   `"gemini"` and `"openai"` providers; the `"stub"` provider SHALL complete within 100 ms.
9. THE AI_Explanation_Service SHALL ensure that for ALL returned AI_Explanation objects,
   the `markdown_report` field is a non-empty string and all list fields
   (`immediate_actions`, `long_term_recommendations`, `mitre_attack_mapping`,
   `cve_references`) are lists (empty lists are permitted, None is not).
10. THE AI_Explanation_Service SHALL ensure that `generate()` is only called with valid,
    non-null inputs; callers passing null values SHALL receive a ValueError before any
    provider network call is attempted.

---

### Requirement 3: Dashboard Redesign

**User Story:** As a hackathon judge evaluating the demo, I want the main dashboard to look like
a professional SOC console with animated metrics, live charts, and real-time notifications,
so that the system's capabilities are immediately visible and impressive.

#### Acceptance Criteria

1. WHEN the Dashboard page is first loaded, THE Dashboard SHALL populate all seven KPI
   counters from `GET /api/v1/dashboard` before rendering: Packets Processed, Alerts Today,
   Active Blocks, Packets/sec, Blocked IPs (total historical), Detection Accuracy (percentage
   of events where `blocked=true`), and Security Health Score.
2. WHEN a new Threat_Event is received via SocketIO `new_threat` AND the SocketIO connection
   is established, THE Dashboard SHALL animate the affected KPI counter from its previous
   value (or from 0 on first render) to its new value over at most 600 ms using a numeric
   count-up animation; WHILE the SocketIO connection is disconnected, THE Dashboard SHALL
   update KPI values without animation when polling results are received.
3. WHEN a SocketIO event of type `new_threat`, `ip_blocked`, or `ip_unblocked` is received,
   THE Dashboard SHALL prepend the event to the activity feed and retain only the 10 most
   recent entries; each feed entry SHALL display: timestamp, event type label, and a
   severity badge coloured `#F87171` (critical/high), `#FACC15` (medium), or `#4ADE80`
   (low/info).
4. THE Dashboard SHALL display a System Health panel showing: CPU usage, memory usage, uptime,
   and monitoring status — data sourced from `GET /api/v1/status`.
5. THE Dashboard SHALL display a Top Attack Types panel showing the top 5 attack types by
   count, sourced from `GET /api/v1/statistics`.
6. WHEN the Security_Health_Score drops below 50, THE Dashboard SHALL display the score in
   danger colour (`#F87171`); between 50 and 79 in warning colour (`#FACC15`); 80 and above
   in success colour (`#4ADE80`).
7. THE Dashboard SHALL use the SOC colour palette: primary accent `#00E5FF`, success `#4ADE80`,
   warning `#FACC15`, danger `#F87171`, with `#0F172A` background and glassmorphism card
   styling (backdrop-filter: blur, semi-transparent backgrounds).
8. THE Dashboard SHALL display live status badges (pulsing dot) for: Monitoring Active/Stopped,
   Demo Mode Active/Stopped, AI Service Available/Unavailable.
9. WHILE the Dashboard detects that the SocketIO connection is unavailable, THE Dashboard
   SHALL poll `GET /api/v1/dashboard/live` at 2-second intervals, display a reconnecting
   indicator, and retry SocketIO reconnection every 5 seconds.

---

### Requirement 4: Incident Timeline

**User Story:** As a security analyst, I want to view the complete lifecycle of any detected
incident — from first detection to block to notification — on a dedicated timeline page, so
that I can understand exactly when each response step occurred.

#### Acceptance Criteria

1. WHEN `GET /api/v1/timeline/{event_id}` is called for an existing event_id, THE REST_API
   SHALL return an ordered list of Timeline_Entry objects covering the lifecycle steps that
   have occurred for that event, in chronological ascending order by timestamp. Each
   Timeline_Entry SHALL include: `step_name` (string), `timestamp` (ISO-8601), `description`
   (string), and `status` (one of: `"completed"`, `"pending"`, `"skipped"`).
2. THE timeline for any event SHALL include the "Detected" step (timestamp from the `events`
   table, status `"completed"`) as the first entry; all other steps are conditional on whether
   the action occurred (status `"completed"` if occurred, `"skipped"` if not applicable).
3. IF an event has a corresponding active or inactive block in the `blocked_ips` table,
   THE REST_API SHALL include a "Blocked" Timeline_Entry (status `"completed"`) with the
   `blocked_at` timestamp.
4. THE REST_API SHALL include an "Analyzed" Timeline_Entry whose timestamp is derived from
   the event's stored `analyzed_at` field (if present) or computed as `detected_at + 500ms`
   as a fallback; the timestamp SHALL be strictly greater than the "Detected" timestamp.
5. WHEN `GET /api/v1/timeline/{event_id}` is called for a non-existent event_id, THE REST_API
   SHALL return HTTP 404 with error code "NOT_FOUND".
6. THE frontend SHALL include a dedicated `timeline.html` page that accepts an `event_id`
   query parameter (e.g., `/timeline?event_id=<uuid>`), loads the timeline via
   `GET /api/v1/timeline/{event_id}`, and renders each step as a vertical timeline with
   connecting line, step icon, timestamp, and description.
7. IF the Glossary-defined "Notified" or "Reported" steps exist as records in the system for
   an event, THE REST_API SHALL include corresponding Timeline_Entry objects for those steps
   with appropriate timestamps and status `"completed"`; IF they have not occurred, they SHALL
   be included with status `"skipped"`.

---

### Requirement 5: Analytics

**User Story:** As an Administrator, I want to view aggregated attack statistics over hourly,
daily, and weekly periods, with breakdowns by attack type, severity, protocol, and top
attacker IPs, so that I can identify patterns and tune detection thresholds.

#### Acceptance Criteria

1. WHEN `GET /api/v1/analytics` is called with a `period` query parameter of `"hourly"`,
   THE Analytics_Endpoint SHALL return the last 24 hourly buckets; with `"daily"`, the last
   7 daily buckets; with `"weekly"`, the last 4 weekly buckets. Each bucket SHALL be a dict
   containing `bucket` (ISO-8601 period label), `count`, and `breakdown` (attack_type → count).
2. IF the `period` query parameter is absent or invalid, THE Analytics_Endpoint SHALL default
   to `"daily"` and return the last 7 daily buckets.
3. THE Analytics_Endpoint SHALL return, in the same response: top 5 attacker source IPs by
   count (`top_ips`), severity distribution (`severity_counts`), protocol breakdown
   (`protocol_counts`), total events in the queried period (`total_events`), and blocked vs.
   detected-only counts (`blocked_count`, `detected_count`).
4. FOR ALL analytics responses, the sum of all bucket `count` values SHALL equal the
   `total_events` field in the same response, for the queried period.
5. THE frontend SHALL include a dedicated `analytics.html` page displaying: a bar chart of
   attack counts over time using Chart.js (one bar per bucket), a severity distribution
   doughnut chart, a top-attacker-IPs table, and summary KPI cards showing `total_events`,
   `blocked_count`, and `detected_count` for the selected period.
6. WHEN the user selects a different period on `analytics.html`, THE frontend SHALL issue a
   new `GET /api/v1/analytics?period=<selected>` request and update all charts and KPI cards
   without a full page reload.

---

### Requirement 6: Export Reports

**User Story:** As an Administrator, I want to export detection records as PDF, CSV, JSON, or
Markdown with professional branding, so that I can share incident reports with stakeholders.

#### Acceptance Criteria

1. WHEN `GET /api/v1/export?format=json` is called (with optional filters matching
   `GET /api/v1/detections` filter parameters), THE Export_Service SHALL return a
   JSON file with HTTP headers `Content-Type: application/json` and
   `Content-Disposition: attachment; filename="netguard-export-{YYYY-MM-DD}.json"` (UTC date).
2. WHEN `GET /api/v1/export?format=csv` is called, THE Export_Service SHALL return a valid
   CSV file where the first row is a header row containing all field names returned by
   `GET /api/v1/detections`, with HTTP headers `Content-Type: text/csv` and
   `Content-Disposition: attachment; filename="netguard-export-{YYYY-MM-DD}.csv"` (UTC date).
3. WHEN `GET /api/v1/export?format=markdown` is called, THE Export_Service SHALL return a
   Markdown document with HTTP headers `Content-Type: text/markdown` and
   `Content-Disposition: attachment; filename="netguard-export-{YYYY-MM-DD}.md"` (UTC date),
   containing: a report header (NetGuard branding, export date, total count), a summary
   table, and one section per event with explanation and recommendation.
4. WHEN `GET /api/v1/export?format=pdf` is called and the `reportlab` or `weasyprint` library
   is installed, THE Export_Service SHALL return a PDF document with HTTP headers
   `Content-Type: application/pdf` and
   `Content-Disposition: attachment; filename="netguard-export-{YYYY-MM-DD}.pdf"` (UTC date);
   IF neither library is installed, THE Export_Service SHALL return HTTP 501 with error code
   "PDF_NOT_SUPPORTED" and a message directing the user to install the dependency.
5. FOR ALL export formats, the count of exported records SHALL equal the count returned by
   `GET /api/v1/detections` with the same filter parameters applied, and all exports SHALL
   be ordered by timestamp descending.
6. IF no filter parameters are provided, THE Export_Service SHALL export all events,
   ordered by timestamp descending.
7. IF `GET /api/v1/export` is called with a `format` value other than `json`, `csv`,
   `markdown`, or `pdf`, THE Export_Service SHALL return HTTP 400 with error code
   "INVALID_EXPORT_FORMAT".

---

### Requirement 7: Attack Simulator (Interactive)

**User Story:** As a developer or demo operator, I want to manually trigger individual simulated
attacks from the dashboard, so that I can demonstrate specific detection capabilities on demand.

#### Acceptance Criteria

1. WHEN `POST /api/v1/demo/trigger` is called with an `attack_type` body parameter matching
   one of the nine Demo_Engine Attack_Template names (case-sensitive, after whitespace strip),
   THE Demo_Engine SHALL emit one synthetic Threat_Event for that attack type within 2 seconds
   and return HTTP 200 with body `{ "event_id": "<uuid>" }`.
2. IF the `attack_type` parameter is absent or does not match a known Attack_Template,
   THE REST_API SHALL return HTTP 422 with error code "INVALID_ATTACK_TYPE".
3. THE Dashboard SHALL display an Attack Simulator panel with nine buttons, one per attack
   type; WHEN a button is clicked, THE Dashboard SHALL call `POST /api/v1/demo/trigger` and
   on HTTP 200, display a success toast notification containing the generated `event_id`
   that auto-dismisses after 3 seconds.
4. WHEN `POST /api/v1/demo/trigger` returns a non-200 response or a network error occurs,
   THE Dashboard SHALL display an error toast notification with the error message that
   auto-dismisses after 5 seconds.
5. THE Demo_Engine SHALL process `POST /api/v1/demo/trigger` regardless of whether a
   Demo_Session is currently active.

---

### Requirement 8: Log Search and Filtering

**User Story:** As an Administrator, I want to search and filter the detections and logs lists
by multiple criteria simultaneously, with paginated results and loading states, so that I can
efficiently locate specific incidents.

#### Acceptance Criteria

1. WHEN `GET /api/v1/detections` is called with a `search` query parameter (1–200 characters),
   THE REST_API SHALL return only events where `source_ip`, `destination_ip`, or `attack_type`
   contains the search string as a case-insensitive substring match.
2. WHILE a detections API request is in-flight, THE frontend detections list SHALL display a
   loading skeleton animation in place of the results rows, replacing it with results or an
   empty-state message upon response.
3. THE frontend detections page SHALL support combined filtering using AND logic: any
   combination of `severity`, `attack_type`, `source_ip`, `date`, and `search` may be active
   simultaneously, and results SHALL include only events matching ALL active filters.
4. WHEN a filter change is applied in the frontend, THE detections list SHALL initiate a new
   API request within 500 ms of the user's action.
5. THE `GET /api/v1/detections` endpoint SHALL support `limit` (integer, minimum 1, default 50,
   max 500) and `offset` (integer, minimum 0, default 0) parameters and SHALL include `total`
   (count of all matching records independent of pagination), `limit`, and `offset` fields
   in the response data.
6. IF `GET /api/v1/detections` is called with `limit` exceeding 500, THE REST_API SHALL
   clamp the limit to 500 and return results without error.
7. IF `GET /api/v1/detections` is called with a `limit` below 1, a non-integer `limit`, or
   a negative `offset`, THE REST_API SHALL return HTTP 422 with error code
   "INVALID_PAGINATION_PARAMS" and SHALL NOT return any event records.

---

### Requirement 9: Security Health Score

**User Story:** As a hackathon judge, I want to see a single score representing the current
security posture of the monitored network, so that I can immediately grasp how well protected
the system is.

#### Acceptance Criteria

1. THE StatsService SHALL expose a `get_health_score()` method that computes Health_Score
   using the formula: `score = max(0, min(100, 100 - (alerts_today * 5) - (active_blocks * 2)))`,
   where `alerts_today` is the count of events with timestamp since 00:00 UTC of the current
   calendar day, and `active_blocks` is the count of IPs currently in the active block list.
2. THE `GET /api/v1/status` endpoint SHALL include a `health_score` integer field in its
   response data.
3. THE `GET /api/v1/dashboard` endpoint SHALL include a `health_score` integer field in its
   response data.
4. WHEN the `live_stats` SocketIO event is emitted and the health_score has changed by 5 or
   more from the value in the previous `live_stats` emit (or on the first emit), THE Stats
   service SHALL include `health_score` in the `live_stats` payload.
5. THE StatsService SHALL ensure that for ALL non-negative integer values of `alerts_today`
   and `active_blocks`, `get_health_score()` returns an integer in the closed range [0, 100].
6. IF `get_health_score()` encounters a database error, THE StatsService SHALL return -1 as
   a sentinel value indicating the score is unavailable, and SHALL log the error.

---

### Requirement 10: Rate Limiting

**User Story:** As a security engineer, I want the REST API to enforce rate limits per client IP,
so that the API itself is not a target for denial-of-service or brute-force attacks.

#### Acceptance Criteria

1. THE Rate_Limiter SHALL enforce a maximum of 120 requests per 60-second sliding window per
   client IP across all `/api/v1` endpoints.
2. WHEN a client IP exceeds the rate limit, THE REST_API SHALL return HTTP 429 with error
   code "RATE_LIMIT_EXCEEDED" and a `Retry-After` header set to the number of seconds until
   the client's oldest request falls outside the 60-second window.
3. THE Rate_Limiter SHALL exempt the following endpoints from enforcement action: `GET /api/v1/health`,
   `GET /api/v1/dashboard/live`, and `GET /api/v1/status`; requests to these endpoints SHALL
   still be counted in the per-IP sliding window.
4. IF a client IP's per-IP request count within the 60-second window would exceed 120
   specifically due to a request to an exempted endpoint, THE Rate_Limiter SHALL NOT return
   HTTP 429 for that request.
5. THE Rate_Limiter SHALL use the leftmost IP from the `X-Forwarded-For` header (if present
   and non-empty) as the client IP, falling back to `request.remote_addr` when the header is
   absent or empty.

---

### Requirement 11: Secure Headers and Input Hardening

**User Story:** As a security engineer, I want the REST API to return security headers and
reject malformed inputs consistently, so that the web interface is protected against common
web vulnerabilities.

#### Acceptance Criteria

1. THE REST_API SHALL include the following HTTP response headers on every response,
   regardless of HTTP status code: `X-Content-Type-Options: nosniff`,
   `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and
   `Referrer-Policy: strict-origin-when-cross-origin`.
2. THE REST_API SHALL sanitise all string fields in request bodies — including fields in
   nested objects and array-of-string elements — by stripping leading and trailing whitespace
   before validation and persistence.
3. IF a request body contains any string field (including nested object fields and array
   elements) whose post-sanitisation length exceeds 1024 characters, THE REST_API SHALL
   return HTTP 422 with error code "INPUT_TOO_LONG", identifying the offending field name,
   and SHALL NOT persist any data from that request.
4. THE REST_API SHALL never return a raw Python exception traceback in any HTTP response.

---

### Requirement 12: Performance — Caching and Indexes

**User Story:** As a developer, I want the dashboard to load in under 500 ms even with
thousands of stored events, so that the UI feels responsive during the hackathon demo.

#### Acceptance Criteria

1. THE database SHALL support filter queries on `GET /api/v1/detections` (filtering by
   `attack_type`, `severity`, `source_ip`, `date`) responding within 200 ms for datasets
   of up to 10 000 events.
2. THE StatsService SHALL cache the result of `get_dashboard_data()` for 2 seconds in
   process memory; IF the cached value is less than 2 seconds old, THE StatsService SHALL
   return the cached value without querying the database.
3. WHEN a new Threat_Event is processed by `_on_threat_event`, THE StatsService SHALL
   invalidate the dashboard cache so that the next `GET /api/v1/dashboard` call returns a
   `total_events` count that includes the newly processed event.
4. THE `GET /api/v1/dashboard` endpoint SHALL respond within 500 ms at the p95 level across
   100 sequential requests under warm-cache conditions with up to 10 000 events in the database.

---

### Requirement 13: Landing Page and Presentation Mode

**User Story:** As a hackathon presenter, I want a polished landing page and a fullscreen
presentation mode, so that judges receive a professional first impression and can follow the
demo without UI distractions.

#### Acceptance Criteria

1. THE frontend SHALL include a `landing.html` page served at `/landing` that statically
   displays: the NetGuard name and tagline, a feature overview with 5 key capabilities and
   icons, a "Launch Dashboard" button (href="/"), and a "Start Demo" button.
2. WHEN the "Start Demo" button on `landing.html` is clicked, THE frontend SHALL call
   `POST /api/v1/demo/start`; on HTTP 200, THE frontend SHALL redirect to `/`; IF the
   request returns non-200, THE frontend SHALL display an inline error message and SHALL
   NOT redirect.
3. WHEN the user presses `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (macOS) on the
   main dashboard, THE Dashboard SHALL toggle fullscreen mode using the browser Fullscreen API;
   IF the browser denies the fullscreen request, THE Dashboard SHALL display a toast
   notification informing the user.
4. THE `landing.html` page SHALL render with no HTTP requests to external domains; all
   fonts, icons, scripts, and styles SHALL be served from the Flask application's own
   `/css/` and `/js/` routes or inlined in the HTML.

---

### Requirement 14: Correctness Properties

**User Story:** As a developer, I want provable correctness guarantees on all new components,
so that the hackathon implementation is reliable and edge-case safe.

The following properties MUST hold for all inputs to the new components.

#### Acceptance Criteria

1. **Property A — Demo Event Schema Invariant**: THE Demo_Engine SHALL ensure that for ALL
   synthetic Threat_Events it generates, the event stored in the `events` table contains
   non-null values for every required ORM field: event_id, timestamp, attack_type, source_ip,
   rule_name, severity, confidence, explanation, and recommendation.
2. **Property B — AI Explanation Fields Invariant**: THE AI_Explanation_Service SHALL ensure
   that for ALL AI_Explanation objects returned by `generate()`, the fields markdown_report,
   immediate_actions, long_term_recommendations, mitre_attack_mapping, and cve_references are
   non-null; list fields are Python lists (not None).
3. **Property C — Health Score Bounds**: THE StatsService SHALL ensure that for ALL
   non-negative integer values of `alerts_today` and `active_blocks`, `get_health_score()`
   returns an integer in the closed range [0, 100].
4. **Property D — Analytics Bucket Sum**: WHEN `GET /api/v1/analytics?period=X` is called
   with X ∈ {"hourly", "daily", "weekly"}, THE Analytics_Endpoint SHALL ensure the sum of
   all bucket `count` values equals the `total_events` field in the same response.
5. **Property E — Export Count Parity**: WHEN `GET /api/v1/export?format=json` is called
   with any combination of valid filter parameters from {severity, attack_type, source_ip,
   date, search}, THE Export_Service SHALL return a JSON array whose record count equals the
   `total` field returned by `GET /api/v1/detections` with the same filter parameters.
6. **Property F — Pagination Non-Overlap**: WHEN `GET /api/v1/detections` is called with
   `limit=N, offset=0` and then `limit=N, offset=N` where N ∈ [1, 500], THE REST_API SHALL
   return two result sets that share no common `event_id` values.
7. **Property G — Rate Limit Enforcement**: WHEN a client IP submits 121 or more requests
   within any 60-second sliding window to rate-limited endpoints, THE Rate_Limiter SHALL
   return HTTP 429 for every request from the 121st onward; requests 1 through 120 inclusive
   SHALL be processed normally with no burst allowance beyond 120.
