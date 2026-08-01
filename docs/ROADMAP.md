# NetGuard Roadmap

> **Status as of latest release:** Phase A–D complete. Items marked ✓ below have been implemented.

This roadmap is based on gaps and limitations observed in the current v1.0.0
implementation. Items are grouped by priority and complexity.

---

## v1.1 — Stability and Hardening

These items address known limitations with low implementation risk.

### IPv6 Blocking Support

**Current state:** ARP spoofing detection works for IPv4 and IPv6 source
addresses, but `PreventionEngine` only calls `iptables` (IPv4). An attacker
on an IPv6 address is detected but not blocked.

**Work:** Add `ip6tables` alongside `iptables` calls in `PreventionEngine.block_ip()`
and `unblock_ip()`. Detect which command to use from the IP family via
`ipaddress.ip_address(ip).version`.

---

### MAC Address Aging for ARP Spoofing

**Current state:** `ArpSpoofRule._ip_to_macs` accumulates MAC addresses for
the lifetime of the process. A legitimate DHCP rebind or VM migration
eventually adds a second MAC, which triggers a (false positive) detection.

**Work:** Add a timestamp per MAC entry and evict MACs older than a configurable
TTL (e.g. 5 minutes). This keeps the dict bounded and reduces false positives on
dynamic networks.

---

### iptables State Recovery on Startup

**Current state:** If NetGuard is restarted while blocks are active, the
database records show `active=1` but the iptables rules are gone (they were
removed at OS restart or by a `flush`).

**Work:** At startup, query `block_repo.get_all_active()` and re-issue
`iptables -I INPUT -s {ip} -j DROP` for each. This is a handful of lines in
`main.py` after `prevention_engine` is initialized.

---

### API Authentication

> **✓ IMPLEMENTED in Phase A** — API key authentication is live. `NETGUARD_API_KEY` + `X-API-Key` header with `hmac.compare_digest`. See `SECURITY.md` for details.

**Current state:** No authentication on any API endpoint. Anyone on the network
can manage blocks and whitelist entries.

**Work:** Add HTTP Basic Auth or token-based auth middleware as a Flask
`before_request` hook. The simplest option is a single token stored in `.env`
checked against `Authorization: Bearer <token>`.

---

## v1.2 — Detection Quality

### HTTP Response Code Inspection for Brute Force

**Current state:** `BruteForceRule` counts all TCP connections to auth ports as
"failures". It cannot distinguish a successful login from a failed one at the
packet level without stream reassembly.

**Work:** Use Scapy's `TCPSession` or a simple byte-stream accumulator per
`(src_ip, dst_port)` to reassemble HTTP responses. Count only packets where the
response contains `401 Unauthorized`, `403 Forbidden`, or SSH `Permission denied`
banners. This significantly reduces false positives.

---

### Signature-Based Payload Detection

**Current state:** SQL injection detection uses five hard-coded patterns.

**Work:** Load patterns from a YAML signature file at startup. Allow patterns to
be added and reloaded via `PUT /api/v1/settings` without restart. Apply the same
pattern format to a new `CommandInjectionRule` for payloads containing `; rm -rf`,
backtick execution, etc.

---

### Rate Limiting on the REST API

> **✓ IMPLEMENTED** — In-process sliding-window rate limiter (120 req/60s per IP) with `Retry-After` header. Trust proxy headers gated on `TRUST_PROXY_HEADERS` env var. See `SECURITY.md`. Redis backend remains a future upgrade path.

**Current state:** No rate limiting on any endpoint. A client could flood
`POST /block` or `POST /whitelist` to DoS the dashboard.

**Work:** Add `flask-limiter` with an in-memory backend. Limit mutation endpoints
(`/block`, `/unblock`, `/whitelist POST`, `/settings PUT`) to 60 requests/minute
per client IP.

---

## v1.3 — Observability

### Prometheus Metrics Endpoint

**Current state:** `GET /api/v1/statistics` returns aggregate counts but is not
in Prometheus format.

**Work:** Add `GET /metrics` using `prometheus_client`. Export gauges for
`netguard_packets_per_second`, `netguard_active_blocks_total`,
`netguard_alerts_total` (labelled by attack_type and severity), and
`netguard_detection_engine_running`.

---

### Structured JSON Logging

**Current state:** Log files use a human-readable format
(`%(asctime)s %(levelname)s %(name)s %(message)s`).

**Work:** Add a `JSON_LOGS=true` environment variable flag. When set, format
each log record as a JSON object with `timestamp`, `level`, `module`, `event`,
`message`, and `metadata` keys. This makes logs parseable by Elasticsearch,
Loki, and other SIEM tools.

---

### Email / Webhook Alerting

**Current state:** Detections are visible in the dashboard and log files only.

**Work:** Add an `AlertDispatcher` service that calls a configurable webhook URL
(e.g. Slack incoming webhook, PagerDuty, or a generic HTTP POST) on `Critical`
detections. Configure URL and severity threshold in `.env`.

---

## v2.0 — Architectural Improvements

### PostgreSQL Support

**Current state:** SQLite is suitable for a single-machine deployment but does
not support multi-process writes or horizontal scaling.

**Work:** The SQLAlchemy ORM already abstracts the database. Switching requires
only a `DATABASE_URL` change and adding `psycopg2` to `requirements.txt`. Test
coverage for the repository layer handles the rest.

---

### Distributed Detection (Multi-Sensor)

**Current state:** Single-machine capture. A distributed attack from many low-rate
sources will not exceed per-IP thresholds.

**Work:** Allow multiple NetGuard sensors to forward decoded `Packet` objects to a
central `DetectionEngine` over a message queue (Redis Streams or RabbitMQ). The
`packet_queue` interface is already the abstraction boundary — replacing it with a
remote queue consumer is the primary change.

---

### TLS Inspection

**Current state:** HTTPS payloads are encrypted and invisible to the SQL injection
rule.

**Work:** Integrate with a local TLS termination proxy (mitmproxy or sslsplit).
Forwarded plaintext packets flow into the existing packet pipeline unchanged.
Requires certificate trust installation on clients or on the gateway.

---

### Machine Learning Anomaly Detection

**Current state:** All rules are threshold-based with manually tuned parameters.

**Work:** Add an `AnomalyRule` that maintains a rolling baseline of per-IP traffic
rate distributions and flags statistical outliers. A simple z-score or IQR outlier
detector on the packet rate deque requires no external ML library. More sophisticated
approaches (Isolation Forest, LSTM on time-series) would require `scikit-learn` or
`torch`.
