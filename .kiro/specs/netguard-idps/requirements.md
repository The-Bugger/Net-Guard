# Requirements Document

## Introduction

NetGuard is an Explainable Intrusion Detection and Prevention System (IDPS) built for the MVIC Build Nepal Hackathon 2026. It runs entirely offline on a single Linux machine, continuously monitors network traffic via Scapy, detects five categories of network attack, automatically blocks attackers via iptables, and explains every security decision in plain language through a live SOC-style dashboard.

The system is designed for schools, colleges, startups, and small organizations that need enterprise-grade security visibility without cloud infrastructure or expensive hardware. A complete attack-to-block demonstration must complete reliably within 90 seconds.

---

## Glossary

- **NetGuard**: The top-level application described by this specification.
- **Capture_Engine**: The Scapy-based component that opens a network interface and continuously reads raw packets.
- **Packet_Decoder**: The component that converts a raw Scapy packet into a normalized internal Packet object.
- **Detection_Engine**: The component that evaluates normalized packets against all enabled detection rules and emits Threat_Events when thresholds are exceeded.
- **Rule_Engine**: The sub-component of the Detection_Engine that loads, enables/disables, and evaluates individual detection rules.
- **Flow_Tracker**: The in-memory data structure maintained by the Detection_Engine that accumulates per-source-IP counters within configurable sliding time windows.
- **Explainability_Engine**: The component that converts a Threat_Event into a human-readable Explanation object containing a summary, evidence, confidence score, severity, recommendation, and plain-English rationale.
- **Prevention_Engine**: The component that checks the Whitelist_Manager and issues iptables block/unblock commands.
- **Whitelist_Manager**: The component that manages the set of trusted IP addresses that must never be automatically blocked.
- **Logging_Engine**: The component that persists all activity to the SQLite database and to the three log files.
- **REST_API**: The Flask application exposing all endpoints under `http://localhost:5000/api/v1`.
- **Dashboard**: The single-page dark-theme web UI served by the REST_API.
- **Configuration_Manager**: The component that reads and writes `config/config.yaml` and applies settings at runtime.
- **Attack_Simulator**: The demo toolkit in `demo/` that launches each of the five supported attack types on command.
- **Threat_Event**: The structured object emitted by the Detection_Engine upon confirmed detection; contains event_id, attack_type, severity, confidence, source_ip, destination_ip, rule_name, evidence, and timestamp.
- **Explanation**: The structured object produced by the Explainability_Engine; contains summary, evidence, recommendation, rule_triggered, severity, confidence_score, and plain_english_text.
- **Packet**: The normalized internal object produced by the Packet_Decoder; contains src_ip, dst_ip, src_port, dst_port, protocol, flags, timestamp, and length.
- **Administrator**: A human user with Linux root/sudo privileges who operates NetGuard.
- **Sliding window**: A time window that continuously advances so that only events within the most recent N seconds are counted; old events outside the window are discarded automatically.

---

## Requirements

### Requirement 1: Project Structure and Configuration

**User Story:** As an Administrator, I want NetGuard to use a well-defined folder structure and a single YAML configuration file, so that I can understand the codebase and adjust thresholds without editing source code.

#### Acceptance Criteria

1. THE NetGuard SHALL create all of the following directories on first startup if they do not already exist: `backend/api/`, `backend/services/`, `backend/models/`, `backend/routes/`, `backend/utils/`, `frontend/css/`, `frontend/js/`, `frontend/assets/`, `detection/rules/`, `detection/parsers/`, `detection/capture/`, `database/migrations/`, `config/`, `logs/`, `scripts/`, `tests/`, `demo/`, and `docs/`.
2. WHEN NetGuard starts, THE Configuration_Manager SHALL load all runtime settings from `config/config.yaml` before any other module initializes.
3. THE Configuration_Manager SHALL expose the following configurable settings with the specified defaults and valid ranges: network interface (string, no default), SYN flood packet threshold (integer ≥ 1, default 100), SYN flood time window (integer 1–60 s, default 3), port scan port threshold (integer ≥ 1, default 20), port scan time window (integer 1–60 s, default 10), brute force failure threshold (integer ≥ 1, default 10), brute force time window (integer 1–300 s, default 60), auto-block duration (integer 1–3600 s, default 120), dashboard refresh interval (integer 1–60 s, default 1), and per-rule enabled flags (boolean, default true for all five rules).
4. WHEN an Administrator submits a valid PUT /api/v1/settings request with values within the defined ranges, THE Configuration_Manager SHALL apply the updated values in memory and persist them to `config/config.yaml` without requiring an application restart.
5. IF an Administrator submits a PUT /api/v1/settings request with a value outside the defined range for any setting, THEN THE REST_API SHALL return HTTP 422 with error code "VALIDATION_ERROR" and a message identifying the invalid field, without modifying any configuration values.
6. IF `config/config.yaml` is missing or unparseable at startup, THEN THE Configuration_Manager SHALL log a CRITICAL error to `logs/errors.log` and apply the built-in default values listed in criterion 3 so that monitoring can still start.
7. THE NetGuard SHALL complete application startup — including database initialization, configuration loading, and interface enumeration — within 10 seconds on hardware with at least a dual-core CPU and 4 GB RAM.

---

### Requirement 2: Packet Capture

**User Story:** As an Administrator, I want NetGuard to continuously capture live packets on a selected interface, so that all network traffic is available for analysis.

#### Acceptance Criteria

1. WHEN an Administrator submits a POST /api/v1/monitor/start request with an interface name that appears in the list returned by GET /api/v1/monitor/interfaces, and monitoring is not already active, THE Capture_Engine SHALL begin capturing packets on that interface within 2 seconds and return HTTP 200.
2. WHEN an Administrator submits a POST /api/v1/monitor/start request while monitoring is already active, THE REST_API SHALL return HTTP 409 with error code "ALREADY_MONITORING" without restarting the capture session.
3. WHILE monitoring is active, THE Capture_Engine SHALL forward every captured packet to the Packet_Decoder without buffering delays exceeding 100 ms per packet.
4. IF a raw packet cannot be decoded by the Packet_Decoder, THEN THE Capture_Engine SHALL log a WARNING to `logs/system.log`, discard the malformed packet, and continue capturing subsequent packets without interruption.
5. WHEN GET /api/v1/monitor/interfaces is called, THE REST_API SHALL return the list of all network interfaces currently reported by the host operating system, including loopback interfaces.
6. WHEN an Administrator submits a POST /api/v1/monitor/stop request while monitoring is active, THE Capture_Engine SHALL cease packet capture within 2 seconds and update monitoring status to inactive.
7. WHEN an Administrator submits a POST /api/v1/monitor/stop request while monitoring is not active, THE REST_API SHALL return HTTP 409 with error code "NOT_MONITORING".
8. IF the POST /api/v1/monitor/start request specifies an interface name that is not present in the interfaces list, THEN THE REST_API SHALL return HTTP 422 with error code "INVALID_INTERFACE" without starting capture.
9. IF the host operating system fails to enumerate network interfaces, THEN THE REST_API SHALL return an empty list for GET /api/v1/monitor/interfaces and log a WARNING to `logs/system.log`.

---

### Requirement 3: Packet Decoding and Normalization

**User Story:** As a developer, I want every captured packet normalized into a consistent internal object, so that all detection rules operate on a uniform data structure.

#### Acceptance Criteria

1. THE Packet_Decoder SHALL extract the following fields from every successfully parsed packet: src_ip, dst_ip, src_port (null for non-TCP/UDP), dst_port (null for non-TCP/UDP), protocol (TCP/UDP/ICMP/ARP/UNKNOWN), TCP flags (null for non-TCP), timestamp (UTC ISO-8601), and packet length in bytes.
2. WHEN a packet uses an unrecognized protocol, THE Packet_Decoder SHALL set the protocol field to "UNKNOWN", populate all available fields, and pass the Packet to the Detection_Engine.
3. THE Packet_Decoder SHALL produce a normalized Packet object for every successfully decoded raw packet within 10 ms of receipt.
4. IF the Packet_Decoder raises an unhandled exception while processing a packet, THEN THE Capture_Engine SHALL log the exception class and message to `logs/errors.log` and continue processing the next packet without propagating the exception.

---

### Requirement 4: SYN Flood Detection

**User Story:** As an Administrator, I want NetGuard to detect SYN flood attacks from any source IP, so that volumetric TCP-based denial-of-service attempts are identified and blocked automatically.

#### Acceptance Criteria

1. WHEN the Flow_Tracker records 100 or more TCP SYN packets from the same source IP within a 3-second sliding window, THE Detection_Engine SHALL emit a Threat_Event with attack_type "SYN Flood" and rule_name "SYN_FLOOD_001".
2. IF a SYN flood Threat_Event is generated and the SYN packet count from the source IP within the window is between 100 and 199 inclusive, THEN THE Detection_Engine SHALL assign severity "Medium" to the Threat_Event.
3. IF a SYN flood Threat_Event is generated and the SYN packet count from the source IP within the window is between 200 and 399 inclusive, THEN THE Detection_Engine SHALL assign severity "High" to the Threat_Event.
4. IF a SYN flood Threat_Event is generated and the SYN packet count from the source IP within the window is 400 or more, THEN THE Detection_Engine SHALL assign severity "Critical" to the Threat_Event.
5. THE Detection_Engine SHALL calculate the confidence score for a SYN flood Threat_Event using the formula: `round(min(packet_count / configured_threshold, 2.0) / 2.0 * 100)`, where configured_threshold is the active SYN flood packet threshold from Configuration_Manager, capped at a maximum of 100.
6. THE Detection_Engine SHALL include in the SYN flood Threat_Event evidence: source IP, SYN packet count, time window duration in seconds, destination IP(s) targeted, and up to 5 sample packet timestamps from within the window.
7. IF a SYN flood Threat_Event has already been emitted for a source IP within the 10-second cooldown period, and a subsequent evaluation of that IP produces a higher severity than the most recently emitted event, THEN THE Detection_Engine SHALL emit a new Threat_Event for that IP with the higher severity and reset the cooldown timer.

---

### Requirement 5: Port Scan Detection

**User Story:** As an Administrator, I want NetGuard to detect port scanning from any source IP, so that reconnaissance attempts against protected hosts are identified promptly.

#### Acceptance Criteria

1. WHEN the Flow_Tracker records TCP or UDP connection attempts to 20 or more unique destination ports from the same source IP within a 10-second sliding window, THE Detection_Engine SHALL emit a Threat_Event with attack_type "Port Scan" and rule_name "PORT_SCAN_001".
2. IF a port scan Threat_Event is generated and the unique destination port count is between 20 and 39 inclusive, THEN THE Detection_Engine SHALL assign severity "Medium" to the Threat_Event.
3. IF a port scan Threat_Event is generated and the unique destination port count is between 40 and 79 inclusive, THEN THE Detection_Engine SHALL assign severity "High" to the Threat_Event.
4. IF a port scan Threat_Event is generated and the unique destination port count is 80 or more, THEN THE Detection_Engine SHALL assign severity "Critical" to the Threat_Event.
5. THE Detection_Engine SHALL include in the port scan Threat_Event evidence: source IP, the complete list of unique scanned destination ports, total unique port count, time window duration in seconds, and confidence score calculated as `round(min(unique_port_count / configured_threshold, 2.0) / 2.0 * 100)` capped at 100.
6. IF a port scan Threat_Event has already been emitted for a source IP within the 10-second cooldown period, and a subsequent evaluation produces a higher severity, THEN THE Detection_Engine SHALL emit a new Threat_Event with the higher severity and reset the cooldown timer.

---

### Requirement 6: SQL Injection Detection

**User Story:** As an Administrator, I want NetGuard to detect SQL injection payloads in HTTP traffic, so that application-layer attacks against web services are caught in real time.

#### Acceptance Criteria

1. WHEN the Packet_Decoder produces a Packet where the TCP payload contains an HTTP request, and case-insensitive pattern matching of the URL path, query string, or request body matches at least one of the following strings: `' OR`, `UNION SELECT`, `DROP TABLE`, `--`, `xp_cmdshell`, THE Detection_Engine SHALL emit a Threat_Event with attack_type "SQL Injection" and rule_name "SQL_INJECTION_001".
2. IF a SQL injection Threat_Event is generated from a source IP that has not triggered SQL_INJECTION_001 previously since the current application start, THEN THE Detection_Engine SHALL assign severity "High" to the Threat_Event.
3. IF a SQL injection Threat_Event is generated from a source IP that has triggered SQL_INJECTION_001 one or more times since the current application start, THEN THE Detection_Engine SHALL assign severity "Critical" to the Threat_Event.
4. THE Detection_Engine SHALL include in the SQL injection Threat_Event evidence: source IP, destination IP, HTTP method, request URL, and the exact matched pattern string.
5. THE Detection_Engine SHALL assign a confidence score of 100 to every SQL injection Threat_Event; a single matching payload constitutes definitive evidence.
6. THE Detection_Engine SHALL not require a minimum packet count threshold to trigger SQL injection detection; detection is triggered by a single matching payload.

---

### Requirement 7: Brute Force Login Detection

**User Story:** As an Administrator, I want NetGuard to detect brute force login attempts against any service, so that credential stuffing and password spraying attacks are identified and blocked.

#### Acceptance Criteria

1. WHEN the Flow_Tracker records 10 or more authentication failure indicators from the same source IP within a 60-second sliding window, THE Detection_Engine SHALL emit a Threat_Event with attack_type "Brute Force" and rule_name "BRUTE_FORCE_001".
2. IF a brute force Threat_Event is generated and the failure count within the window is between 10 and 19 inclusive, THEN THE Detection_Engine SHALL assign severity "Medium" to the Threat_Event.
3. IF a brute force Threat_Event is generated and the failure count within the window is between 20 and 39 inclusive, THEN THE Detection_Engine SHALL assign severity "High" to the Threat_Event.
4. IF a brute force Threat_Event is generated and the failure count within the window is 40 or more, THEN THE Detection_Engine SHALL assign severity "Critical" to the Threat_Event.
5. THE Detection_Engine SHALL include in the brute force Threat_Event evidence: source IP, authentication failure count, time window duration in seconds, and target service identifier (e.g., "SSH" for port 22, "HTTP" for port 80/443) when determinable from the destination port; if not determinable, the target service SHALL be recorded as "Unknown".
6. THE Detection_Engine SHALL calculate the confidence score for a brute force Threat_Event using the formula: `round(min(failure_count / configured_threshold, 2.0) / 2.0 * 100)` capped at 100.

---

### Requirement 8: ARP Spoofing Detection

**User Story:** As an Administrator, I want NetGuard to detect ARP spoofing on the local network, so that man-in-the-middle attacks via gratuitous ARP are identified and reported.

#### Acceptance Criteria

1. WHEN the Flow_Tracker observes two or more different MAC addresses claiming the same IP address within ARP reply or gratuitous ARP packets, THE Detection_Engine SHALL emit a Threat_Event with attack_type "ARP Spoofing" and rule_name "ARP_SPOOF_001".
2. THE Detection_Engine SHALL assign severity "High" to every ARP spoofing Threat_Event regardless of the number of conflicting MAC addresses observed.
3. THE Detection_Engine SHALL assign a confidence score of 97 to every ARP spoofing Threat_Event where exactly two conflicting MAC addresses are observed, and 100 where three or more conflicting MAC addresses are observed.
4. THE Detection_Engine SHALL include in the ARP spoofing Threat_Event evidence: the conflicting IP address, the complete list of observed conflicting MAC addresses, and the UTC timestamps of the first and most recent conflicting ARP packets.

---

### Requirement 9: Detection Engine — General Rules

**User Story:** As a developer, I want the Detection_Engine to enforce consistent cross-rule behavior, so that detections are reliable, non-duplicative, and extensible.

#### Acceptance Criteria

1. THE Detection_Engine SHALL assign a unique event_id (UUID4 format) to every Threat_Event; no two Threat_Events may share the same event_id within the lifetime of the application.
2. THE Detection_Engine SHALL emit at most one Threat_Event per source IP per rule within a 10-second cooldown period, unless the severity of the subsequent detection is strictly higher than the severity of the most recently emitted event for that source IP and rule combination.
3. THE Detection_Engine SHALL complete evaluation of all enabled rules for a single Packet within 100 ms of receiving the Packet from the Packet_Decoder.
4. THE Detection_Engine SHALL support enabling and disabling individual rules via flags in the Configuration_Manager without requiring a source code change or application restart.
5. IF a detection rule raises an unhandled exception during packet evaluation, THEN THE Detection_Engine SHALL log the exception to `logs/errors.log`, mark that rule as disabled for the remainder of the current session, and continue evaluating all remaining enabled rules.
6. THE Detection_Engine SHALL expire Flow_Tracker counters for a source IP when no packets from that IP have been observed for a duration exceeding the longest time window configured across all currently enabled rules.
7. FOR ALL valid Packets provided to the Detection_Engine, the Detection_Engine SHALL either emit a Threat_Event or produce no output; it SHALL never raise an unhandled exception to the caller.

---

### Requirement 10: Explainability Engine

**User Story:** As an Administrator, I want every detected threat to include a plain-English explanation, so that I can understand what happened and what action was taken without needing security expertise.

#### Acceptance Criteria

1. THE Explainability_Engine SHALL produce an Explanation object for every Threat_Event emitted by the Detection_Engine.
2. THE Explanation object SHALL contain the following fields: attack_name, rule_triggered, plain_english_text, evidence (packet count, time window, source IP), confidence_score (integer 0–100), severity (one of: Low, Medium, High, Critical), and recommendation.
3. THE Explainability_Engine SHALL set the plain_english_text to a non-empty string of at most 500 characters that describes: (a) what traffic pattern was observed, (b) which threshold was exceeded or which pattern was matched, and (c) what action was taken (blocked or monitored only).
4. THE Explainability_Engine SHALL set the recommendation field to one of the following attack-type-specific strings: SYN Flood — "Investigate the source host and verify whether the traffic is legitimate."; Port Scan — "Review exposed services and verify firewall rules."; SQL Injection — "Inspect application logs and validate input sanitization on affected endpoints."; Brute Force — "Enable account lockout policies and review authentication logs."; ARP Spoofing — "Verify gateway configuration and inspect network devices for unauthorized ARP entries."
5. IF a Threat_Event's source IP is present in the Whitelist at the time the Explainability_Engine processes the event, THEN THE Explainability_Engine SHALL append the phrase "Whitelisted device — monitoring only, no block applied." to the plain_english_text.
6. WHEN the Explainability_Engine receives a Threat_Event, THE Explainability_Engine SHALL produce and return the Explanation object within 50 ms.
7. FOR ALL Threat_Events, the Explanation produced by the Explainability_Engine SHALL have a non-null, non-empty plain_english_text.
8. FOR ALL Explanation objects, the confidence_score SHALL be an integer in the closed range [0, 100].
9. FOR ALL Explanation objects, the severity field SHALL be exactly one of the four values: "Low", "Medium", "High", or "Critical".
10. IF the Explainability_Engine raises an unhandled exception while generating an Explanation, THEN THE Explainability_Engine SHALL log the error to `logs/errors.log` and return a fallback Explanation with plain_english_text set to "A security event was detected. Details unavailable due to an internal error." and the original Threat_Event's severity and confidence unchanged.


---

### Requirement 11: Automatic IP Blocking via iptables

**User Story:** As an Administrator, I want malicious IP addresses blocked automatically within seconds of detection, so that attacks are stopped without requiring manual intervention.

#### Acceptance Criteria

1. WHEN the Prevention_Engine receives a Threat_Event whose source IP is not on the Whitelist, THE Prevention_Engine SHALL execute an `iptables -I INPUT -s <ip> -j DROP` rule for that IP within 3 seconds of the Threat_Event timestamp.
2. THE Prevention_Engine SHALL record every successful block in the `blocked_ips` database table with: ip_address, blocked_at (UTC ISO-8601), expires_at (UTC ISO-8601), reason (attack_type), active = TRUE, and the originating event_id.
3. WHEN an iptables block's expires_at timestamp is reached, THE Prevention_Engine SHALL automatically execute `iptables -D INPUT -s <ip> -j DROP` to remove the rule and update the `active` field of the corresponding `blocked_ips` record to FALSE.
4. THE Prevention_Engine SHALL read the block duration from the Configuration_Manager; the value must be in the range 1–3600 seconds; the default is 120 seconds.
5. IF an iptables command fails for any reason, THEN THE Prevention_Engine SHALL log the OS error message to `logs/errors.log`, record the event in the `events` table with blocked = FALSE, and continue processing subsequent Threat_Events.
6. IF the same source IP receives a new Threat_Event while an active block for that IP already exists in `blocked_ips`, THEN THE Prevention_Engine SHALL NOT issue a duplicate iptables rule; it SHALL log the duplicate event and extend the existing block's expires_at by the configured block duration.
7. WHEN an Administrator submits a POST /api/v1/unblock request with a valid IP address that has an active block, THE Prevention_Engine SHALL remove the iptables DROP rule within 2 seconds and set the `active` field to FALSE in the `blocked_ips` table.
8. WHEN NetGuard starts up, THE Prevention_Engine SHALL verify it can execute iptables commands; IF the process lacks the required privileges, THEN THE Prevention_Engine SHALL log a CRITICAL error to `logs/errors.log` and raise a startup exception before accepting any connections.

---

### Requirement 12: Whitelist Management

**User Story:** As an Administrator, I want to maintain a list of trusted IP addresses that are never automatically blocked, so that critical infrastructure devices such as routers and servers remain accessible during monitoring.

#### Acceptance Criteria

1. THE Whitelist_Manager SHALL prevent the Prevention_Engine from automatically blocking any IP address that appears in the `whitelist` database table at the time a Threat_Event is processed.
2. WHEN an Administrator submits a POST /api/v1/whitelist request with a valid IPv4 or IPv6 address and an optional description, THE Whitelist_Manager SHALL insert the entry into the `whitelist` table within a single database transaction and return HTTP 201.
3. WHEN an Administrator submits a DELETE /api/v1/whitelist/{ip} request for an IP that exists in the `whitelist` table, THE Whitelist_Manager SHALL remove the entry within a single database transaction and return HTTP 204.
4. WHEN an Administrator submits a DELETE /api/v1/whitelist/{ip} request for an IP that does not exist in the `whitelist` table, THE REST_API SHALL return HTTP 404 with error code "NOT_FOUND".
5. WHEN GET /api/v1/whitelist is called, THE REST_API SHALL return all whitelist entries including ip_address, description, created_at, and created_by for each entry.
6. IF an Administrator submits a POST /api/v1/whitelist request with a malformed IP address (not valid IPv4 or IPv6), THEN THE REST_API SHALL return HTTP 422 with error code "INVALID_IP" without modifying the whitelist.
7. FOR ALL Threat_Events, IF the source IP is present in the Whitelist at the time of event processing, THEN the Prevention_Engine SHALL NOT execute any iptables block command for that IP.

---

### Requirement 13: REST API

**User Story:** As a developer, I want a complete, well-structured REST API, so that the Dashboard and future clients can reliably query all system state and trigger all actions.

#### Acceptance Criteria

1. THE REST_API SHALL serve all endpoints under the base URL `http://localhost:5000/api/v1`.
2. THE REST_API SHALL implement all of the following endpoints: GET /health, GET /status, POST /monitor/start, POST /monitor/stop, GET /monitor/interfaces, POST /detect, GET /detections, GET /detections/{event_id}, POST /block, POST /unblock, GET /blocked, GET /whitelist, POST /whitelist, DELETE /whitelist/{ip}, GET /dashboard, GET /dashboard/live, GET /statistics, GET /statistics/rules, GET /evidence/{event_id}, GET /logs, PUT /settings.
3. THE REST_API SHALL return all responses using the JSON envelope `{"success": true, "message": "...", "data": {}}` for successful operations and `{"success": false, "error": "...", "code": <HTTP status>}` for error responses; no other response shape is permitted.
4. THE REST_API SHALL return: HTTP 200 for successful reads, HTTP 201 for successful resource creation, HTTP 204 for successful deletions with no body, HTTP 400 for syntactically malformed requests, HTTP 404 for requests targeting unknown resources, HTTP 409 for state conflicts, HTTP 422 for semantically invalid inputs, and HTTP 500 for unhandled server errors.
5. THE REST_API SHALL respond to every request within 200 ms under normal operating conditions.
6. IF a request body contains an IP address field that is not a valid IPv4 or IPv6 address, THEN THE REST_API SHALL return HTTP 422 with error code "INVALID_IP" without performing any database or firewall operation.
7. THE REST_API SHALL contain no business logic; all request handling SHALL delegate to the corresponding Service layer class.
8. THE REST_API SHALL support filtering GET /detections by the following query parameters: severity (one of Low/Medium/High/Critical), attack_type (string), source_ip (valid IPv4/IPv6), and date (ISO-8601 date string).
9. THE REST_API SHALL support filtering GET /logs by the following query parameters: severity, date, module, attack_type, and source_ip.
10. THE REST_API SHALL never return a raw Python exception traceback in any HTTP response.

---

### Requirement 14: SQLite Database

**User Story:** As a developer, I want all system state persisted in a structured SQLite database, so that detections, blocks, and logs survive application restarts.

#### Acceptance Criteria

1. THE Logging_Engine SHALL initialize the SQLite database at `database/netguard.db` with all six tables — `events`, `blocked_ips`, `whitelist`, `detection_rules`, `settings`, `system_logs` — on first startup if the file does not already exist.
2. THE Logging_Engine SHALL persist every Threat_Event to the `events` table within 50 ms of event generation, including all fields: event_id, timestamp, attack_type, source_ip, destination_ip, protocol, rule_name, severity, confidence, packet_count, evidence (JSON string), explanation, recommendation, and blocked.
3. THE `events` table SHALL enforce a CHECK constraint on the `confidence` column: `confidence BETWEEN 0 AND 100`.
4. THE `events` table SHALL enforce a UNIQUE constraint on the `event_id` column.
5. THE Logging_Engine SHALL complete each event insert in under 50 ms and each system_log insert in under 20 ms.
6. THE Logging_Engine SHALL use SQLAlchemy ORM methods or parameterized queries for all database operations; raw SQL string concatenation is prohibited.
7. WHEN the database becomes unavailable, THE Logging_Engine SHALL log the error to `logs/errors.log`, queue pending events in a thread-safe in-memory queue for up to 60 seconds, retry inserts when the database becomes available, and continue monitoring throughout; events SHALL NOT be silently dropped.

---

### Requirement 15: Logging System

**User Story:** As an Administrator, I want all system activity written to structured log files, so that I can audit detections, debug issues, and demonstrate a complete audit trail.

#### Acceptance Criteria

1. THE Logging_Engine SHALL write system lifecycle events — startup, shutdown, monitoring start, monitoring stop, configuration changes — to `logs/system.log` using Python's standard logging module at INFO level.
2. THE Logging_Engine SHALL write every Threat_Event detection and every block/unblock action to `logs/detections.log`, including: UTC timestamp, source IP, attack_type, severity, confidence score, rule_name, and action taken.
3. THE Logging_Engine SHALL write all WARNING, ERROR, and CRITICAL level events from any module to `logs/errors.log`.
4. THE Logging_Engine SHALL never write passwords, private keys, tokens, or other secret values to any log file.
5. WHILE monitoring is active, THE Logging_Engine SHALL write to log files asynchronously using a background thread so that log I/O does not block packet capture or detection processing.
6. THE REST_API SHALL return paginated log entries when GET /api/v1/logs is called, using a default page size of 50 entries, supporting all filters defined in Requirement 13.

---

### Requirement 16: SOC Dashboard

**User Story:** As an Administrator, I want a live dark-theme dashboard that shows all monitoring state, threat activity, and evidence, so that I can observe the system's behavior in real time and during demonstrations.

#### Acceptance Criteria

1. THE Dashboard SHALL display four KPI cards showing: total packets processed (cumulative since monitoring start), active threat count (distinct source IPs with unresolved detections), currently blocked IP count, and detection rate (detections per minute over the last 60 seconds).
2. THE Dashboard SHALL display a live traffic rate line chart using Chart.js, updating every 1 second with the packets-per-second value from the most recent GET /api/v1/dashboard/live response.
3. THE Dashboard SHALL display a severity distribution doughnut chart using Chart.js, showing the count of Low, Medium, High, and Critical Threat_Events from the current monitoring session.
4. THE Dashboard SHALL display a threat timeline table listing the 20 most recent Threat_Events in reverse-chronological order, with columns: timestamp, attack_type, source_ip, severity badge, and confidence percentage.
5. THE Dashboard SHALL display an evidence panel that expands inline when a threat timeline row is clicked, showing the full Explanation object fields: attack_name, rule_triggered, plain_english_text, evidence detail, confidence_score, severity, and recommendation.
6. THE Dashboard SHALL display an active blocks panel listing all entries from GET /api/v1/blocked with: ip_address, reason, blocked_at, time remaining until expiry (counting down), and a Manual Unblock button.
7. THE Dashboard SHALL display a whitelist panel with the current whitelist from GET /api/v1/whitelist and an inline form to add a new IP with optional description, plus a Remove button per entry.
8. THE Dashboard SHALL use Flask-SocketIO WebSocket events as the primary mechanism for live updates, with automatic fallback to polling GET /api/v1/dashboard/live at 1-second intervals when WebSocket is unavailable.
9. THE Dashboard SHALL apply the dark color theme with background #0F172A, card background #1E293B, border #334155, success #22C55E, warning #FACC15, danger #EF4444, critical #DC2626, info #3B82F6.
10. WHEN a new Threat_Event is received via SocketIO, THE Dashboard SHALL update the threat timeline and all four KPI card values within 1 second.
11. THE Dashboard SHALL contain no business logic; all data SHALL be fetched from the REST_API or received via SocketIO events.
12. THE Dashboard SHALL display a visible "Reconnecting…" status indicator when the SocketIO connection is lost and automatically retry connection at 5-second intervals.

