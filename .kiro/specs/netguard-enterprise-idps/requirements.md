# Requirements Document

## Introduction

Net-Guard Enterprise IDPS transforms the existing Net-Guard project into a
commercial-grade, AI-powered Intrusion Detection and Prevention System capable
of competing against Fortinet, Palo Alto, Cisco Secure, Microsoft Defender XDR,
CrowdStrike Falcon, SentinelOne, IBM QRadar, Splunk Enterprise Security, Wazuh,
Elastic Security, Suricata, Zeek, and Seceon aiSIEM/aiXDR.

The system extends the current Flask + SQLite + Scapy + vanilla-JS stack with
thirteen capability areas: enterprise-grade IP blocking, attack scheduling,
a full attack lab, a realistic threat simulation engine, accurate world-map
GeoIP, enterprise settings, a professional log viewer, a complete UI/UX
redesign, an AI/ML detection engine, threat hunting and enrichment, horizontal
scalability, DevSecOps pipelines, and compliance reporting. All new capabilities
are built on top of the existing service, repository, and rule architecture —
new code reuses current patterns and is added only where the current
implementation is insufficient.

## Glossary

- **IDPS**: Intrusion Detection and Prevention System — the Net-Guard platform.
- **Block_Manager**: The upgraded prevention service responsible for persistent IP blocking, expiry, and audit.
- **Attack_Scheduler**: The new scheduling subsystem that queues and triggers simulated attacks.
- **Attack_Lab**: The interactive simulation environment replacing auto-start demo mode.
- **Threat_Simulator**: The engine that synthesises realistic attacker context (IP, ASN, threat actor, campaign) for simulated attacks.
- **GeoIP_Engine**: The service resolving IPs to geographic and ASN metadata.
- **World_Map**: The frontend globe/map visualisation powered by GeoIP_Engine.
- **Log_Viewer**: The resizable, searchable, exportable log inspection modal.
- **Detection_Engine**: The existing rule-based packet analysis engine, extended with ML/AI capabilities.
- **AI_Engine**: The new machine-learning anomaly and behaviour analytics layer.
- **Threat_Intel**: The enrichment pipeline (VirusTotal, AbuseIPDB, Shodan, MITRE ATT&CK, CVE).
- **SOAR_Engine**: The Security Orchestration, Automation and Response automation layer.
- **SOC_Dashboard**: The enterprise security operations centre UI.
- **Settings_Manager**: The extended configuration service covering all enterprise settings categories.
- **Compliance_Reporter**: The component generating NIST CSF, CIS Controls, ISO 27001, and MITRE ATT&CK compliance reports.
- **Plugin_Registry**: The plugin marketplace and loader.
- **RBAC**: Role-Based Access Control.
- **IOC**: Indicator of Compromise.
- **MITRE_ATT&CK**: MITRE Adversarial Tactics, Techniques, and Common Knowledge framework.
- **CIDR**: Classless Inter-Domain Routing — a compact notation for IP ranges.
- **ASN**: Autonomous System Number — identifies a network operator's routing block.
- **TOR**: The Onion Router anonymisation network.


## Requirements

---

### Requirement 1: Enterprise IP Block Management

**User Story:** As a SOC analyst, I want a robust, persistent IP blocking system
with full audit trail, so that I can reliably stop attackers and prove compliance
to auditors.

#### Acceptance Criteria

1. WHEN a manual block is submitted via the UI or REST API AND the firewall rule is applied successfully AND the block record is persisted to the database, THE Block_Manager SHALL return an HTTP 200 success response within 2 seconds; IF either the firewall apply or the database persist fails, THE Block_Manager SHALL return an HTTP 500 error and not leave a partial state.
2. WHEN the system restarts, THE Block_Manager SHALL re-apply all database records where `active = 1` to the firewall within 30 seconds of startup, restoring the blocklist without operator intervention.
3. WHEN a block is created, THE Block_Manager SHALL record the operator identity, timestamp, reason text (maximum 1 000 characters), and IP address in an audit log entry that cannot be modified or deleted after creation.
4. WHEN a block expiry timer reaches zero, THE Block_Manager SHALL automatically remove the firewall rule and mark the record inactive, emitting an `ip_unblocked` WebSocket event containing the block record ID, IP address, and expiry timestamp.
5. WHEN a block request is submitted for an IP that is already actively blocked, THE Block_Manager SHALL extend the expiry from the current remaining expiry time by the requested duration instead of creating a duplicate rule.
6. THE Block_Manager SHALL support blocking individual IPv4/IPv6 addresses, CIDR ranges (up to /8), country codes (ISO 3166-1 alpha-2), and ASNs as distinct block target types.
7. WHEN a block is requested for an IP address that matches an active whitelist entry, THE Block_Manager SHALL reject the request and return a `WHITELISTED_IP` error code without modifying the firewall.
8. THE Block_Manager SHALL assign a threat score (0–100) to each block record, computed from: severity (input 0–10, normalised to 0–40), confidence (input 0–100, weighted 30%), and historical hit count for that IP (non-negative integer, weighted 30%).
9. WHEN a block target's threat score falls below a configurable threshold (default 20) after re-evaluation, THE Block_Manager SHALL mark the record for automatic unblock review and surface it in the analyst queue within 5 seconds of the score update.
10. THE Block_Manager SHALL expose a REST API at `POST /api/v1/blocks`, `DELETE /api/v1/blocks/{id}`, `GET /api/v1/blocks`, and `GET /api/v1/blocks/{id}` with full CRUD, pagination (maximum 100 records per page), and filtering by IP, type, status, and date range.
11. WHEN a manual block action is initiated from the UI, THE SOC_Dashboard SHALL display a confirmation dialog showing the target, reason, duration, and threat score before committing the action.
12. THE Block_Manager SHALL maintain a per-IP block reason history, accessible via `GET /api/v1/blocks/{ip}/history`, returning all past block records for that IP in descending chronological order.
13. WHEN IPv6 blocking is required, THE Block_Manager SHALL issue `ip6tables` commands alongside `iptables` commands, selecting the correct command based on the IP address family.
14. WHEN the firewall rule application fails after the block record has already been persisted, THE Block_Manager SHALL roll back the database record and return an HTTP 500 error so that the database and firewall remain consistent.
15. WHEN the database is unavailable during system restart block restoration, THE Block_Manager SHALL halt the restoration process, log the failure at CRITICAL level, and surface a `blocklist_restore_failed` alert rather than applying a partial blocklist.


---

### Requirement 2: Attack Scheduler

**User Story:** As a red team operator, I want to schedule simulated attacks at
specific times with recurring options, so that I can run predictable drills and
validate detection coverage without manual triggering.

#### Acceptance Criteria

1. WHEN a schedule entry is created, THE Attack_Scheduler SHALL accept a target datetime with timezone offset, attack type, configuration parameters, and an optional recurrence rule (cron expression or predefined interval); IF the target datetime is in the past, the attack type is unrecognised, or the cron expression is malformed, THE Attack_Scheduler SHALL reject the entry with a descriptive validation error and not persist the job.
2. WHEN the scheduled datetime arrives, THE Attack_Scheduler SHALL execute the configured attack simulation with less than 5 seconds of clock drift from the specified time.
3. WHILE a scheduled attack is pending, THE Attack_Scheduler SHALL display a live countdown timer (days, hours, minutes, seconds) in the Attack Lab UI, refreshing the display once per second.
4. WHEN the application restarts and pending jobs are found in the database, THE Attack_Scheduler SHALL skip any occurrences whose scheduled time has already passed and schedule only the next future occurrence, logging each skipped occurrence at INFO level.
5. WHEN a recurring schedule is defined, THE Attack_Scheduler SHALL automatically create the next occurrence after each execution, respecting the recurrence rule until a configured end date or manual cancellation, capping unbounded recurrences at 365 total occurrences.
6. THE Attack_Scheduler SHALL support batch scheduling: accepting a list of up to 50 attack configurations and scheduling them as a campaign with configurable inter-attack delays between 1 and 3 600 seconds; IF the list exceeds 50 items, THE Attack_Scheduler SHALL reject the entire batch with a `BATCH_LIMIT_EXCEEDED` error.
7. WHEN a scheduled job is queued, THE Attack_Scheduler SHALL expose it via `GET /api/v1/scheduler/jobs` with pagination (maximum 100 records per page), filterable by status and attack type.
8. THE Attack_Scheduler SHALL enforce a maximum of 10 concurrently running simulated attacks; WHEN a job is ready to execute but the concurrency cap is reached, THE Attack_Scheduler SHALL mark the job as `QUEUED` and retry execution every 10 seconds until a slot becomes available.
9. WHEN a scheduled attack fails to execute due to a system error, THE Attack_Scheduler SHALL log the failure, mark the job as `FAILED`, and emit a notification event without silently dropping the job.
10. WHEN a cancellation is submitted via `DELETE /api/v1/scheduler/jobs/{id}`, THE Attack_Scheduler SHALL mark the job as `CANCELLED`, stop any in-progress execution within 1 second, and return HTTP 200; IF the job ID does not exist, THE Attack_Scheduler SHALL return HTTP 404.


---

### Requirement 3: Enterprise Attack Lab

**User Story:** As a security engineer, I want to manually select, configure,
and launch realistic attack simulations against the IDPS, so that I can validate
detection rules and demonstrate capabilities to stakeholders.

#### Acceptance Criteria

1. WHEN the Attack Lab page loads, THE Attack_Lab SHALL display all available attack categories without starting any simulation automatically.
2. THE Attack_Lab SHALL provide selectable attack types covering at minimum: Port Scan, SYN Flood, UDP Flood, ICMP Flood, SQL Injection, Brute Force, XSS, Directory Traversal, DNS Amplification, HTTP Flood, SSH Attack, FTP Attack, Ransomware Behaviour, Malware Beacon, Lateral Movement, Privilege Escalation, and Data Exfiltration.
3. WHEN an attack type is selected, THE Attack_Lab SHALL display a configuration panel offering: difficulty level (Low/Medium/High/Critical), duration in seconds (1–3 600), packets per second (1–100 000), number of concurrent simulated attackers (1–100), payload template selection, expected detection outcome, and MITRE ATT&CK tactic/technique mapping.
4. WHEN a simulation is launched, THE Attack_Lab SHALL confirm the configuration with the operator before executing, displaying the target parameters and the estimated detection time in seconds based on the selected difficulty and rule thresholds.
5. WHILE a simulation is running, THE Attack_Lab SHALL display a real-time progress indicator showing elapsed time, packets sent, and current detection status, where detection status is one of: `PENDING`, `DETECTED`, `BLOCKED`, `MISSED`, or `CANCELLED`.
6. WHEN a simulation completes, THE Attack_Lab SHALL display a summary report showing whether the IDPS detected the attack (`DETECTED` or `MISSED`), the detection latency in milliseconds, and the count of MITRE ATT&CK tactics covered out of the total tactics mapped to that attack type.
7. THE Attack_Lab SHALL allow multiple simultaneous simulations up to the concurrency limit defined in Requirement 2.8.
8. WHEN a simulation is cancelled by the operator, THE Attack_Lab SHALL stop packet generation within 1 second and update the progress indicator to `CANCELLED` status.
9. WHEN a simulation launch is attempted and the concurrency limit is already reached, THE Attack_Lab SHALL reject the launch, display an error message identifying the limit value, and not initiate any packet generation.


---

### Requirement 4: Enterprise Threat Simulation Engine

**User Story:** As a security trainer, I want simulated attacks to originate from
realistic synthetic attacker profiles instead of localhost, so that detection rules,
GeoIP visualisations, and threat-intel enrichment are exercised with production-like
data.

#### Acceptance Criteria

1. WHEN a simulation is started, THE Threat_Simulator SHALL generate a unique attacker profile for each concurrent attacker (up to 10 000 simultaneous profiles per session) containing: a public routable IPv4/IPv6 address unique within the active session, country, ASN, ISP name, latitude, longitude, and city.
2. THE Threat_Simulator SHALL generate IP addresses that are uniformly distributed across the public address space, explicitly excluding RFC 1918 private ranges, loopback, link-local, and multicast ranges.
3. THE Threat_Simulator SHALL synthesise a threat actor profile for each simulated attacker including: actor name, risk score (0–100), reputation score (0–100), malware family association, and attack campaign name.
4. THE Threat_Simulator SHALL be able to simulate traffic originating from the following source categories, each selectable independently: major cloud provider ranges (AWS, Azure, GCP, DigitalOcean, OVH, Hetzner, Oracle Cloud, Tencent Cloud, Alibaba Cloud), TOR exit nodes, known botnet IP ranges, VPN service egress IPs, residential proxy pools, compromised server profiles, and CDN edge nodes; IF no source category is selected, THE Threat_Simulator SHALL default to uniform random public IP generation.
5. WHEN a source category is selected, THE Threat_Simulator SHALL generate IPs that fall within the published IP ranges for that category (e.g., AWS ip-ranges.json), such that each generated IP is verifiably within at least one published CIDR block for that provider.
6. THE Threat_Simulator SHALL expose the generated attacker profiles via the `new_threat` WebSocket payload so that GeoIP_Engine and World_Map can render them without additional API calls.
7. FOR ALL generated IP addresses, THE Threat_Simulator SHALL verify that the address is not in the system's whitelist before injecting it into the simulation pipeline; IF all retries within 10 attempts yield only whitelisted IPs, THE Threat_Simulator SHALL emit a `whitelist_exhaustion` warning event and halt generation for that attacker slot.


---

### Requirement 5: World Map & GeoIP Accuracy

**User Story:** As a SOC analyst, I want the world map to accurately show where
attacks originate, with real-time animations and filtering, so that I can identify
geographic attack patterns and communicate threat posture to management.

#### Acceptance Criteria

1. THE GeoIP_Engine SHALL resolve IP addresses to geographic coordinates using at least one of the following providers, selectable via settings: MaxMind GeoLite2 (local database), IPinfo API, or ip-api.com, with a configurable fallback chain; IF all providers in the fallback chain fail for a given IP, THE GeoIP_Engine SHALL return a structured error per criterion 8.
2. WHEN a Nepal or Kathmandu IP address is resolved, THE GeoIP_Engine SHALL return coordinates within 50 km of Kathmandu (27.7°N, 85.3°E), with a maximum error of 50 km for city-level resolution.
3. WHEN a new threat event is received via the WebSocket listener, THE World_Map SHALL animate a pulse effect at the attacker's coordinates within 500 ms of the listener receiving the event.
4. THE World_Map SHALL render connection lines from attacker coordinates to the configured headquarters coordinates (set in Settings_Manager), with line colour corresponding to severity: risk score 0–24 green, 25–49 yellow, 50–74 orange, 75–100 red.
5. THE World_Map SHALL support heatmap clustering mode, where dense attack regions are rendered as a colour-weighted heat gradient rather than individual point markers.
6. THE World_Map SHALL support zoom (scroll or pinch), pan (drag), and region/country filtering by clicking on a country to isolate its events.
7. THE World_Map SHALL include an attack timeline replay control: a scrubber that replays all events within a selected time window (maximum 24 hours) at configurable replay speed (1×, 5×, 10×), and when replay reaches the end of the window, it pauses at the final event.
8. WHEN GeoIP resolution fails for an IP, THE GeoIP_Engine SHALL return a structured error containing the IP address, error code, and timestamp, and THE World_Map SHALL display that event on an "Unknown Location" marker at coordinates (0.0°, 0.0°) rather than silently dropping it.
9. THE GeoIP_Engine SHALL cache resolved coordinates in memory (LRU, max 10 000 entries, TTL 24 hours) to avoid redundant API calls for repeated IPs.


---

### Requirement 6: Enterprise Settings

**User Story:** As a system administrator, I want a comprehensive settings
interface that covers every aspect of the IDPS, so that I can configure the
system without editing files or restarting services.

#### Acceptance Criteria

1. THE Settings_Manager SHALL organise all settings into named sections: General, Appearance, Detection Engine, Threat Intelligence, Alerting, Performance, Notifications, Firewall, AI Detection, ML Sensitivity, Rule Management, Signature Updates, SOC Integrations, API Keys, GeoIP Providers, Email/Slack/Discord/Telegram/Syslog/SIEM, Database, Retention, Backup, Restore, Accessibility, Localization, Role Management, User Management, RBAC, Audit Logs, Licensing, Plugin Marketplace, and Developer/Experimental.
2. WHEN a setting is changed via the UI or `PUT /api/v1/settings`, THE Settings_Manager SHALL apply the change within 2 seconds without requiring an application restart, except for settings explicitly documented as restart-required; restart-required settings SHALL display a visible warning banner in the UI before the operator saves them.
3. THE Settings_Manager SHALL persist all settings to the database so that they survive application restarts, with the YAML file acting only as the initial seed for defaults.
4. THE Appearance section SHALL provide Dark Mode and Light Mode theme toggles, applying the selected theme across all pages within 200 ms without a full page reload.
5. THE Settings_Manager SHALL enforce RBAC: only users with the `admin` role may write to Security, Firewall, AI Detection, Role Management, and Licensing sections; users with the `analyst` role may write to Alerting and Notification settings only; all other roles have read-only access to settings; WHEN an unauthorised write is attempted, THE Settings_Manager SHALL return HTTP 403 and log the attempt in the audit log.
6. WHEN backup is triggered via the Backup section, THE Settings_Manager SHALL export all settings, rules, block history, and whitelist entries to a single password-protected archive file downloadable by the operator, completing the export within 60 seconds for datasets up to 1 GB.
7. WHEN a backup archive is uploaded in the Restore section, THE Settings_Manager SHALL validate the archive checksum and decrypt it, then present the operator with a list of any conflicts (same key, differing values) and require explicit confirmation before committing any data.
8. THE Plugin_Registry SHALL discover, list, enable, disable, and load plugins from a designated plugin directory, exposing a `GET /api/v1/plugins` endpoint that returns each plugin's name, version, description, and enabled status.
9. WHEN the API Keys section is accessed, THE Settings_Manager SHALL display existing key IDs, creation dates, and the last 4 characters of each key value with the remainder masked; WHEN a key is rotated via `POST /api/v1/settings/apikeys/rotate`, THE Settings_Manager SHALL return the new key value exactly once in the response and never store or display it in plain text thereafter.


---

### Requirement 7: Enterprise Log Viewer

**User Story:** As a SOC analyst, I want a powerful, in-page log viewer that
lets me search, filter, and export log events, so that I can investigate
incidents without leaving the dashboard or switching to a terminal.

#### Acceptance Criteria

1. WHEN the log viewer is opened, THE Log_Viewer SHALL render as a resizable modal that defaults to 70% of the viewport and can be dragged to full-screen mode.
2. WHEN the operator types in the search field, THE Log_Viewer SHALL filter and highlight matching results across all visible log fields (timestamp, level, module, event, message) within 200 ms of the last keystroke (debounced), displaying the count of matching entries above the log list.
3. THE Log_Viewer SHALL support filtering by severity level (DEBUG, INFO, WARNING, ERROR, CRITICAL), module name, date range, MITRE ATT&CK tactic, and CVE ID; WHEN multiple filters are active simultaneously, THE Log_Viewer SHALL apply them with AND logic and display the combined match count.
4. WHEN the operator selects one or more log entries and clicks Export, THE Log_Viewer SHALL offer download in JSON or CSV format containing all visible fields of the selected entries; IF no entries are selected, THE Log_Viewer SHALL disable the Export button and display a tooltip indicating that at least one entry must be selected.
5. WHEN the log viewer renders, THE Log_Viewer SHALL display a mini-timeline above the log list showing event density in time buckets (one bucket per 8 pixels of timeline width, minimum 10 buckets, maximum 120 buckets), and WHEN the operator clicks a bucket, THE Log_Viewer SHALL scroll the log list to the first entry within that time segment.
6. THE Log_Viewer SHALL display severity badges (colour-coded pill labels), MITRE ATT&CK tactic/technique badges, CVE ID badges, and IOC indicator badges on each log row where applicable data is present.
7. THE Log_Viewer SHALL support pinning up to 10 log entries to a sticky section at the top of the viewer that persists across searches and filter changes within the session; WHEN an operator attempts to pin an 11th entry, THE Log_Viewer SHALL reject the action and display an error indicating the 10-entry limit.
8. WHEN the ESC key is pressed while the Log_Viewer is open, THE Log_Viewer SHALL close the modal and restore focus to the previously focused element.
9. WHEN `Ctrl+F` is pressed while the Log_Viewer is open, THE Log_Viewer SHALL focus the search field; WHEN `Ctrl+A` is pressed while the Log_Viewer is focused, THE Log_Viewer SHALL select all visible log entries for bulk export, suppressing the browser's default select-all behaviour within the modal.


---

### Requirement 8: UI/UX Complete Redesign

**User Story:** As a SOC operator, I want a professional, consistent, and
accessible dashboard that matches enterprise SOC tools, so that I can work
efficiently during high-pressure incidents without UI friction or visual confusion.

#### Acceptance Criteria

1. THE SOC_Dashboard SHALL implement a glassmorphism-style design system with a consistent 8-point spacing grid, a defined set of design tokens (colour palette, typography scale, border-radius, shadow levels), and the project logo from `logooo.jpeg` displayed in the header and login page.
2. THE SOC_Dashboard SHALL render correctly on viewport widths from 1024 px to 3840 px (ultrawide), with responsive layout shifts only at the four defined breakpoints (1024 px, 1440 px, 1920 px, 2560 px), and no unintended layout shifts (CLS score < 0.1).
3. WHEN an async data region finishes loading, THE SOC_Dashboard SHALL replace the skeleton placeholder with real content within 5 seconds of the fetch completing, without a full-page flash.
4. THE SOC_Dashboard SHALL provide smooth CSS transitions (duration 150–300 ms, easing `ease-out`) for all interactive state changes (hover, focus, active, modal open/close, panel expand/collapse).
5. THE SOC_Dashboard SHALL achieve WCAG 2.1 AA colour contrast ratios for all text and interactive elements in both Dark and Light themes.
6. WHEN the operator presses `Ctrl+K`, THE SOC_Dashboard SHALL open the command palette; WHEN the operator presses ESC or activates a command, THE SOC_Dashboard SHALL close the command palette and return focus to the previously active element.
7. THE SOC_Dashboard SHALL support resizable panels and dockable widgets: analysts can drag panel dividers to resize the threat timeline, log viewer, and map sections, with layout persisted across sessions; IF the persistence store is unavailable, THE SOC_Dashboard SHALL fall back to the default layout without error.
8. THE SOC_Dashboard SHALL render the following data visualisations: real-time line charts for traffic rate, donut charts for severity distribution, heatmap grids for hourly/daily attack frequency, network graph for lateral movement paths, attack timeline with MITRE ATT&CK swim lanes, and threat score gauge widgets; WHEN a visualisation has no data to display, it SHALL show a clearly labelled empty-state placeholder.
9. THE SOC_Dashboard SHALL provide full keyboard navigation: all interactive elements are reachable by Tab, activatable by Enter/Space, and modal dialogs trap focus correctly with a visible focus ring.
10. WHEN the Dark/Light mode toggle is activated, THE SOC_Dashboard SHALL switch themes within 200 ms without a page reload and persist the selection across sessions.


---

### Requirement 9: AI & Detection Engine

**User Story:** As a security architect, I want the IDPS to move beyond
threshold-based rules to AI-driven anomaly and behaviour detection, so that
it can catch zero-day attacks and unknown attack patterns that signature rules miss.

#### Acceptance Criteria

1. THE AI_Engine SHALL implement a baseline statistical anomaly detector that monitors per-IP packet rate, connection frequency, and payload entropy, flagging deviations greater than 3 standard deviations from a rolling 5-minute baseline as anomaly events; WHILE the detector has fewer than 5 minutes of baseline data (cold-start), it SHALL suppress anomaly flagging and log a `baseline_warming_up` status event.
2. THE AI_Engine SHALL implement a behaviour analytics module that correlates sequences of at least 3 events from the same source IP across a 10-minute window, detecting multi-stage attack patterns (reconnaissance → exploitation → exfiltration) as defined in MITRE ATT&CK; WHEN a correlated sequence is detected, THE AI_Engine SHALL emit a behaviour event containing the source IP, matched tactic sequence, and contributing event IDs.
3. THE Detection_Engine SHALL support loading Sigma rules from a configurable directory, converting them to internal rule objects at startup, and hot-reloading them when the directory contents change; IF a Sigma rule file fails to parse, THE Detection_Engine SHALL skip that file, log the parse error with the file name and line number, and continue loading remaining rules.
4. THE Detection_Engine SHALL support loading YARA rules from a configurable directory and evaluating them against HTTP payload content captured by existing packet parsers; IF a YARA rule file fails to compile, THE Detection_Engine SHALL skip that file, log the compile error, and continue loading remaining rules.
5. THE Detection_Engine SHALL provide export adapters for Suricata rule format: `GET /api/v1/rules/export?format=suricata` returns all active rules converted to Suricata rule syntax; IF no active rules exist, the endpoint SHALL return an empty array with HTTP 200.
6. THE SOAR_Engine SHALL execute automated response playbooks triggered by ThreatEvent severity and type, supporting at minimum: auto-block (call Block_Manager), Slack/webhook notification, email alert, and syslog forwarding as playbook action types.
7. WHEN a SOAR playbook action fails, THE SOAR_Engine SHALL log the failure, retry up to 3 times with exponential backoff (1 s, 2 s, 4 s), and emit a `soar_action_failed` event if all retries are exhausted.
8. THE Detection_Engine SHALL produce a per-event MITRE ATT&CK tactic and technique annotation for all detected events, stored in the `evidence` field and surfaced in the UI threat timeline.
9. WHEN `GET /api/v1/ai/calibration` is called, THE AI_Engine SHALL return a JSON object containing: per-IP rolling mean and standard deviation for packet rate, connection frequency, and payload entropy; the current baseline window start time; and the warm-up status; WHEN an operator submits a manual override via `PUT /api/v1/ai/calibration`, THE AI_Engine SHALL replace the stored baseline values with the operator-supplied values and tag the calibration record as manually overridden until the next automatic recalculation.


---

### Requirement 10: Threat Hunting & Enrichment

**User Story:** As a threat hunter, I want every detected event automatically
enriched with external threat-intelligence context and MITRE/CVE mappings, so
that I can triage faster and focus investigation effort on high-confidence threats.

#### Acceptance Criteria

1. WHEN a ThreatEvent is persisted, THE Threat_Intel SHALL asynchronously enrich the source IP by querying at least one configured external source (VirusTotal, AbuseIPDB, Shodan, or Censys) and updating the event record with the enrichment result within 30 seconds; IF all configured external sources fail or are unreachable, THE Threat_Intel SHALL mark the event `enrichment_failed` and log the failure without blocking event persistence.
2. THE Threat_Intel SHALL correlate all active IOCs (source IP, domain, file hash from payload) against the enrichment results, tagging events with a boolean `ioc_match` flag and the matching IOC identifiers.
3. THE Threat_Intel SHALL assign a composite risk score (0–100) to each event based on: base severity (40%), external reputation score (30%), IOC match (20%), and historical recurrence for that IP (10%); the four weights SHALL sum to 100%.
4. THE Threat_Intel SHALL assign a confidence score (0–100) to each event, with false-positive suppression rules configurable per rule name, allowing operators to tune down noisy rules without disabling them; a suppression adjustment SHALL not reduce confidence below 1.
5. THE Threat_Intel SHALL support adaptive learning: WHEN an operator marks an event as a false positive via `POST /api/v1/events/{id}/feedback`, THE Threat_Intel SHALL persist the feedback and decrease the confidence score for future events matching the same rule name and source IP subnet (/24) by a configurable step value (default 5 points), not reducing below 1.
6. THE Threat_Intel SHALL expose a `GET /api/v1/hunt?ioc={value}` endpoint that returns all events, blocks, and enrichment data related to a given IOC value across the full event history, paginated at 100 records per page.
7. WHEN a new CVE identifier is referenced in a Sigma or YARA rule loaded by Detection_Engine, THE Threat_Intel SHALL attempt to fetch the CVE summary from the NVD API within 60 seconds and cache it locally (TTL 24 hours) for display in the Log_Viewer CVE badge; IF the NVD API is unreachable, THE Threat_Intel SHALL display the raw CVE ID without a summary and retry on the next rule reload.
8. THE Threat_Intel SHALL provide an OSINT pivot panel in the threat detail view, rendering enrichment data as a structured card with external links to VirusTotal, AbuseIPDB, and Shodan for each source IP.


---

### Requirement 11: Performance & Scalability

**User Story:** As a platform engineer, I want the IDPS to support horizontal
scaling, message queues, and caching, so that it can handle enterprise-level
traffic volumes without packet loss or API latency degradation.

#### Acceptance Criteria

1. THE Detection_Engine SHALL process packets using multi-threaded rule evaluation: each rule runs in a dedicated worker from a configurable thread pool (default 4 workers, minimum 1, maximum 32), so that a slow rule does not block others.
2. THE IDPS SHALL expose a Docker Compose configuration that starts the backend, a Redis instance for caching and queuing, and a reverse-proxy (nginx) in a single `docker compose up` command with no manual pre-configuration required.
3. WHEN Redis is configured and reachable, THE Detection_Engine SHALL publish ThreatEvents to a Redis Streams channel (`netguard:events`) in addition to the in-process queue; IF Redis is unreachable, THE Detection_Engine SHALL fall back to the in-process queue only and log a `redis_unavailable` warning.
4. THE API Gateway layer SHALL enforce rate limiting at 300 requests per minute per authenticated user, returning HTTP 429 with a `Retry-After` header (value in seconds) when the limit is exceeded.
5. THE IDPS SHALL use Redis as a shared cache for: GeoIP resolution results (TTL 24 h), enrichment results (TTL 1 h), and live stats (TTL 2 s), falling back to direct computation when Redis is unavailable.
6. WHEN the packet queue depth reaches 8 000 of 10 000 slots (80% capacity), THE Detection_Engine SHALL emit a `queue_pressure` warning event and log it at WARNING level.
7. THE IDPS architecture documentation SHALL describe a horizontal scaling pattern using Redis Streams as the shared event bus, allowing multiple Detection_Engine instances to consume from separate packet capture nodes.
8. WHEN `TLS_CERT_FILE` and `TLS_KEY_FILE` environment variables are set, THE IDPS SHALL terminate all API and WebSocket connections over TLS with a minimum protocol version of TLS 1.2, rejecting connections that propose lower protocol versions.


---

### Requirement 12: DevSecOps

**User Story:** As a DevOps engineer, I want automated security scanning,
supply chain protection, and high-availability configuration, so that the
IDPS itself is hardened and resilient.

#### Acceptance Criteria

1. THE IDPS SHALL provide a Dockerfile with a non-root user (UID ≥ 1000), the `python:3.12-slim` base image, no secrets or credentials in any image layer, and a `HEALTHCHECK` instruction that calls `GET /api/v1/health` every 30 seconds with a 10-second timeout.
2. THE IDPS repository SHALL include a `sbom.json` file in CycloneDX 1.4 JSON format, regenerated by the CI pipeline on each merge to main, listing all direct and transitive Python dependencies with their version and SPDX licence identifier.
3. WHEN a `pip audit` scan is run against the pinned `requirements.txt`, THE IDPS SHALL have zero known vulnerabilities with CVSSv3 base score ≥ 7.0 in direct dependencies; IF any are found, the CI pipeline SHALL fail the build and block merging.
4. THE IDPS test suite SHALL include property-based fuzz tests for `PacketDecoder.decode()` and `ConfigurationManager.load()` using Hypothesis strategies that generate arbitrary byte sequences and arbitrary key-value mappings respectively, asserting that no unhandled exception propagates to the caller.
5. THE IDPS SHALL include a `backup.sh` script that: dumps the SQLite database to a timestamped `.db` file, compresses it with gzip, and writes a SHA-256 checksum file alongside it; the script SHALL exit with code 1 and print an error if the dump or compression fails.
6. WHEN the `BACKUP_RESTORE` API endpoint receives a backup archive, THE Settings_Manager SHALL compute the SHA-256 checksum of the uploaded file and compare it against the checksum file included in the archive, rejecting the archive with a `CHECKSUM_MISMATCH` error code if they do not match, before applying any data.
7. THE IDPS deployment documentation SHALL describe a high-availability pattern: two active instances sharing a PostgreSQL backend (replacing SQLite), with a load balancer health-checking `GET /api/v1/health` every 10 seconds and routing traffic only to instances returning HTTP 200.


---

### Requirement 13: Compliance & Reporting

**User Story:** As a CISO, I want automated compliance reports and role-based
dashboards, so that I can demonstrate security posture to regulators, board
members, and customers without manually compiling data.

#### Acceptance Criteria

1. THE Compliance_Reporter SHALL generate compliance gap reports for the following frameworks on demand: NIST CSF (Identify/Protect/Detect/Respond/Recover), CIS Controls v8, ISO 27001 Annex A, and MITRE ATT&CK Enterprise.
2. WHEN a compliance report is requested, THE Compliance_Reporter SHALL produce a PDF or JSON document within 60 seconds containing: framework name, assessment date, total controls evaluated, percentage compliant (rounded to one decimal place), and a per-control finding with status (Pass/Fail/Partial) and a reference to the evidence or IDPS feature that supports or fails the control.
3. THE SOC_Dashboard SHALL provide four distinct dashboard views selectable by the current user's role: Executive (high-level KPIs and risk score), SOC Analyst (threat timeline, active blocks, MITRE coverage), Threat Hunter (IOC search, enrichment panel, pivot links), and Customer (aggregated summary without internal IP details); WHEN a user's role does not match a view, that view SHALL not be selectable.
4. THE Compliance_Reporter SHALL expose `GET /api/v1/reports/compliance?framework={name}` returning the most recently generated report for the requested framework with a `last_generated` ISO 8601 timestamp; WHEN `regenerate=true` is passed, THE Compliance_Reporter SHALL recompute the report before responding; IF the framework name is unrecognised, the endpoint SHALL return HTTP 400 with the list of supported framework names.
5. THE SOC_Dashboard executive view SHALL render a risk score trend chart showing the organisation's composite risk score (computed from active threats, unresolved CVEs, and compliance gaps) over the last 30 days, with one data point per day.
6. THE Plugin_Registry SHALL support at minimum one example plugin that adds a new dashboard widget, with the plugin loading mechanism documented so that third-party developers can build and install additional plugins without modifying core IDPS files.


---

### Requirement 14: Authentication, RBAC & Multi-User

**User Story:** As an IT security manager, I want role-based access control with
multi-factor authentication, so that junior analysts, senior SOC engineers, and
executives each see and can do only what their role permits.

#### Acceptance Criteria

1. THE IDPS SHALL implement JWT-based session authentication: `POST /api/v1/auth/login` returns a signed JWT (HS256, 8-hour expiry) and a refresh token (30-day expiry); all non-public API endpoints SHALL require a valid `Authorization: Bearer <token>` header and return HTTP 401 if the token is absent, expired, or invalid.
2. THE IDPS SHALL support at minimum four built-in RBAC roles: `admin` (full access), `analyst` (read/write on threats, blocks, whitelist; no settings), `hunter` (read-only with enrichment pivot access), and `viewer` (read-only dashboard access); role assignments SHALL be stored in the database and applied on every authenticated request without requiring a restart.
3. WHEN a user attempts an action not permitted by their role, THE IDPS SHALL return HTTP 403 with a `FORBIDDEN` error code and log the attempt in the audit log with the user identity, attempted action, resource path, and timestamp.
4. WHEN MFA is enabled for a user account, THE IDPS SHALL require a valid TOTP code (RFC 6238, 30-second window, 1-step clock drift tolerance) at login in addition to the password, returning HTTP 401 with an `MFA_REQUIRED` or `MFA_INVALID` error code as appropriate.
5. THE IDPS SHALL maintain an immutable audit log of all authentication events (login, logout, failed login, token refresh, MFA challenge) and all mutating API calls (create, update, delete), accessible only via `GET /api/v1/audit` to users with the `admin` role; audit log entries SHALL NOT be modifiable or deletable via any API endpoint.
6. WHEN a user account is created, THE IDPS SHALL enforce a minimum password of 12 characters including at least one uppercase letter, one digit, and one special character; IF the submitted password does not meet this policy, THE IDPS SHALL return HTTP 400 with a human-readable error listing the unmet criteria.


---

### Requirement 15: External Integrations & Alerting

**User Story:** As a SOC team lead, I want the IDPS to push critical alerts to
Slack, email, Discord, Telegram, and SIEM platforms, so that the team is notified
through their existing communication channels without polling the dashboard.

#### Acceptance Criteria

1. THE SOAR_Engine SHALL support the following notification channels, each independently configurable and togglable via Settings_Manager: Email (SMTP with STARTTLS), Slack (Incoming Webhook), Discord (Webhook), Telegram (Bot API), generic HTTP Webhook, and Syslog (UDP/TCP RFC 3164/5424).
2. WHEN a Critical severity ThreatEvent is persisted, THE SOAR_Engine SHALL dispatch notifications to all enabled channels within 10 seconds of the event being written to the database.
3. THE SOAR_Engine SHALL support per-channel severity threshold configuration: each channel independently specifies the minimum severity (Low/Medium/High/Critical) that triggers a notification; events below the channel threshold SHALL be silently skipped for that channel only.
4. THE SOAR_Engine SHALL format all notifications with the following fields: attack type, source IP, GeoIP country (or "Unknown" if unresolved), severity label, confidence score (0–100), ISO 8601 timestamp, and a direct HTTPS link to the event detail page.
5. WHEN a notification channel delivery fails, THE SOAR_Engine SHALL retry up to 3 times with exponential backoff (delays: 2 s, 4 s, 8 s); IF all retries fail, THE SOAR_Engine SHALL mark the channel status as `degraded` in the Settings_Manager notification health panel and emit a `channel_degraded` WebSocket event.
6. THE IDPS SHALL support forwarding structured events to external SIEMs via: Elastic Common Schema (ECS) JSON over HTTPS, Splunk HEC (HTTP Event Collector) JSON, Wazuh agent socket (JSON over TCP), and OpenSearch HTTP Bulk API; each integration SHALL be independently selectable from the SOC Integrations settings section.
7. WHEN a SIEM integration is tested via `POST /api/v1/settings/integrations/test`, THE IDPS SHALL send a synthetic test event to the configured target and return the HTTP status code and response body from the target system in the API response within 15 seconds; IF the target does not respond within 15 seconds, THE IDPS SHALL return a `INTEGRATION_TIMEOUT` error.

