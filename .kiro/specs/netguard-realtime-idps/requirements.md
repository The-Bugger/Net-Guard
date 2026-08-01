# Requirements Document

## Introduction

This spec supersedes the demo-related requirements in `netguard-hackathon-upgrade` and transforms
NetGuard from a simulation-based application into a production-ready Intrusion Detection &
Prevention System (IDPS) suitable for a live hackathon demonstration against a real attacker
device on the same LAN.

The existing Flask/SQLAlchemy/SQLite/SocketIO/CaptureEngine/DetectionEngine/PreventionEngine
architecture is **preserved in full**. No components are rewritten. This spec removes demo
infrastructure and replaces it with real capture, real detection, real blocking, a weighted
health-score formula, an explainable Security Advisor, and attack test scripts.

All component names from the `netguard-idps` Glossary are reused unchanged.

---

## Glossary

- **CaptureEngine**: The existing Scapy-based packet capture engine at
  `detection/capture/sniffer.py`. Starts on a named interface; forwards decoded `Packet`
  objects to `packet_queue`.
- **DetectionEngine**: The existing service at `backend/services/detection_service.py` that
  runs five `BaseRule` subclasses (SynFloodRule, PortScanRule, SqlInjectionRule,
  BruteForceRule, ArpSpoofRule) and invokes `_on_threat_event` on confirmed detections.
- **PreventionEngine**: The existing service at `backend/services/prevention_service.py` that
  issues iptables DROP rules and manages timed unblocks via `BlockRepository`.
- **LanScanService**: The existing service at `backend/services/lan_scan_service.py` that
  discovers LAN devices via Scapy ARP scan or OS ARP cache fallback.
- **ExplainabilityEngine**: The existing service at `backend/services/explain_service.py` that
  generates plain-English `Explanation` objects for every `ThreatEvent`.
- **SecurityAdvisor**: The new service (`backend/services/security_advisor.py`) — an offline
  rule-based engine that computes a weighted Health_Score and returns contextual security
  advice from a built-in knowledge base of 20+ entries. Optionally delegates to the Gemini
  API when `GEMINI_API_KEY` is set; silently falls back to the offline engine on any error.
- **HealthScore**: An integer in [0, 100] computed deterministically from attack types
  detected today. Formula: start at 100, subtract per-attack-type deductions (see
  Requirement 9), floor at 0. Never random.
- **DemoService**: `backend/services/demo_service.py` — **to be deleted**. No simulated
  events, no demo routes, no placeholder data anywhere in the application.
- **AttackTestScript**: A standalone shell/Python script in `scripts/attack_tests/` that
  a second laptop runs to trigger one specific real attack type (hping3 for SYN flood, nmap
  for port scan, hydra for brute force, arpspoof for ARP spoofing, curl for SQL injection).
- **EvidencePanel**: The dashboard UI panel that displays structured evidence (packet counts,
  matched patterns, conflicting MACs, timestamps) for each detected `ThreatEvent`.
- **MonitorService**: The existing service at `backend/services/monitor_service.py` that
  starts and stops `CaptureEngine` and `DetectionEngine` together.
- **Interface**: A named OS network adapter (e.g. `eth0`, `wlan0`, `Ethernet`) on which
  `CaptureEngine` captures packets.

---

## Requirements

### Requirement 1: Remove All Demo Infrastructure

**User Story:** As a hackathon judge, I want the dashboard to show only real network data,
so that I can trust every alert and statistic represents actual captured traffic.

#### Acceptance Criteria

1. THE Dashboard SHALL NOT display any simulated, placeholder, random, or pre-seeded alert,
   statistic, or packet count at any time.
2. WHEN the application starts and `CaptureEngine` has not yet decoded any `Packet` object
   from a live interface, THE Dashboard SHALL display zero for `packets_processed`,
   `alerts_today`, `active_blocks`, and `packets_per_second`.
3. THE System SHALL remove `backend/services/demo_service.py` and
   `backend/routes/demo_routes.py` from the codebase; no file named `demo_service.py` or
   `demo_routes.py` SHALL exist anywhere under `backend/`.
4. THE System SHALL remove all demo-mode UI elements (demo start/stop buttons, demo status
   badges, demo toggle switches, attack simulator panels) from every file under `frontend/`
   (HTML, JS, and CSS).
5. THE REST_API SHALL return HTTP 404 for any request to `/api/v1/demo/*` endpoints after
   removal.
6. IF `demo_service` or `demo_routes` is imported anywhere after removal, THEN THE System
   SHALL fail to start with a clear `ImportError` identifying the deleted module.
7. THE System SHALL remove `scripts/start_demo.sh` and any other shell script whose sole
   purpose is to start or exercise demo mode; general-purpose test scripts in
   `scripts/attack_tests/` are unaffected.

---

### Requirement 2: Real Packet Capture on Live Interfaces

**User Story:** As a security operator, I want NetGuard to capture packets from a real network
interface, so that detection is based on actual LAN traffic.

#### Acceptance Criteria

1. WHEN `MonitorService.start(interface)` is called, THE CaptureEngine SHALL begin capturing
   live packets on the named `Interface` within 2 seconds. The engine may run briefly without
   processing packets if no traffic is present on the interface.
2. THE REST_API SHALL provide `GET /api/v1/interfaces` that returns a list of available OS
   network interfaces (name, description, is_up) discoverable via `psutil.net_if_stats()`.
3. WHEN `CaptureEngine` is started without specifying an interface, THE System SHALL
   auto-select the first active non-loopback interface returned by `psutil.net_if_stats()`.
4. IF the specified `Interface` does not exist or is down, THEN THE CaptureEngine SHALL log
   an error to `logs/system.log` and emit a `monitoring_error` SocketIO event with the
   interface name and reason, without crashing.
5. WHILE `CaptureEngine` is running, THE StatsService SHALL increment `packets_processed`
   for every decoded `Packet` received from `packet_queue`.
6. WHILE `CaptureEngine` is running, THE Dashboard SHALL display the active `Interface` name
   and a green "Monitoring Active" status badge.

---

### Requirement 3: SYN Flood Detection from Real Traffic

**User Story:** As a security operator, I want NetGuard to detect SYN flood attacks launched
from a real device, so that volumetric DoS attempts are caught in real time.

#### Acceptance Criteria

1. WHEN `SynFloodRule` processes packets and counts ≥ 100 TCP packets with the SYN flag set
   and the ACK flag clear from a single source IP within a 3-second sliding window,
   THE DetectionEngine SHALL emit a `ThreatEvent` with `attack_type = "SYN Flood"` and
   `rule_name = "SYN_FLOOD_001"`.
2. THE `ThreatEvent.severity` SHALL be `"Medium"` for 100–199 packets, `"High"` for 200–399
   packets, and `"Critical"` for ≥ 400 packets per window.
3. THE `ThreatEvent.confidence` SHALL equal `min(round(count / threshold * 50), 100)` where
   `threshold = 100`; a count of exactly 100 yields confidence 50, a count of 200 yields 100.
4. THE `ThreatEvent.evidence` SHALL contain `syn_packet_count` (int), `time_window_seconds`
   (float), `threshold` (int), `destination_ips` (list, up to 10 entries), and
   `sample_timestamps` (list, up to 5 entries in ISO-8601 format).
5. IF a SYN flood `ThreatEvent` was already emitted for a source IP within the last 10 seconds
   AND the new event's severity does not exceed the previous event's severity,
   THEN THE DetectionEngine SHALL suppress the duplicate event and SHALL NOT call
   `_on_threat_event`.
6. THE AttackTestScript `scripts/attack_tests/syn_flood.sh` SHALL trigger this detection by
   running `hping3 -S -p 80 --flood <TARGET_IP>` for at least 5 seconds, which SHALL
   reliably produce ≥ 100 qualifying SYN packets within a 3-second window.

---

### Requirement 4: Port Scan Detection from Real Traffic

**User Story:** As a security operator, I want NetGuard to detect Nmap port scans launched
from a real device, so that network reconnaissance is immediately flagged.

#### Acceptance Criteria

1. WHEN `PortScanRule` observes ≥ 20 unique destination ports contacted via TCP (any flags)
   or UDP from a single source IP within a 10-second sliding window,
   THE DetectionEngine SHALL emit a `ThreatEvent` with `attack_type = "Port Scan"` and
   `rule_name = "PORT_SCAN_001"`.
2. THE `ThreatEvent.severity` SHALL be `"Medium"` for 20–39 ports, `"High"` for 40–79 ports,
   and `"Critical"` for ≥ 80 ports.
3. THE `ThreatEvent.evidence` SHALL contain `scanned_ports` (list of integers, up to 20
   entries showing first 20 distinct ports), `unique_port_count` (integer), and
   `time_window_seconds` (float).
4. THE AttackTestScript `scripts/attack_tests/port_scan.sh` SHALL trigger this detection by
   running `nmap -sS -T4 <TARGET_IP>` which scans the top 1000 ports and SHALL reliably
   contact ≥ 30 unique ports within the 10-second window, completing in under 30 seconds.

---

### Requirement 5: SQL Injection Detection from Real HTTP Traffic

**User Story:** As a security operator, I want NetGuard to detect SQL injection payloads sent
over HTTP from a real device, so that web application attacks are flagged at the network layer.

#### Acceptance Criteria

1. WHEN `SqlInjectionRule` receives a TCP packet destined for port 80, 443, 8080, or 8443 and
   the decoded payload (UTF-8 with `errors="ignore"`) matches any of the five patterns
   case-insensitively: `' OR`, `UNION SELECT`, `DROP TABLE`, `--`, `xp_cmdshell`,
   THE DetectionEngine SHALL emit a `ThreatEvent` with `attack_type = "SQL Injection"` and
   `confidence = 100`.
2. WHEN the first `SQL Injection` `ThreatEvent` is emitted for a source IP within a session
   (no prior SQL injection event in the last 300 seconds), THE severity SHALL be `"High"`;
   WHEN a second or subsequent SQL injection event from the same IP occurs within 300 seconds,
   THE severity SHALL be `"Critical"`.
3. THE `ThreatEvent.evidence` SHALL contain `matched_pattern` (the exact matching string from
   the payload), `request_url` (decoded URL path if present, else `null`), `http_method`
   (e.g. `"GET"`, `"POST"`, or `"Unknown"`), `source_ip` (string), and
   `destination_ip` (string).
4. IF the TCP payload cannot be decoded (empty or binary), THEN THE `SqlInjectionRule` SHALL
   skip the packet without emitting an event and without logging a warning.
5. THE AttackTestScript `scripts/attack_tests/sql_injection.sh` SHALL trigger this detection
   by running `curl "http://<TARGET_IP>/search?q=%27%20OR%201%3D1%20--%20UNION%20SELECT%201"`,
   which encodes `' OR 1=1 -- UNION SELECT 1` in the URL and SHALL produce a detectable
   payload on port 80 within 2 seconds.

---

### Requirement 6: Brute Force Detection from Real Traffic

**User Story:** As a security operator, I want NetGuard to detect brute-force login attempts
against SSH and HTTP services from a real device.

#### Acceptance Criteria

1. WHEN `BruteForceRule` observes ≥ 10 TCP packets with any flag combination (SYN, SYN-ACK,
   or established) destined for port 22, 80, 443, or 21 from a single source IP within a
   60-second sliding window, THE DetectionEngine SHALL emit a `ThreatEvent` with
   `attack_type = "Brute Force"` and `rule_name = "BRUTE_FORCE_001"`.
2. THE `ThreatEvent.severity` SHALL be `"Medium"` for 10–19 attempts, `"High"` for 20–39,
   and `"Critical"` for ≥ 40.
3. THE `ThreatEvent.evidence` SHALL contain `failure_count` (int), `time_window_seconds`
   (float), `threshold` (int, value 10), and `target_service` (one of `"SSH"` for port 22,
   `"HTTP"` for port 80 or 443, `"FTP"` for port 21, `"Unknown"` for any other port).
4. THE AttackTestScript `scripts/attack_tests/brute_force.sh` SHALL trigger this detection by
   running `hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh://<TARGET_IP>`,
   which sends ≥ 15 authentication attempts and SHALL reliably trigger `BruteForceRule`
   within 60 seconds of starting.

---

### Requirement 7: ARP Spoofing Detection from Real Traffic

**User Story:** As a security operator, I want NetGuard to detect ARP spoofing attacks from a
real device, so that man-in-the-middle attempts on the LAN are immediately flagged.

#### Acceptance Criteria

1. WHEN `ArpSpoofRule` observes ARP reply packets (opcode 2) or gratuitous ARP packets where
   ≥ 2 different source MAC addresses have claimed the same source IP within a 300-second
   observation window, THE DetectionEngine SHALL emit a `ThreatEvent` with
   `attack_type = "ARP Spoofing"` and `rule_name = "ARP_SPOOF_001"`.
2. THE `ThreatEvent.severity` SHALL always be `"High"`.
3. THE `ThreatEvent.confidence` SHALL be 97 when exactly 2 distinct MAC addresses have claimed
   the IP, and 100 when ≥ 3 distinct MAC addresses have claimed the same IP.
4. THE `ThreatEvent.evidence` SHALL contain `conflicting_ip` (string), `conflicting_macs`
   (list of strings, up to 5 entries), `first_observed_timestamp` (ISO-8601), and
   `most_recent_timestamp` (ISO-8601).
5. THE AttackTestScript `scripts/attack_tests/arp_spoof.sh` SHALL trigger this detection by
   running `arpspoof -i <IFACE> -t <TARGET_IP> <GATEWAY_IP>` for at least 10 seconds, which
   sends ARP replies with a spoofed MAC and SHALL reliably produce conflicting ARP entries
   within the observation window.

---

### Requirement 8: Auto-Block Confirmed Attackers

**User Story:** As a security operator, I want NetGuard to automatically block confirmed
attacker IPs via iptables, so that attacks are contained without manual intervention.

#### Acceptance Criteria

1. WHEN `_on_threat_event` processes a `ThreatEvent` whose `source_ip` is not whitelisted,
   THE PreventionEngine SHALL issue `iptables -I INPUT -s <source_ip> -j DROP` within
   500 milliseconds of detection.
2. THE `BlockRepository` SHALL record `ip_address`, `blocked_at`, `expires_at`, `reason`,
   and `event_id` for every new block.
3. WHEN a block's `expires_at` timestamp passes, THE ExpiryThread SHALL issue
   `iptables -D INPUT -s <ip> -j DROP` and mark the record inactive in the database.
4. THE default block duration SHALL be configurable via `settings.block_duration` (default:
   120 seconds).
5. IF the `source_ip` is on the whitelist, THEN THE PreventionEngine SHALL skip the block
   and log `"whitelisted — no block applied"` to `logs/system.log`.
6. IF a block already exists for the `source_ip`, THEN THE PreventionEngine SHALL extend
   `expires_at` by `block_duration` rather than inserting a duplicate record.
7. WHEN an IP is blocked, THE System SHALL emit a `ip_blocked` SocketIO event with `ip`,
   `reason`, `blocked_at`, and `expires_at`.
8. WHEN an IP is unblocked, THE System SHALL emit a `ip_unblocked` SocketIO event with `ip`.

---

### Requirement 9: Deterministic Weighted Health Score

**User Story:** As a security operator, I want the health score to reflect the actual attack
types detected today, so that the dashboard accurately represents current threat posture.

#### Acceptance Criteria

1. THE `StatsService.get_health_score()` SHALL compute the score using the following
   deterministic formula, querying events with timestamps in the current UTC calendar day
   (00:00:00 UTC to 23:59:59 UTC), and the score SHALL never be random:
   - Start at 100
   - Subtract 15 if `"SYN Flood"` appears in today's detected attack types
   - Subtract 8 if `"Port Scan"` appears in today's detected attack types
   - Subtract 12 if `"SQL Injection"` appears in today's detected attack types
   - Subtract 10 if `"Brute Force"` appears in today's detected attack types
   - Subtract 20 if `"ARP Spoofing"` appears in today's detected attack types
   - Subtract an additional 15 if ≥ 3 distinct attack types from the above five are present
   - Apply `max(0, min(100, score))` as the final step
2. THE health score SHALL NOT use the `alerts_today * 5` or `active_blocks * 2` formula from
   any previous implementation.
3. WHEN `EventRepository` returns zero events for the current UTC calendar day, THE health
   score SHALL be exactly 100. WHEN today's events contain at least one recognized attack
   type from the deduction list, THE health score SHALL be strictly less than 100; IF
   today's events exist but contain no attack type from the deduction list, THE health score
   SHALL remain 100.
4. WHEN the `_background_live_stats` loop emits a `live_stats` SocketIO event, it SHALL
   include `health_score` in the payload on the first emission per client connection and on
   any subsequent emission where the score has changed by ≥ 5 points since the last included
   emission; IF the score change is < 5 points, `health_score` SHALL be omitted from the
   payload.
5. WHEN the Dashboard receives a `live_stats` or `GET /api/v1/dashboard` response containing
   `health_score`, THE Dashboard SHALL display it as a percentage badge with color: green
   for scores ≥ 80, yellow for 60–79, orange for 40–59, and red for scores < 40.

---

### Requirement 10: Security Advisor (Offline + Gemini)

**User Story:** As a security operator, I want contextual security advice based on my current
threat posture, so that I can take the right action immediately after an attack is detected.

#### Acceptance Criteria

1. THE System SHALL implement `backend/services/security_advisor.py` containing a
   `SecurityAdvisor` class that exposes a single `advise(health_score: int,
   detected_attack_types: list[str]) -> dict` method.
2. THE `SecurityAdvisor` knowledge base SHALL contain ≥ 20 distinct advice entries covering:
   - At least 5 entries for the green tier (health score 80–100): general hygiene,
     monitoring continuity, periodic audits, patch cadence, posture maintenance
   - At least 5 entries for the yellow tier (60–79): elevated vigilance, review of
     recent alerts, hardening recommendations, log retention increase
   - At least 5 entries for the orange tier (40–59): active incident response steps,
     escalation guidance, network segmentation review, credential rotation
   - At least 5 entries for the red tier (0–39): immediate containment, forensics
     initiation, stakeholder notification, full lockdown steps
   - At least one per-attack-type entry for each of: SYN Flood, Port Scan, SQL Injection,
     Brute Force, ARP Spoofing
3. WHEN `GEMINI_API_KEY` is set as an environment variable and the Gemini API call succeeds
   within 10 seconds, THE SecurityAdvisor SHALL map the Gemini response to the criterion-5
   dict schema (extracting title, message, actions) and return it.
4. IF `GEMINI_API_KEY` is not set, or the Gemini API call raises any exception (including
   timeout after 10 seconds), THEN THE SecurityAdvisor SHALL return a valid criterion-5
   dict generated by the offline engine with NO error field and NO visible error to the user.
5. THE `advise()` method SHALL always return a dict containing: `score` (int), `badge_color`
   (one of `"green"`, `"yellow"`, `"orange"`, `"red"`), `title` (str), `message` (str), and
   `actions` (list of str, ≥ 1 entry).
6. THE REST_API SHALL expose `GET /api/v1/advisor` that calls `SecurityAdvisor.advise()` with
   the current `health_score` and the list of distinct `attack_type` values from events
   detected in the current UTC calendar day, and returns the advice dict as JSON. The offline
   engine SHALL select the tier entry based on `health_score` range and append per-attack-type
   `actions` for each attack type in the input list.
7. THE Dashboard SHALL display the `SecurityAdvisor` output in a dedicated panel showing the
   score percentage, badge, title, message, and action list.

---

### Requirement 11: Connected Device Discovery

**User Story:** As a security operator, I want to see all devices on my LAN, so that I can
identify which hosts are attackers and which are legitimate.

#### Acceptance Criteria

1. THE REST_API SHALL expose `GET /api/v1/devices` that calls
   `LanScanService.get_devices(interface)` and returns the device list as JSON.
2. EACH device entry SHALL contain: `ip`, `mac`, `hostname`, `vendor`, `status`,
   `last_seen`.
3. THE `LanScanService` SHALL use Scapy ARP scan as the primary method and OS ARP cache
   (`ip neigh` / `arp -a`) as the fallback when Scapy or raw socket privileges are
   unavailable.
4. THE device list SHALL be cached for 30 seconds to avoid flooding the network.
5. WHEN `LanScanService.invalidate()` is called, THE next `get_devices()` call SHALL
   perform a fresh scan bypassing the cache.
6. THE Dashboard SHALL display the device list in a panel showing IP, MAC, hostname, vendor,
   and status, refreshed every 30 seconds.

---

### Requirement 12: Live Dashboard — Real Data Only

**User Story:** As a security operator, I want the dashboard to update automatically with
real packet counts, bandwidth, alerts, and blocked IPs, so that I have situational awareness
at a glance.

#### Acceptance Criteria

1. WHILE `CaptureEngine` is running, THE Dashboard SHALL update the following counters via
   SocketIO `live_stats` events every 1 second: `packets_processed`, `packets_per_second`,
   `alerts_today`, `active_threats` (blocked IP count), and `monitoring` (boolean).
2. THE Dashboard SHALL render an attack timeline showing the last 20 detected `ThreatEvent`
   objects sorted by `timestamp` descending.
3. WHEN a `new_threat` SocketIO event is received, THE Dashboard SHALL prepend the new event
   to the attack timeline without a full page reload.
4. THE `EvidencePanel` SHALL display structured evidence from `ThreatEvent.evidence` for the
   selected alert row, including all fields present in the evidence dict.
5. THE Dashboard SHALL display `severity` as a color-coded label (Low=blue, Medium=yellow,
   High=orange, Critical=red) and `confidence` as a percentage badge.
6. THE Dashboard SHALL display the currently monitored `Interface` name and a green
   "Monitoring Active" / red "Monitoring Stopped" status badge.
7. THE Dashboard SHALL NOT show demo controls, demo status, simulation toggles, or any other
   demo-mode UI elements.

---

### Requirement 13: Evidence Logging

**User Story:** As a security operator, I want every detected attack to be logged with full
evidence, so that I have an audit trail for post-incident analysis.

#### Acceptance Criteria

1. WHEN `_on_threat_event` processes a `ThreatEvent`, THE `LoggingEngine` SHALL persist the
   event to the `events` database table with all fields including the `evidence` JSON blob.
2. THE `logs/system.log` file SHALL record a line for every block action: IP address, reason,
   block duration, and timestamp.
3. THE `logs/system.log` file SHALL record a line for every unblock action: IP address and
   timestamp.
4. IF the database write fails, THEN THE `LoggingEngine` SHALL log the failure to
   `logs/system.log` and NOT crash the `_on_threat_event` pipeline.
5. THE REST_API SHALL expose `GET /api/v1/events` returning the last 100 events with
   `event_id`, `timestamp`, `attack_type`, `source_ip`, `severity`, `confidence`, and
   `evidence`.

---

### Requirement 14: Attack Test Scripts

**User Story:** As a hackathon demonstrator, I want ready-made attack scripts for a second
laptop, so that I can trigger every detection type in under 5 minutes per attack.

#### Acceptance Criteria

1. THE System SHALL provide `scripts/attack_tests/syn_flood.sh` — uses `hping3 -S --flood`
   to send ≥ 150 SYN packets per second at the target, reliably triggering `SynFloodRule`.
2. THE System SHALL provide `scripts/attack_tests/port_scan.sh` — uses `nmap -sS -T4` to
   scan ≥ 30 ports, reliably triggering `PortScanRule`.
3. THE System SHALL provide `scripts/attack_tests/sql_injection.sh` — uses `curl` to send
   a GET request with a URL-encoded `UNION SELECT` payload to port 80 of the target,
   reliably triggering `SqlInjectionRule`.
4. THE System SHALL provide `scripts/attack_tests/brute_force.sh` — uses `hydra` against
   SSH (port 22) to send ≥ 15 attempts, reliably triggering `BruteForceRule`.
5. THE System SHALL provide `scripts/attack_tests/arp_spoof.sh` — uses `arpspoof` to send
   conflicting ARP replies, reliably triggering `ArpSpoofRule`.
6. EACH script SHALL include a header comment documenting: prerequisites (tools required),
   usage syntax, expected detection in NetGuard, and safe usage warning.
7. THE System SHALL provide `scripts/attack_tests/README.md` documenting all five scripts,
   pre-requisites, and the expected sequence of NetGuard alerts.

---

### Requirement 15: Graceful Interface Failure Handling

**User Story:** As a security operator, I want NetGuard to handle interface errors gracefully,
so that a missing or flapping interface does not crash the application.

#### Acceptance Criteria

1. IF `CaptureEngine._capture_loop` raises an exception (e.g. interface not found, permission
   denied), THEN THE System SHALL log the error to `logs/system.log` and emit a
   `monitoring_error` SocketIO event without terminating the Flask process.
2. IF `CaptureEngine` stops unexpectedly, THEN `MonitorService` SHALL set
   `monitoring_state.active = False` and update the Dashboard status badge to
   "Monitoring Stopped".
3. THE `GET /api/v1/interfaces` endpoint SHALL return all interfaces including those that are
   currently down, with an `is_up` boolean field indicating their state.
4. WHEN `MonitorService.start()` is called with an interface that fails within 5 seconds,
   THE REST_API SHALL return a `monitoring_error` event to connected SocketIO clients with
   the failure reason.

---

### Requirement 16: Verification Criteria

**User Story:** As a hackathon judge, I want a clear end-to-end verification path, so that
I can confirm the system is operating on real traffic with no fake data.

#### Acceptance Criteria

1. WHEN a second device sends a SYN flood using `scripts/attack_tests/syn_flood.sh`,
   THE Dashboard SHALL display a `"SYN Flood"` alert within 5 seconds of attack onset.
2. WHEN a second device runs `scripts/attack_tests/port_scan.sh`,
   THE Dashboard SHALL display a `"Port Scan"` alert within 15 seconds of scan start.
3. WHEN a second device runs `scripts/attack_tests/sql_injection.sh`,
   THE Dashboard SHALL display a `"SQL Injection"` alert within 3 seconds of the curl
   request completing.
4. WHEN a second device runs `scripts/attack_tests/brute_force.sh`,
   THE Dashboard SHALL display a `"Brute Force"` alert within 10 seconds of hydra starting.
5. WHEN a second device runs `scripts/attack_tests/arp_spoof.sh`,
   THE Dashboard SHALL display an `"ARP Spoofing"` alert within 5 seconds.
6. FOR EACH alert generated by a real attack, THE `events` database table SHALL contain a
   row with a non-null `evidence` JSON blob and `evidence.demo` SHALL NOT be present.
7. WHEN an attack is detected and the source IP is not whitelisted, THE `iptables -L INPUT -n`
   output SHALL contain a DROP rule for that source IP within 1 second of the alert appearing
   on the Dashboard.
8. WHEN `GET /api/v1/events` is called after running all five attack scripts,
   THE response SHALL contain ≥ 5 events each with a distinct `attack_type`.
