# Detection Engine Specification

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

Document ID: NG-DE-001

---

# Purpose

The Detection Engine is responsible for analyzing captured network traffic, identifying malicious behavior, assigning confidence and severity scores, collecting evidence, and generating structured threat events for downstream modules.

The engine is designed to be:

- Modular
- Explainable
- Rule-based
- Extensible
- Real-time
- Offline-first

---

# Detection Pipeline

Network Interface

↓

Packet Capture (Scapy)

↓

Packet Decoder

↓

Packet Normalization

↓

Flow Tracker

↓

Rule Engine

↓

Threat Scoring

↓

Explainability Engine

↓

Threat Event

↓

Prevention Engine

↓

Logging

↓

Dashboard

---

# Detection Principles

- Process packets continuously.
- Never stop monitoring because of malformed packets.
- Multiple detections may occur simultaneously.
- Each detection is independent.
- Every alert must include evidence.
- Every decision must be explainable.

---

# Packet Normalization

Each packet is converted into a standard internal object.

Example

```json
{
  "timestamp":"2026-08-01T10:00:22Z",
  "src_ip":"192.168.1.5",
  "dst_ip":"192.168.1.10",
  "src_port":54321,
  "dst_port":80,
  "protocol":"TCP",
  "flags":"SYN",
  "length":60
}
```

---

# Flow Tracker

Purpose

Track activity by source IP over configurable time windows.

Maintains

- Packet count
- SYN count
- Destination ports
- Login failures
- HTTP payloads
- ARP mappings
- Time windows

Data expires automatically after inactivity.

---

# Supported Attack Types

1. SYN Flood
2. Port Scan
3. SQL Injection
4. Brute Force Login
5. ARP Spoofing

Future-ready for additional rule modules.

---

# Detection Rule: SYN Flood

Goal

Detect unusually high numbers of TCP SYN packets from a single source.

Indicators

- TCP SYN flag set
- Large packet burst
- Same source IP
- Short time window

Default Threshold

- 100 SYN packets
- Within 3 seconds

Evidence Collected

- Source IP
- Packet count
- Time window
- Destination IP(s)
- Sample packet timestamps

Severity

| Packet Count | Severity |
|--------------|----------|
| 100–199 | Medium |
| 200–399 | High |
| 400+ | Critical |

Confidence Formula

```
confidence =
(min(packet_count / threshold, 2.0) / 2.0) × 100
```

Maximum

100%

---

# Detection Rule: Port Scan

Goal

Detect sequential connection attempts to many ports.

Indicators

- Same source IP
- Multiple destination ports
- Short interval

Threshold

20 unique ports

within

10 seconds

Evidence

- Source IP
- Port list
- Total ports scanned
- Time window

Severity

20–39 → Medium

40–79 → High

80+ → Critical

---

# Detection Rule: SQL Injection

Goal

Detect suspicious SQL payloads inside HTTP requests.

Patterns

Examples include:

- `' OR '1'='1`
- `UNION SELECT`
- `DROP TABLE`
- `--`
- `;--`
- `xp_cmdshell`

Detection Method

Pattern matching against HTTP request payloads.

Evidence

- Source IP
- URL
- HTTP Method
- Matched pattern
- Request snippet

Severity

Usually

High

Critical if repeated.

---

# Detection Rule: Brute Force Login

Goal

Detect repeated authentication failures.

Indicators

- Same username or IP
- Multiple failed attempts
- Small time window

Threshold

10 failures

within

60 seconds

Evidence

- Username (if available)
- Source IP
- Failure count
- Target service

Severity

10–19 → Medium

20–39 → High

40+ → Critical

---

# Detection Rule: ARP Spoofing

Goal

Detect conflicting IP-to-MAC mappings.

Indicators

- Same IP
- Multiple MAC addresses

Evidence

- IP address
- MAC addresses
- Packet timestamps

Severity

High

Confidence

95–100%

---

# Threat Event Object

Every confirmed detection generates:

```json
{
  "event_id":"EVT-000456",
  "attack_type":"Port Scan",
  "severity":"High",
  "confidence":94,
  "timestamp":"2026-08-01T10:12:22Z",
  "source_ip":"192.168.1.20",
  "destination_ip":"192.168.1.10",
  "rule":"PORT_SCAN_001",
  "blocked":false
}
```

---

# Severity Calculation

Severity depends on:

- Attack type
- Packet volume
- Threshold exceeded
- Repeat offenses
- Confidence

Levels

Low

Medium

High

Critical

---

# Confidence Scoring

Confidence is based on:

- Number of indicators matched
- Threshold exceeded
- Historical observations
- Detection consistency

Range

0–100

Categories

| Score | Confidence |
|--------|------------|
| 0–39 | Low |
| 40–69 | Medium |
| 70–89 | High |
| 90–100 | Very High |

---

# Explainability Engine

Every alert must produce a human-readable explanation.

Example

Technical

```
PORT_SCAN_001 triggered
```

Displayed

```
Detected connection attempts to 37 different ports from
192.168.1.20 within 10 seconds.
This behavior matches a port scanning pattern.
The source was temporarily blocked for 120 seconds.
```

---

# Recommendation Generator

Each alert includes recommended action.

Examples

SYN Flood

> Investigate the source host and verify whether the traffic is legitimate.

Port Scan

> Review exposed services and verify firewall rules.

SQL Injection

> Inspect application logs and validate input sanitization.

Brute Force

> Enable account lockout and review authentication logs.

ARP Spoofing

> Verify gateway configuration and inspect network devices.

---

# False Positive Handling

Detection engine should:

- Respect whitelist
- Require thresholds
- Avoid duplicate alerts
- Suppress repeated identical events during cooldown

---

# Cooldown Period

After an alert,

ignore identical detections from the same source

for

10 seconds

unless severity increases.

---

# Rule Configuration

Each rule supports:

```yaml
enabled: true
threshold: 100
time_window: 3
severity: High
block_duration: 120
cooldown: 10
```

---

# Extensibility

New attack rules must implement:

```
initialize()

process_packet(packet)

evaluate()

generate_event()

explain()

cleanup()
```

This allows plug-and-play detection modules.

---

# Performance Targets

Packet Processing

< 100 ms

Detection Latency

< 3 seconds

Event Generation

< 100 ms

Explanation Generation

< 50 ms

---

# Error Handling

Malformed Packet

- Log warning
- Ignore packet
- Continue monitoring

Unknown Protocol

- Skip packet

Firewall Failure

- Detection still recorded
- Alert administrator

Rule Failure

- Disable faulty rule
- Continue other detections

---

# Testing Requirements

Each rule must include:

- Unit tests
- Integration tests
- False-positive tests
- Performance tests
- Live demonstration tests

---

# Future Detection Modules

Planned additions:

- DNS Tunneling
- DDoS Detection
- ICMP Flood
- Slowloris
- SSH Brute Force
- Ransomware Indicators
- Beacon Detection
- Malware C2 Traffic
- Machine Learning Anomaly Detection

---

# Acceptance Criteria

✓ All five attack types detected.

✓ Every alert includes evidence.

✓ Confidence score generated.

✓ Severity calculated.

✓ Plain-language explanation displayed.

✓ Recommendation included.

✓ Detection continues despite malformed packets.

✓ New rule modules can be added independently.

---

# Revision History

| Version | Date | Description |
|----------|------|-------------|
| 1.0 | July 2026 | Initial Detection Engine Specification |

---

End of Document