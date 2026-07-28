# Software Requirements Specification (SRS)

# NetGuard

Version: 1.0

Document ID: NGSRS-001

Project:
NetGuard – Explainable Intrusion Detection & Prevention System

Event:
MVIC Build Nepal Hackathon 2026

---

# 1. Purpose

This document defines all functional and non-functional requirements for NetGuard.

It acts as the single source of truth for developers, AI coding assistants, testers, and future contributors.

---

# 2. Product Overview

NetGuard is a lightweight, explainable Intrusion Detection and Prevention System (IDPS) that continuously monitors network traffic, detects suspicious behavior, automatically blocks malicious actors, and explains every security decision in plain language.

---

# 3. Functional Requirements

---

# Module 1 — Packet Capture

### FR-001

The system shall continuously capture network packets in real time.

Priority:
Critical

Acceptance Criteria

- Packet capture begins automatically.
- No manual refresh required.

---

### FR-002

The system shall support monitoring a user-selected network interface.

Priority

Critical

Acceptance

- Available interfaces listed.
- User selects interface.
- Monitoring begins.

---

### FR-003

The system shall decode:

- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol
- Timestamp

Priority

Critical

---

### FR-004

The system shall ignore malformed packets that cannot be parsed.

Priority

Medium

---

### FR-005

The packet capture engine shall continue running even if individual packets fail parsing.

Priority

High

---

# Module 2 — Detection Engine

---

### FR-006

The system shall detect SYN Flood attacks.

Priority

Critical

Acceptance

Threshold exceeded

↓

Alert generated

---

### FR-007

The system shall detect Port Scan attacks.

Priority

Critical

---

### FR-008

The system shall detect SQL Injection attempts.

Priority

Critical

---

### FR-009

The system shall detect Brute Force login attempts.

Priority

Critical

---

### FR-010

The system shall detect ARP Spoofing.

Priority

Critical

---

### FR-011

Each detection rule shall have configurable thresholds.

Priority

High

---

### FR-012

Each rule shall have:

- Name
- Description
- Severity
- Threshold
- Block duration

Priority

High

---

### FR-013

Rules may be enabled or disabled without changing source code.

Priority

Medium

---

# Module 3 — Threat Evaluation

---

### FR-014

Every detected event shall receive a severity level.

Allowed values

- Low
- Medium
- High
- Critical

---

### FR-015

Severity shall be calculated using:

- Packet count
- Packet rate
- Attack type
- Historical behavior

---

### FR-016

Every event shall receive a confidence score.

Range

0–100

---

# Module 4 — Prevention

---

### FR-017

The system shall automatically block malicious IP addresses.

Priority

Critical

---

### FR-018

Blocking shall occur within seconds of confirmed detection.

---

### FR-019

Blocked IPs shall expire automatically.

Default

120 seconds

Configurable

Yes

---

### FR-020

Whitelist entries shall never be automatically blocked.

---

### FR-021

Administrators may manually unblock IP addresses.

---

# Module 5 — Logging

---

### FR-022

Every security event shall be logged.

Fields

- Timestamp
- Source IP
- Destination IP
- Rule
- Severity
- Evidence
- Action Taken

---

### FR-023

Logs shall persist after application restart.

---

### FR-024

Logs shall support filtering.

Filter by

- Date
- Severity
- Rule
- IP

---

### FR-025

Logs shall support searching.

---

# Module 6 — Explainability Engine

---

### FR-026

Every detection shall include a plain-language explanation.

Example

"This IP sent 214 SYN packets within 3 seconds, exceeding the configured threshold of 100."

---

### FR-027

Evidence shall include

- Triggered rule
- Packet count
- Time window
- Source IP
- Severity

---

### FR-028

The explanation shall describe why blocking occurred.

---

### FR-029

If no block occurs, the dashboard shall explain why.

Example

"Whitelisted device."

---

# Module 7 — Dashboard

---

### FR-030

Display live packet count.

---

### FR-031

Display active threats.

---

### FR-032

Display blocked IP addresses.

---

### FR-033

Display traffic graphs.

---

### FR-034

Display attack history.

---

### FR-035

Display severity distribution.

---

### FR-036

Display rule statistics.

---

### FR-037

Evidence panel updates automatically.

---

### FR-038

Dashboard refreshes automatically.

---

# Module 8 — API

---

### FR-039

REST API shall expose:

GET /events

GET /statistics

POST /detect

POST /block

GET /health

---

### FR-040

All API responses shall return JSON.

---

### FR-041

Invalid requests return descriptive error messages.

---

# Module 9 — Configuration

---

### FR-042

Users shall configure

- Thresholds
- Timeout
- Interface
- Rules

without editing source code.

---

### FR-043

Configuration stored locally.

---

### FR-044

Application loads configuration during startup.

---

# Module 10 — Administration

---

### FR-045

View whitelist.

---

### FR-046

Add whitelist entry.

---

### FR-047

Remove whitelist entry.

---

### FR-048

View blocked IPs.

---

### FR-049

Manually unblock IP.

---

### FR-050

Reset statistics.

---

# 4. Non-Functional Requirements

## Performance

### NFR-001

Dashboard updates within one second.

---

### NFR-002

Threat detection occurs within three seconds.

---

### NFR-003

Application startup under ten seconds.

---

### NFR-004

Memory usage below 500 MB.

---

### NFR-005

CPU usage below 40% during normal operation.

---

# Reliability

### NFR-006

Application shall recover from packet parsing failures.

---

### NFR-007

Logging failures shall not stop monitoring.

---

### NFR-008

Unexpected exceptions shall be logged.

---

# Security

### NFR-009

Only privileged operations require administrator rights.

---

### NFR-010

Configuration files shall be protected.

---

### NFR-011

Logs shall be tamper resistant.

---

# Scalability

### NFR-012

New detection rules can be added without modifying existing rules.

---

### NFR-013

Future cloud deployment supported.

---

### NFR-014

Future machine learning engine supported.

---

# Maintainability

### NFR-015

Modular project architecture.

---

### NFR-016

Every module documented.

---

### NFR-017

Source code follows consistent naming conventions.

---

# Compatibility

### NFR-018

Supports Ubuntu Linux.

---

### NFR-019

Supports Kali Linux.

---

### NFR-020

Runs on Python 3.11+.

---

# Availability

### NFR-021

Monitoring continues until manually stopped.

---

# 5. Assumptions

- Linux firewall available.
- Network interface accessible.
- Administrative privileges granted.
- Local network available.

---

# 6. Constraints

- Offline deployment only.
- Single-machine architecture.
- Local dashboard.
- No cloud dependency.

---

# 7. Acceptance Criteria

The project is considered complete when:

✓ Detects all five supported attacks.

✓ Blocks malicious IPs automatically.

✓ Displays live dashboard.

✓ Generates explainable evidence.

✓ Logs all events.

✓ Supports whitelist management.

✓ Demonstrates complete attack-to-block workflow in under 90 seconds.

---

# 8. Future Requirements

Future releases may include:

- Machine Learning Detection
- MITRE ATT&CK Mapping
- Threat Intelligence Feeds
- PDF Incident Reports
- Cloud Dashboard
- Multi-node Monitoring
- Email Alerts
- Role-Based Access Control

---

End of Documentgi