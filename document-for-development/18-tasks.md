# Implementation Tasks

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

Document ID: NG-TASK-001

---

# Purpose

This document breaks the NetGuard project into executable implementation tasks.

Each task includes:

- Priority
- Owner
- Dependencies
- Estimated effort
- Acceptance criteria

The goal is to allow parallel development by team members and AI coding assistants while maintaining a clear implementation order.

---

# Project Milestones

| Milestone | Goal |
|------------|------|
| M1 | Development Environment Ready |
| M2 | Detection Engine Complete |
| M3 | Backend & API Complete |
| M4 | Dashboard Complete |
| M5 | Explainability Complete |
| M6 | Demo Ready |
| M7 | Final Polish |

---

# Epic 1 – Project Setup

Priority: Critical

## Task 1.1

Title

Create repository structure

Owner

All Members

Estimate

30 minutes

Deliverables

```
backend/
frontend/
detection/
database/
config/
logs/
scripts/
tests/
demo/
docs/
```

Acceptance Criteria

- Folder structure committed
- README added
- Git initialized

---

## Task 1.2

Install dependencies

Owner

All Members

Estimate

45 minutes

Acceptance Criteria

- Python installed
- Scapy working
- Flask working
- SQLite working
- iptables accessible
- Kali VM ready

---

## Task 1.3

Configuration

Deliverables

- .env
- config.yaml
- requirements.txt

Acceptance Criteria

Configuration loads successfully.

---

# Epic 2 – Detection Engine

Priority: Critical

Owner

Detection Engineer

---

## Task 2.1

Packet Capture

Deliverables

- Live packet sniffer
- Interface selection

Acceptance

Packets visible in terminal.

---

## Task 2.2

Packet Parser

Deliverables

Normalize

- TCP
- UDP
- ICMP
- ARP

Acceptance

Packets converted into internal format.

---

## Task 2.3

Detection Rules

Implement

- SYN Flood
- Port Scan
- SQL Injection
- Brute Force
- ARP Spoofing

Acceptance

All five attacks detected.

---

## Task 2.4

Confidence Engine

Calculate

- Confidence Score
- Severity

Acceptance

Every alert includes both values.

---

## Task 2.5

Evidence Generator

Generate

- Rule triggered
- Packet count
- Time window
- Recommendation
- Explanation

Acceptance

Evidence displayed for every alert.

---

# Epic 3 – Backend

Priority: Critical

Owner

Backend Engineer

---

## Task 3.1

Create Flask Server

Acceptance

Runs successfully.

---

## Task 3.2

REST API

Implement

GET

- /health
- /dashboard
- /statistics
- /events
- /rules

POST

- /detect
- /block
- /unblock
- /monitor/start
- /monitor/stop

Acceptance

All endpoints tested.

---

## Task 3.3

Database

Implement

- Event storage
- Block history
- Whitelist
- Rules

Acceptance

CRUD operations complete.

---

## Task 3.4

Firewall Integration

Implement

- Block IP
- Unblock IP
- Auto expiry

Acceptance

Attacker blocked automatically.

---

## Task 3.5

Logging

Implement

- detections.log
- system.log
- errors.log

Acceptance

Logs written correctly.

---

# Epic 4 – Frontend

Priority: High

Owner

Frontend Engineer

---

## Task 4.1

Dashboard Layout

Create

- Sidebar
- Header
- KPI cards
- Graph area

Acceptance

Responsive UI.

---

## Task 4.2

Charts

Implement

- Traffic graph
- Severity chart
- Detection timeline

Acceptance

Charts update every second.

---

## Task 4.3

Threat Table

Columns

- Time
- IP
- Attack
- Severity
- Status

Acceptance

Live updates.

---

## Task 4.4

Evidence Panel

Display

- Explanation
- Recommendation
- Confidence
- Evidence

Acceptance

Instant loading.

---

## Task 4.5

Blocked IP Page

Acceptance

Manual unblock works.

---

## Task 4.6

Whitelist Page

Acceptance

CRUD complete.

---

# Epic 5 – Explainability

Priority: High

Owner

Detection + Frontend

---

## Task 5.1

Plain Language Explanation

Acceptance

Every alert readable by non-experts.

---

## Task 5.2

Recommendation Generator

Acceptance

Every alert includes mitigation advice.

---

## Task 5.3

Confidence Visualization

Acceptance

Displayed as percentage and badge.

---

# Epic 6 – Demo

Priority: Critical

Owner

Demo Lead

---

## Task 6.1

Prepare Kali VM

Install

- hping3
- nmap
- hydra
- arpspoof

Acceptance

All attacks executable.

---

## Task 6.2

Attack Scripts

Create

```
attack_syn.sh
attack_scan.sh
attack_sql.sh
attack_bruteforce.sh
attack_arp.sh
```

Acceptance

One-command execution.

---

## Task 6.3

Demo Script

Acceptance

90-second rehearsal completed.

---

## Task 6.4

Backup Video

Acceptance

Recorded successfully.

---

# Epic 7 – Testing

Priority: Critical

---

## Task 7.1

Unit Tests

Acceptance

All pass.

---

## Task 7.2

Integration Tests

Acceptance

Detection → API → Firewall → Dashboard works.

---

## Task 7.3

Performance Tests

Acceptance

Latency < 3 seconds.

---

## Task 7.4

False Positive Testing

Acceptance

Normal traffic not blocked.

---

## Task 7.5

Stress Testing

Acceptance

System remains stable.

---

# Epic 8 – Documentation

Priority: Medium

---

## Task 8.1

README

Include

- Installation
- Usage
- Architecture
- Screenshots

---

## Task 8.2

API Documentation

Acceptance

Every endpoint documented.

---

## Task 8.3

Architecture Diagram

Acceptance

Updated.

---

# Epic 9 – Polish

Priority: Medium

---

## Task 9.1

Dark Theme

Acceptance

Consistent colors.

---

## Task 9.2

Icons

Acceptance

Professional appearance.

---

## Task 9.3

Animations

Acceptance

Smooth transitions.

---

## Task 9.4

Loading States

Acceptance

No blank screens.

---

## Task 9.5

Error Messages

Acceptance

Human-readable.

---

# Final Demo Checklist

## System

☐ Backend running

☐ Frontend running

☐ Database initialized

☐ Packet capture active

☐ Firewall active

☐ Dashboard accessible

---

## Detection

☐ SYN Flood

☐ Port Scan

☐ SQL Injection

☐ Brute Force

☐ ARP Spoofing

---

## Explainability

☐ Confidence score

☐ Severity

☐ Evidence

☐ Recommendation

☐ Rule name

---

## Demo

☐ Kali ready

☐ Attack scripts verified

☐ Browser fullscreen

☐ Backup video

☐ Slides prepared

☐ Team rehearsed

---

# Definition of Done

The project is complete when:

✓ All five attack types are detected.

✓ Automatic blocking works correctly.

✓ Dashboard updates in real time.

✓ Every detection includes explainable evidence.

✓ Logs are stored correctly.

✓ Whitelist functions properly.

✓ No critical defects remain.

✓ Three consecutive demo rehearsals complete successfully.

✓ Documentation is complete.

✓ Source code is committed to GitHub.

---

# Overall Timeline

| Day | Goal |
|------|------|
| Day 1 | Environment & Packet Capture |
| Day 2 | Detection Rules |
| Day 3 | Backend & Firewall |
| Day 4 | Dashboard & Explainability |
| Day 5 | Testing, Polish & Demo |

---

# Revision History

| Version | Date | Description |
|----------|------|-------------|
| 1.0 | July 2026 | Initial Task Breakdown |

---

End of Document