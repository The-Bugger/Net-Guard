# Testing Plan

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

Document ID: NG-TEST-001

---

# Purpose

This document defines the complete testing strategy for NetGuard.

Objectives

- Verify all detection rules
- Validate prevention mechanisms
- Ensure dashboard accuracy
- Measure performance
- Reduce false positives
- Prepare for a reliable hackathon demonstration

---

# Testing Objectives

NetGuard must:

- Detect supported attacks accurately
- Block malicious traffic automatically
- Generate explainable alerts
- Remain stable under continuous traffic
- Recover gracefully from failures
- Support repeatable demonstrations

---

# Test Levels

1. Unit Testing
2. Integration Testing
3. System Testing
4. Performance Testing
5. Security Testing
6. Usability Testing
7. Demo Validation

---

# Test Environment

Target System

Ubuntu 24.04 LTS

Python 3.11+

Flask

SQLite

Scapy

iptables

Frontend

Chrome (latest)

Firefox (latest)

Attack Machine

Kali Linux

Tools

- hping3
- nmap
- hydra
- arpspoof
- curl

---

# Unit Testing

## Packet Decoder

Verify

- IPv4 parsing
- IPv6 parsing
- TCP parsing
- UDP parsing
- ICMP parsing
- ARP parsing

Expected

Correct normalized packet object.

---

## Detection Rules

Each rule must be tested independently.

### SYN Flood

Input

150 SYN packets

Expected

Threat detected.

Severity assigned.

Evidence generated.

---

### Port Scan

Input

30 sequential ports

Expected

Port Scan alert.

---

### SQL Injection

Input

HTTP payload

```
' OR '1'='1
```

Expected

SQL Injection alert.

---

### Brute Force

Input

15 failed login attempts

Expected

Brute Force detected.

---

### ARP Spoofing

Input

Conflicting MAC addresses

Expected

ARP Spoofing detected.

---

# Explainability Tests

Verify every alert contains

- Explanation
- Recommendation
- Evidence
- Confidence
- Severity

No alert should contain empty fields.

---

# Prevention Tests

Test automatic blocking.

Scenario

Attack detected

Expected

iptables rule added.

Timer starts.

Rule removed after expiration.

---

# Whitelist Tests

Scenario

Whitelisted IP launches attack.

Expected

Alert generated.

No automatic block.

Log entry created.

---

# Logging Tests

Verify

- Timestamp
- Event ID
- Severity
- Rule
- Source IP
- Recommendation

Logs must remain consistent after application restart.

---

# Dashboard Tests

Verify

- Dashboard loads successfully
- Statistics update live
- Evidence panel displays correctly
- Charts update every second
- Notifications appear immediately

---

# API Testing

Endpoints

GET /health

GET /dashboard

GET /statistics

POST /detect

POST /block

POST /unblock

POST /monitor/start

POST /monitor/stop

Verify

- Status codes
- Response schema
- Error handling
- Validation

---

# Database Testing

Verify

- Event insertion
- Log insertion
- Block insertion
- Whitelist operations
- Rule updates

Ensure no duplicate event IDs.

---

# Performance Testing

## Packet Capture

Target

10,000 packets

Expected

No crashes.

---

## Detection Latency

Target

< 3 seconds

---

## Dashboard Refresh

Target

1 second

---

## API Response

Target

< 200 ms

---

## Database Insert

Target

< 50 ms

---

# Stress Testing

Simulate

- Continuous SYN Flood
- Multiple Port Scans
- Mixed attacks

Expected

System remains responsive.

No memory leak.

No crashes.

---

# False Positive Testing

Scenarios

Normal web browsing

SSH login

File download

Video streaming

Software update

Expected

No alerts.

---

# False Negative Testing

Known attack traffic.

Expected

Every supported attack detected.

---

# Recovery Testing

## Packet Parsing Failure

Expected

Continue monitoring.

---

## Firewall Failure

Expected

Log error.

Detection continues.

---

## Database Failure

Expected

Retry.

Queue pending events.

---

## Dashboard Disconnect

Expected

Reconnect automatically.

---

# Security Testing

Validate

- Input validation
- SQL injection resistance
- API parameter validation
- Configuration validation
- Log integrity

---

# UI Testing

Verify

Navigation

Search

Filters

Dark theme

Evidence panel

Charts

Responsive layout

---

# Browser Compatibility

Supported

Chrome

Firefox

Edge

---

# Manual Test Checklist

## Startup

☐ Application starts

☐ Dashboard loads

☐ Monitoring starts

☐ Database connected

---

## Detection

☐ SYN Flood

☐ Port Scan

☐ SQL Injection

☐ Brute Force

☐ ARP Spoofing

---

## Prevention

☐ IP blocked

☐ Timer expires

☐ IP automatically unblocked

---

## Explainability

☐ Explanation shown

☐ Confidence displayed

☐ Recommendation displayed

☐ Evidence visible

---

## Dashboard

☐ Live graph

☐ Alerts

☐ Statistics

☐ Timeline

☐ Evidence panel

---

## Logs

☐ Event stored

☐ Search works

☐ Filters work

---

## Whitelist

☐ Add IP

☐ Remove IP

☐ Whitelisted IP not blocked

---

# Live Demo Validation

Perform full demo three consecutive times.

Scenario

1. Start monitoring

2. Launch SYN Flood

3. Detection appears

4. Block occurs

5. Evidence displayed

6. Dashboard updates

7. Auto unblock

Pass Criteria

Three successful demonstrations without failure.

---

# Acceptance Criteria

Detection Accuracy

≥ 95%

False Positive Rate

≤ 5%

Dashboard Availability

100%

API Success Rate

100%

Database Integrity

100%

Demo Success Rate

100%

---

# Test Automation (Future)

Planned

- pytest
- pytest-flask
- Selenium
- Playwright
- GitHub Actions CI
- Automated attack replay

---

# Bug Severity Levels

Critical

System crash

Firewall failure

Data corruption

---

High

Missed attack

Incorrect blocking

Dashboard unavailable

---

Medium

Incorrect explanation

UI rendering issue

Slow performance

---

Low

Visual issue

Minor typo

Spacing issue

---

# Exit Criteria

Testing is complete when

✓ All unit tests pass.

✓ All integration tests pass.

✓ All five attack types are detected.

✓ Automatic blocking functions correctly.

✓ Dashboard updates in real time.

✓ Evidence is generated for every alert.

✓ No critical or high-severity defects remain.

✓ Three full demo rehearsals complete successfully.

---

# Revision History

| Version | Date | Description |
|----------|------|-------------|
| 1.0 | July 2026 | Initial Testing Plan |

---

End of Document