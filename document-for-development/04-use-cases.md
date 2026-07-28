# Use Case Specification

# NetGuard

Version: 1.0

Document ID: NG-UC-001

Project:
NetGuard – Explainable Intrusion Detection & Prevention System

---

# Purpose

This document defines how users and external systems interact with NetGuard.

Each use case includes:

- Actors
- Preconditions
- Trigger
- Main Flow
- Alternative Flow
- Exception Flow
- Postconditions

---

# Primary Actors

| Actor | Description |
|--------|-------------|
| Network Administrator | Configures and manages NetGuard |
| Security Analyst | Reviews alerts and evidence |
| System | Packet Capture + Detection Engine |
| Attacker | Generates malicious traffic |
| Hackathon Judge | Observes the live demonstration |

---

# UC-001
## Start Monitoring

### Goal

Begin monitoring network traffic.

### Primary Actor

Administrator

### Preconditions

- NetGuard is installed.
- Administrator has launched the application.
- Required permissions are granted.
- Network interface exists.

### Trigger

Administrator presses **Start Monitoring**.

### Main Flow

1. Application lists available network interfaces.
2. Administrator selects an interface.
3. Packet Capture Engine initializes.
4. Monitoring begins.
5. Dashboard changes status to **Monitoring Active**.
6. Live traffic statistics begin updating.

### Alternative Flow

If only one interface exists:

- Automatically select it.
- Begin monitoring.

### Exception Flow

If interface cannot be opened:

- Display error.
- Allow user to select another interface.

### Postconditions

- Monitoring is active.
- Dashboard updates continuously.

---

# UC-002
## Detect SYN Flood

### Goal

Detect a SYN Flood attack.

### Primary Actor

System

### Preconditions

- Monitoring is active.
- Detection rules loaded.

### Trigger

Large number of SYN packets received.

### Main Flow

1. Capture packet.
2. Decode packet.
3. Count SYN packets.
4. Compare with threshold.
5. Threshold exceeded.
6. Generate alert.
7. Calculate severity.
8. Send event to backend.

### Alternative Flow

Threshold not exceeded.

No alert generated.

### Exception Flow

Malformed packet.

Ignore packet.

Continue monitoring.

### Postconditions

Detection event created.

---

# UC-003
## Detect Port Scan

### Goal

Detect sequential connection attempts.

### Trigger

Single source accesses many ports.

### Main Flow

1. Capture TCP packets.
2. Count unique destination ports.
3. Compare with configured threshold.
4. Alert generated.
5. Evidence recorded.

### Postconditions

Port Scan detection logged.

---

# UC-004
## Detect SQL Injection

### Goal

Detect SQL Injection payloads.

### Trigger

HTTP request contains suspicious SQL syntax.

### Main Flow

1. Inspect HTTP payload.
2. Compare against detection patterns.
3. Match found.
4. Generate event.
5. Send to backend.

### Alternative Flow

No suspicious pattern.

Continue monitoring.

---

# UC-005
## Detect Brute Force

### Goal

Detect repeated login attempts.

### Trigger

Many failed authentication requests.

### Main Flow

1. Observe login attempts.
2. Count failures.
3. Compare with threshold.
4. Generate alert.
5. Send evidence.

---

# UC-006
## Detect ARP Spoofing

### Goal

Detect conflicting ARP responses.

### Trigger

Multiple MAC addresses claim same IP.

### Main Flow

1. Capture ARP packets.
2. Compare IP-MAC mappings.
3. Detect conflict.
4. Raise alert.
5. Record evidence.

---

# UC-007
## Automatically Block Attacker

### Goal

Prevent further malicious traffic.

### Primary Actor

System

### Preconditions

Threat severity exceeds blocking threshold.

### Trigger

Confirmed attack.

### Main Flow

1. Receive detection.
2. Verify whitelist.
3. Execute firewall command.
4. Add timeout.
5. Log action.
6. Update dashboard.

### Alternative Flow

IP is whitelisted.

Do not block.

Log decision.

### Exception Flow

Firewall command fails.

Display warning.

Continue monitoring.

### Postconditions

Attacker blocked.

---

# UC-008
## Automatically Unblock

### Goal

Remove expired firewall rules.

### Trigger

Timeout expires.

### Main Flow

1. Check block timer.
2. Remove firewall rule.
3. Update dashboard.
4. Record log.

---

# UC-009
## View Dashboard

### Goal

Observe current security status.

### Primary Actor

Administrator

### Main Flow

Dashboard displays

- Monitoring status
- Live traffic
- Alerts
- Blocked IPs
- Statistics
- Severity chart
- Recent attacks

---

# UC-010
## View Evidence

### Goal

Understand why an alert occurred.

### Trigger

User clicks an alert.

### Main Flow

Display

- Source IP
- Destination IP
- Rule matched
- Packet count
- Time window
- Severity
- Confidence
- Plain-language explanation

---

# UC-011
## Search Logs

### Goal

Locate historical events.

### Main Flow

User selects filters.

System searches logs.

Matching results displayed.

---

# UC-012
## Manage Whitelist

### Goal

Add trusted devices.

### Main Flow

1. Open Whitelist.
2. Add IP.
3. Save.
4. Future detections bypass blocking.

---

# UC-013
## Remove Whitelist Entry

### Goal

Remove trusted device.

### Main Flow

1. Open Whitelist.
2. Select device.
3. Remove.
4. Save.

---

# UC-014
## View Statistics

### Goal

Display security metrics.

### Dashboard shows

- Packets processed
- Alerts
- Blocked IPs
- Active threats
- Top attackers
- Top rules
- Average response time

---

# UC-015
## Configure Detection Rules

### Goal

Adjust detection sensitivity.

### Main Flow

1. Open Settings.
2. Select rule.
3. Modify threshold.
4. Save configuration.
5. Detection Engine reloads.

---

# UC-016
## Export Incident Report

### Goal

Generate investigation report.

### Main Flow

1. Select event.
2. Click Export.
3. System generates report.

Contains

- Attack summary
- Evidence
- Severity
- Timeline
- Recommendation

---

# UC-017
## Demonstration Mode

### Goal

Perform live hackathon demo.

### Main Flow

1. Start monitoring.
2. Launch attack.
3. Detect attack.
4. Dashboard updates.
5. Evidence displayed.
6. IP blocked.
7. Show logs.
8. Repeat with second attack.

Total duration

90 seconds

---

# UC-018
## System Shutdown

### Goal

Stop monitoring safely.

### Main Flow

1. User clicks Stop.
2. Packet capture stops.
3. Background tasks stop.
4. Logs saved.
5. Dashboard shows Monitoring Stopped.

---

# Business Rules

BR-001

Only confirmed attacks trigger blocking.

---

BR-002

Whitelisted IPs are never automatically blocked.

---

BR-003

Every alert must contain evidence.

---

BR-004

Every block must be logged.

---

BR-005

Expired blocks are automatically removed.

---

BR-006

Monitoring continues after recoverable errors.

---

# Global Preconditions

- Python installed.
- Administrator privileges granted.
- Firewall available.
- Network interface available.

---

# Global Postconditions

- Logs updated.
- Dashboard synchronized.
- Configuration preserved.
- Monitoring continues unless manually stopped.

---

End of Document