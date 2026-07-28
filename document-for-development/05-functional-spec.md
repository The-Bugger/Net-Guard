# Functional Specification

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

Document ID: NG-FS-001

---

# Purpose

This document defines the functional architecture of NetGuard.

Each module includes:

- Purpose
- Responsibilities
- Inputs
- Outputs
- Dependencies
- Failure Handling
- Internal Workflow

---

# System Overview

                   +----------------------+
                   | Network Interface    |
                   +----------+-----------+
                              |
                              v
                     Packet Capture Engine
                              |
                              v
                     Packet Decoder Engine
                              |
                              v
                     Detection Engine
                              |
                   +----------+----------+
                   |                     |
                   v                     v
          Explainability Engine   Prevention Engine
                   |                     |
                   +----------+----------+
                              |
                              v
                     Logging & Database
                              |
                              v
                         Flask REST API
                              |
                              v
                     Web Dashboard UI

---

# Module 1
Packet Capture Engine

Purpose

Capture packets continuously from the selected network interface.

Responsibilities

- Open network interface
- Capture packets
- Timestamp packets
- Forward packets
- Continue monitoring indefinitely

Inputs

- Network interface
- Packet stream

Outputs

- Raw packets

Dependencies

- Scapy
- Linux networking

Failure Handling

If one packet cannot be decoded:

- Ignore packet
- Continue monitoring

Never terminate monitoring because of one malformed packet.

---

Workflow

Start Monitoring

↓

Select Interface

↓

Open Interface

↓

Capture Packet

↓

Send Packet

↓

Repeat Forever

---

# Module 2
Packet Decoder

Purpose

Convert raw packets into structured objects.

Responsibilities

Extract

- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol
- Flags
- Timestamp
- Packet Length

Outputs

Structured Packet Object

Example

{
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol,
    timestamp,
    flags
}

Failure Handling

Unknown protocols ignored.

Malformed packets skipped.

---

# Module 3
Detection Engine

Purpose

Analyze packets for malicious behavior.

Responsibilities

- Maintain packet statistics
- Compare traffic against rules
- Trigger detections
- Assign severity

Supported Rules

- SYN Flood
- Port Scan
- SQL Injection
- Brute Force
- ARP Spoofing

Outputs

Threat Event

---

Threat Event Object

Contains

- Event ID
- Source IP
- Destination IP
- Attack Type
- Severity
- Confidence
- Evidence
- Timestamp

---

Detection Workflow

Receive Packet

↓

Decode

↓

Update Counters

↓

Evaluate Rules

↓

Attack?

↓

No → Continue

↓

Yes

↓

Generate Event

↓

Send to Backend

---

# Module 4
Rule Engine

Purpose

Evaluate packet behavior against configured detection rules.

Responsibilities

- Load rules
- Enable/Disable rules
- Threshold comparison
- Confidence calculation

Rule Format

Rule Name

Description

Threshold

Severity

Block Duration

Enabled

Priority

---

# Module 5
Threat Scoring Engine

Purpose

Assign severity and confidence.

Inputs

- Attack Type
- Packet Rate
- Threshold
- Historical Events

Outputs

Severity

Low

Medium

High

Critical

Confidence

0–100

Example

Port Scan

Severity

Medium

Confidence

84%

---

# Module 6
Explainability Engine

Purpose

Generate human-readable explanations.

Responsibilities

Translate detection logic into plain language.

Example

Instead of

SYN_THRESHOLD_EXCEEDED

Display

"Detected 245 SYN packets from 192.168.1.10 within 3 seconds. This exceeded the configured threshold of 100 packets. The source has been temporarily blocked for 120 seconds."

Outputs

Explanation Object

Contains

- Summary
- Evidence
- Recommendation
- Rule Triggered
- Severity

---

# Module 7
Prevention Engine

Purpose

Automatically block attackers.

Responsibilities

- Check whitelist
- Execute firewall command
- Schedule unblock
- Update dashboard

Workflow

Threat

↓

Check Whitelist

↓

Whitelisted?

↓

Yes

↓

Log Decision

↓

End

↓

No

↓

Execute Block

↓

Store Timeout

↓

Log Success

---

Inputs

Threat Event

Outputs

Block Result

---

# Module 8
Whitelist Manager

Purpose

Protect trusted devices.

Responsibilities

- Add Entry
- Remove Entry
- Search
- Validate

Every detection must check whitelist before blocking.

---

# Module 9
Logging Engine

Purpose

Persist all activity.

Events Logged

- Detection
- Block
- Unblock
- Errors
- Configuration Changes
- Startup
- Shutdown

Fields

Timestamp

Source IP

Rule

Severity

Evidence

Action

User

Result

---

# Module 10
Database Layer

Purpose

Store persistent information.

Tables

Events

BlockedIPs

Whitelist

Rules

Settings

SystemLogs

Responsibilities

- Insert
- Update
- Delete
- Query

---

# Module 11
REST API

Purpose

Expose backend services.

Endpoints

GET /events

GET /dashboard

GET /statistics

POST /block

POST /unblock

GET /health

Responses

JSON

---

# Module 12
Dashboard

Purpose

Provide real-time visibility.

Components

Monitoring Status

Traffic Graph

Packet Counter

Blocked IP Cards

Recent Events

Severity Pie Chart

Rule Statistics

Evidence Panel

Live Alerts

---

Dashboard Refresh

Every 1 second

---

# Module 13
Configuration Manager

Purpose

Manage runtime configuration.

Editable Settings

Thresholds

Timeout

Interface

Rules

Theme

Refresh Interval

Configuration persists after restart.

---

# Module 14
Attack Simulator

Purpose

Support demonstrations.

Supported Simulations

SYN Flood

Port Scan

SQL Injection

Brute Force

ARP Spoofing

Each attack launched using one command.

---

# Module 15
Error Handler

Purpose

Recover from failures.

Errors

Packet Decode Error

Firewall Error

Database Error

Configuration Error

API Error

Dashboard Error

Rules

Log error.

Display warning.

Continue monitoring whenever possible.

---

# Module Communication

Packet Capture

↓

Decoder

↓

Detection Engine

↓

Threat Event

↓

Explainability

↓

Prevention

↓

Logging

↓

Database

↓

REST API

↓

Dashboard

---

# Functional Constraints

Only Linux supported.

Offline operation.

No cloud dependency.

Single-machine deployment.

Monitoring must never stop because of one failed packet.

Firewall operations require administrator privileges.

---

# Functional Success Criteria

The implementation is complete when:

✓ Live packet capture works.

✓ All five attacks are detected.

✓ Blocking occurs automatically.

✓ Dashboard updates live.

✓ Explanations are generated.

✓ Events are logged.

✓ Whitelist functions correctly.

✓ Demonstration completes in under 90 seconds.

---

# Future Functional Extensions

- Machine Learning Detection
- Threat Intelligence Integration
- MITRE ATT&CK Mapping
- PDF Incident Reports
- Email Alerts
- Multi-node Correlation
- Cloud Dashboard
- Role-Based Authentication

---

End of Document