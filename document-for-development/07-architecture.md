 # System Architecture

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

Document ID: NG-ARCH-001

---

# Purpose

This document defines the complete architecture of NetGuard.

It describes:

- Overall system design
- Component interactions
- Data flow
- Module responsibilities
- Deployment architecture
- Threading model
- Security boundaries
- Future scalability

This document serves as the architectural blueprint for implementation.

---

# 1. Architecture Style

NetGuard follows a layered, modular architecture with event-driven communication between components.

Architecture Pattern

Presentation Layer

↓

API Layer

↓

Business Logic Layer

↓

Detection Layer

↓

Infrastructure Layer

↓

Operating System

---

# 2. High-Level Architecture

                    +----------------------------+
                    |      Web Dashboard         |
                    | HTML • CSS • JS • Chart.js|
                    +-------------+--------------+
                                  |
                                  | REST API
                                  |
                    +-------------v--------------+
                    |        Flask Backend       |
                    | API • Logging • Services   |
                    +-------------+--------------+
                                  |
                 +----------------+----------------+
                 |                                 |
        +--------v---------+              +--------v--------+
        | Explainability   |              | Prevention      |
        | Engine           |              | Engine          |
        +--------+---------+              +--------+--------+
                 |                                 |
                 +---------------+-----------------+
                                 |
                         Threat Event Object
                                 |
                    +------------v-------------+
                    | Detection Engine         |
                    | Rule Evaluation          |
                    +------------+-------------+
                                 |
                    +------------v-------------+
                    | Packet Decoder           |
                    +------------+-------------+
                                 |
                    +------------v-------------+
                    | Packet Capture           |
                    | Scapy                    |
                    +------------+-------------+
                                 |
                        Network Interface

---

# 3. Layer Responsibilities

## Presentation Layer

Responsibilities

- Dashboard
- Charts
- Statistics
- Evidence Viewer
- Live Updates
- Settings

Technology

- HTML5
- CSS3
- JavaScript
- Chart.js

No business logic exists in this layer.

---

## API Layer

Responsibilities

- REST Endpoints
- Request Validation
- JSON Serialization
- Error Responses
- Authentication (Future)

Technology

Flask

---

## Business Layer

Responsibilities

- Detection Processing
- Severity Calculation
- Explainability
- Logging
- Firewall Requests
- Whitelist Validation

This layer contains all application logic.

---

## Detection Layer

Responsibilities

- Packet Inspection
- Rule Matching
- Threshold Tracking
- Threat Generation

Technology

Scapy

Custom Detection Rules

---

## Infrastructure Layer

Responsibilities

- Firewall
- Database
- File Storage
- Configuration

Technology

iptables

SQLite

Filesystem

---

# 4. Component Architecture

Packet Capture Engine

↓

Packet Decoder

↓

Detection Engine

↓

Threat Scoring

↓

Explainability

↓

Prevention

↓

Logging

↓

REST API

↓

Dashboard

---

# 5. Internal Components

## Packet Capture

Responsibilities

- Open interface
- Capture packets
- Forward packets
- Recover from capture errors

Input

Network packets

Output

Raw Packet Object

---

## Packet Decoder

Responsibilities

Convert packets into normalized objects.

Output

Packet

{
    src_ip
    dst_ip
    protocol
    ports
    flags
    timestamp
}

---

## Detection Engine

Responsibilities

- Maintain counters
- Evaluate thresholds
- Detect attacks
- Generate Threat Events

Supported Attacks

- SYN Flood
- Port Scan
- SQL Injection
- Brute Force
- ARP Spoofing

---

## Threat Scoring

Responsibilities

Determine

- Severity
- Confidence
- Priority

Output

Threat Score Object

---

## Explainability Engine

Responsibilities

Translate technical detections into administrator-friendly explanations.

Example

Instead of

SYN_THRESHOLD_EXCEEDED

Display

Detected 184 SYN packets from 192.168.1.15 within 2.7 seconds. The configured threshold was exceeded, so the IP was temporarily blocked.

---

## Prevention Engine

Responsibilities

- Validate whitelist
- Execute firewall commands
- Schedule unblock

Output

Firewall Action

---

## Logging Engine

Responsibilities

Store

- Alerts
- Blocks
- Errors
- Configuration Changes

---

## REST API

Responsibilities

Serve

Dashboard

Statistics

Logs

Evidence

Configuration

Health

---

## Dashboard

Widgets

Monitoring Status

Traffic Graph

Active Threats

Blocked IPs

Rule Statistics

Recent Events

Evidence Panel

Health Status

---

# 6. Data Flow

Packet

↓

Decoder

↓

Detection Rules

↓

Attack?

↓

No

↓

Discard

↓

Yes

↓

Threat Event

↓

Threat Score

↓

Explainability

↓

Whitelist Check

↓

Blocked?

↓

Yes

↓

iptables

↓

Logging

↓

Dashboard

---

# 7. Event Lifecycle

Incoming Packet

↓

Parsed

↓

Analyzed

↓

Rule Triggered

↓

Threat Event Created

↓

Severity Assigned

↓

Explanation Generated

↓

Block Decision

↓

Firewall Updated

↓

Database Updated

↓

Dashboard Refreshed

---

# 8. Threading Model

Main Thread

Application Startup

↓

Packet Capture Thread

Continuous Monitoring

↓

Detection Thread

Packet Analysis

↓

Logging Thread

Async Event Storage

↓

API Thread

HTTP Requests

↓

Dashboard

Live Updates

Blocking operations should not stop packet capture.

---

# 9. Folder Architecture

NetGuard/

backend/

api/

services/

models/

database/

detection/

capture/

decoder/

rules/

engines/

frontend/

css/

js/

assets/

config/

logs/

tests/

demo/

docs/

---

# 10. Configuration Flow

Configuration File

↓

Configuration Manager

↓

Detection Rules

↓

Dashboard

↓

API

Configuration changes should not require recompilation.

---

# 11. Database Architecture

Tables

Events

BlockedIPs

Whitelist

Rules

Settings

SystemLogs

Relationships

Events

↓

Generated Block

↓

BlockedIPs

Whitelist

↓

Prevention Engine

---

# 12. Security Architecture

Network

↓

Packet Capture

↓

Threat Detection

↓

Whitelist

↓

Firewall

↓

Logging

↓

Dashboard

Security Principles

Least Privilege

Fail Safe Defaults

Audit Logging

Defense in Depth

---

# 13. Failure Recovery

Packet Parsing Error

↓

Log Error

↓

Continue Monitoring

Firewall Failure

↓

Notify User

↓

Continue Detection

Database Failure

↓

Retry

↓

Temporary Queue

↓

Persist

Dashboard Failure

↓

Reconnect

↓

Continue Backend

---

# 14. Deployment Architecture

Student Laptop

│

├── Flask Backend

├── Scapy

├── SQLite

├── iptables

├── Dashboard

└── Browser

Kali Linux VM

│

└── Attack Generator

Communication

Kali VM

↓

Target Laptop

↓

Detection

↓

Blocking

↓

Dashboard

---

# 15. Future Architecture

Future modules can be inserted without changing the core pipeline.

Packet Capture

↓

Detection

↓

Machine Learning

↓

Threat Intelligence

↓

Correlation Engine

↓

Decision Engine

↓

Dashboard

---

# 16. Design Principles

- Modular Design
- Single Responsibility Principle
- Separation of Concerns
- Loose Coupling
- High Cohesion
- Event-Driven Processing
- Fail Gracefully
- Offline First
- Explainability by Design

---

# 17. Architectural Decisions

Decision: Offline deployment

Reason

Reliable hackathon demonstration without internet dependency.

---

Decision: Flask

Reason

Lightweight, simple, and sufficient for REST APIs.

---

Decision: Scapy

Reason

Flexible packet capture and parsing.

---

Decision: SQLite

Reason

Zero configuration, portable, ideal for demonstrations.

---

Decision: iptables

Reason

Native Linux firewall integration with minimal dependencies.

---

Decision: Modular Detection Engine

Reason

Allows future attack types to be added without modifying existing modules.

---

# 18. Success Criteria

The architecture is considered successful when:

✓ Components remain loosely coupled.

✓ Packet capture never blocks dashboard updates.

✓ Detection pipeline is modular.

✓ New attack rules can be added independently.

✓ Explainability remains separate from detection logic.

✓ Frontend contains no business logic.

✓ Backend remains independent of UI.

✓ Future ML integration requires minimal architectural changes.

---

End of Document