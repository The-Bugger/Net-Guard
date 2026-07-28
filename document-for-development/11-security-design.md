# Security Design Specification

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

Document ID: NG-SEC-001

---

# Purpose

This document defines the security architecture of NetGuard.

It covers:

- Threat model
- Trust boundaries
- Secure coding practices
- Firewall security
- Logging integrity
- Input validation
- Configuration security
- Future authentication architecture

NetGuard follows the principle of **Secure by Design**.

---

# Security Objectives

Primary goals

- Detect malicious activity
- Prevent unauthorized access
- Protect configuration
- Preserve log integrity
- Prevent privilege abuse
- Continue operating during attacks
- Maintain explainability

---

# Security Principles

- Least Privilege
- Defense in Depth
- Fail Secure
- Secure Defaults
- Separation of Duties
- Input Validation
- Auditability
- Explainability
- Offline First

---

# Trust Boundaries

                     Internet / LAN
                           │
                           ▼
                Packet Capture Engine
                           │
          ─────────────────────────────────
           Trusted Internal Application
          ─────────────────────────────────
                           │
                    Detection Engine
                           │
                           ▼
                 Explainability Engine
                           │
                           ▼
                 Prevention Engine
                           │
                           ▼
                     iptables Firewall
                           │
                           ▼
                    SQLite Database
                           │
                           ▼
                    Dashboard (Local)

---

# Threat Model

Potential Threats

| Threat | Risk | Mitigation |
|---------|------|------------|
| SYN Flood | High | Detect and temporarily block source |
| Port Scan | High | Detect reconnaissance and block attacker |
| SQL Injection | High | Pattern detection and alert generation |
| Brute Force Login | High | Threshold detection and temporary block |
| ARP Spoofing | High | ARP conflict detection |
| Malformed Packets | Medium | Ignore safely, continue monitoring |
| False Positives | Medium | Whitelist + configurable thresholds |
| Firewall Failure | Medium | Log failure, continue monitoring |
| Database Corruption | Low | Transactions + backup strategy |
| Unauthorized Configuration Changes | Medium | Restrict write access |

---

# Security Zones

Zone 1

External Network

Contains

- Users
- Attackers
- Internet
- Local LAN

Untrusted

---

Zone 2

Packet Capture

Receives all packets.

Treat all packet data as untrusted.

---

Zone 3

Detection Layer

Performs packet analysis.

Never executes packet contents.

---

Zone 4

Prevention Layer

Communicates with the operating system firewall.

Requires elevated privileges.

---

Zone 5

Storage Layer

SQLite database

Logs

Configuration

Trusted

---

Zone 6

Dashboard

Displays processed data only.

No direct packet access.

---

# Privilege Model

Normal User

Allowed

- View dashboard
- View logs
- View evidence

Not Allowed

- Modify firewall
- Change system rules

---

Administrator

Allowed

- Modify configuration
- Update whitelist
- Start monitoring
- Stop monitoring
- Manage rules

---

System Process

Allowed

- Capture packets
- Execute firewall commands
- Write logs

---

# Firewall Integration

Firewall technology

iptables

Responsibilities

- Temporary blocking
- Automatic expiration
- Logging
- Safe rollback

Rules

Never permanently block without administrator approval.

Whitelist entries always bypass automatic blocking.

---

# Input Validation

Validate

- IP addresses
- Network interface names
- Rule thresholds
- API parameters
- Configuration values

Reject

- Invalid IPv4/IPv6
- Negative durations
- Unknown severity levels
- Invalid JSON payloads

---

# Secure Coding Guidelines

Never use:

- `eval()`
- `exec()`
- Shell command construction with unsanitized input
- Hardcoded credentials

Always:

- Validate input
- Catch exceptions
- Log failures
- Use parameterized database queries
- Escape user-controlled output where applicable

---

# Configuration Security

Configuration File

config.yaml

Contains

- Interface
- Thresholds
- Block duration
- Dashboard settings

Must NOT contain

- Passwords
- API keys
- Secrets

File permissions

Read/Write for administrator only.

---

# Log Integrity

Every log entry shall include

- Timestamp
- Module
- Severity
- Event
- Result

Example

```json
{
  "timestamp":"2026-08-01T10:20:15Z",
  "module":"DetectionEngine",
  "severity":"HIGH",
  "event":"SYN Flood",
  "result":"Blocked"
}
```

Logs are append-only during normal operation.

---

# Error Handling

Malformed Packet

- Ignore packet
- Log warning
- Continue monitoring

Firewall Failure

- Log error
- Notify administrator
- Continue detection

Database Failure

- Retry
- Queue events in memory
- Persist when available

Dashboard Failure

- Reconnect automatically

---

# API Security

Current Version

Local-only API

Authentication

Not required for hackathon deployment

Future

- JWT
- RBAC
- API Keys
- HTTPS

---

# Data Protection

Sensitive Data

- Configuration
- Logs
- Detection history
- Whitelist

Non-sensitive Data

- Live dashboard metrics
- Packet statistics
- Rule descriptions

---

# Security Logging

Log the following

- Detection events
- Block actions
- Unblock actions
- Configuration changes
- Whitelist modifications
- Startup
- Shutdown
- Unexpected exceptions

---

# Availability

System must continue operating when

- One detection rule fails
- One packet fails parsing
- Dashboard disconnects
- Firewall temporarily fails

---

# Explainability Security

Every security decision shall include

- Rule triggered
- Threshold exceeded
- Evidence collected
- Confidence score
- Severity
- Recommendation

No alert should be displayed without supporting evidence.

---

# Whitelist Protection

Whitelisted IPs

- Continue monitoring
- Never automatically blocked
- Still logged if suspicious activity occurs

All whitelist changes are auditable.

---

# Future Authentication

Planned

Users

Roles

- Administrator
- Analyst
- Viewer

Authentication

- JWT
- Password hashing (Argon2 or bcrypt)
- Session timeout
- Multi-factor authentication (future)

---

# Secure Deployment

Recommended Environment

- Ubuntu 24.04 LTS
- Python 3.11+
- SQLite
- Flask
- iptables

Run backend with minimum required privileges.

---

# Incident Response

When an attack is detected

1. Create Threat Event
2. Calculate Severity
3. Generate Explanation
4. Check Whitelist
5. Execute Block (if applicable)
6. Record Log
7. Update Dashboard

---

# Security Testing

Required tests

- Input validation tests
- Firewall integration tests
- False-positive tests
- Rule accuracy tests
- API validation tests
- Log integrity tests
- Privilege tests
- Configuration validation tests

---

# Future Security Enhancements

- nftables support
- Suricata rule import
- YARA rule management UI
- TLS for remote dashboard
- Threat intelligence feeds
- MITRE ATT&CK mapping
- CVE enrichment
- Digital signature verification for configuration
- Secure update mechanism

---

# Security Acceptance Criteria

✓ All inputs validated.

✓ Firewall commands executed safely.

✓ Logs remain tamper-evident and append-only.

✓ Detection continues despite malformed packets.

✓ Whitelist prevents automatic blocking.

✓ Configuration contains no secrets.

✓ Security events are fully auditable.

✓ Dashboard never exposes raw packet data unnecessarily.

---

# Revision History

| Version | Date | Description |
|----------|------|-------------|
| 1.0 | July 2026 | Initial Security Design Specification |

---

End of Document