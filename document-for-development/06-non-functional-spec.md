# Non-Functional Specification (NFS)

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

Document ID: NG-NFS-001

---

# Purpose

This document defines all quality attributes of NetGuard.

Unlike Functional Requirements, these requirements describe how well the system must perform rather than what it should do.

These specifications guide architecture, implementation, testing, deployment, and future scalability.

---

# 1. Performance

## NFR-P-001

Packet processing latency shall remain below **100 milliseconds** under normal operating conditions.

Priority

Critical

---

## NFR-P-002

Attack detection shall occur within **3 seconds** after sufficient evidence is collected.

Priority

Critical

---

## NFR-P-003

Automatic IP blocking shall complete within **1 second** after a confirmed detection.

Priority

Critical

---

## NFR-P-004

Dashboard updates shall occur every **1 second**.

Priority

High

---

## NFR-P-005

Application startup time shall not exceed **10 seconds**.

Priority

Medium

---

## NFR-P-006

Configuration loading shall complete in under **2 seconds**.

---

## NFR-P-007

API responses shall normally complete within **500 milliseconds**.

---

# 2. Resource Usage

## NFR-R-001

Memory usage should remain below **500 MB** during normal operation.

---

## NFR-R-002

CPU utilization should remain below **40%** on a typical student laptop while monitoring moderate traffic.

---

## NFR-R-003

The application shall not continuously consume 100% CPU under expected traffic loads.

---

## NFR-R-004

Log files shall rotate automatically to prevent uncontrolled disk usage.

---

# 3. Reliability

## NFR-REL-001

Monitoring shall continue indefinitely until stopped by the administrator.

---

## NFR-REL-002

Malformed packets shall never terminate the application.

---

## NFR-REL-003

Packet decoding failures shall be logged.

---

## NFR-REL-004

Unexpected exceptions shall be caught and logged.

---

## NFR-REL-005

Background monitoring threads shall restart automatically when possible.

---

## NFR-REL-006

Application crashes should be recoverable without database corruption.

---

# 4. Availability

## NFR-A-001

System availability target during demonstrations:

99%

---

## NFR-A-002

The monitoring engine should recover automatically after temporary network interruptions.

---

## NFR-A-003

Dashboard shall reconnect automatically if the backend becomes temporarily unavailable.

---

# 5. Security

## NFR-S-001

Only firewall operations require administrator privileges.

---

## NFR-S-002

Configuration files shall not contain plaintext secrets.

---

## NFR-S-003

Input validation shall be performed on all API requests.

---

## NFR-S-004

All logs shall include timestamps.

---

## NFR-S-005

Security events shall not be silently discarded.

---

## NFR-S-006

Whitelist modifications shall be logged.

---

## NFR-S-007

Firewall failures shall never stop packet monitoring.

---

## NFR-S-008

Every blocked IP shall include supporting evidence.

---

# 6. Scalability

## NFR-SC-001

The architecture shall support adding new attack detection rules without changing existing detection modules.

---

## NFR-SC-002

New dashboard widgets should be pluggable.

---

## NFR-SC-003

Future database migration should require minimal code changes.

---

## NFR-SC-004

The backend shall be modular enough to support future cloud deployment.

---

## NFR-SC-005

Future machine learning modules shall integrate without redesigning the detection pipeline.

---

# 7. Maintainability

## NFR-M-001

Each module shall have a single responsibility.

---

## NFR-M-002

Functions should remain concise and focused.

---

## NFR-M-003

Public functions shall include documentation.

---

## NFR-M-004

Modules shall avoid circular dependencies.

---

## NFR-M-005

Configuration values shall not be hardcoded.

---

## NFR-M-006

Detection rules shall remain independent from dashboard logic.

---

## NFR-M-007

Business logic shall remain separate from presentation logic.

---

# 8. Usability

## NFR-U-001

The dashboard shall remain understandable for users without cybersecurity expertise.

---

## NFR-U-002

Every alert shall include a plain-language explanation.

---

## NFR-U-003

High and Critical alerts shall be visually distinguishable.

---

## NFR-U-004

The interface shall remain usable on 1366×768 laptop displays.

---

## NFR-U-005

Navigation should require no more than three clicks to access any major feature.

---

# 9. Portability

## NFR-PORT-001

Primary deployment platform:

Ubuntu Linux

---

## NFR-PORT-002

Supported development environments:

- Ubuntu
- Kali Linux

---

## NFR-PORT-003

Python version:

3.11+

---

## NFR-PORT-004

The frontend shall run in modern Chromium-based browsers.

---

# 10. Compatibility

Compatible with

- Scapy
- Flask
- SQLite
- iptables
- Chart.js

---

Future Compatibility

- PostgreSQL
- Redis
- Docker
- Kubernetes

---

# 11. Observability

The application shall expose:

- Health Status
- Monitoring Status
- Active Alerts
- Active Blocks
- System Errors
- Packet Rate
- Detection Count

---

Every important event shall be logged.

---

# 12. Logging

Each log entry shall contain:

Timestamp

Severity

Module

Event Type

Description

Result

---

Log Levels

INFO

WARNING

ERROR

CRITICAL

DEBUG (development only)

---

# 13. Error Recovery

If packet capture fails:

- Log error
- Notify user
- Allow retry

---

If firewall command fails:

- Log failure
- Continue monitoring

---

If dashboard disconnects:

- Attempt automatic reconnection

---

If database becomes unavailable:

- Queue events temporarily
- Retry writes
- Notify administrator

---

# 14. Backup & Recovery

Configuration files should be exportable.

Logs should remain recoverable after restart.

System should restart using the previous configuration.

---

# 15. Code Quality

The project shall follow:

PEP 8 (Python)

REST API best practices

Modular architecture

Dependency injection where practical

Consistent naming conventions

Meaningful exception handling

---

# 16. Documentation

Every module shall include:

Purpose

Inputs

Outputs

Dependencies

Error Handling

Usage

---

Public APIs shall be documented.

---

Configuration shall be documented.

---

Deployment steps shall be documented.

---

# 17. Testability

Every major component shall support:

Unit Testing

Integration Testing

System Testing

Manual Testing

Demonstration Testing

---

Dependencies should be replaceable with mocks during testing.

---

# 18. Accessibility

Dashboard should maintain:

Readable typography

Clear color contrast

Consistent icons

Keyboard navigation where practical

Responsive layouts

---

# 19. Future Readiness

Architecture should support future integration with:

Machine Learning

Threat Intelligence

SIEM Platforms

Cloud Dashboard

Distributed Monitoring

Email Alerts

MITRE ATT&CK Mapping

---

# 20. Acceptance Criteria

The non-functional specification is considered satisfied when:

✓ Dashboard updates within one second.

✓ Detection latency remains below three seconds.

✓ Automatic blocking works reliably.

✓ Monitoring survives malformed packets.

✓ Memory usage remains below 500 MB during normal operation.

✓ CPU utilization remains below 40% on typical hardware.

✓ Logs are persisted successfully.

✓ No module failure causes total application shutdown.

✓ All configuration persists after restart.

✓ Documentation remains synchronized with implementation.

---

# Revision History

| Version | Date | Description |
|----------|------|-------------|
| 1.0 | July 2026 | Initial non-functional specification |

---

End of Document