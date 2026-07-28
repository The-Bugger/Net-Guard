# Risk Analysis

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

Document ID: NG-RISK-001

---

# Purpose

This document identifies the major technical, operational, security, and project risks associated with NetGuard.

Each risk includes:

- Description
- Probability
- Impact
- Mitigation Strategy
- Contingency Plan

The objective is to reduce uncertainty and improve the reliability of the project, especially during the hackathon demonstration.

---

# Risk Assessment Scale

## Probability

| Level | Meaning |
|--------|---------|
| Low | Unlikely |
| Medium | Possible |
| High | Likely |

---

## Impact

| Level | Meaning |
|--------|---------|
| Low | Minor inconvenience |
| Medium | Feature degradation |
| High | Demo failure or major functionality loss |

---

# Technical Risks

---

## R1 - Packet Capture Failure

Category

Technical

Description

Scapy may fail to capture packets due to incorrect interface selection or insufficient permissions.

Probability

Medium

Impact

High

Mitigation

- Detect interfaces automatically.
- Validate selected interface.
- Display meaningful error messages.
- Verify permissions before starting capture.

Contingency

Restart packet capture using a verified interface.

---

## R2 - Firewall Blocking Failure

Category

Technical

Description

iptables commands may fail because of insufficient privileges.

Probability

Medium

Impact

High

Mitigation

- Validate permissions at startup.
- Test firewall integration before the demo.
- Log all firewall errors.

Contingency

Continue detection mode and clearly indicate that prevention is unavailable.

---

## R3 - Dashboard Freeze

Category

Technical

Description

High event rates may slow the dashboard.

Probability

Medium

Impact

Medium

Mitigation

- Update UI asynchronously.
- Limit refresh frequency.
- Batch UI updates.

Contingency

Refresh dashboard while backend continues running.

---

## R4 - Database Corruption

Category

Technical

Description

Unexpected shutdown may corrupt SQLite.

Probability

Low

Impact

High

Mitigation

- Use transactions.
- Perform automatic backups.
- Graceful shutdown.

Contingency

Restore latest backup.

---

## R5 - Detection Rule Failure

Category

Technical

Description

A faulty detection rule may generate incorrect alerts.

Probability

Medium

Impact

Medium

Mitigation

- Unit testing
- Rule validation
- Independent rule execution

Contingency

Disable faulty rule without affecting others.

---

# Security Risks

---

## R6 - False Positives

Description

Legitimate traffic incorrectly classified as malicious.

Probability

Medium

Impact

Medium

Mitigation

- Threshold tuning
- Whitelist support
- Confidence scoring
- Cooldown periods

Contingency

Allow administrator override.

---

## R7 - False Negatives

Description

Malicious activity goes undetected.

Probability

Medium

Impact

High

Mitigation

- Multiple detection indicators
- Comprehensive testing
- Continuous rule improvements

Contingency

Manual review of traffic logs.

---

## R8 - Configuration Tampering

Description

Unauthorized modification of configuration files.

Probability

Low

Impact

High

Mitigation

- Restrict file permissions.
- Validate configuration at startup.
- Maintain backups.

Contingency

Restore default configuration.

---

## R9 - Log Manipulation

Description

Logs altered or deleted.

Probability

Low

Impact

Medium

Mitigation

- Append-only logging.
- Backup logs.
- Audit configuration changes.

Contingency

Restore archived logs.

---

# Operational Risks

---

## R10 - Power Failure

Description

Laptop loses power during demonstration.

Probability

Medium

Impact

High

Mitigation

- Fully charge laptops.
- Carry chargers.
- Bring power bank.

Contingency

Restart using backup startup script.

---

## R11 - Network Failure

Description

Venue Wi-Fi becomes unavailable.

Probability

High

Impact

Low

Mitigation

- Use a local network.
- No internet dependency.
- Local API only.

Contingency

Use Ethernet cable or private hotspot if needed.

---

## R12 - Hardware Failure

Description

Laptop or VM crashes.

Probability

Low

Impact

High

Mitigation

- Test hardware.
- Keep spare USB with project.
- Clone repository locally.

Contingency

Move to another team member's laptop.

---

# Demo Risks

---

## R13 - Attack Demo Does Not Trigger

Description

Attack traffic does not meet detection thresholds.

Probability

Medium

Impact

High

Mitigation

- Test attack scripts repeatedly.
- Verify thresholds before presentation.

Contingency

Run an alternative attack or replay the recorded demonstration.

---

## R14 - Dashboard Not Updating

Description

Frontend loses connection to backend.

Probability

Medium

Impact

Medium

Mitigation

- Automatic reconnect.
- Health checks.

Contingency

Restart frontend without restarting backend.

---

## R15 - Time Overrun

Description

Presentation exceeds allotted time.

Probability

Medium

Impact

Medium

Mitigation

- Rehearse multiple times.
- Assign speaking roles.
- Use a timer.

Contingency

Skip secondary attack demonstration.

---

# Project Risks

---

## R16 - Feature Creep

Description

Adding unnecessary features before the hackathon.

Probability

High

Impact

High

Mitigation

- Freeze feature development before the event.
- Focus on stability.
- Prioritize bug fixes.

Contingency

Remove unfinished features.

---

## R17 - Team Coordination Issues

Description

Members duplicate work or block each other.

Probability

Medium

Impact

Medium

Mitigation

- Daily stand-up meetings.
- Git branching strategy.
- Clearly defined responsibilities.

Contingency

Reassign tasks.

---

## R18 - Git Merge Conflicts

Description

Conflicting code changes delay development.

Probability

Medium

Impact

Medium

Mitigation

- Feature branches.
- Frequent commits.
- Pull before pushing.

Contingency

Resolve conflicts collaboratively.

---

# Performance Risks

---

## R19 - High CPU Usage

Description

Packet processing consumes excessive CPU.

Probability

Medium

Impact

Medium

Mitigation

- Optimize detection logic.
- Efficient data structures.
- Adjustable sampling (future).

Contingency

Reduce monitoring rate during demonstrations.

---

## R20 - Memory Leak

Description

Long-running monitoring increases memory usage.

Probability

Low

Impact

High

Mitigation

- Periodic cleanup.
- Expiring cached data.
- Memory profiling.

Contingency

Restart monitoring service.

---

# Risk Matrix

| Risk | Probability | Impact | Priority |
|------|-------------|--------|----------|
| Packet Capture Failure | Medium | High | High |
| Firewall Failure | Medium | High | High |
| False Positives | Medium | Medium | Medium |
| False Negatives | Medium | High | High |
| Power Failure | Medium | High | High |
| Network Failure | High | Low | Medium |
| Demo Failure | Medium | High | High |
| Feature Creep | High | High | Critical |
| Merge Conflicts | Medium | Medium | Medium |
| High CPU Usage | Medium | Medium | Medium |

---

# Risk Monitoring

Review risks:

- Before coding begins
- At the end of each development day
- Before every demo rehearsal
- Immediately before the final presentation

---

# Risk Response Strategy

Avoid

- Unnecessary features
- Last-minute changes

Reduce

- Bugs
- False positives
- Performance issues

Transfer

- Share knowledge among team members to avoid single points of failure.

Accept

- Minor UI imperfections that do not affect functionality.

---

# Success Criteria

Risk management is considered successful when:

✓ No critical issues prevent the live demonstration.

✓ Recovery procedures are documented and tested.

✓ Team members understand contingency plans.

✓ Backup demo is available.

✓ High-priority risks have mitigation strategies.

---

# Revision History

| Version | Date | Description |
|----------|------|-------------|
| 1.0 | July 2026 | Initial Risk Analysis |

---

End of Document