# User Stories

# NetGuard

Version: 1.0

Document ID: NG-US-001

---

# Overview

This document defines the primary user stories for NetGuard. Each story follows the format:

> As a <role>, I want <goal>, so that <benefit>.

Priority Levels

- P0 – Critical
- P1 – High
- P2 – Medium
- P3 – Low

---

# Epic 1 – System Monitoring

## US-001

**As a network administrator, I want the system to start monitoring immediately after launch so that I don't have to manually begin packet capture.**

Priority: P0

Acceptance Criteria

- Monitoring starts automatically.
- Dashboard status changes to **Monitoring Active**.

---

## US-002

As a network administrator, I want to select the network interface before monitoring starts so that I can monitor the correct network.

Priority: P0

---

## US-003

As a user, I want to see whether monitoring is running so that I know the system is operational.

Priority: P0

---

## US-004

As a user, I want to stop monitoring safely so that maintenance can be performed.

Priority: P2

---

# Epic 2 – Threat Detection

## US-005

As a security administrator, I want SYN Flood attacks detected automatically so that denial-of-service attempts are identified quickly.

Priority: P0

---

## US-006

As a security administrator, I want Port Scan attempts detected so attackers probing my network are identified.

Priority: P0

---

## US-007

As a security administrator, I want SQL Injection attempts detected before they reach vulnerable applications.

Priority: P0

---

## US-008

As a security administrator, I want repeated login failures detected as brute-force attacks.

Priority: P0

---

## US-009

As a security administrator, I want ARP Spoofing detected to protect devices on the local network.

Priority: P0

---

## US-010

As a user, I want every attack assigned a severity level so I know which threats require immediate attention.

Priority: P1

---

## US-011

As a user, I want a confidence score displayed so I understand how certain the system is about a detection.

Priority: P2

---

# Epic 3 – Automatic Prevention

## US-012

As a network administrator, I want malicious IP addresses blocked automatically so manual intervention is unnecessary.

Priority: P0

---

## US-013

As an administrator, I want blocked IPs automatically unblocked after a timeout so temporary threats don't stay blocked forever.

Priority: P1

---

## US-014

As a user, I want the timeout duration configurable.

Priority: P2

---

## US-015

As a user, I want to manually unblock any IP if necessary.

Priority: P1

---

# Epic 4 – Explainability

## US-016

As a school administrator with limited cybersecurity knowledge, I want every alert explained in plain language so I understand what happened.

Priority: P0

---

## US-017

As a user, I want to know which detection rule triggered.

Priority: P0

---

## US-018

As a user, I want packet statistics displayed so I can verify the decision.

Priority: P1

---

## US-019

As a user, I want evidence attached to every alert.

Priority: P0

---

## US-020

As a user, I want the system to explain why an attack was blocked.

Priority: P0

---

## US-021

As a user, I want the system to explain why traffic was not blocked.

Priority: P1

---

# Epic 5 – Dashboard

## US-022

As a user, I want a live traffic graph.

Priority: P1

---

## US-023

As a user, I want active attack counters.

Priority: P1

---

## US-024

As a user, I want blocked IP cards.

Priority: P1

---

## US-025

As a user, I want attack history.

Priority: P1

---

## US-026

As a user, I want severity charts.

Priority: P2

---

## US-027

As a user, I want dashboard updates in real time.

Priority: P0

---

## US-028

As a user, I want visual indicators for High and Critical threats.

Priority: P1

---

# Epic 6 – Logging

## US-029

As an administrator, I want every event stored permanently.

Priority: P1

---

## US-030

As a user, I want logs searchable.

Priority: P2

---

## US-031

As a user, I want logs filtered by date.

Priority: P2

---

## US-032

As a user, I want logs filtered by IP.

Priority: P2

---

## US-033

As a user, I want logs filtered by severity.

Priority: P2

---

# Epic 7 – Whitelist

## US-034

As an administrator, I want trusted devices whitelisted.

Priority: P1

---

## US-035

As an administrator, I want to remove whitelist entries.

Priority: P2

---

## US-036

As an administrator, I want whitelisted devices still monitored but never automatically blocked.

Priority: P1

---

# Epic 8 – Configuration

## US-037

As a user, I want attack thresholds configurable.

Priority: P2

---

## US-038

As a user, I want block duration configurable.

Priority: P2

---

## US-039

As a user, I want configuration saved between restarts.

Priority: P2

---

# Epic 9 – Reliability

## US-040

As a user, I want the application to continue running if one packet fails parsing.

Priority: P1

---

## US-041

As a user, I want monitoring to recover automatically after temporary failures.

Priority: P1

---

## US-042

As a user, I want unexpected errors logged instead of crashing the application.

Priority: P1

---

# Epic 10 – Demonstration

## US-043

As a hackathon judge, I want to watch an attack detected live.

Priority: P0

---

## US-044

As a judge, I want to immediately see the attack explanation.

Priority: P0

---

## US-045

As a judge, I want to observe automatic blocking without manual intervention.

Priority: P0

---

## US-046

As a judge, I want evidence proving why the attack was blocked.

Priority: P0

---

## US-047

As a judge, I want the demonstration completed in under 90 seconds.

Priority: P0

---

## US-048

As a judge, I want the interface to remain responsive throughout the demonstration.

Priority: P1

---

# Future User Stories

## US-049

As an administrator, I want email alerts for critical attacks.

Priority: Future

---

## US-050

As an administrator, I want AI to detect unknown attack patterns.

Priority: Future

---

## US-051

As an administrator, I want MITRE ATT&CK mapping for each detection.

Priority: Future

---

## US-052

As an administrator, I want PDF incident reports generated automatically.

Priority: Future

---

## US-053

As an administrator, I want cloud synchronization across multiple devices.

Priority: Future

---

## US-054

As an administrator, I want role-based user accounts.

Priority: Future

---

# Story Completion Definition

A user story is considered complete when:

- Acceptance criteria are satisfied.
- Code is reviewed.
- Unit tests pass.
- Integration tests pass.
- Dashboard behavior is verified.
- Documentation is updated.
- Feature is demonstrated successfully.

---

End of Document