# Technical Steering

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

---

# Purpose

This document defines the official technical architecture and engineering standards for NetGuard.

All generated code should follow this document unless a later specification explicitly overrides it.

---

# Technology Stack

## Backend

Language

Python 3.11+

Framework

Flask

Reason

- Lightweight
- Fast startup
- Simple REST APIs
- Excellent for hackathons
- Easy deployment

---

## Frontend

Languages

- HTML5
- CSS3
- JavaScript (ES6+)

Libraries

- Chart.js
- Socket.IO Client

Reason

Avoid heavy frontend frameworks unless required.

The dashboard should remain lightweight and responsive.

---

## Database

SQLite

Reason

- Zero configuration
- Offline
- Portable
- Perfect for local deployment

Future versions may support PostgreSQL.

---

## Detection Engine

Libraries

- Scapy
- YARA (where applicable)
- psutil

Responsibilities

- Packet capture
- Packet parsing
- Attack detection
- Evidence generation

---

## Firewall Integration

Linux

iptables

Future Support

- nftables
- Windows Defender Firewall
- pf (BSD)

---

## Real-Time Communication

Primary

Flask-SocketIO

Fallback

REST API polling

Dashboard updates should use WebSockets whenever available.

---

# Project Structure

```
NetGuard/

backend/
    api/
    services/
    models/
    routes/
    utils/

frontend/
    css/
    js/
    assets/

detection/
    rules/
    parsers/
    capture/

database/
    migrations/

config/

logs/

scripts/

tests/

demo/

docs/
```

---

# Architecture

```
Packet Capture

↓

Packet Parser

↓

Detection Engine

↓

Evidence Generator

↓

REST API

↓

SQLite

↓

Dashboard

↓

Administrator
```

---

# Backend Design

Use layered architecture.

Controllers

↓

Services

↓

Repositories

↓

Database

Business logic must never exist inside route handlers.

---

# API Design

RESTful APIs only.

JSON request/response.

Use:

GET

POST

PUT

DELETE

Appropriate HTTP status codes.

---

# Error Handling

Every API returns

```
{
  "success": true,
  "message": "...",
  "data": {}
}
```

Errors

```
{
  "success": false,
  "error": "...",
  "code": 400
}
```

Never return raw exceptions.

---

# Database Standards

Tables

- events
- blocked_ips
- whitelist
- detection_rules
- system_logs
- settings

Primary keys

UUID preferred.

Use timestamps in UTC.

---

# Logging Standards

Log Levels

- DEBUG
- INFO
- WARNING
- ERROR
- CRITICAL

Separate files

- detections.log
- system.log
- errors.log

Never print sensitive information.

---

# Configuration

Store configuration in

```
config/config.yaml
```

Environment variables

```
.env
```

Never hardcode

- API keys
- Passwords
- Paths

---

# Coding Principles

Follow

- SOLID
- DRY
- KISS
- Separation of Concerns

Prefer composition over inheritance.

Keep functions small and focused.

---

# Performance Goals

Detection latency

< 3 seconds

Dashboard refresh

1 second

API response

< 200 ms

Memory usage

< 500 MB

CPU

Optimized for standard laptops.

---

# Security Practices

Validate all input.

Escape user-generated output.

Use parameterized SQL queries.

Restrict file permissions.

Never execute shell commands with unsanitized input.

---

# Testing Requirements

Every module should include

- Unit tests
- Integration tests (where applicable)

Use

pytest

Target

>80% test coverage

---

# Git Workflow

Main Branch

main

Feature Branches

feature/<feature-name>

Bug Fixes

fix/<bug-name>

Commits

Use descriptive commit messages.

Examples

```
feat: add SYN flood detection

fix: resolve firewall timeout

docs: update API specification
```

---

# Documentation Standards

Every module should include

- Purpose
- Inputs
- Outputs
- Error conditions

Public functions should include docstrings.

---

# Code Review Checklist

Before merging

- Code builds successfully
- Tests pass
- No duplicated logic
- No unused imports
- No debug code
- Documentation updated

---

# Future Technology Roadmap

Possible future upgrades

- FastAPI
- PostgreSQL
- Redis
- Docker
- Kubernetes
- React Dashboard
- AI-assisted anomaly detection
- Distributed sensors

These are not part of the MVP.

---

# Technical Decision Rules

When multiple implementations are possible:

Choose the option that is:

1. Simpler
2. Easier to test
3. Easier to explain
4. Easier to maintain
5. Reliable during live demos

Avoid unnecessary dependencies.

---

# Definition of Technical Success

The system is considered technically complete when:

- Detection engine operates reliably
- Dashboard updates in real time
- APIs respond consistently
- Database stores all required information
- Logs are complete
- Code is modular and documented
- Tests pass successfully

---

# End of Technical Steering