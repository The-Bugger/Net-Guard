# Coding Guidelines

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

---

# Purpose

This document defines the coding standards, architecture rules, naming conventions, testing expectations, documentation requirements, and security practices for NetGuard.

All generated code must follow these guidelines.

---

# Core Principles

Every piece of code must be:

- Simple
- Readable
- Modular
- Testable
- Explainable
- Secure
- Maintainable

Prefer clarity over cleverness.

---

# Programming Philosophy

Follow

- SOLID Principles
- DRY (Don't Repeat Yourself)
- KISS (Keep It Simple)
- YAGNI (You Aren't Gonna Need It)
- Separation of Concerns

Avoid unnecessary abstractions.

---

# Python Style

Follow

PEP 8

Maximum line length

100 characters

Indentation

4 spaces

Encoding

UTF-8

Use type hints whenever practical.

Example

```python
def block_ip(ip: str, duration: int) -> bool:
    ...
```

---

# Naming Conventions

## Variables

snake_case

Example

```python
packet_count
source_ip
attack_type
```

---

## Functions

snake_case

Good

```python
detect_syn_flood()
generate_evidence()
block_attacker()
```

Bad

```python
DoDetection()
run()
temp()
```

---

## Classes

PascalCase

```python
PacketAnalyzer
DetectionEngine
FirewallManager
EvidenceGenerator
```

---

## Constants

UPPER_SNAKE_CASE

```python
MAX_PACKET_RATE
DEFAULT_BLOCK_DURATION
API_VERSION
```

---

## Files

snake_case

Examples

```
packet_parser.py
firewall_manager.py
dashboard_service.py
```

---

# Folder Responsibilities

backend/

- REST API
- Business logic
- Database access

frontend/

- HTML
- CSS
- JavaScript

detection/

- Packet capture
- Detection rules
- Evidence generation

database/

- Schema
- Migrations
- Seed data

tests/

- Unit tests
- Integration tests

Never mix responsibilities.

---

# Function Design

Functions should:

- Do one thing well
- Be under ~50 lines when practical
- Return predictable values
- Avoid hidden side effects

Prefer early returns over deeply nested conditions.

---

# Class Design

Classes should have a single responsibility.

Example

Good

```
PacketParser

↓

DetectionEngine

↓

FirewallManager
```

Bad

```
MegaSecurityClass
```

---

# Error Handling

Never ignore exceptions.

Good

```python
try:
    capture_packets()
except Exception as e:
    logger.error(str(e))
```

Bad

```python
except:
    pass
```

Never expose stack traces to end users.

---

# Logging Standards

Use Python's logging module.

Levels

- DEBUG
- INFO
- WARNING
- ERROR
- CRITICAL

Every important event should be logged.

Examples

- Monitoring started
- Rule matched
- IP blocked
- Firewall failure
- Database error

Do not log secrets or sensitive data.

---

# Comments

Write comments that explain *why*, not *what*.

Good

```python
# Ignore loopback traffic to reduce noise.
```

Bad

```python
# Increment i
i += 1
```

---

# Docstrings

Every public function should include a docstring.

Example

```python
def detect_port_scan(packet):
    """
    Analyze incoming packets for port scanning activity.

    Args:
        packet: Parsed network packet.

    Returns:
        Detection result or None.
    """
```

---

# API Standards

All responses must be JSON.

Success

```json
{
  "success": true,
  "data": {}
}
```

Error

```json
{
  "success": false,
  "error": "Invalid request"
}
```

Use appropriate HTTP status codes.

---

# Database Guidelines

- Use parameterized queries or ORM methods.
- Never build SQL with string concatenation.
- Store timestamps in UTC.
- Validate inputs before insertion.

---

# Security Guidelines

Always

- Validate user input
- Sanitize output where appropriate
- Use least-privilege permissions
- Escape untrusted content
- Restrict access to configuration files

Never

- Hardcode passwords
- Commit secrets
- Execute unsanitized shell commands
- Disable firewall protections in production

---

# Configuration

Configuration belongs in:

```
config/config.yaml
```

Secrets belong in:

```
.env
```

Never hardcode environment-specific values.

---

# Frontend Guidelines

Use

- Semantic HTML
- Responsive CSS
- Modern JavaScript (ES6+)

Avoid unnecessary libraries.

UI should remain lightweight and responsive.

---

# CSS Rules

Use

- CSS variables
- Flexbox
- Grid where appropriate

Avoid

- Inline styles
- !important (unless unavoidable)

---

# JavaScript Rules

Prefer

```javascript
const
let
```

Avoid

```javascript
var
```

Use async/await for asynchronous operations.

---

# Testing Standards

Every major module should include tests.

Test

- Normal behavior
- Invalid input
- Edge cases
- Error handling

Use pytest for backend testing.

---

# Performance Guidelines

Avoid

- Unnecessary loops
- Duplicate computations
- Blocking operations in request handlers

Optimize only after correctness.

---

# Git Commit Format

Examples

```
feat: add ARP spoof detection

fix: resolve dashboard refresh issue

refactor: simplify packet parser

docs: update deployment guide

test: add firewall integration tests
```

Keep commits focused on one logical change.

---

# Pull Request Checklist

Before merging:

- Code runs successfully
- Tests pass
- No debug statements
- No commented-out code
- Documentation updated
- Linting completed

---

# Code Review Checklist

Review for:

- Readability
- Correctness
- Security
- Performance
- Simplicity
- Documentation
- Test coverage

Reject code that introduces unnecessary complexity.

---

# AI Code Generation Rules (Kiro)

When generating code:

- Prefer small, focused modules.
- Avoid large monolithic files.
- Reuse existing utilities before creating new ones.
- Preserve backward compatibility when practical.
- Follow the project structure.
- Generate tests alongside new features.
- Update documentation when interfaces change.
- Explain non-obvious implementation decisions in comments or docs.

---

# Definition of Done

A feature is complete only when:

- Functionality implemented
- Tests passing
- Documentation updated
- Logging added where appropriate
- Error handling included
- Code reviewed
- No known critical bugs

---

# End of Coding Guidelines