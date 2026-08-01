# Database Schema

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

Document ID: NG-DB-001

Database: SQLite 3

ORM: SQLAlchemy

---

# Purpose

This document defines the complete database design for NetGuard.

The database stores:

- Detection events
- Firewall blocks
- Whitelist entries
- Detection rules
- System settings
- Application logs

The schema is normalized to reduce redundancy while remaining lightweight for a single-machine deployment.

---

# Database Overview

Database Name

netguard.db

Tables

1. events
2. blocked_ips
3. whitelist
4. detection_rules
5. settings
6. system_logs

---

# Entity Relationship Diagram (Logical)

events
    |
    |--- generates ---> blocked_ips

detection_rules
    |
    |--- referenced by ---> events

whitelist
    |
    |--- checked by ---> blocked_ips

settings
    |
    |--- used by ---> application

system_logs
    |
    |--- stores ---> all activities

---

# Table: events

Purpose

Stores every detected attack.

Columns

| Column | Type | Constraints |
|---------|------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| event_id | TEXT | UNIQUE NOT NULL |
| timestamp | DATETIME | NOT NULL |
| attack_type | TEXT | NOT NULL |
| source_ip | TEXT | NOT NULL |
| destination_ip | TEXT | NOT NULL |
| source_port | INTEGER | NULL |
| destination_port | INTEGER | NULL |
| protocol | TEXT | NOT NULL |
| rule_name | TEXT | NOT NULL |
| severity | TEXT | NOT NULL |
| confidence | INTEGER | CHECK(confidence BETWEEN 0 AND 100) |
| packet_count | INTEGER | DEFAULT 0 |
| evidence | TEXT | JSON string |
| explanation | TEXT | NOT NULL |
| recommendation | TEXT | NULL |
| blocked | BOOLEAN | DEFAULT FALSE |

Indexes

- idx_events_timestamp
- idx_events_source_ip
- idx_events_attack_type
- idx_events_severity

---

# Sample Event Record

event_id

EVT-000123

attack_type

SYN Flood

severity

High

confidence

98

blocked

true

---

# Table: blocked_ips

Purpose

Tracks active and historical firewall blocks.

Columns

| Column | Type | Constraints |
|---------|------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| event_id | TEXT | REFERENCES events(event_id) |
| ip_address | TEXT | NOT NULL |
| blocked_at | DATETIME | NOT NULL |
| expires_at | DATETIME | NOT NULL |
| unblock_time | DATETIME | NULL |
| reason | TEXT | NOT NULL |
| active | BOOLEAN | DEFAULT TRUE |

Indexes

- idx_blocked_ip
- idx_active_block

---

# Table: whitelist

Purpose

Trusted devices that should never be automatically blocked.

Columns

| Column | Type | Constraints |
|---------|------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| ip_address | TEXT | UNIQUE NOT NULL |
| description | TEXT | NULL |
| created_at | DATETIME | NOT NULL |
| created_by | TEXT | DEFAULT 'admin' |

Indexes

- idx_whitelist_ip

---

# Table: detection_rules

Purpose

Stores configurable detection rules.

Columns

| Column | Type | Constraints |
|---------|------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| rule_name | TEXT | UNIQUE NOT NULL |
| attack_type | TEXT | NOT NULL |
| threshold | INTEGER | NOT NULL |
| severity | TEXT | NOT NULL |
| block_duration | INTEGER | NOT NULL |
| enabled | BOOLEAN | DEFAULT TRUE |
| priority | INTEGER | DEFAULT 1 |
| description | TEXT | NULL |

Example

SYN Flood

threshold

100 packets / 3 seconds

---

# Table: settings

Purpose

Stores application configuration.

Columns

| Column | Type | Constraints |
|---------|------|-------------|
| key | TEXT | PRIMARY KEY |
| value | TEXT | NOT NULL |
| updated_at | DATETIME | NOT NULL |

Example

dashboard_refresh = 1

block_duration = 120

theme = dark

network_interface = eth0

---

# Table: system_logs

Purpose

Stores operational logs.

Columns

| Column | Type | Constraints |
|---------|------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| timestamp | DATETIME | NOT NULL |
| level | TEXT | NOT NULL |
| module | TEXT | NOT NULL |
| event | TEXT | NOT NULL |
| message | TEXT | NOT NULL |
| metadata | TEXT | JSON string |

Log Levels

INFO

WARNING

ERROR

CRITICAL

DEBUG

Indexes

- idx_logs_level
- idx_logs_timestamp

---

# Relationships

events

1

↓

many

blocked_ips

events.rule_name

↓

references

detection_rules.rule_name

No direct relationship exists between whitelist and events because whitelist is checked at runtime.

---

# Data Types

Text

SQLite TEXT

Integer

SQLite INTEGER

Boolean

SQLite INTEGER (0 or 1)

Timestamp

SQLite DATETIME (ISO-8601 UTC)

JSON

Stored as TEXT containing serialized JSON

---

# Constraints

event_id must be unique.

Whitelist IPs must be unique.

Confidence range:

0–100

Severity allowed values

- Low
- Medium
- High
- Critical

Block duration

1–3600 seconds

IP addresses must be valid IPv4 or IPv6 before insertion.

---

# Indexing Strategy

events

- timestamp
- source_ip
- attack_type
- severity

blocked_ips

- ip_address
- active

whitelist

- ip_address

system_logs

- timestamp
- level

Indexes optimize:

- Dashboard queries
- Search
- Filtering
- Historical reports

---

# Data Retention

Events

Retain for 90 days (configurable).

System Logs

Retain for 30 days (configurable).

Blocked IP History

Retain indefinitely unless manually cleared.

Whitelist

Never automatically deleted.

---

# Backup Strategy

Database backup:

Daily export

Startup backup before migrations

Manual export from dashboard (future)

Supported formats:

- SQLite
- SQL dump
- JSON (future)

---

# Migration Strategy

Migration Tool

Alembic (recommended)

Migration Rules

- Never modify tables manually.
- All schema changes use versioned migrations.
- Backup before applying migrations.
- Support rollback where practical.

---

# Sample Queries

Recent High Severity Events

```sql
SELECT *
FROM events
WHERE severity = 'High'
ORDER BY timestamp DESC
LIMIT 20;
```

Currently Blocked IPs

```sql
SELECT *
FROM blocked_ips
WHERE active = 1;
```

Top Attack Types

```sql
SELECT attack_type,
       COUNT(*) AS total
FROM events
GROUP BY attack_type
ORDER BY total DESC;
```

---

# Performance Goals

Dashboard queries

< 200 ms

Event insert

< 50 ms

Log insert

< 20 ms

Statistics query

< 500 ms

---

# Future Database Extensions

Additional tables planned:

- users
- roles
- notifications
- incident_reports
- threat_intelligence
- ml_predictions
- mitre_mapping
- audit_logs

---

# Acceptance Criteria

✓ Events stored successfully.

✓ Firewall blocks linked to events.

✓ Whitelist prevents automatic blocking.

✓ Detection rules are configurable.

✓ Logs are searchable.

✓ Database supports dashboard reporting.

✓ Indexes improve query performance.

✓ Schema supports future expansion.

---

# Revision History

| Version | Date | Description |
|----------|------|-------------|
| 1.0 | July 2026 | Initial SQLite schema |

---

End of Document