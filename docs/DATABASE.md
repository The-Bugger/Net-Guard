# NetGuard Database Reference

SQLite database at `database/netguard.db`. Managed by SQLAlchemy 2.x ORM.
Schema defined in `database/schema.py`. Initialized by `database/init_db.py`.

WAL journal mode and foreign key enforcement are enabled at startup.

---

## Table of Contents

1. [events](#events)
2. [blocked_ips](#blocked_ips)
3. [whitelist](#whitelist)
4. [detection_rules](#detection_rules)
5. [settings](#settings)
6. [system_logs](#system_logs)
7. [Relationships](#relationships)
8. [Indexes](#indexes)
9. [SQLAlchemy Models](#sqlalchemy-models)

---

## events

Stores every threat event detected by the five detection rules.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PK, autoincrement | Internal surrogate key |
| `event_id` | VARCHAR(36) | UNIQUE, NOT NULL | UUID4 string assigned by the detection rule |
| `timestamp` | VARCHAR(30) | NOT NULL | UTC ISO-8601 string: `2025-07-01T12:34:56Z` |
| `attack_type` | VARCHAR(50) | NOT NULL | `SYN Flood`, `Port Scan`, `SQL Injection`, `Brute Force`, `ARP Spoofing` |
| `source_ip` | VARCHAR(45) | NOT NULL | Attacker source IP (IPv4 or IPv6) |
| `destination_ip` | VARCHAR(45) | NOT NULL | Primary target IP (empty string if not applicable) |
| `source_port` | INTEGER | NULL | Source port or NULL |
| `destination_port` | INTEGER | NULL | Destination port or NULL |
| `protocol` | VARCHAR(10) | NOT NULL | `TCP`, `UDP`, `ICMP`, `ARP`, `UNKNOWN` |
| `rule_name` | VARCHAR(50) | NOT NULL | `SYN_FLOOD_001`, `PORT_SCAN_001`, etc. |
| `severity` | VARCHAR(10) | NOT NULL | `Low`, `Medium`, `High`, `Critical` |
| `confidence` | INTEGER | NOT NULL, CHECK 0–100 | Confidence score in [0, 100] |
| `packet_count` | INTEGER | DEFAULT 0 | Number of packets contributing to detection |
| `evidence` | TEXT | NULL | JSON-serialised evidence dict from the detection rule |
| `explanation` | TEXT | NOT NULL | Plain-English explanation from ExplainabilityEngine |
| `recommendation` | TEXT | NULL | Actionable recommendation for the administrator |
| `blocked` | INTEGER | DEFAULT 0 | 1 if an iptables block was applied, 0 otherwise |

### Example row

```json
{
  "id": 1,
  "event_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": "2025-07-01T14:22:05Z",
  "attack_type": "SYN Flood",
  "source_ip": "10.0.0.5",
  "destination_ip": "192.168.1.100",
  "source_port": null,
  "destination_port": null,
  "protocol": "TCP",
  "rule_name": "SYN_FLOOD_001",
  "severity": "High",
  "confidence": 95,
  "packet_count": 250,
  "evidence": "{\"syn_packet_count\": 250, \"time_window_seconds\": 3, \"threshold\": 100}",
  "explanation": "Detected 250 SYN packets from 10.0.0.5 within 3s. The threshold of 100 was exceeded. Blocked.",
  "recommendation": "Investigate the source host and verify whether the traffic is legitimate.",
  "blocked": 1
}
```

### ORM model

```python
from database.schema import Event
```

---

## blocked_ips

Tracks active and historical iptables DROP rules applied by the PreventionEngine.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PK, autoincrement | Internal surrogate key |
| `event_id` | VARCHAR(36) | FK → events.event_id, NOT NULL | Originating ThreatEvent |
| `ip_address` | VARCHAR(45) | NOT NULL | Blocked IP address |
| `blocked_at` | VARCHAR(30) | NOT NULL | UTC ISO-8601 time when block was applied |
| `expires_at` | VARCHAR(30) | NOT NULL | UTC ISO-8601 time when block should expire |
| `unblock_time` | VARCHAR(30) | NULL | UTC ISO-8601 time when block was removed (NULL if still active) |
| `reason` | VARCHAR(50) | NOT NULL | Attack type or `Manual` |
| `active` | INTEGER | DEFAULT 1 | 1 = block is active; 0 = expired or manually removed |

### Example row

```json
{
  "id": 1,
  "event_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "ip_address": "10.0.0.5",
  "blocked_at": "2025-07-01T14:22:05Z",
  "expires_at": "2025-07-01T14:24:05Z",
  "unblock_time": null,
  "reason": "SYN Flood",
  "active": 1
}
```

### ORM model

```python
from database.schema import BlockedIP
```

---

## whitelist

Stores trusted IP addresses that bypass automatic blocking.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PK, autoincrement | Internal surrogate key |
| `ip_address` | VARCHAR(45) | UNIQUE, NOT NULL | Trusted IP address |
| `description` | TEXT | NULL | Human-readable label (e.g. "Internal gateway") |
| `created_at` | VARCHAR(30) | NOT NULL | UTC ISO-8601 timestamp |
| `created_by` | VARCHAR(100) | DEFAULT "admin" | Creator identifier |

### Example row

```json
{
  "id": 1,
  "ip_address": "192.168.1.1",
  "description": "Default gateway",
  "created_at": "2025-07-01T10:00:00Z",
  "created_by": "admin"
}
```

### ORM model

```python
from database.schema import WhitelistEntry
```

---

## detection_rules

Configurable detection rule definitions seeded on first run.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PK, autoincrement | Internal surrogate key |
| `rule_name` | VARCHAR(50) | UNIQUE, NOT NULL | Rule identifier: `SYN_FLOOD_001`, etc. |
| `attack_type` | VARCHAR(50) | NOT NULL | Human-readable attack category |
| `threshold` | INTEGER | NOT NULL | Default detection threshold |
| `severity` | VARCHAR(10) | NOT NULL | Default severity label |
| `block_duration` | INTEGER | NOT NULL | Default block duration in seconds |
| `enabled` | INTEGER | DEFAULT 1 | 1 = enabled; 0 = disabled |
| `priority` | INTEGER | DEFAULT 1 | Evaluation order (lower = first) |
| `description` | TEXT | NULL | Human-readable rule description |

### Default seed rows

| rule_name | attack_type | threshold | severity | block_duration | priority |
|-----------|-------------|-----------|----------|----------------|----------|
| SYN_FLOOD_001 | SYN Flood | 100 | High | 120 | 1 |
| PORT_SCAN_001 | Port Scan | 20 | Medium | 120 | 2 |
| SQL_INJECTION_001 | SQL Injection | 1 | High | 120 | 3 |
| BRUTE_FORCE_001 | Brute Force | 10 | Medium | 120 | 4 |
| ARP_SPOOF_001 | ARP Spoofing | 2 | High | 120 | 5 |

### ORM model

```python
from database.schema import DetectionRule
```

---

## settings

Key-value configuration store. Mirrors `config/config.yaml`.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `key` | VARCHAR(100) | PK | Setting name |
| `value` | TEXT | NOT NULL | Setting value (always stored as string) |
| `updated_at` | VARCHAR(30) | NOT NULL | UTC ISO-8601 of last update |

### Default seed keys

| key | default value |
|-----|---------------|
| `network_interface` | `""` |
| `syn_flood_threshold` | `"100"` |
| `syn_flood_window` | `"3"` |
| `port_scan_threshold` | `"20"` |
| `port_scan_window` | `"10"` |
| `brute_force_threshold` | `"10"` |
| `brute_force_window` | `"60"` |
| `block_duration` | `"120"` |
| `dashboard_refresh_interval` | `"1"` |
| `rules_enabled` | `'{"syn_flood": true, ...}'` (JSON) |
| `debug` | `"false"` |

### ORM model

```python
from database.schema import Setting
```

---

## system_logs

Operational log entries viewable in the dashboard log viewer.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PK, autoincrement | Internal surrogate key |
| `timestamp` | VARCHAR(30) | NOT NULL | UTC ISO-8601 string |
| `level` | VARCHAR(10) | NOT NULL | `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `module` | VARCHAR(50) | NOT NULL | Originating service name |
| `event` | VARCHAR(100) | NOT NULL | Short event label (e.g. `MONITOR_START`) |
| `message` | TEXT | NOT NULL | Human-readable description |
| `metadata` | TEXT | NULL | JSON-serialised context dict (sensitive keys stripped) |

### Example row

```json
{
  "id": 1,
  "timestamp": "2025-07-01T14:22:00Z",
  "level": "INFO",
  "module": "MonitorService",
  "event": "MONITOR_START",
  "message": "Monitoring started on eth0",
  "metadata": "{\"interface\": \"eth0\"}"
}
```

### ORM model

```python
from database.schema import SystemLog
```

---

## Relationships

```
events (event_id) ← foreign key ─ blocked_ips (event_id)
```

All other tables are independent. The `detection_rules` table is seeded at
startup but not used as a foreign key target — thresholds are read from
`config.yaml` at runtime by `ConfigurationManager`.

---

## Indexes

| Table | Column(s) | Index name | Purpose |
|-------|-----------|------------|---------|
| events | timestamp | idx_events_timestamp | Range queries for date filters |
| events | source_ip | idx_events_source_ip | Filter by attacker IP |
| events | attack_type | idx_events_attack_type | Filter by attack category |
| events | severity | idx_events_severity | Filter by severity level |
| blocked_ips | ip_address | idx_blocked_ip | Lookup active block for an IP |
| blocked_ips | active | idx_active_block | Efficient `WHERE active=1` queries |
| whitelist | ip_address | idx_whitelist_ip | O(1) DB lookup (backed by in-memory set) |
| system_logs | level | idx_logs_level | Filter by log level |
| system_logs | timestamp | idx_logs_timestamp | Range queries for date filters |

---

## SQLAlchemy Models

All models are in `database/schema.py` and inherit from `Base` (SQLAlchemy
2.x `DeclarativeBase`).

```python
from database.schema import Base, Event, BlockedIP, WhitelistEntry, DetectionRule, Setting, SystemLog
```

To create all tables (idempotent):

```python
from database.init_db import initialize_db
initialize_db()  # uses default SQLite path

# Or with custom URL:
initialize_db("sqlite:////absolute/path/netguard.db")
```
