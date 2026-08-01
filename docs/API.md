# NetGuard REST API Documentation

Base URL: `http://localhost:5000/api/v1`

## Standard Response Envelope

All API responses follow a standard JSON envelope:

```json
{
  "success": true,
  "message": "Optional success message",
  "data": { ... },
  "error_code": null
}
```

On error:
```json
{
  "success": false,
  "error": "Description of the error",
  "error_code": "ERROR_CODE",
  "data": null
}
```

Common HTTP Status Codes:
- `200` — Success
- `201` — Created
- `204` — No Content (successful DELETE)
- `400` — Bad Request (missing fields)
- `401` — Unauthorized (X-API-Key missing or invalid)
- `404` — Not Found
- `409` — Conflict (e.g. already monitoring)
- `422` — Validation Error
- `500` — Internal Server Error

---

## Authentication

When `NETGUARD_API_KEY` is set in the environment, all mutating endpoints
(`POST`, `PUT`, `DELETE`, `PATCH`) require an `X-API-Key` request header:

```
X-API-Key: <your-api-key>
```

When `NETGUARD_API_KEY` is **not set**, the app runs in dev no-auth mode and
the header is not checked. When `REQUIRE_AUTH_FOR_READS=true`, `GET` endpoints
are also protected. SocketIO paths (`/socket.io/`) are always exempt.

---

## Endpoints

### 1. Health Check

**GET /health**

Liveness check for the backend service.

Response `200`:
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "1.0.0",
    "uptime": "00:05:32"
  }
}
```

---

### 2. System Status

**GET /status**

Detailed system status including monitoring state and detection engine state.

Response `200`:
```json
{
  "success": true,
  "data": {
    "monitoring": true,
    "interface": "eth0",
    "packets_processed": 15234,
    "active_blocks": 3,
    "detection_engine_running": true
  }
}
```

---

### 3. Start Monitoring

**POST /monitor/start**

Start packet capture on a specified network interface.

Request Headers:
- `X-API-Key: <key>` — required when `NETGUARD_API_KEY` is set

Request Body:
```json
{
  "interface": "eth0"
}
```

Response `200`:
```json
{
  "success": true,
  "message": "Monitoring started.",
  "data": { "interface": "eth0" }
}
```

Error Responses:
- `400 VALIDATION_ERROR` — missing `interface` field
- `409 ALREADY_MONITORING` — monitoring already active
- `422 INVALID_INTERFACE` — interface not found on the system

---

### 4. Stop Monitoring

**POST /monitor/stop**

Stop packet capture.

Request Headers:
- `X-API-Key: <key>` — required when `NETGUARD_API_KEY` is set

Request Body: `{}` (empty)

Response `200`:
```json
{
  "success": true,
  "message": "Monitoring stopped.",
  "data": null
}
```

Error Responses:
- `409 NOT_MONITORING` — monitoring is not active

---

### 5. List Interfaces

**GET /monitor/interfaces**

List available network interfaces on the system.

Response `200`:
```json
{
  "success": true,
  "data": {
    "interfaces": ["eth0", "lo", "wlan0"]
  }
}
```

---

### 6. Full Dashboard

**GET /dashboard**

Complete dashboard snapshot including KPIs, recent events, active blocks, whitelist entries, and monitoring state.

Response `200`:
```json
{
  "success": true,
  "data": {
    "monitoring": true,
    "interface": "eth0",
    "packets_processed": 15234,
    "alerts_today": 12,
    "blocked_ips": 3,
    "packets_per_second": 234.5,
    "active_threats": 0,
    "traffic_rate": 234.5,
    "recent_events": [
      {
        "event_id": "a1b2c3d4-...",
        "timestamp": "2026-07-29T10:30:00Z",
        "attack_type": "SYN Flood",
        "source_ip": "10.0.0.5",
        "severity": "High",
        "confidence": 87,
        "blocked": true,
        "rule_name": "SYN_FLOOD_001"
      }
    ],
    "active_blocks": [
      {
        "ip_address": "10.0.0.5",
        "reason": "SYN Flood detected",
        "blocked_at": "2026-07-29T10:30:01Z",
        "expires_at": "2026-07-29T10:32:01Z",
        "expires_in": 120
      }
    ],
    "whitelist": [
      {
        "ip_address": "192.168.1.1",
        "description": "Gateway",
        "created_at": "2026-07-29T09:00:00Z",
        "created_by": "admin"
      }
    ],
    "attack_type_counts": {
      "SYN Flood": 5,
      "Port Scan": 3,
      "SQL Injection": 2,
      "Brute Force": 1,
      "ARP Spoofing": 1
    }
  }
}
```

---

### 7. Live Dashboard Stats

**GET /dashboard/live**

Lightweight live statistics for real-time polling (no events or blocks included).

Response `200`:
```json
{
  "success": true,
  "data": {
    "packets_per_second": 234.5,
    "active_threats": 3,
    "alerts_today": 12,
    "monitoring": true
  }
}
```

---

### 8. List Detections

**GET /detections**

Retrieve detection events with optional filters.

Query Parameters:
| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | string | Filter by severity: `Low`, `Medium`, `High`, `Critical` |
| `attack_type` | string | Filter by attack type |
| `source_ip` | string | Filter by source IP address |
| `date` | string | Filter by date (ISO 8601, e.g. `2026-07-29`) |
| `limit` | int | Max results (default 100, max 500) |
| `offset` | int | Pagination offset (default 0) |

Response `200`:
```json
{
  "success": true,
  "data": {
    "events": [
      {
        "event_id": "a1b2c3d4-...",
        "timestamp": "2026-07-29T10:30:00Z",
        "attack_type": "SYN Flood",
        "source_ip": "10.0.0.5",
        "severity": "High",
        "confidence": 87,
        "blocked": true,
        "rule_name": "SYN_FLOOD_001",
        "evidence": { ... }
      }
    ],
    "count": 1
  }
}
```

Error Responses:
- `422 VALIDATION_ERROR` — invalid severity value
- `422 INVALID_IP` — invalid source_ip value

---

### 9. Get Detection by ID

**GET /detections/{event_id}**

Retrieve a single detection event by its UUID.

Response `200`:
```json
{
  "success": true,
  "data": {
    "event_id": "a1b2c3d4-...",
    "timestamp": "2026-07-29T10:30:00Z",
    "attack_type": "SYN Flood",
    "source_ip": "10.0.0.5",
    "severity": "High",
    "confidence": 87,
    "blocked": true,
    "rule_name": "SYN_FLOOD_001",
    "evidence": { ... }
  }
}
```

Error Responses:
- `404 NOT_FOUND` — event ID not found

---

### 10. Manual Detection

**POST /detect**

Submit a detection event manually (internal endpoint for the detection engine).

Request Headers:
- `X-API-Key: <key>` — required when `NETGUARD_API_KEY` is set

Request Body:
```json
{
  "attack_type": "SYN Flood",
  "source_ip": "10.0.0.5",
  "severity": "High",
  "rule": "SYN_FLOOD_001",
  "confidence": 87,
  "evidence": {},
  "timestamp": "2026-07-29T10:30:00Z"
}
```

Response `201`:
```json
{
  "success": true,
  "message": "Detection received.",
  "data": { "received": true }
}
```

Error Responses:
- `400 VALIDATION_ERROR` — missing required fields
- `422 INVALID_IP` — invalid source IP

---

### 11. Get Evidence

**GET /evidence/{event_id}**

Retrieve the explanation and evidence for a detection event.

Response `200`:
```json
{
  "success": true,
  "data": {
    "event_id": "a1b2c3d4-...",
    "attack_name": "SYN Flood",
    "rule_triggered": "SYN_FLOOD_001",
    "plain_english_text": "This device at 10.0.0.5 sent 250 SYN packets in 3 seconds. That is unusually fast — normal networks see fewer than 100 SYN packets per 3-second window from a single device. This behaviour matches a SYN Flood attack, where the attacker overwhelms the target by opening many connections without completing the handshake.",
    "evidence": {
      "source_ip": "10.0.0.5",
      "syn_packet_count": 250,
      "time_window_seconds": 3,
      "destination_ips": ["10.0.0.1"],
      "sample_timestamps": ["2026-07-29T10:30:00Z", "..."]
    },
    "confidence_score": 87,
    "severity": "High",
    "recommendation": "Block the source IP immediately and investigate the device for compromise.",
    "source_ip": "10.0.0.5",
    "timestamp": "2026-07-29T10:30:00Z"
  }
}
```

Error Responses:
- `404 NOT_FOUND` — event ID not found

---

### 12. Block IP

**POST /block**

Manually block an IP address via iptables.

Request Headers:
- `X-API-Key: <key>` — required when `NETGUARD_API_KEY` is set

Request Body:
```json
{
  "ip": "10.0.0.5",
  "reason": "Manual block — suspicious activity",
  "duration": 120
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `ip` | string | Yes | — | IP address to block |
| `reason` | string | No | `"Manual"` | Reason for blocking |
| `duration` | int | No | `120` | Block duration in seconds |

Response `201`:
```json
{
  "success": true,
  "message": "IP blocked successfully.",
  "data": { "blocked": true, "ip": "10.0.0.5" }
}
```

Error Responses:
- `400 VALIDATION_ERROR` — missing `ip` field
- `422 INVALID_IP` — invalid IP address format
- `500 BLOCK_FAILED` — iptables command failed

---

### 13. Unblock IP

**POST /unblock**

Manually unblock an IP address.

Request Headers:
- `X-API-Key: <key>` — required when `NETGUARD_API_KEY` is set

Request Body:
```json
{
  "ip": "10.0.0.5"
}
```

Response `200`:
```json
{
  "success": true,
  "data": { "success": true, "ip": "10.0.0.5" }
}
```

Error Responses:
- `400 VALIDATION_ERROR` — missing `ip` field
- `422 INVALID_IP` — invalid IP address format
- `404 NOT_FOUND` — no active block for this IP
- `500 BLOCK_FAILED` — iptables command failed

---

### 14. List Blocked IPs

**GET /blocked**

List all currently active IP blocks.

Response `200`:
```json
{
  "success": true,
  "data": {
    "blocked": [
      {
        "ip_address": "10.0.0.5",
        "reason": "SYN Flood detected",
        "blocked_at": "2026-07-29T10:30:01Z",
        "expires_at": "2026-07-29T10:32:01Z",
        "expires_in": 120,
        "event_id": "a1b2c3d4-..."
      }
    ]
  }
}
```

---

### 15. List Whitelist

**GET /whitelist**

List all whitelisted IP addresses.

Response `200`:
```json
{
  "success": true,
  "data": {
    "whitelist": [
      {
        "ip_address": "192.168.1.1",
        "description": "Gateway Router",
        "created_at": "2026-07-29T09:00:00Z",
        "created_by": "admin"
      }
    ]
  }
}
```

---

### 16. Add to Whitelist

**POST /whitelist**

Add an IP address to the whitelist. Whitelisted IPs are monitored but never blocked.

Request Headers:
- `X-API-Key: <key>` — required when `NETGUARD_API_KEY` is set

Request Body:
```json
{
  "ip": "192.168.1.1",
  "description": "Corporate Gateway"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ip` | string | Yes | IP address to whitelist |
| `description` | string | No | Optional description |

Response `201`:
```json
{
  "success": true,
  "message": "192.168.1.1 added to whitelist.",
  "data": {
    "ip": "192.168.1.1",
    "description": "Corporate Gateway"
  }
}
```

Error Responses:
- `400 VALIDATION_ERROR` — missing `ip` field
- `422 INVALID_IP` — invalid IP address format
- `500 DATABASE_ERROR` — database write failure

---

### 17. Remove from Whitelist

**DELETE /whitelist/{ip}**

Remove an IP address from the whitelist.

Request Headers:
- `X-API-Key: <key>` — required when `NETGUARD_API_KEY` is set

Response `204`: No Content (successful removal)

Error Responses:
- `422 INVALID_IP` — invalid IP address format
- `404 NOT_FOUND` — IP not in whitelist

---

### 18. Get Statistics

**GET /statistics**

Aggregate detection statistics.

Response `200`:
```json
{
  "success": true,
  "data": {
    "total_events": 150,
    "events_by_severity": {
      "Low": 30,
      "Medium": 60,
      "High": 40,
      "Critical": 20
    },
    "events_by_attack_type": {
      "SYN Flood": 50,
      "Port Scan": 40,
      "SQL Injection": 25,
      "Brute Force": 20,
      "ARP Spoofing": 15
    },
    "active_blocks": 3,
    "total_blocked": 45,
    "packets_processed": 15234,
    "alerts_today": 12
  }
}
```

---

### 19. Get Rule Statistics

**GET /statistics/rules**

Per-rule detection counts and status.

Response `200`:
```json
{
  "success": true,
  "data": {
    "rules": [
      { "rule_id": "SYN_FLOOD_001", "attack_type": "SYN Flood", "count": 50, "enabled": true },
      { "rule_id": "PORT_SCAN_001", "attack_type": "Port Scan", "count": 40, "enabled": true },
      { "rule_id": "SQL_INJECTION_001", "attack_type": "SQL Injection", "count": 25, "enabled": true },
      { "rule_id": "BRUTE_FORCE_001", "attack_type": "Brute Force", "count": 20, "enabled": true },
      { "rule_id": "ARP_SPOOF_001", "attack_type": "ARP Spoofing", "count": 15, "enabled": true }
    ]
  }
}
```

---

### 20. Get Logs

**GET /logs**

Retrieve paginated system logs with optional filters.

Query Parameters:
| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | string | Filter by level: `INFO`, `WARNING`, `ERROR`, `CRITICAL`, `DEBUG` |
| `level` | string | Alias for `severity` |
| `date` | string | Filter by date (ISO 8601) |
| `module` | string | Filter by source module name |
| `attack_type` | string | Filter by attack type |
| `source_ip` | string | Filter by source IP |
| `limit` | int | Page size (default 50, max 500) |
| `offset` | int | Pagination offset (default 0) |

Response `200`:
```json
{
  "success": true,
  "data": {
    "logs": [
      {
        "id": 1,
        "timestamp": "2026-07-29T10:30:00Z",
        "level": "INFO",
        "module": "DetectionEngine",
        "event": "SYN_FLOOD_001",
        "message": "Threat detected: SYN Flood from 10.0.0.5 (confidence: 87%)"
      }
    ],
    "total": 500,
    "limit": 50,
    "offset": 0
  }
}
```

Error Responses:
- `422 VALIDATION_ERROR` — invalid severity level

---

### 21. Get Settings

**GET /settings**

Retrieve current system configuration.

Response `200`:
```json
{
  "success": true,
  "data": {
    "network_interface": "eth0",
    "syn_flood_threshold": 100,
    "syn_flood_window": 3,
    "port_scan_threshold": 20,
    "port_scan_window": 10,
    "brute_force_threshold": 10,
    "brute_force_window": 60,
    "block_duration": 120,
    "dashboard_refresh_interval": 1,
    "rules_enabled": {
      "syn_flood": true,
      "port_scan": true,
      "sql_injection": true,
      "brute_force": true,
      "arp_spoof": true
    }
  }
}
```

---

### 22. Update Settings

**PUT /settings**

Update system configuration settings. Only provided fields are updated.

Request Headers:
- `X-API-Key: <key>` — required when `NETGUARD_API_KEY` is set

Request Body (partial updates supported):
```json
{
  "syn_flood_threshold": 150,
  "block_duration": 300
}
```

Response `200`:
```json
{
  "success": true,
  "message": "Settings updated successfully.",
  "data": null
}
```

Error Responses:
- `400 VALIDATION_ERROR` — missing JSON body
- `422 VALIDATION_ERROR` — invalid value for one or more fields (includes field names in error message)
- `500 DATABASE_ERROR` — persist to config.yaml failed

Valid Ranges for Settings:
| Setting | Min | Max |
|---------|-----|-----|
| `syn_flood_threshold` | 1 | 10000 |
| `syn_flood_window` | 1 | 60 |
| `port_scan_threshold` | 1 | 1000 |
| `port_scan_window` | 1 | 60 |
| `brute_force_threshold` | 1 | 1000 |
| `brute_force_window` | 1 | 300 |
| `block_duration` | 1 | 86400 |
| `dashboard_refresh_interval` | 1 | 60 |

---

### 23. Incident Timeline

**GET /timeline/{event_id}**

Step-by-step incident timeline for a single detection event.

Response `200`:
```json
{
  "success": true,
  "data": {
    "timeline": [
      { "step_name": "Detected",  "timestamp": "2026-07-29T10:30:00Z", "description": "Attack detected by SYN_FLOOD_001", "status": "completed" },
      { "step_name": "Analyzed",  "timestamp": "2026-07-29T10:30:00.500Z", "description": "Explanation generated", "status": "completed" },
      { "step_name": "Blocked",   "timestamp": "2026-07-29T10:30:01Z", "description": "Source IP blocked", "status": "completed" },
      { "step_name": "Notified",  "timestamp": null, "description": "No notification sent", "status": "skipped" },
      { "step_name": "Reported",  "timestamp": null, "description": "No report generated", "status": "skipped" }
    ]
  }
}
```

Error Responses:
- `404 NOT_FOUND` — event ID not found

---

### 24. Analytics

**GET /analytics**

Hourly, daily, or weekly detection statistics for charts and dashboards.

Query Parameters:
| Parameter | Type | Description |
|-----------|------|-------------|
| `period` | string | `hourly` (24 h), `daily` (7 d, default), or `weekly` (4 w) |

Response `200`:
```json
{
  "success": true,
  "data": {
    "buckets": [
      { "bucket": "2026-07-29", "count": 12, "breakdown": { "SYN Flood": 8, "Port Scan": 4 } }
    ],
    "top_ips": [{ "source_ip": "10.0.0.5", "count": 8 }],
    "severity_counts": { "High": 10, "Medium": 2 },
    "protocol_counts": { "TCP": 12 },
    "total_events": 12,
    "blocked_count": 10,
    "detected_count": 2
  }
}
```

---

### 25. Export

**GET /export**

Export detection events as JSON, CSV, Markdown, or PDF.

Query Parameters:
| Parameter | Type | Description |
|-----------|------|-------------|
| `format` | string | `json`, `csv`, `markdown`, or `pdf` (required) |
| `severity` | string | Filter by severity |
| `attack_type` | string | Filter by attack type |
| `source_ip` | string | Filter by source IP |
| `date` | string | Filter by date (ISO 8601) |
| `search` | string | Free-text search |

Response: File download with appropriate `Content-Disposition` and MIME type.

Error Responses:
- `400 INVALID_EXPORT_FORMAT` — unknown format value
- `501` — PDF export not supported (missing optional dependency)

---

### 26. AI Security Assistant

**POST /ai-assistant**

Ask the AI security assistant a free-text question. Returns a contextual answer based on
current detections.

Request Headers:
- `X-API-Key: <key>` — required when `NETGUARD_API_KEY` is set

Request Body:
```json
{ "question": "What are the most common attacks today?" }
```

Response `200`:
```json
{
  "success": true,
  "data": { "answer": "You asked about: ..." }
}
```

Error Responses:
- `400 VALIDATION_ERROR` — missing `question` field

---

### 27. LAN Devices

**GET /lan-devices** _(alias: GET /devices)_

List all LAN devices discovered by the most recent ARP scan.

Response `200`:
```json
{
  "success": true,
  "data": {
    "devices": [
      { "ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "gateway" }
    ],
    "count": 1
  }
}
```

Error Responses:
- `503 SERVICE_UNAVAILABLE` — LAN scan service not initialised

---

**POST /lan-devices/refresh**

Invalidate the device cache and trigger a fresh ARP scan.

Request Headers:
- `X-API-Key: <key>` — required when `NETGUARD_API_KEY` is set

Response `200`: Same shape as `GET /lan-devices`.

---

### 28. Security Advisor

**GET /advisor**

Return contextual security advice based on the current health score and today's attack types.

Response `200`:
```json
{
  "health_score": 85,
  "advice": [ "Enable rate limiting on port 22.", "Review recent SYN Flood detections." ]
}
```

---

## Socket.IO Events

The server emits the following real-time events via Socket.IO:

| Event | Payload | Description |
|-------|---------|-------------|
| `new_threat` | `{ event_id, attack_type, source_ip, severity, confidence, timestamp, blocked }` | Emitted when a new threat is detected |
| `ip_blocked` | `{ ip, reason, expires_at }` | Emitted when an IP is blocked |
| `ip_unblocked` | `{ ip }` | Emitted when an IP is unblocked (manual or expired) |
| `live_stats` | `{ packets_per_second, active_threats, alerts_today }` | Emitted every second during monitoring |
| `monitoring_status` | `{ active: bool, interface: string }` | Emitted when monitoring starts or stops |

## Error Codes

| Code | Meaning |
|------|---------|
| `VALIDATION_ERROR` | Required fields missing or invalid |
| `UNAUTHORIZED` | X-API-Key header missing or invalid |
| `INVALID_IP` | IP address format validation failed |
| `INVALID_INTERFACE` | Network interface not found |
| `ALREADY_MONITORING` | Capture already active |
| `NOT_MONITORING` | No active capture to stop |
| `NOT_FOUND` | Requested resource not found |
| `BLOCK_FAILED` | iptables command execution failed |
| `DATABASE_ERROR` | Database operation failed |
| `SERVICE_UNAVAILABLE` | Internal service dependency unavailable |
| `UNKNOWN_ERROR` | Unexpected internal error |
