# API Specification

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

Document ID: NG-API-001

API Version: v1

Protocol: HTTP/REST

Data Format: JSON

---

# Purpose

This document defines the REST API contract for NetGuard.

The API is responsible for communication between:

- Detection Engine
- Prevention Engine
- Logging Service
- Dashboard
- Future Mobile/Desktop Clients

All responses use JSON.

---

# Base URL

http://localhost:5000/api/v1

---

# API Design Principles

- RESTful architecture
- Stateless requests
- JSON request/response
- Consistent status codes
- Standardized error responses
- Future authentication support

---

# Standard Response Format

Success

```json
{
  "success": true,
  "message": "Operation completed successfully.",
  "data": {}
}
```

Error

```json
{
  "success": false,
  "message": "Validation failed.",
  "error": {
    "code": "VALIDATION_ERROR",
    "details": "Missing source IP"
  }
}
```

---

# HTTP Status Codes

| Code | Meaning |
|------|---------|
|200|Success|
|201|Created|
|204|No Content|
|400|Bad Request|
|401|Unauthorized (Future)|
|403|Forbidden|
|404|Not Found|
|409|Conflict|
|422|Validation Error|
|500|Internal Server Error|

---

# Health Endpoints

## GET /health

Purpose

Check backend availability.

Response

```json
{
  "status":"healthy",
  "version":"1.0.0",
  "uptime":"02:14:31"
}
```

---

## GET /status

Returns

```json
{
  "monitoring": true,
  "interface": "eth0",
  "packets_processed": 18322,
  "active_blocks": 2
}
```

---

# Monitoring Endpoints

## POST /monitor/start

Purpose

Start packet monitoring.

Request

```json
{
  "interface":"eth0"
}
```

Response

```json
{
  "success":true,
  "message":"Monitoring started."
}
```

---

## POST /monitor/stop

Stops packet monitoring.

Response

```json
{
  "success":true
}
```

---

## GET /monitor/interfaces

Returns all available network interfaces.

Response

```json
{
 "interfaces":[
   "eth0",
   "wlan0",
   "lo"
 ]
}
```

---

# Detection Endpoints

## POST /detect

Internal endpoint used by Detection Engine.

Request

```json
{
  "attack_type":"SYN Flood",
  "source_ip":"192.168.1.5",
  "destination_ip":"192.168.1.10",
  "severity":"High",
  "confidence":97,
  "rule":"SYN_FLOOD_001",
  "evidence":{
      "packet_count":243,
      "window_seconds":3
  }
}
```

Response

```json
{
  "event_id":"EVT-001023",
  "blocked":true
}
```

---

## GET /detections

Returns all detections.

Query Parameters

severity

attack_type

source_ip

date

Example

```
GET /detections?severity=High
```

---

## GET /detections/{event_id}

Returns one detection.

Example Response

```json
{
  "event_id":"EVT-001023",
  "attack_type":"SYN Flood",
  "severity":"High",
  "confidence":97,
  "blocked":true,
  "timestamp":"2026-08-01T10:15:42Z"
}
```

---

# Blocking Endpoints

## POST /block

Blocks an IP.

Request

```json
{
 "ip":"192.168.1.55",
 "duration":120,
 "reason":"SYN Flood"
}
```

Response

```json
{
 "blocked":true
}
```

---

## POST /unblock

Request

```json
{
 "ip":"192.168.1.55"
}
```

Response

```json
{
 "success":true
}
```

---

## GET /blocked

Returns active blocked IPs.

Example

```json
[
 {
   "ip":"192.168.1.44",
   "expires_in":74
 }
]
```

---

# Whitelist API

## GET /whitelist

Returns whitelist.

---

## POST /whitelist

Request

```json
{
 "ip":"192.168.1.15",
 "description":"School Router"
}
```

---

## DELETE /whitelist/{ip}

Removes whitelist entry.

---

# Dashboard API

## GET /dashboard

Returns complete dashboard data.

Example

```json
{
 "monitoring":true,
 "packets":45391,
 "alerts":14,
 "blocked_ips":3,
 "traffic_rate":248,
 "top_attack":"Port Scan"
}
```

---

## GET /dashboard/live

Returns live statistics.

Example

```json
{
 "packets_per_second":148,
 "active_threats":2,
 "alerts_today":31
}
```

---

# Statistics API

## GET /statistics

Response

```json
{
 "packets_processed":845219,
 "detections":72,
 "blocks":41,
 "false_positives":2
}
```

---

## GET /statistics/rules

Returns rule statistics.

Example

```json
[
 {
   "rule":"SYN Flood",
   "count":12
 },
 {
   "rule":"Port Scan",
   "count":19
 }
]
```

---

# Evidence API

## GET /evidence/{event_id}

Returns explanation.

Example

```json
{
 "rule":"SYN_FLOOD_001",
 "severity":"High",
 "summary":"Detected 243 SYN packets within 3 seconds.",
 "recommendation":"IP temporarily blocked for 120 seconds."
}
```

---

# Logs API

## GET /logs

Filters

severity

date

module

attack_type

source_ip

---

## GET /logs/{log_id}

Returns one log.

---

# Configuration API

## GET /settings

Returns application configuration.

---

## PUT /settings

Updates configuration.

Example

```json
{
 "block_duration":120,
 "syn_threshold":100,
 "dashboard_refresh":1
}
```

---

# Error Codes

| Code | Description |
|------|-------------|
|INVALID_INTERFACE|Interface not found|
|RULE_NOT_FOUND|Detection rule missing|
|INVALID_IP|IP format invalid|
|BLOCK_FAILED|Firewall command failed|
|DATABASE_ERROR|Database unavailable|
|VALIDATION_ERROR|Input validation failed|
|UNKNOWN_ERROR|Unexpected exception|

---

# Validation Rules

IP Address

- Must be valid IPv4 or IPv6

Severity

Allowed

- Low
- Medium
- High
- Critical

Confidence

0–100

Duration

1–3600 seconds

---

# Rate Limiting (Future)

Dashboard

10 requests/sec

Logs

5 requests/sec

Statistics

20 requests/sec

---

# Authentication (Future)

Current Version

No authentication

Future

JWT

API Keys

RBAC

---

# API Versioning

Current

v1

Future

v2

Breaking changes require a new version.

---

# OpenAPI Compatibility

The API should be structured so an OpenAPI 3.1 specification can be generated automatically in the future.

---

# Acceptance Criteria

✓ All endpoints return JSON.

✓ Standard response format is consistent.

✓ Proper HTTP status codes are used.

✓ Validation is enforced.

✓ Dashboard receives live updates.

✓ Internal modules communicate through the API contract.

---

End of Document