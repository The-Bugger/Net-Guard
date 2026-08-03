# NetGuard Architecture

This document describes the internal design of NetGuard IDPS at the component,
thread, and data-flow levels.

---

## Table of Contents

1. [Overall Architecture](#overall-architecture)
2. [Threading Model](#threading-model)
3. [Packet Flow](#packet-flow)
4. [Detection Pipeline](#detection-pipeline)
5. [API Flow](#api-flow)
6. [Database Flow](#database-flow)
7. [Service Dependencies](#service-dependencies)
8. [Key Design Decisions](#key-design-decisions)

---

## Overall Architecture

```mermaid
graph TB
    subgraph Capture["Capture Layer"]
        NIC["Network Interface"]
        CE["CaptureEngine\n(Packet_Capture_Thread)"]
        PD["PacketDecoder"]
    end
    subgraph Detection["Detection Layer"]
        PQ["packet_queue\n(maxsize=10 000)"]
        DE["DetectionEngine\n(Detection_Thread)"]
        R1["SynFloodRule"]
        R2["PortScanRule"]
        R3["SqlInjectionRule"]
        R4["BruteForceRule"]
        R5["ArpSpoofRule"]
        R6["IcmpFloodRule"]
        R7["SlowHttpRule"]
        R8["DnsTunnelRule"]
    end
    subgraph Response["Response Layer"]
        EE["ExplainabilityEngine"]
        PE["PreventionEngine"]
        LE["LoggingEngine\n(Logging_Thread)"]
        ET["ExpiryThread"]
        EQ["event_queue"]
    end
    subgraph Persistence["Persistence Layer"]
        DB[(SQLite\nnetguard.db)]
        LF["logs/\nsystem.log\ndetections.log\nerrors.log"]
    end
    subgraph API["API Layer"]
        FLASK["Flask REST API"]
        SIO["Flask-SocketIO"]
    end
    subgraph UI["UI Layer"]
        DASH["Browser Dashboard\nVanilla JS + Chart.js"]
    end

    NIC -->|raw packets| CE
    CE --> PD --> PQ
    PQ --> DE
    DE --> R1 & R2 & R3 & R4 & R5 & R6 & R7 & R8
    R1 & R2 & R3 & R4 & R5 & R6 & R7 & R8 -->|ThreatEvent| DE
    DE --> EE --> PE
    EE --> EQ --> LE
    LE --> DB & LF
    PE -->|iptables -I| NIC
    ET -->|iptables -D| NIC
    ET --> DB
    DE -->|SocketIO| SIO
    PE -->|SocketIO| SIO
    FLASK <--> DB
    SIO <-->|WebSocket| DASH
    FLASK <-->|HTTP| DASH
```


---

## Threading Model

NetGuard runs a main thread plus these background threads. All inter-thread
communication is via `queue.Queue` (packet_queue, event_queue) or
`threading.Event` (stop signals).

| Thread | Owner | Purpose |
|--------|-------|---------|
| `Packet_Capture_Thread` | CaptureEngine | Scapy sniff loop → decode → packet_queue |
| `Detection_Thread` | DetectionEngine | packet_queue → rules → on_event callback |
| `Logging_Thread` | LoggingEngine | event_queue → SQLite + log files |
| `Expiry_Thread` | ExpiryThread | Poll DB every 5s, remove expired blocks |
| `SigmaWatcher` | DetectionEngine | Hot-reload Sigma rules on file mtime change |
| `ThreatIntelWorker` | ThreatIntelService | Background feed refresh |
| Attack-lab session threads | AttackLabService | One daemon thread per running simulation |
| APScheduler pool (10) | SchedulerService | Scheduled attack jobs (when started) |
| API thread(s) | Flask-SocketIO | HTTP + WebSocket (eventlet on Linux, threading on Windows) |

```mermaid
graph LR
    subgraph Main["Main Thread (startup)"]
        INIT["Initialize all services\nCreate Flask app\nStart background threads"]
    end
    subgraph PCT["Packet_Capture_Thread"]
        SNIFF["Scapy sniff() loop\n0.5s timeout bursts"]
        DEC["PacketDecoder.decode()"]
        SNF["packet_queue.put_nowait()"]
    end
    subgraph DT["Detection_Thread"]
        DGET["packet_queue.get(timeout=1s)"]
        DRULE["Run all 8 built-in rules\n+ Sigma/YARA matching"]
        DCALL["on_event callback"]
    end
    subgraph LT["Logging_Thread"]
        LGET["event_queue.get(timeout=1s)"]
        LPERS["Persist to SQLite + log files"]
    end
    subgraph ET2["Expiry_Thread"]
        EPOLL["Poll DB every 5s\nget_expired()"]
        EREM["iptables -D\nset_inactive()"]
    end
    subgraph AT["API Thread(s)"]
        FLASK2["Flask HTTP + SocketIO"]
    end

    INIT --> PCT & DT & LT & ET2 & AT
    SNIFF --> DEC --> SNF
    SNF -->|packet_queue| DGET
    DRULE --> DCALL
    DCALL -->|event_queue| LGET
    LGET --> LPERS
    EPOLL --> EREM
```

### Thread Safety

| Resource | Protection |
|----------|------------|
| `packet_queue` | `queue.Queue` (thread-safe by design) |
| `event_queue` | `queue.Queue` (thread-safe by design) |
| `WhitelistManager._ip_set` | `threading.RLock` |
| `MonitoringState` fields | `threading.Lock` (via `increment_packets`) |
| `StatsService._pkt_timestamps` | `threading.Lock` |
| `ConfigurationManager._settings` | `threading.Lock` |
| SQLite connections | `check_same_thread=False` + session-per-operation |


---

## Packet Flow

```mermaid
sequenceDiagram
    participant NIC as Network Interface
    participant CE as CaptureEngine
    participant PD as PacketDecoder
    participant PQ as packet_queue
    participant DE as DetectionEngine
    participant Rule as Detection Rule (×8)
    participant EE as ExplainabilityEngine
    participant PE as PreventionEngine
    participant LE as LoggingEngine
    participant EQ as event_queue
    participant DB as SQLite
    participant SIO as SocketIO

    NIC->>CE: raw Scapy packet
    CE->>PD: decode(raw_pkt)
    alt decode success
        PD-->>CE: Packet dataclass
        CE->>PQ: put_nowait(Packet)
    else decode failure
        PD-->>CE: None
        CE->>CE: log WARNING to system.log
    end

    PQ->>DE: get(timeout=1.0)
    loop for each enabled rule
        DE->>Rule: process_packet(Packet)
        DE->>Rule: evaluate()
        alt threshold exceeded
            Rule-->>DE: ThreatEvent
            DE->>DE: _should_emit() cooldown check
            alt emit allowed
                DE->>EE: explain(ThreatEvent)
                EE-->>DE: Explanation
                DE->>PE: handle_event(ThreatEvent, Explanation)
                PE->>DB: INSERT blocked_ips
                PE->>SIO: emit("ip_blocked")
                DE->>DB: INSERT events
                DE->>EQ: put((event, explanation))
                DE->>SIO: emit("new_threat")
            end
        else no detection
            Rule-->>DE: None
        end
    end

    EQ->>LE: get(timeout=1.0)
    LE->>DB: INSERT system_logs
    LE->>LE: write to detections.log
```


---

## Detection Pipeline

Each detection rule implements the `BaseRule` interface:

```mermaid
flowchart TD
    PKT["Packet arrives on Detection_Thread"]
    CHK{"Rule enabled?\n(rule.enabled AND\nnot in _disabled_rules)"}
    SKIP["Skip rule"]
    PP["rule.process_packet(packet)\nUpdate internal counters"]
    EV["rule.evaluate()\nCheck threshold"]
    NONE{"Returns None?"}
    COOL{"_should_emit(event)?\n(cooldown + severity check)"}
    DROP["Drop event\n(suppressed by cooldown)"]
    EMIT["on_event callback\n→ explain → prevent → log → SocketIO"]
    ERR["Exception?\nDisable rule for session\nLog ERROR"]

    PKT --> CHK
    CHK -- No --> SKIP
    CHK -- Yes --> PP
    PP --> EV
    EV -- Exception --> ERR
    EV --> NONE
    NONE -- Yes --> PKT
    NONE -- No --> COOL
    COOL -- No --> DROP
    COOL -- Yes --> EMIT
```

### Cooldown Logic

The `_should_emit()` method in `DetectionEngine` prevents alert storms:

- Default cooldown: **10 seconds** per `(source_ip, rule_name)` pair
- Within the cooldown window, a new event is emitted **only if** its severity
  is strictly higher than the previously emitted severity
- Example: Medium at t=0 → suppressed at t=3 (same severity) → High at t=7 is
  emitted (escalation) → suppressed at t=9 (same High) → cooldown expires at t=10

### Rule Exception Isolation

If `process_packet()` or `evaluate()` raises an uncaught exception, the
DetectionEngine:
1. Logs the exception at ERROR level with `exc_info=True`
2. Adds the rule's `rule_name` to `_disabled_rules`
3. Continues processing all other rules
4. Exposes the disabled rule name via `disabled_rule_names` property
5. Restores the rule on the next `reload_rules()` call

### Active Detection Rules

| Rule | ID | Attack Type | Phase |
|------|----|-------------|-------|
| `SynFloodRule` | `SYN_FLOOD_001` | TCP SYN Flood | Baseline |
| `PortScanRule` | `PORT_SCAN_001` | Port Reconnaissance | Baseline |
| `SqlInjectionRule` | `SQL_INJECT_001` | SQL Injection (HTTP) | Baseline |
| `BruteForceRule` | `BRUTE_FORCE_001` | Brute Force Login | Baseline |
| `ArpSpoofRule` | `ARP_SPOOF_001` | ARP Spoofing / MitM | Baseline |
| `IcmpFloodRule` | `ICMP_FLOOD_001` | ICMP Flood / Smurf Attack | Phase B |
| `SlowHttpRule` | `SLOW_HTTP_001` | Slow HTTP / Slowloris | Phase B |
| `DnsTunnelRule` | `DNS_TUNNEL_001` | DNS Tunneling (heuristic) | Phase B |

### Sigma and YARA Rules

In addition to the 8 built-in Python rules, DetectionEngine loads:

- **Sigma rules** — YAML files from `rules/sigma/` (or `ai.sigma_rules_dir`
  config override). Matched against serialised events via a lightweight
  condition evaluator (not full pySigma algebra). A `SigmaWatcher` daemon
  thread polls file mtimes and hot-reloads on change.
- **YARA rules** — compiled from the configured directory and matched against
  packet payloads when the `yara` package is available.

---

## API Flow

```mermaid
flowchart LR
    CLIENT["HTTP Client\nor Browser"]
    FLASK3["Flask Route Handler\n(blueprint)"]
    VAL["Input Validation\nvalidators.py"]
    DEP["dependencies.get_*()\nService Registry"]
    SVC["Service Layer"]
    REPO["Repository Layer"]
    DB2[(SQLite)]
    RESP["response.py\nJSON envelope"]

    CLIENT -->|HTTP request| FLASK3
    FLASK3 --> VAL
    VAL -- invalid --> RESP
    VAL -- valid --> DEP
    DEP --> SVC
    SVC --> REPO --> DB2
    DB2 --> REPO --> SVC --> RESP
    RESP -->|HTTP response| CLIENT
```

Route handlers are intentionally thin. The pattern is:

1. Parse and validate request input
2. Retrieve the service via `dependencies.get_*()`
3. Call one service method
4. Return `success_response()` or `error_response()` from `response.py`

No business logic lives in route handlers.

### API Surface

28 blueprints are registered under `/api/v1` in
[backend/api/__init__.py](../backend/api/__init__.py):

| Group | Blueprints |
|-------|-----------|
| Core IDPS | health, monitor, detection, block, blocks_v2, whitelist, evidence |
| Visibility | dashboard, stats, logs, timeline, analytics, map, hunt |
| Config & auth | settings, auth, audit, reset, plugins |
| Reporting | export, reports, advisor, ai, ai_assistant |
| Lab & LAN | lab, scheduler, lan_devices |

### Before-Request Chain

Incoming HTTP requests pass through three `before_request` hooks (registered in
`create_app()`) before reaching any route handler:

| Order | Hook | Purpose |
|-------|------|---------|
| 1 | `sanitise_and_validate()` | Reject oversized or malformed input fields |
| 2 | `RateLimiter.check()` | Rate-limit per client IP (gated on `TRUST_PROXY_HEADERS`) |
| 3 | `ApiKeyAuth.check()` | Authenticate mutating requests via `X-API-Key` header |

After the route handler returns, `add_security_headers()` runs as an
`after_request` hook and appends CSP, HSTS (HTTPS only), and Permissions-Policy
response headers.

---

## Database Flow

```mermaid
flowchart TD
    MAIN["main.py startup"]
    INIT2["initialize_db()\nCreate tables + seed defaults"]
    SF["session_factory\ncontextmanager"]
    REPO2["Repository classes\nEventRepository\nBlockRepository\nWhitelistRepository\nLogRepository\nSettingsRepository"]
    ORM["SQLAlchemy ORM\nSession per operation"]
    DB3[(SQLite\nWAL mode)]

    MAIN --> INIT2 --> DB3
    MAIN --> SF
    SF --> REPO2
    REPO2 --> ORM --> DB3
```

Each repository receives `session_factory` (a context manager) as a
constructor argument. This keeps the session lifecycle inside the repository
and makes it straightforward to swap the session factory in tests.

---

## Service Dependencies

All services are instantiated in `main.py` and registered by name in
`backend/api/dependencies.py`. Route blueprints retrieve them via
`dependencies.get_*()` accessors. Services do not import each other — they
communicate via constructor injection, callbacks (`on_event`, `socketio_emit`),
or the shared queues.

### Core pipeline (wired in main.py)

```mermaid
graph TD
    MAIN2["main.py"]
    CM["ConfigurationManager"]
    WM["WhitelistManager"]
    LE2["LoggingEngine"]
    PE2["PreventionEngine"]
    DE2["DetectionEngine"]
    EE2["ExplainabilityEngine"]
    MS["MonitorService"]
    ET3["ExpiryThread"]
    SS["StatsService"]
    CE2["CaptureEngine"]
    BM["BlockManager"]

    MAIN2 --> CM & WM & LE2 & PE2 & DE2 & EE2 & MS & ET3 & SS & CE2 & BM

    PE2 --> WM
    PE2 --> LE2
    EE2 --> WM
    DE2 --> CM
    MS --> CE2
    MS --> DE2
    MS --> LE2
    ET3 --> LE2
    SS --> MS
    BM --> WM
    BM --> LE2
```

### Extended services (registered in dependencies.py)

| Service | Depends on | Purpose |
|---------|-----------|---------|
| `AuditService` | session_factory | Audit trail of mutating API calls |
| `AuthService` | settings_repo, audit_service | API-key / login authentication |
| `AIExplainService` | — | LLM-assisted event explanation |
| `LanScanService` | — | LAN device discovery |
| `SecurityAdvisor` | — | Posture recommendations |
| `ComplianceReporter` | — | Compliance report generation |
| `ThreatSimulator` | whitelist set | Synthetic attack traffic generator |
| `AttackLabService` | packet_queue, threat_simulator | Lab sessions; daemon thread per session |
| `GeoIPEngine` | settings_repo | IP geolocation with cache + TTL |
| `ThreatIntelService` | event_repo, settings_repo, log_engine | Feed refresh on a daemon worker thread |
| `AnomalyEngine` | — | Statistical baseline anomaly detection |
| `PluginRegistry` | settings_repo | Third-party widget/plugin loading |
| `ExportService` | event_repo | Data export (CSV/JSON) |
| `SOAREngine` | settings_repo, log_engine, geoip_engine | Multi-channel alerting / SIEM forwarding |
| `SchedulerService` | attack_lab_service, log_engine | Scheduled attack jobs via APScheduler (SQLite jobstore) |

`SchedulerService` requires two extra startup steps in `main.py`:
`wire_session(session_factory)` after DB init, then `start()` in the
`__main__` block to launch APScheduler. Both scheduler and SOAR routes return
503 when the service is not registered.

---

## Key Design Decisions

### Why eventlet? (now platform-conditional)

Flask-SocketIO requires an async worker to serve WebSocket connections alongside
HTTP. On Linux, eventlet provides cooperative multitasking via green threads and
monkey-patches the standard library at startup — which is why `monkey_patch()`
must run before any other import.

On Windows, eventlet's patching of select/socket corrupts Scapy's pcap fd
handling and causes `monitor/start` to hang, so `main.py` forces
`SOCKETIO_ASYNC_MODE=threading` there instead. The same fallback applies on
Python 3.14+ where eventlet compatibility is not yet assumed.

### Why queue.Queue for inter-thread communication?

Direct calls from CaptureEngine to DetectionEngine would couple the two threads
and slow packet capture if detection is slow. The queue decouples them: capture
can run at full speed and detection processes at its own rate. The `maxsize=10000`
prevents unbounded memory growth under heavy load (packets are dropped with a WARNING
if the queue is full).

### Why SQLite?

Single-machine deployment, no multi-process writes, hackathon scope. WAL mode
provides good concurrent read performance for the dashboard queries while
detection writes happen. Replacing with PostgreSQL would require changing only
the `DATABASE_URL` and the `create_engine` call.

### Why separate log files per category?

`system.log` is for operations teams monitoring startup/shutdown and interface
changes. `detections.log` is for security analysts reviewing attack timelines.
`errors.log` is for developers debugging failures. Keeping them separate avoids
noisy cross-contamination and allows different log rotation or alerting policies.
