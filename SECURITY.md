# Security Policy

## Supported Versions

| Version | Security fixes |
|---------|----------------|
| 1.0.x   | Yes            |

---

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email the maintainers at the address in the repository profile with:
- A description of the vulnerability and the affected component
- Steps to reproduce (proof-of-concept if possible)
- Potential impact in your assessment

You will receive an acknowledgement within 72 hours. We aim to issue a fix within
14 days for critical issues and 30 days for other severity levels.

---

## Threat Model

NetGuard runs on a single Linux machine with root privileges and direct access to
the network interface and iptables. The threat model below documents what NetGuard
protects against and what it does not.

### Assets

| Asset | Description |
|-------|-------------|
| Monitored network | Traffic on the interface NetGuard captures |
| SQLite database | Events, blocks, whitelist, settings, logs |
| iptables ruleset | The system firewall NetGuard manages |
| Configuration | `config/config.yaml` and `.env` |
| Log files | `logs/system.log`, `detections.log`, `errors.log` |

### Threats Mitigated by NetGuard

| Threat | Mitigation |
|--------|------------|
| TCP SYN flood | Auto-block via iptables DROP within seconds of threshold breach |
| Port reconnaissance | Auto-block; alert with scanned port list |
| SQL injection (HTTP) | Alert; auto-block; matched pattern in evidence |
| Brute-force login (SSH/HTTP/FTP) | Alert; auto-block |
| ARP spoofing / MitM | Alert (blocking ARP-level attacks via IP is limited; see Known Limitations) |
| Repeated attacker | Whitelist check prevents blocking trusted IPs; cooldown prevents alert storms |

### Threats Outside NetGuard's Scope

- Encrypted traffic inspection (TLS/HTTPS payloads are not decrypted)
- Application-layer auth (NetGuard does not inspect HTTP response codes)
- IPv6 firewall management (iptables is IPv4-only; ip6tables is not called)
- Host intrusion detection (file integrity, process monitoring)
- Distributed attacks from many source IPs below per-IP thresholds
- Physical network access
- Attacks that originate from whitelisted IPs

---

## Security Architecture

### Privilege Separation

NetGuard requires root to:
1. Open a raw socket for Scapy packet capture
2. Execute `iptables` commands via `subprocess.run()`

The Flask API itself does not require elevated privileges but runs in the same
process. In production, consider using `CAP_NET_ADMIN` and `CAP_NET_RAW`
capabilities instead of full root.

### Input Validation

All IP addresses are validated with `ipaddress.ip_address()` before any:
- Database insert
- iptables command execution
- Whitelist operation

All iptables commands use `shlex.quote(ip)` to prevent shell injection.

Integer settings (thresholds, durations) are range-checked by
`ConfigurationManager.validate_settings()` before application.

### Secrets

- `SECRET_KEY` is the Flask session secret. Change it before any production or
  public deployment. The default value `change-me-before-production` is
  intentionally obvious.
- The `.env` file is excluded from version control via `.gitignore`.
- The `LoggingEngine` redacts any metadata key matching `password`, `passwd`,
  `secret`, `token`, `private_key`, `api_key`, `auth`, or `credential` before
  writing to log files or the database.

### API Security

- CORS is enabled for all `/api/*` origins. Restrict this in production to your
  dashboard origin.
- There is no authentication on the REST API. In production, place NetGuard behind
  a reverse proxy (nginx) with HTTP Basic Auth or mutual TLS.
- All API responses use a standard envelope; internal error details are not
  leaked to clients (services log details server-side).

### Database

- SQLite WAL mode is enabled for concurrent read performance.
- Foreign key constraints are enforced at the SQLite level.
- The database file is local to the server; no remote DB connections.

---

## Known Limitations

| Limitation | Impact | Notes |
|------------|--------|-------|
| No TLS inspection | SQL injection in HTTPS traffic is invisible | Would require SSL bump proxy |
| TCP-level brute-force proxy | False positives on high-traffic auth endpoints | Connection count, not actual auth failures |
| ARP block has limited effect | ARP spoofing detection cannot be stopped by IP-layer iptables rules | Alert operators; consider static ARP entries or 802.1X |
| Single-machine deployment | No distributed correlation | Per-IP thresholds can be bypassed by low-rate distributed attacks |
| No IPv6 iptables | IPv6 attackers are detected but not blocked | Extend with `ip6tables` if IPv6 is used |
| No API authentication | Dashboard is accessible to anyone on the network | Add a reverse proxy with auth in production |
| Root required | Process runs as root | Use Linux capabilities as a hardening step |

---

## API Key Authentication

### Model

A single shared secret (`NETGUARD_API_KEY` env var) is compared against the
`X-API-Key` request header using `hmac.compare_digest` (constant-time comparison,
preventing timing-oracle attacks). The check is enforced by the `check_api_key()`
`before_request` hook registered in `create_app()`, after input validation and rate
limiting.

Authentication is required for all **mutating** methods (POST, PUT, DELETE, PATCH).
Read-only GET requests are open by default; set `REQUIRE_AUTH_FOR_READS=true` to
require auth on GET as well (see SocketIO Exclusion section for the one exception).

### Dev Mode (No Key Configured)

When `NETGUARD_API_KEY` is **not set**, `check_api_key()` returns `None` and all
requests pass through. This keeps local development frictionless. There is no
placeholder or dummy key that grants access — absence of the env var is the explicit
dev-mode signal.

### Trade-offs

| Property | Value |
|----------|-------|
| Key rotation | Manual (restart required) |
| Per-client scoping | None — single shared secret |
| Revocation | Remove/change env var and restart |
| Brute-force resistance | Rate limiter + constant-time compare |

This model is appropriate for a single-server dev/demo deployment. For production at
scale, replace with a secrets manager and per-client tokens.

---

## SocketIO Exclusion

SocketIO upgrade handshakes arrive as GET requests to `/socket.io/`. Because
`REQUIRE_AUTH_FOR_READS` defaults to `false`, GET requests pass through the auth
hook without requiring a key — which means SocketIO connections are never blocked
by the authentication middleware.

Even when `REQUIRE_AUTH_FOR_READS=true`, the `check_api_key()` hook explicitly
skips paths that start with `/socket.io/`, so the real-time dashboard feed remains
available regardless of the auth configuration.

**Trade-off:** Any client that can reach the server can subscribe to the SocketIO
event stream (threat alerts, IP blocks) without presenting an API key. This is
intentional for the current dev/demo deployment model. In production, place
NetGuard behind a reverse proxy with WebSocket authentication (e.g., cookie-based
session or mutual TLS) if the SocketIO feed should be restricted.

---

## Proxy Trust Model

### `TRUST_PROXY_HEADERS` Flag

The `RateLimiter._client_ip()` method determines which IP to rate-limit per
request. Its behaviour is controlled by the `TRUST_PROXY_HEADERS` environment
variable (default: `false`):

| Value | Behaviour |
|-------|-----------|
| `false` (default) | Always uses `request.remote_addr` — the TCP peer address |
| `true` | Reads the leftmost IP from `X-Forwarded-For` header |

### When to Enable

Set `TRUST_PROXY_HEADERS=true` **only** when NetGuard sits behind a reverse proxy
(nginx, HAProxy, etc.) that **overwrites** (not appends to) the `X-Forwarded-For`
header with the real client IP. In that topology, `remote_addr` is always the
proxy's address, and reading `X-Forwarded-For` gives the actual client.

### Spoofing Risk

If `TRUST_PROXY_HEADERS=true` is set without a proper sanitising proxy in front,
any client can forge `X-Forwarded-For: 1.2.3.4` in their request and effectively
choose their own rate-limit identity. This allows a single attacker to bypass
per-IP rate limiting entirely. **Do not enable this flag on a server directly
exposed to the internet.**

See `DEPLOYMENT.md` for specific proxy configuration guidance.

---

## Private IP Block Guard

### Protected Ranges

The `PreventionEngine.block_ip()` method refuses to add an iptables DROP rule for
any address that falls in a protected range, unless explicitly overridden. Protected
ranges are:

| Range | Description |
|-------|-------------|
| `10.0.0.0/8` | RFC 1918 private |
| `172.16.0.0/12` | RFC 1918 private |
| `192.168.0.0/16` | RFC 1918 private |
| `127.0.0.0/8` | IPv4 loopback |
| `169.254.0.0/16` | Link-local |
| `224.0.0.0/4` | IPv4 multicast |
| `::1/128` | IPv6 loopback |
| `fe80::/10` | IPv6 link-local |
| `ff00::/8` | IPv6 multicast |

In addition, any IP that matches one of the server's own interface addresses
(detected via `psutil.net_if_addrs()`) is refused regardless of whether it
falls in the ranges above.

When a block is refused, a WARNING is logged and `block_ip()` returns `False`.
No iptables rule is inserted and no block record is written to the database.

### Override

Pass `allow_private_block=True` to `block_ip()` to bypass both checks. This kwarg
is intended exclusively for integration tests and administrative scripts that
intentionally target private-range IPs in a controlled environment. Normal
detection-engine flow never passes this flag.
