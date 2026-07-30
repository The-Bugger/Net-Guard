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
