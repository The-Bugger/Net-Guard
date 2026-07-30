# NetGuard Deployment Guide

---

## Table of Contents

1. [Local Development](#local-development)
2. [Production Linux](#production-linux)
3. [systemd Service](#systemd-service)
4. [Environment Variables](#environment-variables)
5. [iptables Setup](#iptables-setup)
6. [Reverse Proxy (nginx)](#reverse-proxy-nginx)
7. [Monitoring and Alerting](#monitoring-and-alerting)
8. [Upgrades](#upgrades)

---

## Local Development

Requires Python 3.11+, a virtual environment, and any OS (Linux preferred for
full blocking capability).

```bash
git clone https://github.com/Midvaley/midvalleyproject.git
cd midvalleyproject
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -c "from database.init_db import initialize_db; initialize_db()"
cp .env.example .env
# Edit .env as needed

# Run without root (iptables calls fail gracefully — detection still works)
python backend/main.py
```

Dashboard: `http://localhost:5000`

---

## Production Linux

### Prerequisites

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip iptables

# Verify iptables is available
sudo iptables -L INPUT -n
```

### Installation

```bash
# Create a dedicated user (do not run as root in production if avoidable)
# NetGuard still needs CAP_NET_ADMIN and CAP_NET_RAW; see capabilities section
sudo useradd -r -s /bin/false -d /opt/netguard netguard

# Clone to /opt/netguard
sudo git clone https://github.com/Midvaley/midvalleyproject.git /opt/netguard
cd /opt/netguard

# Create virtual environment
sudo python3.11 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt

# Initialize database
sudo .venv/bin/python -c "from database.init_db import initialize_db; initialize_db()"

# Set up environment file
sudo cp .env.example .env
sudo nano .env   # Set SECRET_KEY, LOG_LEVEL, etc.

# Set ownership
sudo chown -R netguard:netguard /opt/netguard
```

### Linux Capabilities (hardening alternative to root)

Instead of running as root, grant only the required capabilities:

```bash
# Grant raw socket + net admin to the Python binary in the venv
sudo setcap 'cap_net_admin+ep cap_net_raw+ep' /opt/netguard/.venv/bin/python3.11

# Verify
getcap /opt/netguard/.venv/bin/python3.11
# Expected: /opt/netguard/.venv/bin/python3.11 = cap_net_admin,cap_net_raw+ep
```

With capabilities set, NetGuard can be run as the `netguard` user without sudo.

---

## systemd Service

Create `/etc/systemd/system/netguard.service`:

```ini
[Unit]
Description=NetGuard IDPS — Intrusion Detection and Prevention System
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=netguard
Group=netguard
WorkingDirectory=/opt/netguard
EnvironmentFile=/opt/netguard/.env
ExecStart=/opt/netguard/.venv/bin/python backend/main.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netguard

# Resource limits
LimitNOFILE=65536
MemoryMax=512M

# Security hardening (incompatible with raw socket capability — adjust as needed)
# NoNewPrivileges=yes
# ProtectSystem=strict
# ReadWritePaths=/opt/netguard

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable netguard
sudo systemctl start netguard

# Check status
sudo systemctl status netguard

# View logs
sudo journalctl -u netguard -f

# Restart after config change
sudo systemctl restart netguard
```

---

## Environment Variables

See [`.env.example`](../.env.example) for full documentation.

Minimum required for production:

```bash
FLASK_ENV=production
SECRET_KEY=<random 32+ character string>
DATABASE_URL=sqlite:////opt/netguard/database/netguard.db
LOG_LEVEL=INFO
FLASK_HOST=127.0.0.1   # Listen on loopback only; nginx proxies externally
FLASK_PORT=5000
```

Generate a strong SECRET_KEY:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## iptables Setup

NetGuard manages iptables rules dynamically. You should preserve baseline
rules that NetGuard should not interfere with.

### Verify iptables is functional

```bash
sudo iptables -L INPUT -n --line-numbers
```

### Recommended baseline INPUT chain

```bash
# Allow established connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow SSH from admin subnet only (replace 10.0.0.0/8 with your network)
sudo iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT

# Allow NetGuard dashboard from admin subnet
sudo iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 5000 -j ACCEPT

# Default policy: drop unknown
sudo iptables -P INPUT DROP
```

### Persist iptables rules across reboots

```bash
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

### How NetGuard modifies iptables

NetGuard uses only these two command templates:

```bash
# Block:   inserts at position 1 (top of chain)
iptables -I INPUT -s <ip> -j DROP

# Unblock: removes the specific rule
iptables -D INPUT -s <ip> -j DROP
```

Rules inserted by NetGuard are not persisted across reboots by design — blocked
IPs expire and are cleaned up automatically. If you reboot while blocks are active,
the database records will show `active=1` but the iptables rules will be gone.
Run `sudo systemctl restart netguard` to restore active blocks, or clear them
via the dashboard.

---

## Reverse Proxy (nginx)

In production, place nginx in front of Flask to:
- Terminate TLS
- Restrict dashboard access to internal networks
- Add HTTP Basic Authentication

```nginx
server {
    listen 443 ssl;
    server_name netguard.internal;

    ssl_certificate     /etc/ssl/certs/netguard.crt;
    ssl_certificate_key /etc/ssl/private/netguard.key;

    # Restrict to internal network
    allow 10.0.0.0/8;
    allow 192.168.0.0/16;
    deny all;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        # WebSocket headers required for Flask-SocketIO
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400;
    }
}
```

---

## Monitoring and Alerting

### Log files

| File | Location | Content |
|------|----------|---------|
| system.log | `logs/system.log` | Startup, shutdown, monitor start/stop |
| detections.log | `logs/detections.log` | Every detection, block, and unblock |
| errors.log | `logs/errors.log` | WARNING, ERROR, CRITICAL from all modules |

All files rotate at 10 MB with 5 backups.

### Health check endpoint

```bash
curl http://localhost:5000/api/v1/health
# {"success": true, "data": {"status": "healthy", "version": "1.0.0", "uptime": "00:05:32"}}
```

Use this with your monitoring system (Nagios, Prometheus blackbox exporter, etc.)

### Prometheus integration (future)

The `/api/v1/statistics` endpoint returns aggregate counts suitable for scraping.
A native `/metrics` endpoint is on the roadmap.

---

## Upgrades

```bash
cd /opt/netguard

# Pull latest code
sudo git pull origin main

# Install any new dependencies
sudo .venv/bin/pip install -r requirements.txt

# The database is migrated automatically on startup (initialize_db is idempotent)
# Restart the service
sudo systemctl restart netguard

# Verify
sudo systemctl status netguard
curl http://localhost:5000/api/v1/health
```
