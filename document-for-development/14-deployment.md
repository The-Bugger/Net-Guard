# Deployment Specification

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

Document ID: NG-DEP-001

---

# Purpose

This document describes how NetGuard is installed, configured, deployed, and operated.

It is intended for:

- Developers
- Hackathon team members
- System administrators
- Future contributors

The deployment is designed to be lightweight, reproducible, and fully offline.

---

# Deployment Goals

- Simple installation
- Offline operation
- One-command startup
- Easy recovery
- Minimal dependencies
- Portable between Linux machines

---

# Supported Operating Systems

Primary

- Ubuntu 24.04 LTS

Supported

- Ubuntu 22.04+
- Debian 12+
- Kali Linux
- Linux Mint

Not officially supported

- Windows
- macOS

---

# Minimum Hardware

CPU

Dual Core

RAM

4 GB

Storage

5 GB Free

Network

Ethernet or Wi-Fi Adapter

Display

1366×768 minimum

---

# Recommended Hardware

CPU

Quad Core

RAM

8 GB

Storage

SSD

Network

Gigabit Ethernet

---

# Software Requirements

Python

3.11+

SQLite

3.x

Git

Latest

iptables

Installed

Google Chrome

Latest

---

# Python Dependencies

requirements.txt

```

Flask
Scapy
SQLAlchemy
Flask-CORS
Flask-SocketIO
eventlet
PyYAML
psutil
python-dotenv
requests
pytest

```

Install

```bash
pip install -r requirements.txt
```

---

# Project Directory

```

NetGuard/

backend/
frontend/
detection/
database/
config/
logs/
scripts/
tests/
demo/
docs/

requirements.txt

README.md

```

---

# Configuration Files

config/

```

config.yaml

.env

```

Example

```yaml
network_interface: eth0

dashboard_refresh: 1

block_duration: 120

syn_threshold: 100

portscan_threshold: 20

debug: false
```

---

# Environment Variables

.env

```

FLASK_ENV=production

FLASK_APP=backend/app.py

DATABASE_URL=sqlite:///database/netguard.db

LOG_LEVEL=INFO

```

---

# Database Initialization

```bash
python backend/init_db.py
```

Expected

Creates

- netguard.db
- required tables
- default settings
- default detection rules

---

# Starting Backend

```bash
python backend/app.py
```

Expected Output

```

NetGuard Backend Started

Listening on http://localhost:5000

Database Connected

Monitoring Ready

```

---

# Starting Frontend

Development

```bash
python -m http.server 8080
```

or

```bash
npm install

npm run dev
```

Production

Served through Flask.

---

# Starting Packet Monitoring

```bash
python detection/sniffer.py
```

or

Dashboard

Start Monitoring

---

# Firewall Permissions

NetGuard requires permission to manage iptables.

Run

```bash
sudo python backend/app.py
```

or

Grant only the required capability to the packet capture and firewall management components where possible.

---

# Demo Startup Script

scripts/start_demo.sh

```bash
#!/bin/bash

echo "Starting NetGuard..."

python backend/init_db.py

python backend/app.py &
sleep 3

python detection/sniffer.py &
sleep 2

echo "Dashboard Ready"

xdg-open http://localhost:5000
```

---

# Attack Simulation

Kali Machine

Examples

SYN Flood

```bash
hping3 -S --flood TARGET_IP
```

Port Scan

```bash
nmap -Pn TARGET_IP
```

SQL Injection

```bash
curl "http://TARGET/login?id=' OR '1'='1"
```

Brute Force

```bash
hydra -l admin -P passwords.txt ssh://TARGET_IP
```

ARP Spoof

```bash
arpspoof -i eth0 TARGET_IP
```

---

# Log Storage

logs/

```

system.log

detections.log

errors.log

```

Rotation

- Daily
- Maximum size 50 MB per file

---

# Backup Strategy

Before deployment

Backup

- Database
- Configuration
- Detection rules
- Logs

Backup Folder

```

backup/YYYY-MM-DD/

```

---

# Restore Procedure

```bash
cp backup/latest/netguard.db database/

cp backup/latest/config.yaml config/
```

Restart backend.

---

# Deployment Checklist

Environment

☐ Python installed

☐ Dependencies installed

☐ SQLite initialized

☐ Configuration verified

☐ Firewall available

☐ Dashboard accessible

☐ Detection rules loaded

☐ Network interface selected

---

# Operational Checklist

Before Monitoring

☐ Database connected

☐ Firewall operational

☐ Dashboard running

☐ Packet capture active

☐ Log directory writable

---

# Demo Checklist

Before Presentation

☐ Dashboard open

☐ Kali VM running

☐ Attack scripts verified

☐ Browser in full screen

☐ Monitoring started

☐ Logs cleared

☐ Backup video ready

☐ Power adapter connected

---

# Monitoring During Demo

Observe

- Packet counter
- Live graph
- Alerts
- Blocked IPs
- Evidence panel
- System health

---

# Failure Recovery

Backend Crash

Restart

```bash
python backend/app.py
```

Packet Capture Failure

Restart

```bash
python detection/sniffer.py
```

Database Failure

Restore backup

Restart application

Firewall Failure

Flush temporary rules if necessary

Restart monitoring

---

# Shutdown Procedure

Stop Monitoring

↓

Stop Backend

↓

Backup Database

↓

Archive Logs

↓

Power Off

---

# Security Recommendations

- Use a dedicated Linux user where practical.
- Restrict write access to configuration files.
- Regularly back up the SQLite database.
- Do not expose the API outside the local network for the hackathon.
- Keep the system updated before deployment.

---

# Future Deployment Enhancements

- Docker support
- Docker Compose
- Kubernetes deployment
- systemd service
- Nginx reverse proxy
- HTTPS support
- Remote dashboard
- Multi-node deployment
- Cloud synchronization
- Automatic updates

---

# Acceptance Criteria

✓ Clean installation on Ubuntu.

✓ Application starts successfully.

✓ Database initializes automatically.

✓ Dashboard accessible.

✓ Monitoring starts without errors.

✓ Detection engine operational.

✓ Logs written correctly.

✓ Demo environment reproducible.

---

# Revision History

| Version | Date | Description |
|----------|------|-------------|
| 1.0 | July 2026 | Initial Deployment Specification |

---

End of Document