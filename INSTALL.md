# Installation Guide — NetGuard IDPS

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Quick Install (Linux)](#quick-install-linux)
3. [Manual Install](#manual-install)
4. [Windows / macOS (Development Only)](#windows--macos-development-only)
5. [Virtual Environment Setup](#virtual-environment-setup)
6. [Database Initialization](#database-initialization)
7. [Verifying the Installation](#verifying-the-installation)
8. [Uninstallation](#uninstallation)
9. [Troubleshooting](#troubleshooting)

---

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Linux (any distro) | Ubuntu 22.04 LTS |
| Python | 3.11 | 3.12 |
| RAM | 512 MB | 2 GB |
| CPU | 1 core | 2+ cores |
| Disk | 100 MB | 1 GB |
| Network | Any interface | Dedicated NIC |
| Privileges | root/sudo | root |

> **Note:** iptables-based blocking requires Linux + root. Detection, API, and
> dashboard work on Windows/macOS for development purposes.

### Required System Packages (Linux)

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv iptables libpcap-dev
```

### Optional Tools (Demo Scripts Only)

```bash
sudo apt install -y hping3 nmap hydra dsniff curl
```

---

## Quick Install (Linux)

The fastest path — runs the automated setup script:

```bash
git clone https://github.com/The-Bugger/Net-Guard.git netguard
cd netguard
sudo bash scripts/setup.sh
```

The setup script:
1. Checks Python 3.11+ is available
2. Creates a virtual environment at `.venv/`
3. Installs all pip dependencies from `requirements.txt`
4. Creates required directories
5. Initializes the SQLite database
6. Verifies iptables is available

After setup:
```bash
sudo python backend/main.py
# Dashboard: http://localhost:5000
```

---

## Manual Install

### Step 1 — Clone the Repository

```bash
git clone https://github.com/The-Bugger/Net-Guard.git netguard
cd netguard
```

### Step 2 — Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3 — Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4 — Configure Environment

```bash
cp .env.example .env
# Edit .env as needed (LOG_LEVEL, SECRET_KEY, etc.)
```

### Step 5 — Initialize Database

```bash
python -c "from database.init_db import initialize_db; initialize_db()"
```

### Step 6 — Start NetGuard

```bash
sudo python backend/main.py
```

---

## Windows / macOS (Development Only)

Detection and API testing work without iptables:

```powershell
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -c "from database.init_db import initialize_db; initialize_db()"
python backend/main.py     # iptables calls will log warnings but not crash
```

```bash
# macOS
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -c "from database.init_db import initialize_db; initialize_db()"
python backend/main.py
```

> **Note:** Scapy requires Npcap on Windows and libpcap on macOS.
> Packet capture will not work without these.

---

## Virtual Environment Setup

```bash
# Create
python3 -m venv .venv

# Activate (Linux/macOS)
source .venv/bin/activate

# Activate (Windows)
.venv\Scripts\activate

# Deactivate
deactivate

# Verify
python --version    # Should show Python 3.11+
pip list            # Should show Flask, SQLAlchemy, scapy, etc.
```

---

## Database Initialization

NetGuard uses SQLite. The database file is created at `database/netguard.db`.

```bash
# Initialize (creates tables if they don't exist)
python -c "from database.init_db import initialize_db; initialize_db()"

# Verify tables were created
python -c "
from sqlalchemy import create_engine, inspect
e = create_engine('sqlite:///database/netguard.db')
print(inspect(e).get_table_names())
"
# Output: ['blocked_ips', 'detection_rules', 'events', 'settings', 'system_logs', 'whitelist']
```

---

## Verifying the Installation

```bash
# 1. Run the test suite (no root needed)
pytest tests/ --ignore=tests/integration -q
# Expected: 640+ passed (baseline 511 + new Phase A/B tests); some ARP spoof tests
#            fail on platforms without raw socket access — this is expected

# 2. Check imports
python -c "
import flask, flask_socketio, scapy, sqlalchemy, yaml, hypothesis
print('All core imports OK')
"

# 3. Check the API starts
sudo python backend/main.py &
sleep 3
curl http://localhost:5000/api/v1/health
# Expected: {"success": true, "data": {"status": "healthy"}, ...}
kill %1
```

---

## Uninstallation

```bash
# Remove the virtual environment
deactivate
rm -rf .venv

# Remove the database
rm -f database/netguard.db

# Remove the iptables rules (if any remain)
sudo iptables -L INPUT -n | grep DROP     # inspect
sudo iptables -F INPUT                     # flush ALL INPUT rules (use carefully)
```

---

## Troubleshooting

See [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) for common issues.

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: scapy` | `pip install scapy==2.5.0` |
| `PermissionError: iptables` | Run with `sudo` |
| `OSError: [Errno 1] Operation not permitted` | Scapy requires root for packet capture |
| `sqlalchemy.exc.OperationalError` | Delete `database/netguard.db` and re-initialize |
| Port 5000 already in use | `export FLASK_PORT=5001` in `.env` |
| `eventlet` errors on Python 3.14 | Set `SOCKETIO_ASYNC_MODE=threading` in `.env` |
