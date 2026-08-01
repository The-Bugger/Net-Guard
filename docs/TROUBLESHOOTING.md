# NetGuard Troubleshooting Guide

---

## Quick Diagnostics

```bash
# 1. Is the service running?
sudo systemctl status netguard
# or directly:
ps aux | grep main.py

# 2. Is the API responding?
curl http://localhost:5000/api/v1/health

# 3. Is monitoring active?
curl http://localhost:5000/api/v1/status

# 4. Check recent errors
tail -50 logs/errors.log

# 5. Check recent detections
tail -50 logs/detections.log
```

---

## Common Problems

### 1. "iptables privilege check failed" on startup

**Symptom:** CRITICAL log entry: `iptables privilege check failed`.  
NetGuard starts but blocking is disabled.

**Cause:** The process does not have permission to run iptables.

**Fix:**
```bash
# Option A — run with sudo
sudo python backend/main.py

# Option B — grant capabilities to the Python binary
sudo setcap 'cap_net_admin+ep cap_net_raw+ep' $(which python3)

# Option C — verify iptables is installed
which iptables
sudo apt install iptables   # Debian/Ubuntu
```

**Note:** NetGuard continues running without blocking when this check fails.
Detection and alerting still work normally.

---

### 2. "No interfaces available" / empty interface list

**Symptom:** `GET /api/v1/monitor/interfaces` returns `{"interfaces": []}`.

**Cause:** `psutil.net_if_stats()` failed or returned nothing.

**Fix:**
```bash
# Verify psutil is installed
python -c "import psutil; print(list(psutil.net_if_stats().keys()))"

# If psutil is missing
pip install psutil==6.1.0

# Verify interfaces exist on the OS
ip link show   # Linux
```

---

### 3. "INVALID_INTERFACE" error when starting monitoring

**Symptom:** `POST /monitor/start` returns 422 `INVALID_INTERFACE`.

**Cause:** The interface name passed does not appear in `psutil.net_if_stats()`.

**Fix:**
```bash
# List available interfaces
curl http://localhost:5000/api/v1/monitor/interfaces

# Use an exact name from the list (case-sensitive)
curl -X POST http://localhost:5000/api/v1/monitor/start \
     -H "Content-Type: application/json" \
     -d '{"interface": "eth0"}'
```

On Linux, interface names vary: `eth0`, `enp3s0`, `wlan0`, `wlp2s0`.  
On macOS: `en0`, `en1`, `lo0`.

---

### 4. Packets captured but no detections firing

**Symptom:** Monitoring is active, packets_processed increments, but no events appear.

**Causes and fixes:**

- **Thresholds too high:** Check `config/config.yaml`. SYN flood threshold of 100
  requires 100 SYN packets in 3 seconds. Use the demo scripts (`demo/attack_syn.sh`)
  to verify the rule fires at all.

- **Rules disabled:** Check `rules_enabled` in `config.yaml` or via
  `GET /api/v1/settings`.

- **Rule disabled by exception:** Check `GET /api/v1/status` for
  `disabled_rule_names`. If a rule raised an exception it is silenced for the
  session. Check `logs/errors.log` for the root cause. Restart or call
  `reload_rules()` via a settings update to restore it.

- **Wrong interface:** The monitored interface may not see the attack traffic.
  Verify with `tcpdump -i eth0 -n` that traffic appears on the chosen interface.

- **Scapy permission denied:** Raw socket capture requires root or `CAP_NET_RAW`.
  Check `logs/errors.log` for `PermissionError`.

---

### 5. Scapy import error at startup

**Symptom:** `ImportError: No module named 'scapy'`

**Fix:**
```bash
pip install scapy==2.5.0
# Verify
python -c "from scapy.sendrecv import sniff; print('OK')"
```

---

### 6. SQLite "database is locked" errors

**Symptom:** `logs/errors.log` contains `OperationalError: database is locked`.

**Cause:** Multiple processes writing to the same SQLite file concurrently,
or a long-running transaction from a crashed session.

**Fix:**
```bash
# Ensure only one NetGuard process is running
pgrep -f "python backend/main.py"
pkill -f "python backend/main.py"

# WAL mode is already enabled by initialize_db — verify:
sqlite3 database/netguard.db "PRAGMA journal_mode;"
# Expected: wal
```

---

### 7. WebSocket / dashboard not updating

**Symptom:** Dashboard loads but KPI cards show zeros or never update.

**Cause:** SocketIO WebSocket connection failing, or eventlet not monkey-patched.

**Diagnosis:**
```bash
# Open browser DevTools → Network → WS — is the socket connection established?
# Check for errors in logs/errors.log mentioning "SocketIO" or "eventlet"
```

**Fix:**
- Ensure eventlet is installed: `pip install eventlet==0.36.1`
- The `eventlet.monkey_patch()` call must be the very first thing in `main.py`
  before any other import. Do not import Flask or SQLAlchemy before it.
- If using a reverse proxy, ensure `Upgrade: websocket` headers are forwarded
  (see nginx configuration in DEPLOYMENT.md).

---

### 8. SQL injection rule not detecting payloads

**Symptom:** Sending `UNION SELECT` in HTTP traffic produces no detection.

**Causes:**

- **Wrong port:** The rule only inspects ports 80, 443, 8080, 8443. If your
  HTTP server runs on another port, the packets are not inspected.
- **TLS traffic:** HTTPS payloads are encrypted at the TCP layer. NetGuard
  does not perform TLS termination — it cannot inspect HTTPS bodies.
- **No TCP payload:** If the packet has no Raw layer (e.g. SYN packet only),
  there is no payload to inspect.

**Debug:**
```bash
# Verify the demo script sends to port 80
bash demo/attack_sql.sh

# Check what PacketDecoder sees (set LOG_LEVEL=DEBUG and restart)
LOG_LEVEL=DEBUG python backend/main.py 2>&1 | grep sql
```

---

### 9. ARP spoofing rule firing on legitimate traffic

**Symptom:** Frequent `ARP Spoofing` alerts for your gateway IP.

**Cause:** Network devices that legitimately change their MAC address (virtual
machine migration, failover routers, load balancers with VRRP) will accumulate
multiple MACs for the same IP.

**Fix:**
- Add the gateway IP to the whitelist: `POST /api/v1/whitelist` with
  `{"ip": "192.168.1.1", "description": "VRRP gateway"}`.
- Or disable the ARP spoof rule if your network has many virtual MACs:
  `PUT /api/v1/settings` with `{"rules_enabled": {"arp_spoof": false}}`.

**Note:** The ARP rule has no MAC aging — the `_ip_to_macs` dict accumulates
entries for the lifetime of the process. Restart NetGuard to clear it.

---

### 10. Settings update returns 422 VALIDATION_ERROR

**Symptom:** `PUT /api/v1/settings` fails with `VALIDATION_ERROR`.

**Cause:** One or more values are outside their valid ranges.

**Valid ranges:**

| Setting | Min | Max |
|---------|-----|-----|
| syn_flood_threshold | 1 | none |
| syn_flood_window | 1 | 60 |
| port_scan_threshold | 1 | none |
| port_scan_window | 1 | 60 |
| brute_force_threshold | 1 | none |
| brute_force_window | 1 | 300 |
| block_duration | 1 | 3600 |
| dashboard_refresh_interval | 1 | 60 |

**Fix:** Check the `error` field in the response body — it lists all invalid
field names. Send only valid integer values within the ranges above.

---

### 11. Log files not created

**Symptom:** `logs/` directory is empty or missing.

**Cause:** `setup_logging()` was not called, or the process lacks write permission.

**Fix:**
```bash
# Create logs directory manually
mkdir -p logs
chmod 755 logs

# Verify setup_logging is called (it is called from main.py automatically)
python -c "from backend.services.log_service import setup_logging; setup_logging(); print('OK')"
```

---

### 12. Detection engine not starting (thread dies silently)

**Symptom:** `GET /api/v1/status` shows `detection_engine_running: false` shortly
after startup.

**Cause:** The Detection_Thread crashed. Check `logs/errors.log`.

Common root causes:
- A detection rule's `initialize()` raised an uncaught exception
- A dependency (config_manager, packet_queue) was None
- Import error in one of the rule files

**Fix:**
```bash
tail -100 logs/errors.log
# Find the traceback and fix the underlying issue
# Then restart: sudo systemctl restart netguard
```
