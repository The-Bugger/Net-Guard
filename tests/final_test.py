"""Final integration test for NetGuard IDPS."""
import json, time, sys
import urllib.request, urllib.error

BASE = "http://localhost:5000/api/v1"

def req(method, path, body=None, timeout=6):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        raw = resp.read()
        jbody = json.loads(raw) if raw.strip() else {"success": True}
        return resp.getcode(), jbody.get("success", True), jbody
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            jbody = json.loads(raw)
        except Exception:
            jbody = {}
        return e.code, False, jbody
    except Exception as ex:
        return 0, False, {"error": str(ex)}

# ── Endpoint sweep ────────────────────────────────────────────────────────
TESTS = [
    ("GET",  "/health",                    None),
    ("GET",  "/status",                    None),
    ("GET",  "/dashboard",                 None),
    ("GET",  "/dashboard/live",            None),
    ("GET",  "/detections",                None),
    ("GET",  "/blocked",                   None),
    ("GET",  "/whitelist",                 None),
    ("GET",  "/logs",                      None),
    ("GET",  "/settings",                  None),
    ("GET",  "/statistics",                None),
    ("GET",  "/statistics/rules",          None),
    ("GET",  "/interfaces",                None),
    ("GET",  "/analytics?period=daily",    None),
    ("GET",  "/advisor",                   None),
    ("PUT",  "/settings",                  {"syn_flood_threshold": 150}),
    ("POST", "/ai-assistant",              {"question": "brute force from asia"}),
    ("GET",  "/monitor/interfaces",        None),
    ("POST", "/reset-data",                {}),
    ("POST", "/monitor/start",             {"interface": "Ethernet"}),
]

passed = failed = 0
for method, path, body in TESTS:
    code, ok, resp = req(method, path, body)
    # 409 already-monitoring = OK
    if not ok and code == 409 and "monitor/start" in path:
        ok = True
    mark = "OK  " if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
        extra = str(resp.get("error", resp.get("message", "")))[:55]
        print(f"[{mark}] {method:<6} {path:<35} {code}  -> {extra}")
        continue
    print(f"[{mark}] {method:<6} {path:<35} {code}")

print(f"\nEndpoints: {passed}/{passed+failed} passed\n")

# ── Deep checks ───────────────────────────────────────────────────────────
print("── Deep integration checks ──────────────────────────────────────")
errors = []

# 1. Stop monitoring
time.sleep(1)
c, ok, b = req("POST", "/monitor/stop", {})
stop_msg = b.get("message", b.get("error", ""))
print(f"[{'OK  ' if ok else 'FAIL'}] Stop monitoring: {c} {stop_msg}")
if not ok:
    errors.append("stop failed")

# 2. Check stopped
time.sleep(1)
c, ok, b = req("GET", "/status")
mon = b.get("data", {}).get("monitoring", True)
stopped_ok = not mon
print(f"[{'OK  ' if stopped_ok else 'FAIL'}] Monitoring stopped: {mon}")
if not stopped_ok:
    errors.append("monitoring did not stop")

# 3. Restart
c, ok, b = req("POST", "/monitor/start", {"interface": "Ethernet"})
start_msg = b.get("message", b.get("error", ""))
print(f"[{'OK  ' if (ok or c==409) else 'FAIL'}] Restart monitoring: {c} {start_msg}")

# 4. Wait for simulation warmup then check PPS > 0
time.sleep(6)
c, ok, b = req("GET", "/dashboard/live")
pps = float(b.get("data", {}).get("packets_per_second", 0))
pps_ok = pps > 0
print(f"[{'OK  ' if pps_ok else 'FAIL'}] PPS > 0 (sim flowing): {pps}")
if not pps_ok:
    errors.append("PPS is 0")

# 5. Health score
c, ok, b = req("GET", "/status")
health = b.get("data", {}).get("health_score", -1)
health_ok = isinstance(health, (int, float)) and health >= 0
print(f"[{'OK  ' if health_ok else 'FAIL'}] Health score valid: {health}")

# 6. Dashboard has whitelist key
c, ok, b = req("GET", "/dashboard")
has_wl = "whitelist" in b.get("data", {})
print(f"[{'OK  ' if has_wl else 'FAIL'}] Dashboard has whitelist key: {has_wl}")
if not has_wl:
    errors.append("whitelist missing from dashboard")

# 7. Settings persisted
c, ok, b = req("GET", "/settings")
thr = b.get("data", {}).get("syn_flood_threshold")
settings_ok = thr == 150
print(f"[{'OK  ' if settings_ok else 'FAIL'}] Settings persisted (syn_flood_threshold=150): {thr}")

# 8. All 8 rules in settings response
rules = b.get("data", {}).get("rules_enabled", {})
all8 = all(k in rules for k in ["syn_flood","port_scan","sql_injection","brute_force",
                                   "arp_spoof","icmp_flood","slow_http","dns_tunnel"])
print(f"[{'OK  ' if all8 else 'FAIL'}] All 8 rules in settings: {list(rules.keys())}")
if not all8:
    errors.append("not all 8 rules present")

# 9. AI assistant gives context-aware response
c, ok, b = req("POST", "/ai-assistant", {"question": "brute force from asia"})
ans = b.get("data", {}).get("answer", "")
ai_ok = len(ans) > 80 and ("brute" in ans.lower() or "authentication" in ans.lower())
print(f"[{'OK  ' if ai_ok else 'FAIL'}] AI answer context-aware ({len(ans)} chars)")

# 10. Static file NOT rate-limited
try:
    sr = urllib.request.urlopen("http://localhost:5000/js/api.js", timeout=5)
    static_ok = sr.getcode() == 200
    print(f"[{'OK  ' if static_ok else 'FAIL'}] Static /js/api.js not rate-limited: {sr.getcode()}")
except urllib.error.HTTPError as e:
    print(f"[FAIL] Static /js/api.js rate-limited: {e.code}")
    errors.append("static file rate-limited")

# 11. Reset data
c, ok, b = req("POST", "/reset-data", {})
reset_ok = ok and "events_deleted" in b.get("data", {})
ev_del = b.get("data", {}).get("events_deleted", "?")
print(f"[{'OK  ' if reset_ok else 'FAIL'}] Reset data: deleted {ev_del} events")

# 12. World map image served
try:
    mr = urllib.request.urlopen("http://localhost:5000/images/world-map.png", timeout=5)
    map_ok = mr.getcode() == 200
    print(f"[{'OK  ' if map_ok else 'FAIL'}] World map image served: HTTP {mr.getcode()}")
except Exception as ex:
    print(f"[FAIL] World map image: {ex}")
    errors.append("world map image not served")

print()
print("=" * 54)
all_ok = failed == 0 and not errors
if all_ok:
    print("OVERALL: ALL GOOD")
else:
    print("OVERALL: ISSUES")
    for e in errors:
        print(f"  x {e}")
print("=" * 54)
sys.exit(0 if all_ok else 1)
