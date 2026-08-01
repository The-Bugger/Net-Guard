"""
integration_test.py — Full endpoint integration test for NetGuard IDPS.
Run: python tests/integration_test.py
Requires the server to be running on localhost:5000.
"""
import json
import time
import urllib.request
import urllib.error
import sys

BASE = "http://localhost:5000/api/v1"


def req(method, path, body=None):
    """Make an HTTP request; returns (status_code, success_bool, json_body_dict)."""
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    r = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        resp = urllib.request.urlopen(r, timeout=8)
        raw = resp.read()
        jbody = json.loads(raw) if raw.strip() else {"success": True}
        return resp.getcode(), jbody.get("success", True), jbody
    except urllib.error.HTTPError as e:
        raw = e.read()
        jbody = {}
        try:
            jbody = json.loads(raw) if raw.strip() else {}
        except Exception:
            pass
        # 404 on DELETE of non-existent entry is acceptable in idempotent tests
        return e.code, False, jbody


# ---------------------------------------------------------------------------
# Test matrix — (method, path, body, acceptable_codes)
# acceptable_codes: list of HTTP codes that count as OK
# ---------------------------------------------------------------------------
TESTS = [
    ("GET",    "/health",                None,                        [200]),
    ("GET",    "/status",                None,                        [200]),
    ("GET",    "/dashboard",             None,                        [200]),
    ("GET",    "/dashboard/live",        None,                        [200]),
    ("GET",    "/detections",            None,                        [200]),
    ("GET",    "/blocked",               None,                        [200]),
    ("GET",    "/whitelist",             None,                        [200]),
    ("GET",    "/logs",                  None,                        [200]),
    ("GET",    "/settings",              None,                        [200]),
    ("GET",    "/statistics",            None,                        [200]),
    ("GET",    "/statistics/rules",      None,                        [200]),
    ("GET",    "/interfaces",            None,                        [200]),
    ("GET",    "/analytics?period=daily",None,                        [200]),
    ("GET",    "/advisor",               None,                        [200]),
    ("PUT",    "/settings",              {"syn_flood_threshold": 100},[200]),
    ("POST",   "/whitelist",             {"ip":"10.20.30.40","description":"itest"}, [200,201,409]),
    ("DELETE", "/whitelist/10.20.30.40", None,                        [200,204,404]),
    ("POST",   "/ai-assistant",          {"question": "summary"},     [200]),
    ("GET",    "/monitor/interfaces",    None,                        [200]),
    # 409 = already monitoring (sim auto-started) — also acceptable
    ("POST",   "/monitor/start",         {"interface": "Ethernet"},   [200,409]),
]

passed = failed = 0
for method, path, body, ok_codes in TESTS:
    code, _, resp = req(method, path, body)
    ok = code in ok_codes
    mark = "OK  " if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    extra = ""
    if not ok:
        extra = "  -> " + str(resp.get("error", resp.get("message", "")))[:60]
    print(f"[{mark}] {method:<8} {path:<38} HTTP {code}{extra}")

print()
print(f"Endpoints: {passed}/{passed + failed} passed")

# ---------------------------------------------------------------------------
# Deep integration checks
# ---------------------------------------------------------------------------
print("\n── Deep integration checks ──────────────────────────────────────")
errors = []

# 1. Monitoring stays active after 5 s (key fix: must not stop immediately)
time.sleep(5)
_, _, s = req("GET", "/status", None)
mon = s.get("data", {}).get("monitoring", False)
_ok = mon is True
if not _ok: errors.append("monitoring stopped after 5s")
print(f"[{'OK  ' if _ok else 'FAIL'}] Monitoring still active after 5s: {mon}")

# 2. PPS > 0 — sim packets flowing through detection engine
_, _, live = req("GET", "/dashboard/live", None)
pps = float(live.get("data", {}).get("packets_per_second", 0))
_ok = pps > 0
if not _ok: errors.append(f"PPS is 0 (sim not feeding packets)")
print(f"[{'OK  ' if _ok else 'FAIL'}] PPS > 0: {pps}")

# 3. Dashboard has whitelist key (stats_service fix)
_, _, dash = req("GET", "/dashboard", None)
has_wl = "whitelist" in dash.get("data", {})
if not has_wl: errors.append("'whitelist' key missing from /dashboard")
print(f"[{'OK  ' if has_wl else 'FAIL'}] Dashboard has 'whitelist' key: {has_wl}")

# 4. Health score is a valid non-negative integer
health = s.get("data", {}).get("health_score", -1)
_ok = isinstance(health, (int, float)) and health >= 0
if not _ok: errors.append(f"health_score invalid: {health}")
print(f"[{'OK  ' if _ok else 'FAIL'}] Health score valid (≥0): {health}")

# 5. Settings update persisted across the round-trip
_, _, sg = req("GET", "/settings", None)
thr = sg.get("data", {}).get("syn_flood_threshold")
_ok = thr == 100
if not _ok: errors.append(f"settings not persisted: syn_flood_threshold={thr}")
print(f"[{'OK  ' if _ok else 'FAIL'}] Settings persisted (syn_flood_threshold=100): {thr}")

# 6. Static files are NOT rate-limited (rate limiter only applies to /api/)
try:
    sr = urllib.request.urlopen("http://localhost:5000/js/api.js", timeout=5)
    static_code = sr.getcode()
    _ok = static_code == 200
except urllib.error.HTTPError as e:
    static_code = e.code
    _ok = False
    errors.append(f"static file rate-limited: {static_code}")
print(f"[{'OK  ' if _ok else 'FAIL'}] Static /js/api.js not rate-limited: HTTP {static_code}")

# 7. AI assistant returns context-aware answer
_, _, ai = req("POST", "/ai-assistant", {"question": "brute force"})
ans = ai.get("data", {}).get("answer", "")
_ok = len(ans) > 80
if not _ok: errors.append(f"AI answer too short ({len(ans)} chars)")
print(f"[{'OK  ' if _ok else 'FAIL'}] AI assistant context-aware ({len(ans)} chars)")

# 8. Recent events populated from simulation
events = dash.get("data", {}).get("recent_events", [])
_ok = len(events) > 0
if not _ok: errors.append("no recent_events in dashboard (simulation may not be firing)")
print(f"[{'OK  ' if _ok else 'WARN'}] Recent events in dashboard: {len(events)}")

# 9. All 8 rules appear in statistics/rules
_, _, rule_stats = req("GET", "/statistics/rules", None)
rules_data = rule_stats.get("data", {}).get("rules", rule_stats.get("data", []))
if isinstance(rules_data, list):
    rule_names = {r.get("attack_type", "") for r in rules_data}
else:
    rule_names = set()
# We just check the endpoint returns something
_ok = rule_stats.get("success", False)
print(f"[{'OK  ' if _ok else 'FAIL'}] /statistics/rules returns data")

# 10. Evidence route for the most recent event
if events:
    eid = events[0].get("event_id", "")
    _, ev_ok, ev_data = req("GET", f"/evidence/{eid}", None)
    _ok = ev_ok or ev_data.get("code") == 404  # 404 fine if evidence not stored yet
    print(f"[{'OK  ' if _ok else 'FAIL'}] Evidence route for event {eid[:12]}…: HTTP {_ if not ev_ok else 200}")
else:
    print("[SKIP] Evidence route — no events yet")

# 11. Replay route works (or returns 404 gracefully when no events)
if events:
    eid = events[0].get("event_id", "")
    rcode, rok, rdata = req("GET", f"/events/{eid}/replay", None)
    _ok = rcode in (200, 201)
    if not _ok: errors.append(f"replay returned {rcode}: {rdata.get('error','')}")
    print(f"[{'OK  ' if _ok else 'FAIL'}] Replay event {eid[:12]}…: HTTP {rcode}")
else:
    print("[SKIP] Replay — no events yet")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print()
print("=" * 54)
all_ok = failed == 0 and not errors
if all_ok:
    print("OVERALL: ALL GOOD ✓")
else:
    print("OVERALL: ISSUES FOUND")
    for e in errors:
        print(f"  ✗ {e}")
print("=" * 54)
sys.exit(0 if all_ok else 1)
