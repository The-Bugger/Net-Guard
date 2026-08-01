# Implementation Plan: NetGuard Real-Time IDPS

## Overview

Transform NetGuard from a simulation-based app into a production-ready IDPS by:
1. Removing all demo infrastructure
2. Wiring real packet capture to the existing detection/prevention pipeline
3. Replacing the health score formula with a deterministic attack-weighted version
4. Adding the offline SecurityAdvisor (with optional Gemini fallback)
5. Providing attack test scripts for a second laptop

**All changes are additive or surgical replacements — no rewrites, no new dependencies
beyond `psutil` (already in requirements.txt).**

Language: Python 3.11+ (backend), vanilla JS ES6 (frontend).

---

## Tasks

### Phase 1: Remove Demo Infrastructure

- [x] 1. Delete demo service, routes, and shell scripts
  - Delete `backend/services/demo_service.py`
  - Delete `backend/routes/demo_routes.py`
  - Delete `scripts/start_demo.sh`
  - Remove `demo_service` and `demo_routes` imports and registrations from
    `backend/main.py` and `backend/api/__init__.py`
  - Verify app still starts cleanly after deletion
  - _Requirements: 1.3, 1.5, 1.6, 1.7_

- [x] 2. Strip demo UI from frontend
  - In `frontend/index.html`: remove demo start/stop buttons, demo status badges,
    attack simulator panel, and any element with `demo` in its id or class name
  - Search all files under `frontend/` for `demo` references and remove them
  - Verify dashboard loads without JS errors referencing removed elements
  - _Requirements: 1.1, 1.2, 1.4_

- [x] 3. Checkpoint — app starts, dashboard loads, zero state on fresh DB
  - Start app with empty DB; confirm dashboard shows 0 packets, 0 alerts, 0 blocks
  - Confirm `GET /api/v1/demo/start` returns 404

---

### Phase 2: Interface Discovery Endpoint

- [x] 4. Add `GET /api/v1/interfaces` endpoint
  - In `backend/routes/monitor_routes.py` (or create `interface_routes.py` if it
    doesn't exist): add `GET /api/v1/interfaces` that calls
    `psutil.net_if_stats()` and returns `[{"name": str, "is_up": bool}]`
  - Auto-select logic: add `_pick_default_interface()` helper in `CaptureEngine`
    or `MonitorService` that returns the first non-loopback `is_up` interface
  - Register the blueprint in `backend/api/__init__.py`
  - _Requirements: 2.2, 2.3, 15.3_

- [x] 5. Wire interface auto-select in MonitorService
  - In `backend/services/monitor_service.py`: if `interface` arg is `None` or
    empty string, call `_pick_default_interface()` before passing to
    `CaptureEngine.start()`
  - _Requirements: 2.3_

---

### Phase 3: Graceful Interface Failure Handling

- [x] 6. Emit `monitoring_error` SocketIO event on capture failure
  - In `detection/capture/sniffer.py` `_capture_loop`: on any exception, call
    the existing `socketio_emit` callback (inject it via `CaptureEngine.__init__`
    or pass through `MonitorService`) with event name `"monitoring_error"` and
    payload `{"interface": self._interface, "reason": str(exc)}`
  - In `backend/services/monitor_service.py`: after the capture thread dies
    unexpectedly, set `monitoring_state.active = False` and emit `monitoring_error`
  - _Requirements: 2.4, 15.1, 15.2, 15.4_

---

### Phase 4: Replace Health Score Formula

- [x] 7. Replace `get_health_score()` in StatsService
  - In `backend/services/stats_service.py`:
    - Add helper `_get_attack_types_today() -> set[str]` that queries
      `EventRepository` for distinct `attack_type` values with timestamp in
      current UTC calendar day
    - Replace the existing `get_health_score()` body with the new formula:
      ```python
      DEDUCTIONS = {
          "SYN Flood": 15, "Port Scan": 8, "SQL Injection": 12,
          "Brute Force": 10, "ARP Spoofing": 20,
      }
      score = 100
      types_today = _get_attack_types_today()
      for attack, penalty in DEDUCTIONS.items():
          if attack in types_today:
              score -= penalty
      if len(types_today & DEDUCTIONS.keys()) >= 3:
          score -= 15
      return max(0, min(100, score))
      ```
    - Keep return -1 on DB error (existing behaviour)
  - Add a self-check: `assert get_health_score_from(set()) == 100`
  - _Requirements: 9.1, 9.2, 9.3_

  - [x] 7.1 Property test for new health score formula
    - In `tests/test_properties_hackathon.py` (reuse existing file), add
      `test_weighted_health_score_bounds`: for any subset of the 5 attack types,
      score ∈ [0, 100]; empty set → 100; all 5 → max(0, 100-15-8-12-10-20-15)=20
    - File: `tests/test_properties_hackathon.py`
    - _Requirements: 9.1, 9.3_

---

### Phase 5: Security Advisor Service

- [x] 8. Implement `backend/services/security_advisor.py`
  - Create `SecurityAdvisor` class with:
    - `_KNOWLEDGE_BASE`: list of ≥ 25 dicts, each with `min_score`, `max_score`,
      `title`, `message`, `actions` (list of str). Cover green (80–100), yellow
      (60–79), orange (40–59), red (0–39) tiers — 5+ entries each
    - `_ATTACK_ADVICE`: dict mapping each of the 5 attack types to a list of
      extra action strings
    - `advise(health_score: int, detected_attack_types: list[str]) -> dict`:
      1. Try Gemini if `GEMINI_API_KEY` set (10 s timeout); on any error log
         WARNING and fall through
      2. Select tier entry from `_KNOWLEDGE_BASE` matching `health_score`
      3. Append per-attack-type actions from `_ATTACK_ADVICE` for each type
         in `detected_attack_types`
      4. Return `{score, badge_color, title, message, actions}`
  - `ponytail:` no new dependency — `urllib.request` for Gemini HTTP call if
    `google-generativeai` not installed; ceiling: upgrade to SDK later
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

  - [x] 8.1 Property test for SecurityAdvisor
    - `test_advisor_always_returns_valid_dict`: for any health_score in [0,100]
      and any subset of attack types, `advise()` returns a dict with all 5 keys
      and `badge_color` is one of the four valid values
    - File: `tests/test_properties_hackathon.py`
    - _Requirements: 10.2, 10.5_

- [x] 9. Add `GET /api/v1/advisor` route
  - In `backend/routes/` create `advisor_routes.py` (or add to existing
    `health_routes.py`): `GET /api/v1/advisor` calls
    `security_advisor.advise(stats_service.get_health_score(), today_attack_types)`
    and returns the dict as JSON
  - Register `SecurityAdvisor` in `backend/main.py` dependencies
  - Register the blueprint in `backend/api/__init__.py`
  - _Requirements: 10.6_

---

### Phase 6: Dashboard Updates — Remove Demo UI, Add Advisor + Devices Panels

- [x] 10. Add Security Advisor panel to dashboard
  - In `frontend/index.html`: add `<div id="advisor-panel">` showing score badge,
    title, message, and `<ul id="advisor-actions">` action list
  - In `frontend/js/dashboard.js`: on page load, fetch `GET /api/v1/advisor` and
    populate the panel; re-fetch every 30 seconds or on each `new_threat` event
  - Badge color: apply CSS class `badge-green / badge-yellow / badge-orange /
    badge-red` matching `badge_color` from API response
  - _Requirements: 10.7_

- [x] 11. Add Connected Devices panel to dashboard
  - In `frontend/index.html`: add `<div id="devices-panel">` with a table
    (IP, MAC, hostname, vendor, status, last seen)
  - In `frontend/js/dashboard.js`: fetch `GET /api/v1/devices` on load and every
    30 seconds; populate the table rows
  - _Requirements: 11.1, 11.6_

- [x] 12. Add `GET /api/v1/devices` route
  - In `backend/routes/` create `device_routes.py`: `GET /api/v1/devices` calls
    `lan_scan_service.get_devices(interface)` where `interface` comes from
    `monitoring_state.interface` (add this field to `MonitoringState` when
    `MonitorService.start()` is called)
  - Register the blueprint in `backend/api/__init__.py`
  - _Requirements: 11.1, 11.2_

- [x] 13. Add interface name and monitoring status to dashboard
  - In `frontend/index.html`: add `<span id="monitoring-interface">` and ensure
    the existing monitoring status badge uses green/red CSS classes
  - In `frontend/js/dashboard.js`: populate interface name from
    `GET /api/v1/status` response field `interface`; add `interface` field to
    `GET /api/v1/status` response in `backend/routes/health_routes.py`
  - _Requirements: 2.6, 12.1, 12.6_

- [x] 14. Checkpoint — dashboard loads with real data, advisor panel visible,
    devices panel visible, no demo elements
  - Verify no `demo` string in rendered page source
  - Verify advisor panel shows a score badge

---

### Phase 7: Attack Test Scripts

- [x] 15. Create `scripts/attack_tests/` directory and five attack scripts
  - `syn_flood.sh` — header comment (prereqs: hping3, usage, expected detection,
    safe-use warning); body: `hping3 -S -p 80 --flood "$TARGET_IP"`
    with a 5-second duration using `timeout 5`
  - `port_scan.sh` — `nmap -sS -T4 "$TARGET_IP"`
  - `sql_injection.sh` — `curl -s "http://$TARGET_IP/search?q=%27%20OR%201%3D1%20--%20UNION%20SELECT%201"`
  - `brute_force.sh` — `hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh://"$TARGET_IP"`
  - `arp_spoof.sh` — `timeout 10 arpspoof -i "$IFACE" -t "$TARGET_IP" "$GATEWAY_IP"`
  - Make all scripts executable (`chmod +x`)
  - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6_

- [x] 16. Create `scripts/attack_tests/README.md`
  - Document prerequisites (hping3, nmap, hydra, dsniff/arpspoof, curl)
  - Usage syntax for each script with `TARGET_IP`, `IFACE`, `GATEWAY_IP` vars
  - Expected NetGuard alert for each script
  - Network topology diagram (ASCII) showing attacker ↔ switch ↔ NetGuard laptop
  - _Requirements: 14.7_

---

### Phase 8: Verify Detection Rules Align with Real Traffic

- [x] 17. Audit existing detection rules against requirements
  - Read `detection/rules/syn_flood.py`: confirm threshold=100, window=3s,
    evidence fields match Requirement 3.4; fix any mismatches
  - Read `detection/rules/port_scan.py`: confirm threshold=20, window=10s,
    evidence fields match Requirement 4.3; fix any mismatches
  - Read `detection/rules/sql_injection.py`: confirm HTTP port list and patterns
    match Requirement 5.1; add payload decode with `errors="ignore"` if missing
  - Read `detection/rules/brute_force.py`: confirm threshold=10, window=60s,
    target_service mapping matches Requirement 6.3; fix any mismatches
  - Read `detection/rules/arp_spoof.py`: confirm ARP opcode 2 check and 300s
    observation window match Requirement 7.1; fix any mismatches
  - _Requirements: 3.1–3.5, 4.1–4.3, 5.1–5.4, 6.1–6.3, 7.1–7.4_

- [x] 18. Final checkpoint — end-to-end smoke test
  - Start app; confirm monitoring can be started on a real interface
  - Confirm `GET /api/v1/interfaces` returns at least one interface
  - Confirm `GET /api/v1/advisor` returns a valid dict
  - Confirm `GET /api/v1/devices` returns a list (may be empty if no ARP scan
    privileges, but must not 500)
  - Confirm no 500 errors on any standard dashboard page load
  - _Requirements: 16.1–16.8_

---

## Task Dependency Graph

```json
{
  "waves": [
    { "wave": 1, "tasks": ["1"] },
    { "wave": 2, "tasks": ["2"] },
    { "wave": 3, "tasks": ["3"] },
    { "wave": 4, "tasks": ["4"] },
    { "wave": 5, "tasks": ["5"] },
    { "wave": 6, "tasks": ["6"] },
    { "wave": 7, "tasks": ["7"] },
    { "wave": 8, "tasks": ["7.1", "8"] },
    { "wave": 9, "tasks": ["8.1", "9"] },
    { "wave": 10, "tasks": ["10", "15"] },
    { "wave": 11, "tasks": ["11", "16"] },
    { "wave": 12, "tasks": ["12"] },
    { "wave": 13, "tasks": ["13"] },
    { "wave": 14, "tasks": ["14"] },
    { "wave": 15, "tasks": ["17"] },
    { "wave": 16, "tasks": ["18"] }
  ]
}
```

---

## Notes

- Tasks 1–3 (Phase 1) must complete before any other work begins — they remove demo infrastructure that could interfere with real wiring.
- Tasks 4–6 (Phases 2–3) establish the real capture pipeline; wire interface discovery and error handling before touching detection logic.
- Task 7 and subtask 7.1 are independent of the advisor; property tests validate the formula in isolation.
- Tasks 8/8.1 and 9 (Phase 5) can begin as soon as Task 7 is complete.
- Tasks 10–13 (Phase 6) are frontend/route additions that depend on the backend services from Phases 4–5.
- Tasks 15–16 (Phase 7, attack scripts) are pure file creation and have no runtime dependency; they can be drafted any time after Phase 1.
- Tasks 17–18 (Phase 8) are audit/verification tasks and must run last.
- All property tests live in `tests/test_properties_hackathon.py` (existing file — append, do not replace).
