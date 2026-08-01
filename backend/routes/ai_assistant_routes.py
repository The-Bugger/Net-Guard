"""
ai_assistant_routes.py — AI Security Assistant chat endpoint.

POST /ai-assistant  {"question": "..."}  →  {"answer": "..."}

Uses real detection data from the DB + keyword-matched templated responses
to give contextually useful answers without requiring an external LLM.

Requirements: Task 37
"""

from __future__ import annotations

from flask import Blueprint, request

from backend.api.dependencies import get_event_repo, get_stats_service
from backend.utils.response import success_response, error_response

ai_assistant_bp = Blueprint("ai_assistant", __name__)


@ai_assistant_bp.post("/ai-assistant")
def ask_ai_assistant():
    body = request.get_json(silent=True) or {}
    question = body.get("question", "").strip()
    if not question:
        return error_response("Question is required.", 400, "VALIDATION_ERROR")

    event_repo  = get_event_repo()
    stats_svc   = get_stats_service()

    answer = _generate_answer(question, event_repo, stats_svc)
    return success_response(data={"answer": answer})


# ---------------------------------------------------------------------------
# Answer generation
# ---------------------------------------------------------------------------

def _generate_answer(question: str, event_repo, stats_svc) -> str:
    q = question.lower()

    # Gather live data once
    events       = _safe_events(event_repo, limit=20)
    total        = len(events)
    sev_counts   = _count_severities(events)
    attack_types = _count_attack_types(events)
    top_ips      = _top_ips(events, n=3)
    health       = _safe_health(stats_svc)
    monitoring   = _safe_monitoring(stats_svc)

    # ── Routing by keyword ──────────────────────────────────────────────
    if any(w in q for w in ("health", "score", "secure", "safe", "status")):
        return _answer_health(health, monitoring, sev_counts, total)

    if any(w in q for w in ("syn", "flood", "ddos", "dos")):
        return _answer_attack("SYN Flood", events, sev_counts, attack_types)

    if any(w in q for w in ("sql", "injection", "sqli")):
        return _answer_attack("SQL Injection", events, sev_counts, attack_types)

    if any(w in q for w in ("brute", "force", "password", "login", "ssh")):
        return _answer_attack("Brute Force", events, sev_counts, attack_types)

    if any(w in q for w in ("port", "scan", "nmap", "reconnaissance")):
        return _answer_attack("Port Scan", events, sev_counts, attack_types)

    if any(w in q for w in ("arp", "spoof", "mitm", "man-in-the")):
        return _answer_attack("ARP Spoofing", events, sev_counts, attack_types)

    if any(w in q for w in ("icmp", "ping")):
        return _answer_attack("ICMP Flood", events, sev_counts, attack_types)

    if any(w in q for w in ("dns", "tunnel")):
        return _answer_attack("DNS Tunneling", events, sev_counts, attack_types)

    if any(w in q for w in ("slow", "http", "slowloris")):
        return _answer_attack("Slow HTTP", events, sev_counts, attack_types)

    if any(w in q for w in ("block", "blocked", "ban", "firewall")):
        return _answer_blocks(events, top_ips)

    if any(w in q for w in ("critical", "urgent", "severe", "worst")):
        return _answer_critical(events, sev_counts)

    if any(w in q for w in ("top", "attacker", "source", "ip", "who")):
        return _answer_top_attackers(top_ips, total)

    if any(w in q for w in ("recommend", "advice", "should", "next", "fix", "mitigate")):
        return _answer_recommendations(sev_counts, attack_types, health)

    if any(w in q for w in ("rule", "detect", "detection")):
        return _answer_rules(attack_types, total)

    if any(w in q for w in ("monitor", "start", "stop", "interface")):
        return _answer_monitoring(monitoring)

    if any(w in q for w in ("summary", "overview", "report", "what")):
        return _answer_summary(total, sev_counts, attack_types, top_ips, health, monitoring)

    # Default — always return something useful
    return _answer_summary(total, sev_counts, attack_types, top_ips, health, monitoring)


# ---------------------------------------------------------------------------
# Individual answer builders
# ---------------------------------------------------------------------------

def _answer_health(health, monitoring, sev_counts, total) -> str:
    if health == -1:
        score_str = "unavailable (DB error)"
        grade = "Unknown"
    else:
        score_str = f"{health}/100"
        grade = "Good ✅" if health >= 80 else ("Fair ⚠️" if health >= 50 else "Poor 🔴")

    mon_str = "Active ✅" if monitoring else "Stopped ⏹"
    crit = sev_counts.get("Critical", 0)
    high = sev_counts.get("High", 0)

    lines = [
        f"🛡 Security Health Score: {score_str} — {grade}",
        f"📡 Monitoring: {mon_str}",
        f"⚠️  Recent detections: {total} total ({crit} Critical, {high} High)",
    ]
    if health != -1 and health < 80:
        lines.append("\nTo improve your score:")
        if crit > 0:
            lines.append(f"  • Investigate {crit} Critical alert(s) immediately")
        if not monitoring:
            lines.append("  • Start monitoring to catch live threats")
        lines.append("  • Review blocked IPs and confirm they haven't been prematurely unblocked")
    return "\n".join(lines)


def _answer_attack(attack_type: str, events, sev_counts, attack_types) -> str:
    matching = [e for e in events if attack_type.lower() in e.get("attack_type", "").lower()]
    count    = attack_types.get(attack_type, 0)

    _descriptions = {
        "SYN Flood":    "TCP SYN packets sent without completing the handshake — exhausts server connection tables.",
        "SQL Injection":"Malicious SQL code injected into HTTP payloads to manipulate your database.",
        "Brute Force":  "Repeated login attempts to guess credentials on SSH/HTTP services.",
        "Port Scan":    "Systematic probing of ports to discover open services before an attack.",
        "ARP Spoofing": "Fake ARP replies mapping attacker's MAC to a victim's IP for MITM interception.",
        "ICMP Flood":   "High-volume ICMP (ping) packets to exhaust bandwidth or CPU resources.",
        "DNS Tunneling":"Data exfiltration or C2 communication hidden inside DNS query/response packets.",
        "Slow HTTP":    "Partial HTTP requests held open to exhaust server worker threads (Slowloris style).",
    }
    desc = _descriptions.get(attack_type, "Detected suspicious activity matching this attack pattern.")

    lines = [f"🔍 {attack_type} — {count} detection(s) in recent history", "", desc]
    if matching:
        latest = matching[0]
        lines += [
            "",
            f"Latest event:",
            f"  Source IP : {latest.get('source_ip', '?')}",
            f"  Severity  : {latest.get('severity', '?')}",
            f"  Time      : {latest.get('timestamp', '?')}",
        ]
    _mitigations = {
        "SYN Flood":    ["Enable SYN cookies on your OS", "Lower syn_flood_threshold in Settings", "Rate-limit new TCP connections at the firewall"],
        "SQL Injection":["Use parameterised queries everywhere", "Deploy a WAF in front of your web servers", "Review application logs for DB errors"],
        "Brute Force":  ["Enable account lockout after N failures", "Use fail2ban or equivalent", "Switch SSH to key-based auth only"],
        "Port Scan":    ["Close unused ports", "Enable stealth mode on your firewall", "Monitor for follow-up exploit attempts"],
        "ARP Spoofing": ["Enable Dynamic ARP Inspection on managed switches", "Use static ARP entries for critical hosts", "Monitor your ARP table regularly"],
        "ICMP Flood":   ["Rate-limit ICMP at the perimeter firewall", "Block ICMP from untrusted sources", "Enable ingress filtering (BCP38)"],
        "DNS Tunneling":["Monitor DNS query length — tunnel queries are unusually long", "Block outbound DNS except to authorised resolvers", "Use DNS filtering/RPZ"],
        "Slow HTTP":    ["Set aggressive request timeouts on your web server", "Limit connections per IP", "Deploy a reverse proxy with connection limits"],
    }
    mitigations = _mitigations.get(attack_type, ["Review the event evidence and apply the recommended remediation."])
    lines += ["", "Recommended mitigations:"] + [f"  • {m}" for m in mitigations]
    return "\n".join(lines)


def _answer_blocks(events, top_ips) -> str:
    blocked = [e for e in events if e.get("blocked")]
    lines = [
        f"🚫 Blocked events in recent history: {len(blocked)}",
        "",
        "NetGuard auto-blocks confirmed attackers via iptables (Linux) for the configured block_duration.",
        "On Windows, blocking is logged but iptables rules are not applied.",
    ]
    if top_ips:
        lines += ["", "Top sources (likely candidates for blocking):"]
        for ip, cnt in top_ips:
            lines.append(f"  • {ip} — {cnt} event(s)")
    lines += ["", "Tip: Use the Blocked IPs page to manage blocks manually, or adjust block_duration in Settings."]
    return "\n".join(lines)


def _answer_critical(events, sev_counts) -> str:
    crits = [e for e in events if e.get("severity") in ("Critical", "High")]
    lines = [
        f"🔴 Critical/High alerts: {sev_counts.get('Critical', 0)} Critical, {sev_counts.get('High', 0)} High",
    ]
    if crits:
        lines.append("\nMost recent high-severity events:")
        for e in crits[:5]:
            lines.append(f"  • [{e.get('severity')}] {e.get('attack_type')} from {e.get('source_ip')} at {e.get('timestamp','?')[:19]}")
    else:
        lines.append("\nNo Critical or High events in recent history — system looks clean.")
    lines += ["", "Immediate actions for Critical alerts:", "  1. Verify the source IP is not a legitimate host (check Whitelist)", "  2. Review the event evidence panel for forensic details", "  3. Confirm the block is active on the Blocked IPs page"]
    return "\n".join(lines)


def _answer_top_attackers(top_ips, total) -> str:
    if not top_ips:
        return f"No detections recorded yet (total: {total}). Start monitoring to see attacker IPs."
    lines = [f"👾 Top attacker IPs (of {total} total events):"]
    for ip, cnt in top_ips:
        lines.append(f"  • {ip} — {cnt} event(s)")
    lines += ["", "To block any of these manually, go to Blocked IPs → Block IP.", "To exclude a trusted host, add it to the Whitelist."]
    return "\n".join(lines)


def _answer_recommendations(sev_counts, attack_types, health) -> str:
    lines = ["📋 Security recommendations based on current detections:", ""]
    if sev_counts.get("Critical", 0) > 0:
        lines.append(f"  🔴 {sev_counts['Critical']} Critical alert(s) — investigate immediately, do not dismiss")
    if attack_types.get("Brute Force", 0) > 0:
        lines.append("  🔑 Brute Force detected — enforce account lockout + switch SSH to key auth")
    if attack_types.get("SQL Injection", 0) > 0:
        lines.append("  💉 SQL Injection detected — audit application code for raw query construction")
    if attack_types.get("SYN Flood", 0) > 0:
        lines.append("  🌊 SYN Flood detected — enable SYN cookies, consider rate limiting upstream")
    if attack_types.get("Port Scan", 0) > 0:
        lines.append("  🔭 Port Scan detected — expect follow-up exploitation; close unused ports now")
    if health != -1 and health < 70:
        lines.append(f"  📉 Health score is {health}/100 — review Settings thresholds and rule sensitivity")
    if not lines[2:]:
        lines.append("  ✅ No critical patterns detected in recent history. Keep monitoring active.")
    lines += ["", "Long-term: enable all 8 detection rules, review logs daily, maintain an up-to-date whitelist."]
    return "\n".join(lines)


def _answer_rules(attack_types, total) -> str:
    rules = [
        ("SYN_FLOOD_001",    "SYN Flood",    attack_types.get("SYN Flood", 0)),
        ("PORT_SCAN_001",    "Port Scan",    attack_types.get("Port Scan", 0)),
        ("SQL_INJECTION_001","SQL Injection",attack_types.get("SQL Injection", 0)),
        ("BRUTE_FORCE_001",  "Brute Force",  attack_types.get("Brute Force", 0)),
        ("ARP_SPOOF_001",    "ARP Spoofing", attack_types.get("ARP Spoofing", 0)),
        ("ICMP_FLOOD_001",   "ICMP Flood",   attack_types.get("ICMP Flood", 0)),
        ("SLOW_HTTP_001",    "Slow HTTP",    attack_types.get("Slow HTTP", 0)),
        ("DNS_TUNNEL_001",   "DNS Tunneling",attack_types.get("DNS Tunneling", 0)),
    ]
    lines = [f"📏 8 detection rules active — {total} total event(s) detected:", ""]
    for rid, name, cnt in rules:
        bar = "●" * min(cnt, 10) if cnt > 0 else "○"
        lines.append(f"  {rid:<20} {name:<18} {cnt:>4} hit(s)  {bar}")
    lines += ["", "Adjust thresholds for any rule in Settings."]
    return "\n".join(lines)


def _answer_monitoring(monitoring) -> str:
    if monitoring:
        return (
            "📡 Monitoring is currently ACTIVE.\n\n"
            "NetGuard is capturing live packets and evaluating all 8 detection rules in real time.\n"
            "Use the Stop button on the Dashboard to halt capture.\n\n"
            "Tip: If the interface selector shows no interfaces, try clicking '🔄 Refresh Interfaces'."
        )
    return (
        "⏹ Monitoring is currently STOPPED.\n\n"
        "To start:\n"
        "  1. Select a network interface from the dropdown on the Dashboard\n"
        "  2. Click '▶ Start Monitoring'\n\n"
        "On Windows, Scapy requires Npcap (https://npcap.com) to be installed.\n"
        "If monitoring stops immediately, check the system logs for capture errors."
    )


def _answer_summary(total, sev_counts, attack_types, top_ips, health, monitoring) -> str:
    mon_str    = "✅ Active" if monitoring else "⏹ Stopped"
    health_str = f"{health}/100" if health != -1 else "N/A"
    crit = sev_counts.get("Critical", 0)
    high = sev_counts.get("High", 0)
    med  = sev_counts.get("Medium", 0)
    low  = sev_counts.get("Low", 0)

    top_attack = max(attack_types, key=attack_types.get) if attack_types else "None"

    lines = [
        "📊 NetGuard Security Summary",
        "─" * 36,
        f"  Monitoring    : {mon_str}",
        f"  Health Score  : {health_str}",
        f"  Total Events  : {total}",
        f"  Critical      : {crit}  High: {high}  Medium: {med}  Low: {low}",
        f"  Top Attack    : {top_attack}",
    ]
    if top_ips:
        lines.append(f"  Top Source IP : {top_ips[0][0]} ({top_ips[0][1]} events)")
    lines += [
        "",
        "Ask me about: 'top attackers', 'critical alerts', 'recommendations',",
        "  'SYN Flood', 'brute force', 'health score', 'monitoring', 'rules'…",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def _safe_events(event_repo, limit=20) -> list:
    if not event_repo:
        return []
    try:
        return event_repo.get_all(filters={}, limit=limit, offset=0) or []
    except Exception:
        return []


def _safe_health(stats_svc) -> int:
    if not stats_svc:
        return -1
    try:
        return stats_svc.get_health_score()
    except Exception:
        return -1


def _safe_monitoring(stats_svc) -> bool:
    if not stats_svc:
        return False
    try:
        return stats_svc._state.active
    except Exception:
        return False


def _count_severities(events) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for e in events:
        sev = e.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1
    return counts


def _count_attack_types(events) -> dict:
    counts: dict = {}
    for e in events:
        at = e.get("attack_type", "Unknown")
        counts[at] = counts.get(at, 0) + 1
    return counts


def _top_ips(events, n=3) -> list:
    counts: dict = {}
    for e in events:
        ip = e.get("source_ip", "")
        if ip:
            counts[ip] = counts.get(ip, 0) + 1
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]
