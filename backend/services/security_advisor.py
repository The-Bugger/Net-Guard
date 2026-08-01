"""
security_advisor.py — Offline Security Advisor for NetGuard IDPS.

Returns contextual security advice keyed to the current health score tier.
Optionally delegates to the Gemini REST API when GEMINI_API_KEY is set;
silently falls back to the offline knowledge base on any error (including timeout).

Uses urllib.request — no new dependency needed.

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Optional

logger = logging.getLogger("netguard.security_advisor")

# Badge color boundaries (Req 9.5, 10.5)
_TIER_COLORS = [
    (80, 100, "green"),
    (60,  79, "yellow"),
    (40,  59, "orange"),
    (0,   39, "red"),
]


def _badge_color(score: int) -> str:
    """Return badge color string for score. Clamps to [0, 100] first."""
    s = max(0, min(100, score))
    for lo, hi, color in _TIER_COLORS:
        if lo <= s <= hi:
            return color
    return "red"  # unreachable after clamp, but keeps mypy happy


class SecurityAdvisor:
    """
    Offline rule-based security advisor with optional Gemini fallback.

    Knowledge base: ≥ 25 entries across four tiers (green/yellow/orange/red).
    Attack advice:  per-attack-type supplemental actions for all 5 known types.
    """

    # ------------------------------------------------------------------
    # Knowledge base — 5+ entries per tier, 25 total                    (Req 10.2)
    # Fields: min_score, max_score, title, message, actions
    # ------------------------------------------------------------------

    _KNOWLEDGE_BASE: list[dict] = [
        # ── GREEN tier (80–100) — 5 entries ──────────────────────────
        {
            "min_score": 95, "max_score": 100,
            "title": "Excellent Security Posture",
            "message": (
                "Your network is operating at peak security health. "
                "No attack types have been detected today. "
                "Maintain this posture through consistent monitoring and hygiene."
            ),
            "actions": [
                "Continue routine monitoring with NetGuard running 24/7.",
                "Review and rotate service account credentials monthly.",
                "Verify firewall rule sets are current and minimal.",
                "Schedule a quarterly penetration test to validate defences.",
            ],
        },
        {
            "min_score": 88, "max_score": 94,
            "title": "Strong Security Posture",
            "message": (
                "Your environment is well-defended. Minor deductions reflect "
                "low-severity activity. Stay alert and keep systems patched."
            ),
            "actions": [
                "Apply any outstanding OS and application security patches.",
                "Review NetGuard alerts from the past 7 days for patterns.",
                "Confirm backup procedures are running and restore is tested.",
            ],
        },
        {
            "min_score": 80, "max_score": 87,
            "title": "Good Security Posture",
            "message": (
                "Security health is good. Some low-level activity was detected. "
                "Investigate recent alerts and verify no active threats are lurking."
            ),
            "actions": [
                "Inspect the event timeline for any recurring source IPs.",
                "Ensure IDS/IPS signatures are up to date.",
                "Audit user privilege levels — remove unnecessary admin rights.",
                "Review network segmentation to limit blast radius of any breach.",
            ],
        },
        {
            "min_score": 80, "max_score": 100,
            "title": "Monitoring Continuity — Keep Watching",
            "message": (
                "No immediate threats detected. Sustained vigilance is the best "
                "defence against zero-day incidents."
            ),
            "actions": [
                "Keep packet capture running on all active interfaces.",
                "Set up alerts for off-hours monitoring anomalies.",
                "Review log retention policy — ensure ≥ 90 days of event logs.",
            ],
        },
        {
            "min_score": 80, "max_score": 100,
            "title": "Patch Cadence Check",
            "message": (
                "While the score is healthy, unpatched systems are a silent risk. "
                "Verify patch cadence is met for all critical assets."
            ),
            "actions": [
                "Run vulnerability scanner against hosts on the monitored LAN.",
                "Check vendor security bulletins for all installed software.",
                "Confirm auto-update policies are enabled on endpoints.",
                "Document patch exceptions with a remediation timeline.",
            ],
        },

        # ── YELLOW tier (60–79) — 5 entries ──────────────────────────
        {
            "min_score": 72, "max_score": 79,
            "title": "Elevated Vigilance Required",
            "message": (
                "One or two attack types have been detected today. "
                "The environment is under mild pressure. "
                "Investigate the affected systems and harden exposed services."
            ),
            "actions": [
                "Review today's alerts in detail — identify the source IPs.",
                "Confirm affected services are patched and not running default credentials.",
                "Increase log verbosity on targeted hosts temporarily.",
                "Notify the on-call security analyst of elevated activity.",
            ],
        },
        {
            "min_score": 65, "max_score": 71,
            "title": "Recent Alert Review Recommended",
            "message": (
                "Multiple alerts have been generated today. "
                "Review the evidence for each detection to prioritise response."
            ),
            "actions": [
                "Triage alerts by severity — address Critical and High first.",
                "Cross-reference source IPs with known threat intelligence feeds.",
                "Verify no unauthorised user accounts have been created.",
                "Check for lateral movement indicators in internal traffic logs.",
            ],
        },
        {
            "min_score": 60, "max_score": 64,
            "title": "Hardening Recommendations Active",
            "message": (
                "Score is approaching the orange threshold. "
                "Implement hardening measures on services receiving repeated probes."
            ),
            "actions": [
                "Disable unused network services and ports.",
                "Enable multi-factor authentication on all remote access services.",
                "Apply network access control (NAC) to quarantine suspect devices.",
                "Increase IDS sensitivity to catch low-and-slow attack patterns.",
            ],
        },
        {
            "min_score": 60, "max_score": 79,
            "title": "Log Retention Increase",
            "message": (
                "Elevated activity warrants extended log retention for forensic purposes. "
                "Ensure all relevant logs are being captured and stored."
            ),
            "actions": [
                "Extend system log retention to at least 180 days.",
                "Enable full packet capture on suspicious source subnets.",
                "Back up current event database before any remediation steps.",
            ],
        },
        {
            "min_score": 60, "max_score": 79,
            "title": "Perimeter Review",
            "message": (
                "Attacks are probing your perimeter. "
                "Validate that ingress filtering rules are tight and effective."
            ),
            "actions": [
                "Audit inbound firewall rules — remove permissive catch-all rules.",
                "Verify egress filtering is in place to prevent data exfiltration.",
                "Review rate limiting on all public-facing services.",
                "Test intrusion response procedures with a tabletop exercise.",
            ],
        },

        # ── ORANGE tier (40–59) — 5 entries ──────────────────────────
        {
            "min_score": 50, "max_score": 59,
            "title": "Active Incident Response Required",
            "message": (
                "Multiple attack types detected today. "
                "This score indicates an active threat. "
                "Begin incident response procedures immediately."
            ),
            "actions": [
                "Activate the incident response runbook.",
                "Isolate the highest-risk hosts from the LAN.",
                "Block confirmed attacker IPs at the upstream firewall.",
                "Document all observed indicators of compromise (IOCs).",
                "Preserve forensic evidence — do not reboot affected systems.",
            ],
        },
        {
            "min_score": 45, "max_score": 49,
            "title": "Escalation Guidance",
            "message": (
                "The threat level warrants escalation to senior security personnel "
                "or a managed security service provider (MSSP). "
                "Do not attempt to contain a multi-vector attack alone."
            ),
            "actions": [
                "Escalate to security manager or CISO immediately.",
                "Engage MSSP or incident response retainer if available.",
                "Notify legal and compliance teams of potential data exposure.",
                "Prepare a preliminary incident report for stakeholders.",
            ],
        },
        {
            "min_score": 40, "max_score": 44,
            "title": "Network Segmentation Review",
            "message": (
                "At this score, lateral movement between segments is a real risk. "
                "Review and tighten network segmentation rules now."
            ),
            "actions": [
                "Verify VLAN boundaries are enforced and not bridged.",
                "Block inter-segment traffic that is not business-justified.",
                "Deploy honeypots on critical VLANs to detect lateral probing.",
                "Reassess firewall zone policies between DMZ and internal segments.",
            ],
        },
        {
            "min_score": 40, "max_score": 59,
            "title": "Credential Rotation",
            "message": (
                "With active attacks detected, credentials on targeted systems "
                "should be rotated as a precaution against credential harvesting."
            ),
            "actions": [
                "Rotate passwords and API keys on all internet-facing services.",
                "Revoke and reissue SSH keys for administrative accounts.",
                "Invalidate active sessions on targeted web applications.",
                "Enable login anomaly alerts in your identity provider.",
            ],
        },
        {
            "min_score": 40, "max_score": 59,
            "title": "Containment Preparation",
            "message": (
                "Prepare containment actions in case the score degrades further. "
                "Pre-stage isolation procedures so they can be executed within minutes."
            ),
            "actions": [
                "Identify which hosts can be isolated without service disruption.",
                "Pre-draft iptables DROP rules for rapid deployment.",
                "Ensure out-of-band management access is available for critical hosts.",
                "Test network kill-switch procedures in a staging environment.",
            ],
        },

        # ── RED tier (0–39) — 5 entries ──────────────────────────────
        {
            "min_score": 20, "max_score": 39,
            "title": "Immediate Containment Required",
            "message": (
                "Critical threat level. Multiple high-severity attack types active. "
                "Execute full containment procedures without delay."
            ),
            "actions": [
                "Immediately isolate all hosts showing signs of compromise.",
                "Apply emergency iptables DROP rules for all attacker source IPs.",
                "Disable internet access for compromised network segments.",
                "Alert all system owners and activate the crisis response team.",
                "Capture memory dumps and disk images for forensic analysis.",
            ],
        },
        {
            "min_score": 10, "max_score": 19,
            "title": "Forensics Initiation",
            "message": (
                "The network is under severe attack. "
                "Forensic evidence collection must begin immediately "
                "alongside containment to preserve the chain of custody."
            ),
            "actions": [
                "Engage a digital forensics and incident response (DFIR) firm.",
                "Preserve raw packet captures with timestamps for legal evidence.",
                "Document every action taken with timestamps for the incident log.",
                "Take offline snapshots of affected VM/cloud instances.",
            ],
        },
        {
            "min_score": 0, "max_score": 9,
            "title": "Full Lockdown — Maximum Severity",
            "message": (
                "Network health is critically low. "
                "All known attack categories are active. "
                "Initiate full lockdown and stakeholder notification protocol."
            ),
            "actions": [
                "Disconnect affected network segments from the internet immediately.",
                "Invoke the organisation's business continuity plan (BCP).",
                "Notify executive leadership and legal counsel without delay.",
                "File a formal incident report with relevant regulatory bodies.",
                "Do not restore services until a clean forensic baseline is confirmed.",
            ],
        },
        {
            "min_score": 0, "max_score": 39,
            "title": "Stakeholder Notification",
            "message": (
                "At this threat level, stakeholders must be informed. "
                "Silence is not an option — internal and external communication "
                "is a critical part of the incident response process."
            ),
            "actions": [
                "Send internal all-hands security alert to affected departments.",
                "Prepare customer-facing communication if data exposure is possible.",
                "Coordinate with PR team on external messaging strategy.",
                "Brief board or senior management within 1 hour of declaration.",
            ],
        },
        {
            "min_score": 0, "max_score": 39,
            "title": "Post-Incident Recovery Planning",
            "message": (
                "While containment is underway, begin parallel planning for recovery. "
                "Restoring from clean backups is often the fastest path to normal operations."
            ),
            "actions": [
                "Identify clean backup snapshots taken before the attack onset.",
                "Rebuild compromised hosts from trusted gold images.",
                "Re-harden rebuilt systems before returning them to production.",
                "Conduct a post-mortem within 72 hours of containment.",
                "Update playbooks based on lessons learned from this incident.",
            ],
        },
    ]

    # ------------------------------------------------------------------
    # Per-attack-type supplemental actions                               (Req 10.2)
    # ------------------------------------------------------------------

    _ATTACK_ADVICE: dict[str, list[str]] = {
        "SYN Flood": [
            "Enable SYN cookies on all internet-facing servers to absorb flood traffic.",
            "Configure upstream router to rate-limit TCP SYN packets per source IP.",
            "Engage upstream ISP for traffic scrubbing or null-route of attacker IP.",
            "Verify that all load balancers have half-open connection limits set.",
        ],
        "Port Scan": [
            "Block the scanning source IP at the firewall immediately.",
            "Review which ports are visible externally — close anything not needed.",
            "Enable port-scan detection in the firewall and set auto-block threshold.",
            "Investigate whether the scan was followed by an exploitation attempt.",
        ],
        "SQL Injection": [
            "Review web application firewall (WAF) rules for SQL injection patterns.",
            "Audit all application query builders for parameterised query usage.",
            "Check application logs for successful injection attempts or data reads.",
            "Run OWASP ZAP or SQLMap in audit mode against the targeted application.",
        ],
        "Brute Force": [
            "Implement account lockout after 5 failed attempts on targeted services.",
            "Enable geo-blocking for SSH/RDP if remote access from abroad is unexpected.",
            "Add CAPTCHA or MFA challenge to login endpoints under attack.",
            "Review authentication logs for any successful logins from the attacker IP.",
        ],
        "ARP Spoofing": [
            "Enable Dynamic ARP Inspection (DAI) on managed switches.",
            "Add static ARP entries for critical infrastructure (gateway, DNS).",
            "Investigate the source MAC for rogue device on the local segment.",
            "Use 802.1X port authentication to prevent unapproved devices joining the LAN.",
        ],
    }

    # ------------------------------------------------------------------
    # Gemini REST endpoint (no SDK required)
    # ponytail: raw REST call — upgrade to SDK once google-generativeai is added
    # ------------------------------------------------------------------

    _GEMINI_URL = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-pro:generateContent?key={api_key}"
    )
    _GEMINI_TIMEOUT = 10  # seconds (Req 10.3)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def advise(
        self,
        health_score: int,
        detected_attack_types: list[str],
    ) -> dict:
        """
        Return a security advice dict for the given score and attack types.

        1. Try Gemini if GEMINI_API_KEY is set; log WARNING and fall through on any error.
        2. Select the best matching knowledge-base entry for health_score.
        3. Append per-attack-type supplemental actions.
        4. Return {score, badge_color, title, message, actions}.

        Req 10.1, 10.3, 10.4, 10.5
        """
        api_key: Optional[str] = os.environ.get("GEMINI_API_KEY", "").strip() or None

        if api_key:
            result = self._try_gemini(health_score, detected_attack_types, api_key)
            if result is not None:
                return result

        return self._offline(health_score, detected_attack_types)

    # ------------------------------------------------------------------
    # Gemini path (Req 10.3, 10.4)
    # ------------------------------------------------------------------

    def _try_gemini(
        self,
        health_score: int,
        detected_attack_types: list[str],
        api_key: str,
    ) -> Optional[dict]:
        """
        Call Gemini REST API. Returns a valid advice dict on success, None on any failure.
        Logs WARNING on failure — never raises.
        """
        try:
            prompt = self._build_gemini_prompt(health_score, detected_attack_types)
            payload = json.dumps({
                "contents": [{"parts": [{"text": prompt}]}]
            }).encode()

            url = self._GEMINI_URL.format(api_key=api_key)
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=self._GEMINI_TIMEOUT) as resp:
                raw = json.loads(resp.read().decode())

            text = (
                raw.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
            )
            if not text:
                raise ValueError("Empty Gemini response text")

            return self._parse_gemini_response(text, health_score, detected_attack_types)

        except Exception as exc:  # noqa: BLE001
            logger.warning("Gemini advisor failed (%s) — using offline fallback", exc)
            return None

    @staticmethod
    def _build_gemini_prompt(health_score: int, attack_types: list[str]) -> str:
        types_str = ", ".join(attack_types) if attack_types else "none"
        return (
            f"You are a network security advisor. "
            f"The current security health score is {health_score}/100. "
            f"Attack types detected today: {types_str}. "
            "Respond in JSON with keys: title (str), message (str), actions (list of str). "
            "Provide concise, actionable advice."
        )

    def _parse_gemini_response(
        self,
        text: str,
        health_score: int,
        detected_attack_types: list[str],
    ) -> Optional[dict]:
        """
        Extract JSON from Gemini text. Returns valid advice dict or None on parse failure.
        Strips markdown code fences if present.
        """
        try:
            # Strip ```json ... ``` fences if present
            stripped = text.strip()
            if stripped.startswith("```"):
                lines = stripped.splitlines()
                stripped = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])

            data = json.loads(stripped)
            title = str(data.get("title", "")).strip()
            message = str(data.get("message", "")).strip()
            actions = [str(a) for a in data.get("actions", []) if a]

            if not title or not message or not actions:
                raise ValueError("Gemini JSON missing required fields")

            # Append per-attack supplemental actions
            for attack in detected_attack_types:
                actions.extend(self._ATTACK_ADVICE.get(attack, []))

            return {
                "score": health_score,
                "badge_color": _badge_color(health_score),
                "title": title,
                "message": message,
                "actions": actions,
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("Gemini response parse failed (%s) — using offline fallback", exc)
            return None

    # ------------------------------------------------------------------
    # Offline path (Req 10.2, 10.5)
    # ------------------------------------------------------------------

    def _offline(self, health_score: int, detected_attack_types: list[str]) -> dict:
        """
        Select the best knowledge-base entry and append per-attack-type actions.

        Selection: find entries whose [min_score, max_score] contains health_score,
        pick the one with the highest min_score (most specific). If none match —
        which cannot happen for scores in [0, 100] given the ranges above — fall
        back to the red-tier default.

        ponytail: O(n) scan over ≤ 25 entries — acceptable for this KB size.
        """
        score = max(0, min(100, health_score))
        matches = [e for e in self._KNOWLEDGE_BASE if e["min_score"] <= score <= e["max_score"]]

        if not matches:
            # Defensive fallback — should be unreachable with full tier coverage
            entry = self._KNOWLEDGE_BASE[-1]
        else:
            entry = max(matches, key=lambda e: e["min_score"])

        actions = list(entry["actions"])  # copy — don't mutate the class-level list
        for attack in detected_attack_types:
            actions.extend(self._ATTACK_ADVICE.get(attack, []))

        return {
            "score": score,
            "badge_color": _badge_color(score),
            "title": entry["title"],
            "message": entry["message"],
            "actions": actions,
        }


# ---------------------------------------------------------------------------
# Self-check: verify the offline path returns all 5 required keys at each tier.
# ponytail: inline assert — fails loudly on import if the KB is malformed.
# ---------------------------------------------------------------------------

_advisor = SecurityAdvisor()
for _test_score, _expected_color in [(100, "green"), (70, "yellow"), (50, "orange"), (20, "red")]:
    _result = _advisor.advise(_test_score, [])
    assert set(_result.keys()) == {"score", "badge_color", "title", "message", "actions"}, (
        f"advise({_test_score}) returned unexpected keys: {set(_result.keys())}"
    )
    assert _result["badge_color"] == _expected_color, (
        f"advise({_test_score}) badge_color={_result['badge_color']!r}, expected {_expected_color!r}"
    )
    assert isinstance(_result["actions"], list) and _result["actions"], (
        f"advise({_test_score}) returned empty actions list"
    )
del _advisor, _test_score, _expected_color, _result
