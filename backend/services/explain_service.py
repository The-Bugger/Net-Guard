"""
explain_service.py — Explainability_Engine for NetGuard IDPS.

Converts every ThreatEvent into a human-readable Explanation object within 50 ms.
Every alert produced by NetGuard must be explainable — this is the project's
core differentiator over black-box IDS tools.

Design:
- Uses attack-type-specific templates for plain_english_text
- Appends whitelist annotation when source IP is whitelisted
- Returns fallback Explanation on any exception (never raises to caller)
- Always produces non-null, non-empty plain_english_text (≤ 500 chars)
- confidence_score always in [0, 100]
- severity always one of: Low, Medium, High, Critical

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8, 10.9, 10.10
"""

from __future__ import annotations

import logging
from typing import Optional

from detection.rules.base_rule import Explanation, ThreatEvent

logger = logging.getLogger("netguard.explainability_engine")

# ---------------------------------------------------------------------------
# Severity validation
# ---------------------------------------------------------------------------

_VALID_SEVERITIES = frozenset({"Low", "Medium", "High", "Critical"})

# ---------------------------------------------------------------------------
# Per-attack-type recommendations (Requirement 10.4)
# ---------------------------------------------------------------------------

_RECOMMENDATIONS: dict[str, str] = {
    "SYN Flood": (
        "Investigate the source host and verify whether the traffic is legitimate."
    ),
    "Port Scan": (
        "Review exposed services and verify firewall rules."
    ),
    "SQL Injection": (
        "Inspect application logs and validate input sanitization on affected endpoints."
    ),
    "Brute Force": (
        "Enable account lockout policies and review authentication logs."
    ),
    "ARP Spoofing": (
        "Verify gateway configuration and inspect network devices for unauthorized ARP entries."
    ),
}

_DEFAULT_RECOMMENDATION = "Review the incident and consult your security team."

# Phrase appended when IP is whitelisted (Requirement 10.5)
_WHITELIST_ANNOTATION = "Whitelisted device — monitoring only, no block applied."


# ---------------------------------------------------------------------------
# ExplainabilityEngine
# ---------------------------------------------------------------------------

class ExplainabilityEngine:
    """
    Generates human-readable Explanation objects for every ThreatEvent.

    Usage::

        engine = ExplainabilityEngine(whitelist_manager)
        explanation = engine.explain(threat_event)
    """

    def __init__(self, whitelist_manager=None) -> None:
        """
        Args:
            whitelist_manager: Optional WhitelistManager instance used to check
                               if a source IP is whitelisted. If None, no
                               whitelist annotation is added.
        """
        self._whitelist_manager = whitelist_manager

    def explain(self, event: ThreatEvent) -> Explanation:
        """
        Generate a plain-English Explanation for the given ThreatEvent.

        Always returns an Explanation — never raises.  On any internal error,
        returns a safe fallback Explanation (Requirement 10.10).

        Args:
            event: The ThreatEvent to explain.

        Returns:
            A fully populated Explanation object.
        """
        try:
            return self._explain_internal(event)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "ExplainabilityEngine: failed to explain event %s — %s: %s",
                getattr(event, "event_id", "?"),
                type(exc).__name__,
                exc,
                exc_info=True,
            )
            return self._fallback_explanation(event)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _explain_internal(self, event: ThreatEvent) -> Explanation:
        """Internal explain — may raise; outer explain() catches all exceptions."""
        text = self._build_text(event)

        # Append whitelist annotation if applicable (Requirement 10.5)
        is_whitelisted = self._check_whitelist(event.source_ip)
        if is_whitelisted:
            text = text.rstrip(" .")
            if text:
                text += ". " + _WHITELIST_ANNOTATION
            else:
                text = _WHITELIST_ANNOTATION

        # Enforce max length (Requirement 10.3)
        if len(text) > 500:
            text = text[:497] + "..."

        # Ensure non-empty
        if not text.strip():
            text = f"Security event detected from {event.source_ip}."

        recommendation = self._get_recommendation(event.attack_type)

        # Validate severity (Requirement 10.9)
        severity = event.severity if event.severity in _VALID_SEVERITIES else "High"

        # Validate confidence (Requirement 10.8)
        confidence = max(0, min(100, int(event.confidence)))

        return Explanation(
            attack_name=event.attack_type,
            rule_triggered=event.rule_name,
            plain_english_text=text,
            evidence=event.evidence,
            confidence_score=confidence,
            severity=severity,
            recommendation=recommendation,
        )

    def _build_text(self, event: ThreatEvent) -> str:
        """Build the plain_english_text field using attack-type-specific templates."""
        attack = event.attack_type
        src = event.source_ip
        action = "Blocked." if event.blocked else "Monitored — not blocked."

        if attack == "SYN Flood":
            count = event.evidence.get("syn_packet_count", event.packet_count)
            window = event.evidence.get("time_window_seconds", 3)
            threshold = event.evidence.get("threshold", 100)
            return (
                f"Detected {count} SYN packets from {src} within {window}s. "
                f"The threshold of {threshold} was exceeded. {action}"
            )

        if attack == "Port Scan":
            port_count = event.evidence.get("unique_port_count", event.packet_count)
            window = event.evidence.get("time_window_seconds", 10)
            return (
                f"Detected connection attempts to {port_count} unique ports "
                f"from {src} within {window}s. {action}"
            )

        if attack == "SQL Injection":
            pattern = event.evidence.get("matched_pattern", "SQL pattern")
            dst = event.evidence.get("destination_ip", event.destination_ip or "")
            url = event.evidence.get("request_url", "")
            url_part = f" ({url})" if url else ""
            return (
                f"Detected SQL injection pattern '{pattern}' in HTTP request "
                f"from {src} to {dst}{url_part}. {action}"
            )

        if attack == "Brute Force":
            count = event.evidence.get("failure_count", event.packet_count)
            window = event.evidence.get("time_window_seconds", 60)
            service = event.evidence.get("target_service", "Unknown")
            return (
                f"Detected {count} authentication failures from {src} "
                f"within {window}s targeting {service}. {action}"
            )

        if attack == "ARP Spoofing":
            ip = event.evidence.get("conflicting_ip", src)
            macs = event.evidence.get("conflicting_macs", [])
            macs_str = ", ".join(macs) if macs else "multiple MAC addresses"
            return (
                f"Detected conflicting ARP responses for IP {ip}: "
                f"MAC addresses {macs_str}. {action}"
            )

        # Generic fallback for unknown attack types
        return (
            f"Security event detected from {src} — "
            f"rule {event.rule_name} triggered. {action}"
        )

    def _get_recommendation(self, attack_type: str) -> str:
        """Return the attack-type-specific recommendation string (Requirement 10.4)."""
        return _RECOMMENDATIONS.get(attack_type, _DEFAULT_RECOMMENDATION)

    def _check_whitelist(self, ip: str) -> bool:
        """Return True if the IP is on the whitelist."""
        if self._whitelist_manager is None:
            return False
        try:
            return bool(self._whitelist_manager.is_whitelisted(ip))
        except Exception:
            return False

    def _fallback_explanation(self, event: ThreatEvent) -> Explanation:
        """
        Return a safe fallback Explanation when the normal path fails (Requirement 10.10).
        """
        severity = event.severity if event.severity in _VALID_SEVERITIES else "High"
        confidence = max(0, min(100, int(getattr(event, "confidence", 50))))

        return Explanation(
            attack_name=getattr(event, "attack_type", "Unknown"),
            rule_triggered=getattr(event, "rule_name", "UNKNOWN"),
            plain_english_text=(
                "A security event was detected. "
                "Details unavailable due to an internal error."
            ),
            evidence=getattr(event, "evidence", {}),
            confidence_score=confidence,
            severity=severity,
            recommendation=_DEFAULT_RECOMMENDATION,
        )
