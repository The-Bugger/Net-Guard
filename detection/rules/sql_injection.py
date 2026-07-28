"""
sql_injection.py — SQL Injection detection rule for NetGuard IDPS.

Detects SQL injection payloads in HTTP traffic by pattern matching the
TCP payload of HTTP packets (destination port 80 or 443).

Detection logic:
- Inspect TCP payload of HTTP packets using case-insensitive regex
- Patterns: ' OR, UNION SELECT, DROP TABLE, --, xp_cmdshell
- Match in URL path, query string, or request body
- First detection from an IP → severity High
- Repeated detection from same IP → severity Critical
- Confidence always 100 (single matching payload = definitive evidence)
- No minimum packet count — a single matching payload triggers detection

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from detection.parsers.packet_decoder import Packet
from detection.rules.base_rule import BaseRule, Explanation, ThreatEvent

logger = logging.getLogger("netguard.rule.sql_injection")

_RECOMMENDATION = "Inspect application logs and validate input sanitization on affected endpoints."

# HTTP ports to inspect
_HTTP_PORTS = {80, 443, 8080, 8443}

# SQL injection detection patterns (case-insensitive)
_SQL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("' OR", re.compile(r"'\s*or\b", re.IGNORECASE)),
    ("UNION SELECT", re.compile(r"\bunion\s+select\b", re.IGNORECASE)),
    ("DROP TABLE", re.compile(r"\bdrop\s+table\b", re.IGNORECASE)),
    ("--", re.compile(r"--", re.IGNORECASE)),
    ("xp_cmdshell", re.compile(r"\bxp_cmdshell\b", re.IGNORECASE)),
]


class SqlInjectionRule(BaseRule):
    """
    Detects SQL injection payloads in HTTP request traffic.

    Inspects the raw TCP payload of packets targeting HTTP ports for
    known SQL injection patterns in the URL or request body.
    """

    rule_name: str = "SQL_INJECTION_001"
    attack_type: str = "SQL Injection"

    def __init__(self) -> None:
        self.enabled = True
        # Track which source IPs have previously triggered this rule
        self._previous_triggers: set[str] = set()
        # Last pending event (evaluate returns it once)
        self._pending_event: Optional[ThreatEvent] = None

    def initialize(self) -> None:
        """Reset all state."""
        self._previous_triggers.clear()
        self._pending_event = None
        logger.debug("SqlInjectionRule initialised.")

    def process_packet(self, packet: Packet) -> None:
        """
        Inspect HTTP packets for SQL injection patterns.

        Sets self._pending_event if a match is found; evaluate() returns it.

        Args:
            packet: Normalised packet from PacketDecoder.
        """
        if packet.protocol != "TCP":
            return
        if packet.dst_port not in _HTTP_PORTS:
            return
        if not packet.payload:
            return

        try:
            payload_str = packet.payload.decode("utf-8", errors="replace")
        except Exception:
            return

        # Extract HTTP method and URL from the request line
        http_method, request_url = _parse_http_request_line(payload_str)

        # Search in URL path + query string + body
        matched_pattern = _find_sql_pattern(payload_str)
        if matched_pattern is None:
            return

        # Determine severity
        src = packet.src_ip
        if src in self._previous_triggers:
            severity = "Critical"
        else:
            severity = "High"

        evidence = {
            "source_ip": src,
            "destination_ip": packet.dst_ip,
            "http_method": http_method,
            "request_url": request_url,
            "matched_pattern": matched_pattern,
        }

        self._pending_event = ThreatEvent(
            event_id=str(uuid.uuid4()),
            timestamp=_utc_now(),
            attack_type=self.attack_type,
            source_ip=src,
            destination_ip=packet.dst_ip,
            source_port=packet.src_port,
            destination_port=packet.dst_port,
            protocol="TCP",
            rule_name=self.rule_name,
            severity=severity,
            confidence=100,
            packet_count=1,
            evidence=evidence,
        )
        self._previous_triggers.add(src)

    def evaluate(self) -> Optional[ThreatEvent]:
        """
        Return and clear any pending ThreatEvent.

        Returns:
            ThreatEvent if a SQL injection was detected, otherwise None.
        """
        event = self._pending_event
        self._pending_event = None
        return event

    def generate_event(self) -> ThreatEvent:
        raise NotImplementedError("Use process_packet() + evaluate().")

    def explain(self, event: ThreatEvent) -> Explanation:
        """
        Generate a plain-English explanation for a SQL Injection ThreatEvent.

        Args:
            event: The ThreatEvent to explain.

        Returns:
            Populated Explanation object.
        """
        pattern = event.evidence.get("matched_pattern", "unknown pattern")
        dst_ip = event.evidence.get("destination_ip", event.destination_ip or "")
        url = event.evidence.get("request_url", "")
        action = "Blocked." if event.blocked else "Monitoring."

        url_part = f" ({url})" if url else ""
        text = (
            f"Detected SQL injection pattern '{pattern}' in HTTP request "
            f"from {event.source_ip} to {dst_ip}{url_part}. {action}"
        )
        if len(text) > 500:
            text = text[:497] + "..."

        return Explanation(
            attack_name=self.attack_type,
            rule_triggered=self.rule_name,
            plain_english_text=text,
            evidence=event.evidence,
            confidence_score=100,
            severity=event.severity,
            recommendation=_RECOMMENDATION,
        )

    def cleanup(self) -> None:
        """Release all state."""
        self._previous_triggers.clear()
        self._pending_event = None
        logger.debug("SqlInjectionRule cleaned up.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_sql_pattern(payload: str) -> Optional[str]:
    """Search payload for any SQL injection pattern. Returns pattern name or None."""
    for name, pattern in _SQL_PATTERNS:
        if pattern.search(payload):
            return name
    return None


def _parse_http_request_line(payload: str) -> tuple[str, str]:
    """
    Extract HTTP method and request URL from raw HTTP payload.

    Returns:
        Tuple of (method, url). Both empty strings if not parseable.
    """
    try:
        first_line = payload.split("\r\n", 1)[0].split("\n", 1)[0]
        parts = first_line.split(" ")
        if len(parts) >= 2:
            method = parts[0].upper()
            url = parts[1]
            # Sanitise — keep only printable ASCII
            url = "".join(c for c in url if 32 <= ord(c) < 127)[:500]
            return method, url
    except Exception:
        pass
    return "", ""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
