"""
sql_injection.py — SQL Injection Detection Rule for NetGuard IDPS.

Module purpose:
    Detects SQL injection payloads in HTTP traffic by case-insensitive
    pattern matching on the raw TCP payload of packets destined for HTTP
    ports (80, 443, 8080, 8443).

Detection logic:
    - Inspect TCP payload of HTTP packets using pre-compiled regex patterns
    - Five canonical patterns: ``' OR``, ``UNION SELECT``, ``DROP TABLE``,
      ``--``, ``xp_cmdshell``
    - Match is performed against the URL path, query string, and request body
    - First detection from a source IP → severity ``High``
    - Subsequent detections from the same source IP → severity ``Critical``
    - Confidence is always ``100`` — a single matching payload is definitive
    - No minimum packet count; a single matching payload triggers detection

Architecture role:
    One of five detection rules consumed by ``DetectionEngine``.  Implements
    the ``BaseRule`` interface.  Produces ``ThreatEvent`` objects that are
    forwarded to ``ExplainabilityEngine`` then ``LoggingEngine``.

Dependencies:
    - ``detection.parsers.packet_decoder.Packet`` — normalised packet input
    - ``detection.rules.base_rule.BaseRule`` — abstract rule interface
    - ``detection.rules.base_rule.ThreatEvent`` — output event type
    - ``detection.rules.base_rule.Explanation`` — explanation output type

Related modules:
    - ``detection/rules/syn_flood.py``    — volumetric detection
    - ``detection/rules/brute_force.py``  — auth failure detection
    - ``backend/services/detection_service.py`` — rule orchestration

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6

Example:
    >>> rule = SqlInjectionRule()
    >>> rule.initialize()
    >>> pkt = Packet(dst_port=80, protocol="TCP",
    ...              payload=b"GET /search?q=UNION SELECT 1 HTTP/1.1\\r\\n\\r\\n",
    ...              src_ip="10.0.0.1", ...)
    >>> rule.process_packet(pkt)
    >>> event = rule.evaluate()
    >>> event.attack_type
    'SQL Injection'
    >>> event.confidence
    100
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

# HTTP ports to inspect (80 and 443 per requirements 6.1; 8080/8443 added for coverage)
_HTTP_PORTS = {80, 443, 8080, 8443}

# SQL injection detection patterns (case-insensitive) as (label, compiled_pattern) pairs.
# Pattern labels are the exact strings referenced in Requirement 6.1.
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
        # Track which source IPs have previously triggered this rule (Req 6.2, 6.3)
        self._seen_ips: set[str] = set()
        # Queue of pending ThreatEvent objects; evaluate() pops the first one
        self._pending: list[ThreatEvent] = []

    def initialize(self) -> None:
        """Reset all state."""
        self._seen_ips.clear()
        self._pending.clear()
        logger.debug("SqlInjectionRule initialised.")

    def process_packet(self, packet: Packet) -> None:
        """
        Inspect HTTP packets for SQL injection patterns.

        Appends a ThreatEvent to self._pending if a match is found;
        evaluate() pops and returns it.

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
            payload_str = packet.payload.decode("utf-8", errors="ignore")
        except Exception:
            return

        # Extract HTTP method and URL from the request line
        http_method, request_url = _parse_http_request_line(payload_str)

        # Search in URL path + query string + body
        matched_pattern = _find_sql_pattern(payload_str)
        if matched_pattern is None:
            return

        # Determine severity based on whether this source IP has been seen before
        src = packet.src_ip
        if src in self._seen_ips:
            severity = "Critical"
        else:
            severity = "High"
        # Mark IP as seen before creating the event so next call escalates correctly
        self._seen_ips.add(src)

        evidence = {
            "source_ip": src,
            "destination_ip": packet.dst_ip,
            "http_method": http_method,
            "request_url": request_url,
            "matched_pattern": matched_pattern,
        }

        event = ThreatEvent(
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
        self._pending.append(event)

    def evaluate(self) -> Optional[ThreatEvent]:
        """
        Pop and return the first pending ThreatEvent, if any.

        Returns:
            ThreatEvent if a SQL injection was detected, otherwise None.
        """
        if self._pending:
            return self._pending.pop(0)
        return None

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

        url_part = f" ({url})" if url and url != "UNKNOWN" else ""
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
        self._seen_ips.clear()
        self._pending.clear()
        logger.debug("SqlInjectionRule cleaned up.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_sql_pattern(payload: str) -> Optional[str]:
    """Search payload for any SQL injection pattern. Returns pattern label or None."""
    for name, pattern in _SQL_PATTERNS:
        if pattern.search(payload):
            return name
    return None


def _parse_http_request_line(payload: str) -> tuple[str, Optional[str]]:
    """
    Extract HTTP method and request URL from raw HTTP payload.

    Returns:
        Tuple of (method, url). Returns ("Unknown", None) if not parseable.
    """
    try:
        first_line = payload.split("\r\n", 1)[0].split("\n", 1)[0]
        parts = first_line.split(" ")
        if len(parts) >= 2:
            method = parts[0].upper()
            url = parts[1]
            # Sanitise — keep only printable ASCII
            url = "".join(c for c in url if 32 <= ord(c) < 127)[:500]
            if method and url:
                return method, url
    except Exception:
        pass
    return "Unknown", None


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
