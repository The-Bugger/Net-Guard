"""
brute_force.py — Brute Force Login detection rule for NetGuard IDPS.

Detects credential-stuffing and password-spraying attacks by tracking
repeated authentication failure indicators per source IP within a
configurable sliding time window.

Detection logic:
- Track TCP packets to SSH (port 22), HTTP (port 80/443), and FTP (port 21) per source IP
- Emit ThreatEvent when failure count >= configured threshold within the window
- Severity: 10-19 → Medium, 20-39 → High, ≥40 → Critical
- Confidence: round(min(failure_count/threshold, 2.0) / 2.0 * 100) capped at 100
- Service identified from destination port: "SSH" (22), "HTTP" (80/443), "FTP" (21); "Unknown" otherwise
- 10-second cooldown per source IP; new event only if severity escalates within cooldown window

Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from detection.parsers.packet_decoder import Packet
from detection.rules.base_rule import BaseRule, Explanation, ThreatEvent

logger = logging.getLogger("netguard.rule.brute_force")

_SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
_RECOMMENDATION = "Enable account lockout policies and review authentication logs."

# Port → service name mapping — only the three services specified in Requirement 7.5
# "HTTP" covers both port 80 and 443 (design doc + task 9.11 spec)
SERVICE_PORTS: dict[int, str] = {
    22: "SSH",
    21: "FTP",
    80: "HTTP",
    443: "HTTP",
}

# Ports where we look for auth-failure indicators (TCP only)
_AUTH_PORTS = set(SERVICE_PORTS.keys())


class BruteForceRule(BaseRule):
    """
    Detects brute-force login attempts against SSH, HTTP, and FTP services.

    Monitors connection attempts to authentication ports (SSH port 22,
    HTTP ports 80/443, FTP port 21) from the same source IP within a
    configurable sliding window.  When the attempt count reaches the
    configured threshold a ThreatEvent is emitted.

    Service names in evidence follow the spec:
        "SSH" for port 22, "HTTP" for ports 80 and 443, "FTP" for port 21.
    """

    rule_name: str = "BRUTE_FORCE_001"
    attack_type: str = "Brute Force"

    # Class-level alias so callers can inspect the supported ports without
    # needing to reach into the module-level constant.
    SERVICE_PORTS: dict[int, str] = SERVICE_PORTS

    def __init__(
        self,
        threshold: int = 10,
        window_seconds: int = 60,
        cooldown_seconds: int = 10,
    ) -> None:
        """
        Args:
            threshold: Minimum failure count to trigger detection.
            window_seconds: Sliding window duration in seconds.
            cooldown_seconds: Minimum seconds between events for same IP.
        """
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.enabled = True

        # Per-source-IP tracking: src_ip -> deque of (epoch_float, dst_port)
        self._flows: dict[str, deque] = {}
        self._cooldown: dict[str, tuple[str, float]] = {}

    def initialize(self) -> None:
        """Reset all flow state."""
        self._flows.clear()
        self._cooldown.clear()
        logger.debug(
            "BruteForceRule initialised (threshold=%d, window=%ds).",
            self.threshold, self.window_seconds,
        )

    def process_packet(self, packet: Packet) -> None:
        """
        Record a connection attempt from the source IP to an auth port.

        Only processes TCP packets destined for one of the tracked service
        ports: SSH (22), HTTP (80, 443), FTP (21).

        In live capture these connection attempts serve as authentication
        failure proxies; higher-fidelity detection would inspect response
        codes (e.g. HTTP 401, SSH "Permission denied") from reassembled
        streams.

        Args:
            packet: Normalised packet from PacketDecoder.
        """
        if packet.protocol != "TCP":
            return
        if packet.dst_port is None:
            return
        if packet.dst_port not in _AUTH_PORTS:
            return

        src = packet.src_ip
        if src not in self._flows:
            self._flows[src] = deque()

        epoch = _iso_to_epoch(packet.timestamp)
        self._flows[src].append((epoch, packet.dst_port))

    def evaluate(self) -> Optional[ThreatEvent]:
        """
        Check each tracked source IP against the brute force threshold.

        Returns the first ThreatEvent found, or None.
        """
        now_ts = _utc_now()
        cutoff_wall = datetime.now(timezone.utc).timestamp() - self.window_seconds

        for src_ip, dq in list(self._flows.items()):
            # Evict old entries
            while dq and dq[0][0] < cutoff_wall:
                dq.popleft()

            count = len(dq)
            if count < self.threshold:
                continue

            severity = _bf_severity(count)

            # Cooldown check
            if src_ip in self._cooldown:
                prev_severity, prev_time = self._cooldown[src_ip]
                elapsed = time.monotonic() - prev_time
                if elapsed < self.cooldown_seconds:
                    if _SEVERITY_ORDER.get(severity, 0) <= _SEVERITY_ORDER.get(prev_severity, 0):
                        continue

            # Determine primary target service
            if dq:
                # Most common destination port in the window
                ports = [p for _, p in dq]
                primary_port = max(set(ports), key=ports.count)
                target_service = SERVICE_PORTS.get(primary_port, "Unknown")
                dst_port = primary_port
            else:
                target_service = "Unknown"
                dst_port = None

            confidence = _bf_confidence(count, self.threshold)
            event = self._build_event(
                src_ip, count, severity, confidence, target_service, dst_port, now_ts
            )
            self._cooldown[src_ip] = (severity, time.monotonic())
            return event

        return None

    def generate_event(self) -> ThreatEvent:
        raise NotImplementedError("Use evaluate() to generate events.")

    def explain(self, event: ThreatEvent) -> Explanation:
        """
        Generate a plain-English explanation for a Brute Force ThreatEvent.

        Args:
            event: The ThreatEvent to explain.

        Returns:
            Populated Explanation object.
        """
        count = event.evidence.get("failure_count", event.packet_count)
        window = event.evidence.get("time_window_seconds", self.window_seconds)
        service = event.evidence.get("target_service", "Unknown")
        action = "Blocked." if event.blocked else "Monitoring."

        text = (
            f"Detected {count} authentication failures from {event.source_ip} "
            f"within {window}s targeting {service}. {action}"
        )
        if len(text) > 500:
            text = text[:497] + "..."

        return Explanation(
            attack_name=self.attack_type,
            rule_triggered=self.rule_name,
            plain_english_text=text,
            evidence=event.evidence,
            confidence_score=event.confidence,
            severity=event.severity,
            recommendation=_RECOMMENDATION,
        )

    def cleanup(self) -> None:
        """Release all flow tracking state."""
        self._flows.clear()
        self._cooldown.clear()
        logger.debug("BruteForceRule cleaned up.")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_event(
        self,
        src_ip: str,
        count: int,
        severity: str,
        confidence: int,
        target_service: str,
        dst_port: Optional[int],
        timestamp: str,
    ) -> ThreatEvent:
        evidence = {
            "source_ip": src_ip,
            "failure_count": count,
            "time_window_seconds": self.window_seconds,
            "threshold": self.threshold,
            "target_service": target_service,
        }

        return ThreatEvent(
            event_id=str(uuid.uuid4()),
            timestamp=timestamp,
            attack_type=self.attack_type,
            source_ip=src_ip,
            destination_ip=None,
            source_port=None,
            destination_port=dst_port,
            protocol="TCP",
            rule_name=self.rule_name,
            severity=severity,
            confidence=confidence,
            packet_count=count,
            evidence=evidence,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bf_severity(count: int) -> str:
    if count >= 40:
        return "Critical"
    if count >= 20:
        return "High"
    return "Medium"


def _bf_confidence(count: int, threshold: int) -> int:
    if threshold <= 0:
        return 100
    raw = min(count / threshold, 2.0) / 2.0 * 100
    return min(int(round(raw)), 100)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_to_epoch(ts: str) -> float:
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0.0
