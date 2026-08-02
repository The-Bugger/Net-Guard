"""Brute Force detection rule — tracks auth connection attempts per source IP."""

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

# Port → service name for SSH, FTP, and HTTP (80 and 443 both map to "HTTP")
SERVICE_PORTS: dict[int, str] = {22: "SSH", 21: "FTP", 80: "HTTP", 443: "HTTP"}
_AUTH_PORTS = set(SERVICE_PORTS.keys())


class BruteForceRule(BaseRule):
    """
    Detects brute-force login attempts against SSH, HTTP, and FTP.

    Counts TCP connection attempts to auth ports per source IP within a
    sliding window. Emits when count >= threshold.
    Severity tiers: 10–19 → Medium, 20–39 → High, ≥40 → Critical.
    """

    rule_name: str = "BRUTE_FORCE_001"
    attack_type: str = "Brute Force"
    SERVICE_PORTS: dict[int, str] = SERVICE_PORTS

    def __init__(self, threshold: int = 10, window_seconds: int = 60, cooldown_seconds: int = 10) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.enabled = True
        # src_ip -> deque of (epoch_float, dst_port)
        self._flows: dict[str, deque] = {}
        self._cooldown: dict[str, tuple[str, float]] = {}

    def initialize(self) -> None:
        self._flows.clear()
        self._cooldown.clear()
        logger.debug("BruteForceRule initialised (threshold=%d, window=%ds).", self.threshold, self.window_seconds)

    def process_packet(self, packet: Packet) -> None:
        """Record TCP packets destined for an auth port (SSH/HTTP/FTP)."""
        if packet.protocol != "TCP" or packet.dst_port is None:
            return
        if packet.dst_port not in _AUTH_PORTS:
            return
        src = packet.src_ip
        if src not in self._flows:
            self._flows[src] = deque()
        self._flows[src].append((_iso_to_epoch(packet.timestamp), packet.dst_port))

    def evaluate(self) -> Optional[ThreatEvent]:
        """Return first ThreatEvent exceeding threshold, or None."""
        now_ts = _utc_now()
        cutoff_wall = datetime.now(timezone.utc).timestamp() - self.window_seconds

        for src_ip, dq in list(self._flows.items()):
            while dq and dq[0][0] < cutoff_wall:
                dq.popleft()

            count = len(dq)
            if count < self.threshold:
                continue

            severity = _bf_severity(count)

            if src_ip in self._cooldown:
                prev_severity, prev_time = self._cooldown[src_ip]
                if time.monotonic() - prev_time < self.cooldown_seconds:
                    if _SEVERITY_ORDER.get(severity, 0) <= _SEVERITY_ORDER.get(prev_severity, 0):
                        continue

            if dq:
                ports = [p for _, p in dq]
                primary_port = max(set(ports), key=ports.count)
                target_service = SERVICE_PORTS.get(primary_port, "Unknown")
                dst_port = primary_port
            else:
                target_service, dst_port = "Unknown", None

            event = self._build_event(src_ip, count, severity, _bf_confidence(count, self.threshold), target_service, dst_port, now_ts)
            self._cooldown[src_ip] = (severity, time.monotonic())
            return event

        return None

    def generate_event(self) -> ThreatEvent:
        raise NotImplementedError("Use evaluate() to generate events.")

    def explain(self, event: ThreatEvent) -> Explanation:
        count   = event.evidence.get("failure_count", event.packet_count)
        window  = event.evidence.get("time_window_seconds", self.window_seconds)
        service = event.evidence.get("target_service", "Unknown")
        action  = "Blocked." if event.blocked else "Monitoring."
        text = (
            f"Detected {count} authentication failures from {event.source_ip} "
            f"within {window}s targeting {service}. {action}"
        )
        if len(text) > 500:
            text = text[:497] + "..."
        return Explanation(
            attack_name=self.attack_type, rule_triggered=self.rule_name,
            plain_english_text=text, evidence=event.evidence,
            confidence_score=event.confidence, severity=event.severity,
            recommendation=_RECOMMENDATION,
        )

    def cleanup(self) -> None:
        self._flows.clear()
        self._cooldown.clear()
        logger.debug("BruteForceRule cleaned up.")

    def _build_event(
        self, src_ip: str, count: int, severity: str, confidence: int,
        target_service: str, dst_port: Optional[int], timestamp: str,
    ) -> ThreatEvent:
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
            evidence={
                "source_ip": src_ip,
                "failure_count": count,
                "time_window_seconds": self.window_seconds,
                "threshold": self.threshold,
                "target_service": target_service,
            },
        )


def _bf_severity(count: int) -> str:
    if count >= 40:
        return "Critical"
    if count >= 20:
        return "High"
    return "Medium"


def _bf_confidence(count: int, threshold: int) -> int:
    if threshold <= 0:
        return 100
    return min(int(round(min(count / threshold, 2.0) / 2.0 * 100)), 100)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_to_epoch(ts: str) -> float:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return 0.0
