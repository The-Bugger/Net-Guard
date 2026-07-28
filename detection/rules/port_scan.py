"""
port_scan.py — Port Scan detection rule for NetGuard IDPS.

Detects port scanning activity by tracking the number of unique destination
ports contacted by each source IP within a configurable sliding time window.

Detection logic:
- Track unique (dst_ip, dst_port) pairs per source IP using a set + timestamp deque
- Emit ThreatEvent when unique port count >= configured threshold within the window
- Severity: 20-39 → Medium, 40-79 → High, ≥80 → Critical
- Confidence: round(min(unique_count/threshold, 2.0) / 2.0 * 100) capped at 100
- Cooldown: suppress duplicate events for same IP within 10 seconds unless higher severity

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from detection.parsers.packet_decoder import Packet
from detection.rules.base_rule import BaseRule, Explanation, FlowData, ThreatEvent

logger = logging.getLogger("netguard.rule.port_scan")

_SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
_RECOMMENDATION = "Review exposed services and verify firewall rules."


class PortScanRule(BaseRule):
    """
    Detects port scanning activity.

    A port scan occurs when a single source IP attempts connections to many
    different destination ports in a short time, indicating network reconnaissance.
    """

    rule_name: str = "PORT_SCAN_001"
    attack_type: str = "Port Scan"

    def __init__(
        self,
        threshold: int = 20,
        window_seconds: int = 10,
        cooldown_seconds: int = 10,
    ) -> None:
        """
        Args:
            threshold: Minimum unique destination port count to trigger detection.
            window_seconds: Sliding window duration in seconds.
            cooldown_seconds: Minimum seconds between events for the same IP.
        """
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.enabled = True

        # Per-source-IP tracking
        # FlowData.timestamps holds (timestamp_str, dst_port, dst_ip) tuples
        # FlowData.ports holds set of (dst_ip, dst_port) within current window
        self._flows: dict[str, _PortScanFlow] = {}
        self._cooldown: dict[str, tuple[str, float]] = {}

    def initialize(self) -> None:
        """Reset all flow state."""
        self._flows.clear()
        self._cooldown.clear()
        logger.debug(
            "PortScanRule initialised (threshold=%d, window=%ds).",
            self.threshold, self.window_seconds,
        )

    def process_packet(self, packet: Packet) -> None:
        """
        Record a TCP or UDP connection attempt from the source IP.

        Args:
            packet: Normalised packet from PacketDecoder.
        """
        if packet.protocol not in ("TCP", "UDP"):
            return
        if packet.dst_port is None:
            return

        src = packet.src_ip
        if src not in self._flows:
            self._flows[src] = _PortScanFlow()

        flow = self._flows[src]
        flow.add(packet.timestamp, packet.dst_ip or "", packet.dst_port)

    def evaluate(self) -> Optional[ThreatEvent]:
        """
        Check each tracked source IP against the port scan threshold.

        Returns the first ThreatEvent found, or None.
        """
        now_ts = _utc_now()
        cutoff_wall = datetime.now(timezone.utc).timestamp() - self.window_seconds

        for src_ip, flow in list(self._flows.items()):
            flow.evict_old(cutoff_wall)
            unique_count = flow.unique_port_count()

            if unique_count < self.threshold:
                continue

            severity = _scan_severity(unique_count)

            # Cooldown check
            if src_ip in self._cooldown:
                prev_severity, prev_time = self._cooldown[src_ip]
                elapsed = time.monotonic() - prev_time
                if elapsed < self.cooldown_seconds:
                    if _SEVERITY_ORDER.get(severity, 0) <= _SEVERITY_ORDER.get(prev_severity, 0):
                        continue

            confidence = _scan_confidence(unique_count, self.threshold)
            event = self._build_event(src_ip, flow, unique_count, severity, confidence, now_ts)
            self._cooldown[src_ip] = (severity, time.monotonic())
            return event

        return None

    def generate_event(self) -> ThreatEvent:
        raise NotImplementedError("Use evaluate() to generate events.")

    def explain(self, event: ThreatEvent) -> Explanation:
        """
        Generate a plain-English explanation for a Port Scan ThreatEvent.

        Args:
            event: The ThreatEvent to explain.

        Returns:
            Populated Explanation object.
        """
        port_count = event.evidence.get("unique_port_count", event.packet_count)
        window = event.evidence.get("time_window_seconds", self.window_seconds)
        action = "Blocked." if event.blocked else "Monitoring."

        text = (
            f"Detected connection attempts to {port_count} unique ports from "
            f"{event.source_ip} within {window}s. {action}"
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
        logger.debug("PortScanRule cleaned up.")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_event(
        self,
        src_ip: str,
        flow: "_PortScanFlow",
        unique_count: int,
        severity: str,
        confidence: int,
        timestamp: str,
    ) -> ThreatEvent:
        scanned_ports = sorted(flow.unique_ports())

        evidence = {
            "unique_port_count": unique_count,
            "scanned_ports": scanned_ports,
            "time_window_seconds": self.window_seconds,
            "threshold": self.threshold,
            "confidence_score": confidence,
        }

        return ThreatEvent(
            event_id=str(uuid.uuid4()),
            timestamp=timestamp,
            attack_type=self.attack_type,
            source_ip=src_ip,
            destination_ip=None,
            source_port=None,
            destination_port=None,
            protocol="TCP",
            rule_name=self.rule_name,
            severity=severity,
            confidence=confidence,
            packet_count=unique_count,
            evidence=evidence,
        )


# ---------------------------------------------------------------------------
# Internal flow tracker for port scan
# ---------------------------------------------------------------------------

class _PortScanFlow:
    """Efficient per-IP port scan tracker using a deque + port set."""

    def __init__(self) -> None:
        # deque of (epoch_float, dst_ip, dst_port)
        self._entries: deque = deque()
        # set of (dst_ip, dst_port) in current window
        self._port_set: set = set()

    def add(self, timestamp: str, dst_ip: str, dst_port: int) -> None:
        epoch = _iso_to_epoch(timestamp)
        self._entries.append((epoch, dst_ip, dst_port))
        self._port_set.add((dst_ip, dst_port))

    def evict_old(self, cutoff_epoch: float) -> None:
        """Remove entries older than cutoff and rebuild the port set."""
        changed = False
        while self._entries and self._entries[0][0] < cutoff_epoch:
            self._entries.popleft()
            changed = True
        if changed:
            # Rebuild port set from remaining entries
            self._port_set = {(d, p) for _, d, p in self._entries}

    def unique_port_count(self) -> int:
        return len(self._port_set)

    def unique_ports(self) -> list[int]:
        return list({p for _, p in self._port_set})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _scan_severity(count: int) -> str:
    if count >= 80:
        return "Critical"
    if count >= 40:
        return "High"
    return "Medium"


def _scan_confidence(count: int, threshold: int) -> int:
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
