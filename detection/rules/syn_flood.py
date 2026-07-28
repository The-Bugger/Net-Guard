"""
syn_flood.py — SYN Flood detection rule for NetGuard IDPS.

Detects volumetric TCP SYN floods by tracking the rate of SYN packets
from each source IP within a configurable sliding time window.

Detection logic:
- Track TCP SYN packets per source IP using a deque of timestamps
- Emit ThreatEvent when count >= configured threshold within the window
- Severity: 100-199 → Medium, 200-399 → High, ≥400 → Critical
- Confidence: round(min(count/threshold, 2.0) / 2.0 * 100) capped at 100
- Cooldown: suppress duplicate events for same IP within 10 seconds (unless higher severity)

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7
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

logger = logging.getLogger("netguard.rule.syn_flood")

# Severity ordering for cooldown comparison
_SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

# Recommendations
_RECOMMENDATION = "Investigate the source host and verify whether the traffic is legitimate."


class SynFloodRule(BaseRule):
    """
    Detects TCP SYN flood attacks.

    A SYN flood occurs when a single source IP sends an abnormally high
    number of TCP SYN packets in a short time window, exhausting server
    connection resources.
    """

    rule_name: str = "SYN_FLOOD_001"
    attack_type: str = "SYN Flood"

    def __init__(
        self,
        threshold: int = 100,
        window_seconds: int = 3,
        cooldown_seconds: int = 10,
    ) -> None:
        """
        Args:
            threshold: Minimum SYN packet count to trigger detection.
            window_seconds: Sliding window duration in seconds.
            cooldown_seconds: Minimum seconds between events for same IP/rule.
        """
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.enabled = True

        # Per-source-IP flow tracking: src_ip -> FlowData
        # FlowData.timestamps holds (timestamp_str, dst_ip) tuples
        self._flows: dict[str, FlowData] = {}

        # Cooldown tracker: src_ip -> (severity, emit_monotonic_time)
        self._cooldown: dict[str, tuple[str, float]] = {}

    # ------------------------------------------------------------------
    # BaseRule interface
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Reset all flow state."""
        self._flows.clear()
        self._cooldown.clear()
        logger.debug("SynFloodRule initialised (threshold=%d, window=%ds).",
                     self.threshold, self.window_seconds)

    def process_packet(self, packet: Packet) -> None:
        """
        Record a SYN packet from the given source IP.

        Only processes TCP packets with the SYN flag set (and not ACK).

        Args:
            packet: Normalised packet from PacketDecoder.
        """
        if packet.protocol != "TCP":
            return
        if not packet.flags:
            return
        # Pure SYN: 'S' flag set, ACK not set
        flags_upper = packet.flags.upper()
        if "S" not in flags_upper or "A" in flags_upper:
            return

        src = packet.src_ip
        if src not in self._flows:
            self._flows[src] = FlowData()

        flow = self._flows[src]
        flow.timestamps.append((packet.timestamp, packet.dst_ip))

    def evaluate(self) -> Optional[ThreatEvent]:
        """
        Check each tracked source IP against the SYN flood threshold.

        Returns the first ThreatEvent found, or None if no threshold exceeded.
        """
        now_ts = _utc_now()
        cutoff = time.monotonic() - self.window_seconds
        # Use actual wall-clock cutoff for the deque
        cutoff_wall = datetime.now(timezone.utc).timestamp() - self.window_seconds

        for src_ip, flow in list(self._flows.items()):
            # Expire old entries outside the sliding window
            while flow.timestamps:
                ts_str, _ = flow.timestamps[0]
                ts_epoch = _iso_to_epoch(ts_str)
                if ts_epoch < cutoff_wall:
                    flow.timestamps.popleft()
                else:
                    break

            count = len(flow.timestamps)
            if count < self.threshold:
                continue

            severity = _syn_severity(count)

            # Cooldown check
            if src_ip in self._cooldown:
                prev_severity, prev_time = self._cooldown[src_ip]
                elapsed = time.monotonic() - prev_time
                if elapsed < self.cooldown_seconds:
                    # Only emit if severity escalated
                    if _SEVERITY_ORDER.get(severity, 0) <= _SEVERITY_ORDER.get(prev_severity, 0):
                        continue

            event = self._build_event(src_ip, flow, count, severity, now_ts)
            self._cooldown[src_ip] = (severity, time.monotonic())
            return event

        return None

    def generate_event(self) -> ThreatEvent:
        """Not called directly — see evaluate()."""
        raise NotImplementedError("Use evaluate() to generate events.")

    def explain(self, event: ThreatEvent) -> Explanation:
        """
        Generate a plain-English explanation for a SYN flood ThreatEvent.

        Args:
            event: The ThreatEvent to explain.

        Returns:
            Populated Explanation object.
        """
        count = event.evidence.get("syn_packet_count", event.packet_count)
        window = event.evidence.get("time_window_seconds", self.window_seconds)
        threshold = event.evidence.get("threshold", self.threshold)
        action = "Blocked." if event.blocked else "Monitoring."

        text = (
            f"Detected {count} SYN packets from {event.source_ip} within {window}s. "
            f"The threshold of {threshold} was exceeded. {action}"
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
        logger.debug("SynFloodRule cleaned up.")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_event(
        self,
        src_ip: str,
        flow: FlowData,
        count: int,
        severity: str,
        timestamp: str,
    ) -> ThreatEvent:
        """Construct a ThreatEvent from accumulated flow data."""
        dst_ips = list({dst for _, dst in flow.timestamps})
        # Up to 5 sample timestamps
        sample_ts = [ts for ts, _ in list(flow.timestamps)[-5:]]

        confidence = _syn_confidence(count, self.threshold)

        evidence = {
            "syn_packet_count": count,
            "time_window_seconds": self.window_seconds,
            "threshold": self.threshold,
            "destination_ips": dst_ips,
            "sample_timestamps": sample_ts,
        }

        return ThreatEvent(
            event_id=str(uuid.uuid4()),
            timestamp=timestamp,
            attack_type=self.attack_type,
            source_ip=src_ip,
            destination_ip=dst_ips[0] if dst_ips else None,
            source_port=None,
            destination_port=None,
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

def _syn_severity(count: int) -> str:
    """Map SYN packet count to severity tier (Requirement 4.2-4.4)."""
    if count >= 400:
        return "Critical"
    if count >= 200:
        return "High"
    return "Medium"


def _syn_confidence(count: int, threshold: int) -> int:
    """Calculate confidence score (Requirement 4.5)."""
    if threshold <= 0:
        return 100
    raw = min(count / threshold, 2.0) / 2.0 * 100
    return min(int(round(raw)), 100)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_to_epoch(ts: str) -> float:
    """Convert ISO-8601 UTC string to Unix timestamp float."""
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0.0
