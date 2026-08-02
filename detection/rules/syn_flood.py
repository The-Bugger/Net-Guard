"""SYN Flood detection rule — tracks TCP SYN rate per source IP."""

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

_SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
_RECOMMENDATION = "Investigate the source host and verify whether the traffic is legitimate."


class SynFloodRule(BaseRule):
    """
    Detects TCP SYN floods.

    Emits when a source IP sends >= threshold SYN packets within window_seconds.
    Severity tiers: 100–199 → Medium, 200–399 → High, ≥400 → Critical.
    Suppresses duplicates for the same IP within cooldown_seconds unless severity escalates.
    """

    rule_name: str = "SYN_FLOOD_001"
    attack_type: str = "SYN Flood"

    def __init__(self, threshold: int = 100, window_seconds: int = 3, cooldown_seconds: int = 10) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.enabled = True
        # FlowData.timestamps holds (timestamp_str, dst_ip) tuples
        self._flows: dict[str, FlowData] = {}
        self._cooldown: dict[str, tuple[str, float]] = {}

    def initialize(self) -> None:
        self._flows.clear()
        self._cooldown.clear()
        logger.debug("SynFloodRule initialised (threshold=%d, window=%ds).", self.threshold, self.window_seconds)

    def process_packet(self, packet: Packet) -> None:
        """Record pure SYN packets (S flag set, A flag not set)."""
        if packet.protocol != "TCP" or not packet.flags:
            return
        flags_upper = packet.flags.upper()
        if "S" not in flags_upper or "A" in flags_upper:
            return
        src = packet.src_ip
        if src not in self._flows:
            self._flows[src] = FlowData()
        self._flows[src].timestamps.append((packet.timestamp, packet.dst_ip))

    def evaluate(self) -> Optional[ThreatEvent]:
        """Return first ThreatEvent exceeding threshold, or None."""
        now_ts = _utc_now()
        cutoff_wall = datetime.now(timezone.utc).timestamp() - self.window_seconds

        for src_ip, flow in list(self._flows.items()):
            while flow.timestamps:
                ts_str, _ = flow.timestamps[0]
                if _iso_to_epoch(ts_str) < cutoff_wall:
                    flow.timestamps.popleft()
                else:
                    break

            count = len(flow.timestamps)
            if count < self.threshold:
                continue

            severity = _syn_severity(count)

            if src_ip in self._cooldown:
                prev_severity, prev_time = self._cooldown[src_ip]
                if time.monotonic() - prev_time < self.cooldown_seconds:
                    if _SEVERITY_ORDER.get(severity, 0) <= _SEVERITY_ORDER.get(prev_severity, 0):
                        continue

            event = self._build_event(src_ip, flow, count, severity, now_ts)
            self._cooldown[src_ip] = (severity, time.monotonic())
            return event

        return None

    def generate_event(self) -> ThreatEvent:
        raise NotImplementedError("Use evaluate() to generate events.")

    def explain(self, event: ThreatEvent) -> Explanation:
        count     = event.evidence.get("syn_packet_count", event.packet_count)
        window    = event.evidence.get("time_window_seconds", self.window_seconds)
        threshold = event.evidence.get("threshold", self.threshold)
        action    = "Blocked." if event.blocked else "Monitoring."
        text = (
            f"Detected {count} SYN packets from {event.source_ip} within {window}s. "
            f"The threshold of {threshold} was exceeded. {action}"
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
        logger.debug("SynFloodRule cleaned up.")

    def _build_event(self, src_ip: str, flow: FlowData, count: int, severity: str, timestamp: str) -> ThreatEvent:
        dst_ips   = list({dst for _, dst in flow.timestamps})[:10]
        sample_ts = [ts for ts, _ in list(flow.timestamps)[-5:]]
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
            confidence=_syn_confidence(count, self.threshold),
            packet_count=count,
            evidence={
                "source_ip": src_ip,
                "syn_packet_count": count,
                "time_window_seconds": self.window_seconds,
                "threshold": self.threshold,
                "destination_ips": dst_ips,
                "sample_timestamps": sample_ts,
            },
        )


def _syn_severity(count: int) -> str:
    if count >= 400:
        return "Critical"
    if count >= 200:
        return "High"
    return "Medium"


def _syn_confidence(count: int, threshold: int) -> int:
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
