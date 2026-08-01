"""
icmp_flood.py — ICMP Flood detection rule for NetGuard IDPS.

Detects ICMP Echo Request floods and Smurf attacks by counting ICMP type-8
packets per source IP within a configurable sliding time window.

Detection logic:
- Only inspect ICMP Echo Request packets (icmp_type == 8) per Requirement 6.1
- Maintain _flow: dict[src_ip, deque[float]] — monotonic timestamps within window
- Emit ThreatEvent when count >= threshold OR when dst_ip is a broadcast address
  (Smurf attack pattern), per Requirements 6.2–6.5
- Severity tiers (non-smurf): count < 2×threshold → "Medium",
  count < 4×threshold → "High", count ≥ 4×threshold → "Critical"
- Smurf detection forces severity "Critical" per Requirement 6.3
- Duplicate suppression via _emitted set per IP: once evaluate() has consumed
  an event for a src_ip, further events for that IP are suppressed until
  cleanup()/initialize() clears the set. While a pending event exists,
  process_packet updates its count in-place (mirrors ArpSpoofRule behaviour).
- Evidence fields: icmp_packet_count, time_window_seconds, threshold,
  smurf_pattern, sample_dst_ips (Requirement 6.5)

Architecture role:
- Consumed by DetectionEngine alongside the other five detection rules
- Relies on packet.icmp_type and packet.dst_ip set by PacketDecoder

Dependencies:
- detection.parsers.packet_decoder.Packet (normalised packet dataclass)
- detection.rules.base_rule.BaseRule, ThreatEvent, Explanation

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.7
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

logger = logging.getLogger("netguard.rule.icmp_flood")

_RECOMMENDATION = (
    "Rate-limit or block the offending source IP at the network perimeter. "
    "Verify whether the traffic is a legitimate network probe."
)

_DEFAULT_THRESHOLD = 100
_DEFAULT_WINDOW = 3.0


class IcmpFloodRule(BaseRule):
    """
    Detects ICMP Echo Request floods and Smurf attacks.

    Tracks ICMP type-8 packets per source IP within a sliding time window.
    Emits a ThreatEvent when the packet count meets the threshold or when
    the destination is a broadcast address (Smurf pattern).

    Relies on `packet.icmp_type` and `packet.dst_ip` set by PacketDecoder.
    """

    rule_name: str = "ICMP_FLOOD_001"
    attack_type: str = "ICMP Flood"

    def __init__(self) -> None:
        super().__init__()
        # src_ip → deque of monotonic timestamps within the window
        self._flow: dict[str, deque] = {}
        # src_ip → wall-clock ISO-8601 of first packet seen
        self._first_seen: dict[str, str] = {}
        # src_ip → list of recent dst_ips (capped at 10) for evidence
        self._dst_ips: dict[str, list] = {}
        self._pending: list[ThreatEvent] = []
        # Set of src_ips for which an event has already been *consumed* by evaluate().
        # While an event is still in _pending we update it in-place instead of
        # suppressing it, so severity reflects the latest count.
        self._emitted: set[str] = set()
        self._threshold: int = _DEFAULT_THRESHOLD
        self._window: float = _DEFAULT_WINDOW

    # ------------------------------------------------------------------
    # BaseRule interface
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Reset all state and read config thresholds."""
        self._flow.clear()
        self._first_seen.clear()
        self._dst_ips.clear()
        self._pending.clear()
        self._emitted.clear()
        # Read config at initialize() time so tests can inject values without
        # restarting the app.
        try:
            from backend.api.dependencies import get_config_manager
            cfg = get_config_manager()
            self._threshold = int(cfg.get("icmp_flood_threshold", _DEFAULT_THRESHOLD))
            self._window = float(cfg.get("icmp_flood_window", _DEFAULT_WINDOW))
        except Exception:  # noqa: BLE001
            self._threshold = _DEFAULT_THRESHOLD
            self._window = _DEFAULT_WINDOW
        logger.debug(
            "IcmpFloodRule initialised (threshold=%d, window=%.1fs).",
            self._threshold,
            self._window,
        )

    def process_packet(self, packet: Packet) -> None:
        """
        Inspect ICMP Echo Request packets for flood / Smurf patterns.

        Skips non-ICMP packets and ICMP packets that are not Echo Requests
        (icmp_type != 8).  Never raises.

        Args:
            packet: Normalised packet from PacketDecoder.
        """
        try:
            if packet.protocol != "ICMP":
                return
            if packet.icmp_type != 8:
                return

            src = packet.src_ip
            dst = packet.dst_ip or ""
            now_mono = time.monotonic()
            cutoff = now_mono - self._window

            if src not in self._flow:
                self._flow[src] = deque()
                self._first_seen[src] = _utc_now()
                self._dst_ips[src] = []

            dq = self._flow[src]

            # Evict stale timestamps outside the window
            while dq and dq[0] < cutoff:
                dq.popleft()

            dq.append(now_mono)

            # Track up to 10 distinct dst IPs for evidence
            dst_list = self._dst_ips[src]
            if dst and (not dst_list or dst_list[-1] != dst):
                dst_list.append(dst)
                if len(dst_list) > 10:
                    dst_list.pop(0)

            is_smurf = dst.endswith(".255") or dst == "255.255.255.255"
            count = len(dq)

            if count < self._threshold and not is_smurf:
                return

            # Already consumed by evaluate() — suppress further events for this IP.
            if src in self._emitted:
                return

            # If a pending event for this IP already exists, update it in-place
            # so severity reflects the growing count (mirrors ArpSpoofRule pattern).
            for existing in self._pending:
                if existing.source_ip == src:
                    updated = self._build_event(src, count, is_smurf)
                    existing.severity = updated.severity
                    existing.confidence = updated.confidence
                    existing.packet_count = updated.packet_count
                    existing.evidence = updated.evidence
                    return

            self._pending.append(self._build_event(src, count, is_smurf))

        except Exception:  # noqa: BLE001
            # process_packet must never raise (Requirement 6.7)
            logger.debug("IcmpFloodRule.process_packet: suppressed exception", exc_info=True)

    def evaluate(self) -> Optional[ThreatEvent]:
        """
        Return and consume the first pending ThreatEvent, or None.

        Never raises.
        """
        try:
            if not self._pending:
                return None
            event = self._pending.pop(0)
            self._emitted.add(event.source_ip)
            return event
        except Exception:  # noqa: BLE001
            return None

    def generate_event(self) -> ThreatEvent:
        """Not called directly — use process_packet() + evaluate()."""
        raise NotImplementedError("Use process_packet() + evaluate() instead.")

    def explain(self, event: ThreatEvent) -> Explanation:
        """
        Generate a plain-English explanation for an ICMP Flood ThreatEvent.

        Args:
            event: The ThreatEvent to explain.

        Returns:
            Populated Explanation object.
        """
        count = event.evidence.get("icmp_packet_count", event.packet_count)
        window = event.evidence.get("time_window_seconds", self._window)
        threshold = event.evidence.get("threshold", self._threshold)
        smurf = event.evidence.get("smurf_pattern", False)
        action = "Blocked." if event.blocked else "Monitoring."

        if smurf:
            text = (
                f"Detected Smurf attack from {event.source_ip}: "
                f"{count} ICMP Echo Requests to a broadcast address within {window}s. {action}"
            )
        else:
            text = (
                f"Detected {count} ICMP Echo Requests from {event.source_ip} "
                f"within {window}s (threshold: {threshold}). {action}"
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
        """Release all tracking state."""
        self._flow.clear()
        self._first_seen.clear()
        self._dst_ips.clear()
        self._pending.clear()
        self._emitted.clear()
        logger.debug("IcmpFloodRule cleaned up.")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_event(self, src_ip: str, count: int, is_smurf: bool) -> ThreatEvent:
        """Construct a ThreatEvent from current flow state."""
        if is_smurf:
            severity = "Critical"
        elif count < 2 * self._threshold:
            severity = "Medium"
        elif count < 4 * self._threshold:
            severity = "High"
        else:
            severity = "Critical"

        confidence = min(int(round(min(count / self._threshold, 2.0) / 2.0 * 100)), 100)

        sample_dst = list(self._dst_ips.get(src_ip, []))[:5]
        evidence = {
            "icmp_packet_count": count,
            "time_window_seconds": self._window,
            "threshold": self._threshold,
            "smurf_pattern": is_smurf,
            "sample_dst_ips": sample_dst,
            "first_seen": self._first_seen.get(src_ip, _utc_now()),
        }

        return ThreatEvent(
            event_id=str(uuid.uuid4()),
            timestamp=_utc_now(),
            attack_type=self.attack_type,
            source_ip=src_ip,
            destination_ip=sample_dst[0] if sample_dst else None,
            source_port=None,
            destination_port=None,
            protocol="ICMP",
            rule_name=self.rule_name,
            severity=severity,
            confidence=confidence,
            packet_count=count,
            evidence=evidence,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
