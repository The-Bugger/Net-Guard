"""
dns_tunnel.py — DNS Tunneling heuristic detection rule for NetGuard IDPS.

Module purpose:
    Detects potential DNS tunneling (covert data exfiltration via DNS queries)
    by analysing query names from UDP port 53 traffic.

Detection logic:
    Three independent heuristic indicators are evaluated per source IP within a
    sliding window (default 60 seconds):
    (a) Max DNS label length exceeds dns_tunnel_label_max_len (default 50)
    (b) Rate of TXT/NULL record queries exceeds dns_tunnel_txt_rate_threshold
        (default 5) per window
    (c) Mean Shannon entropy of query labels exceeds dns_tunnel_entropy_threshold
        (default 3.5 bits/char)

    A ThreatEvent is emitted when any indicator fires for a src_ip not already
    emitted. Severity: only (b) fires → "Low"; only (a) or only (c) fires →
    "Medium"; two or more fire → "High". Confidence is always capped at 80.

    This is a heuristic rule with known false positive risk. Confidence is
    capped at 80. Legitimate high-volume DNS traffic (CDN resolvers, internal
    nameservers) may trigger this rule.

Architecture role:
    Consumed by DetectionEngine alongside all other detection rules. Registered
    in backend/services/detection_service.py and config/config.yaml.

Dependencies:
    - detection.parsers.packet_decoder.Packet (normalised packet dataclass)
    - detection.rules.base_rule.BaseRule, ThreatEvent, Explanation
    - stdlib only: math, collections, time, uuid, logging

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.8
"""

from __future__ import annotations

import logging
import math
import time
import uuid
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Optional

from detection.parsers.packet_decoder import Packet
from detection.rules.base_rule import BaseRule, Explanation, ThreatEvent

logger = logging.getLogger("netguard.rule.dns_tunnel")

_RECOMMENDATION = (
    "Inspect DNS traffic from this source for signs of data exfiltration. "
    "Consider blocking external DNS and routing all DNS through an internal resolver "
    "with query logging and anomaly detection."
)

_DEFAULT_WINDOW = 60
_DEFAULT_LABEL_MAX_LEN = 50
_DEFAULT_TXT_RATE = 5
_DEFAULT_ENTROPY = 3.5

# QTYPE constants per RFC 1035 / RFC 1035bis
_QTYPE_TXT = 16
_QTYPE_NULL = 10


def _entropy(s: str) -> float:
    """Shannon entropy in bits/char. Returns 0.0 for empty or single-char strings."""
    if not s:
        return 0.0
    counts = Counter(s.lower())
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _parse_dns_qname(payload: bytes) -> tuple[str, int]:
    """
    Walk RFC 1035 §3.1 label-length encoding to extract the first QNAME and QTYPE
    from the DNS question section.

    The DNS question section begins at byte offset 12 (after the 12-byte fixed header).
    Each label is prefixed by a 1-byte length; a zero byte terminates the name.

    Returns:
        (qname, qtype) on success — qname is dot-joined labels, qtype is the
        2-byte big-endian integer following the name.
        ("", 0) on any parse error — never raises.
    """
    try:
        offset = 12  # skip DNS header
        if len(payload) <= offset:
            return ("", 0)

        labels: list[str] = []
        while offset < len(payload):
            length = payload[offset]
            offset += 1
            if length == 0:
                break
            # Compression pointer check (top 2 bits set) — not supported, bail out
            if length & 0xC0:
                return ("", 0)
            if offset + length > len(payload):
                return ("", 0)
            labels.append(payload[offset: offset + length].decode("ascii", errors="replace"))
            offset += length

        qname = ".".join(labels)

        # Parse QTYPE (2 bytes big-endian)
        if offset + 2 > len(payload):
            return (qname, 0)
        qtype = (payload[offset] << 8) | payload[offset + 1]
        return (qname, qtype)
    except Exception:  # noqa: BLE001
        return ("", 0)


class DnsTunnelRule(BaseRule):
    """
    Heuristic DNS tunneling detection rule.

    Analyses UDP port-53 traffic for three indicators of DNS tunneling:
    long labels, high TXT/NULL query rate, and high Shannon entropy.

    This is a heuristic rule with known false positive risk. Confidence is
    capped at 80. Legitimate high-volume DNS traffic (CDN resolvers, internal
    nameservers) may trigger this rule.
    """

    rule_name: str = "DNS_TUNNEL_001"
    attack_type: str = "DNS Tunneling"

    def __init__(self) -> None:
        super().__init__()
        # src_ip → deque of (monotonic_time, query_name, qtype)
        self._queries: dict[str, deque] = {}
        self._pending: list[ThreatEvent] = []
        self._emitted: set[str] = set()
        self._window: int = _DEFAULT_WINDOW
        self._label_max_len: int = _DEFAULT_LABEL_MAX_LEN
        self._txt_rate_threshold: int = _DEFAULT_TXT_RATE
        self._entropy_threshold: float = _DEFAULT_ENTROPY

    # ------------------------------------------------------------------
    # BaseRule interface
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Reset all state and read config thresholds."""
        self._queries.clear()
        self._pending.clear()
        self._emitted.clear()
        try:
            from backend.api.dependencies import get_config_manager
            cfg = get_config_manager()
            self._window = int(cfg.get("dns_tunnel_window", _DEFAULT_WINDOW))
            self._label_max_len = int(cfg.get("dns_tunnel_label_max_len", _DEFAULT_LABEL_MAX_LEN))
            self._txt_rate_threshold = int(cfg.get("dns_tunnel_txt_rate_threshold", _DEFAULT_TXT_RATE))
            self._entropy_threshold = float(cfg.get("dns_tunnel_entropy_threshold", _DEFAULT_ENTROPY))
        except Exception:  # noqa: BLE001
            self._window = _DEFAULT_WINDOW
            self._label_max_len = _DEFAULT_LABEL_MAX_LEN
            self._txt_rate_threshold = _DEFAULT_TXT_RATE
            self._entropy_threshold = _DEFAULT_ENTROPY
        logger.debug(
            "DnsTunnelRule initialised (window=%ds, label_max=%d, txt_rate=%d, entropy=%.2f).",
            self._window, self._label_max_len, self._txt_rate_threshold, self._entropy_threshold,
        )

    def process_packet(self, packet: Packet) -> None:
        """
        Inspect UDP port-53 packets for DNS tunneling indicators.

        Skips non-UDP packets and packets not destined for port 53. Parses the
        QNAME and QTYPE from the raw payload. Never raises.

        Args:
            packet: Normalised packet from PacketDecoder.
        """
        try:
            if packet.protocol != "UDP":
                return
            if packet.dst_port != 53:
                return

            payload = packet.payload or b""
            qname, qtype = _parse_dns_qname(payload)
            # Skip unparseable or empty queries
            if not qname:
                return

            src = packet.src_ip
            now_mono = time.monotonic()
            cutoff = now_mono - self._window

            if src not in self._queries:
                self._queries[src] = deque()

            dq = self._queries[src]

            # Evict stale entries outside the window
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            dq.append((now_mono, qname, qtype))

            # Already emitted for this IP — suppress
            if src in self._emitted:
                return

            # Evaluate indicators
            indicators = self._evaluate_indicators(dq)
            if not indicators:
                return

            self._emitted.add(src)
            self._pending.append(self._build_event(src, dq, indicators))

        except Exception:  # noqa: BLE001
            logger.debug("DnsTunnelRule.process_packet: suppressed exception", exc_info=True)

    def evaluate(self) -> Optional[ThreatEvent]:
        """Return and consume the first pending ThreatEvent, or None. Never raises."""
        try:
            if not self._pending:
                return None
            return self._pending.pop(0)
        except Exception:  # noqa: BLE001
            return None

    def generate_event(self) -> ThreatEvent:
        """Not called directly — use process_packet() + evaluate()."""
        raise NotImplementedError("Use process_packet() + evaluate() instead.")

    def explain(self, event: ThreatEvent) -> Explanation:
        """
        Generate a plain-English explanation for a DNS Tunneling ThreatEvent.

        Args:
            event: The ThreatEvent to explain.

        Returns:
            Populated Explanation object.
        """
        indicators = event.evidence.get("triggered_indicators", [])
        entropy = event.evidence.get("avg_entropy", 0.0)
        label_len = event.evidence.get("max_label_length", 0)
        txt_count = event.evidence.get("txt_query_count", 0)
        action = "Blocked." if event.blocked else "Monitoring."

        parts = []
        if "label_length" in indicators:
            parts.append(f"max label length {label_len}")
        if "txt_rate" in indicators:
            parts.append(f"{txt_count} TXT/NULL queries")
        if "entropy" in indicators:
            parts.append(f"avg entropy {entropy:.2f} bits/char")

        detail = "; ".join(parts) if parts else "suspicious DNS patterns"
        text = (
            f"Potential DNS tunneling from {event.source_ip}: {detail}. {action}"
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
        self._queries.clear()
        self._pending.clear()
        self._emitted.clear()
        logger.debug("DnsTunnelRule cleaned up.")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _evaluate_indicators(self, dq: deque) -> list[str]:
        """Return list of fired indicator names from the current window deque."""
        fired: list[str] = []
        all_qnames = [entry[1] for entry in dq]
        all_qtypes = [entry[2] for entry in dq]

        # (a) max label length
        max_label = 0
        for qname in all_qnames:
            for label in qname.split("."):
                if len(label) > max_label:
                    max_label = len(label)
        if max_label > self._label_max_len:
            fired.append("label_length")

        # (b) TXT/NULL query count
        txt_count = sum(1 for qt in all_qtypes if qt in (_QTYPE_TXT, _QTYPE_NULL))
        if txt_count > self._txt_rate_threshold:
            fired.append("txt_rate")

        # (c) mean Shannon entropy across labels
        all_labels = []
        for qname in all_qnames:
            all_labels.extend(label for label in qname.split(".") if label)
        if all_labels:
            avg_ent = sum(_entropy(lbl) for lbl in all_labels) / len(all_labels)
            if avg_ent > self._entropy_threshold:
                fired.append("entropy")

        return fired

    def _build_event(self, src_ip: str, dq: deque, indicators: list[str]) -> ThreatEvent:
        """Construct a ThreatEvent from current query window state."""
        all_qnames = [entry[1] for entry in dq]
        all_qtypes = [entry[2] for entry in dq]

        # Max label length
        max_label = 0
        for qname in all_qnames:
            for label in qname.split("."):
                if len(label) > max_label:
                    max_label = len(label)

        # TXT/NULL count
        txt_count = sum(1 for qt in all_qtypes if qt in (_QTYPE_TXT, _QTYPE_NULL))

        # Average entropy over all labels
        all_labels = []
        for qname in all_qnames:
            all_labels.extend(label for label in qname.split(".") if label)
        avg_ent = (
            round(sum(_entropy(lbl) for lbl in all_labels) / len(all_labels), 2)
            if all_labels else 0.0
        )

        # Sample queries (up to 5)
        sample = list(dict.fromkeys(all_qnames))[:5]

        # Severity: ≥2 indicators → High; only (b) → Low; only (a) or (c) → Medium
        if len(indicators) >= 2:
            severity = "High"
        elif indicators == ["txt_rate"]:
            severity = "Low"
        else:
            severity = "Medium"

        # Confidence: more indicators = higher confidence, always capped at 80
        raw_confidence = 40 + (len(indicators) - 1) * 20
        confidence = min(raw_confidence, 80)

        evidence = {
            "triggered_indicators": indicators,
            "max_label_length": max_label,
            "txt_query_count": txt_count,
            "avg_entropy": avg_ent,
            "sample_queries": sample,
        }

        return ThreatEvent(
            event_id=str(uuid.uuid4()),
            timestamp=_utc_now(),
            attack_type=self.attack_type,
            source_ip=src_ip,
            destination_ip=None,
            source_port=None,
            destination_port=53,
            protocol="UDP",
            rule_name=self.rule_name,
            severity=severity,
            confidence=confidence,
            packet_count=len(dq),
            evidence=evidence,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
