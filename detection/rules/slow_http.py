"""
slow_http.py — Slow HTTP / Slowloris detection rule for NetGuard IDPS.

Detects Slowloris-style connection-exhaustion attacks by tracking TCP connections
to web ports that remain open for an extended period without completing an HTTP
request header block (i.e. no `\\r\\n\\r\\n` observed in the payload).

Detection logic:
- Only inspect TCP packets destined for ports 80 or 443
- Maintain _connections: dict[conn_key, ConnState] keyed by (src_ip, src_port, dst_port)
- On SYN: create a new ConnState entry (opened_at, last_data_at, completed=False, bytes_seen=0)
- On payload: update last_data_at and bytes_seen; mark completed=True if \\r\\n\\r\\n seen
- On FIN or RST: remove the connection from _connections
- Periodically (every _timeout seconds) scan for incomplete connections open > _timeout
  with < 1024 bytes total; group by src_ip; emit ThreatEvent when count >= _threshold
- Severity: Medium for [threshold, 2×threshold), High for ≥ 2×threshold
- Confidence: proportional to count/threshold, capped at 95
- Evidence fields: concurrent_connections, threshold, connection_timeout_seconds, target_ports

This rule tracks connection longevity and low data rate. It is not a duplicate of
syn_flood.py, which detects SYN packet volume.

Architecture role:
- Consumed by DetectionEngine alongside the other detection rules
- Relies on packet.protocol, packet.flags, packet.src_port, packet.dst_port,
  packet.src_ip, packet.payload set by PacketDecoder

Dependencies:
- detection.parsers.packet_decoder.Packet (normalised packet dataclass)
- detection.rules.base_rule.BaseRule, ThreatEvent, Explanation

Requirements: 7.1, 7.2, 7.3, 7.4, 7.6
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from detection.parsers.packet_decoder import Packet
from detection.rules.base_rule import BaseRule, Explanation, ThreatEvent

logger = logging.getLogger("netguard.rule.slow_http")

_RECOMMENDATION = (
    "Inspect active connections on ports 80/443 for Slowloris-style clients. "
    "Consider enabling connection-rate limiting or a WAF with request timeout enforcement."
)

_DEFAULT_THRESHOLD = 10
_DEFAULT_TIMEOUT = 10
_TARGET_PORTS = {80, 443}
# Low-data-rate heuristic: incomplete requests with less than this many bytes
_LOW_DATA_BYTES = 1024


class SlowHttpRule(BaseRule):
    """
    Detects Slow HTTP / Slowloris attacks.

    Tracks per-TCP-stream connection state for streams destined at ports 80/443.
    Emits a ThreatEvent when a source IP holds >= threshold long-lived, incomplete,
    low-data-rate connections simultaneously.

    ponytail: Connection state is in-process; not shared across workers.
    Ceiling: per-flow tracking in a shared store (e.g. Redis) for multi-worker deployments.
    """

    rule_name: str = "SLOW_HTTP_001"
    attack_type: str = "Slow HTTP"

    def __init__(self) -> None:
        super().__init__()
        # (src_ip, src_port, dst_port) → ConnState dict
        self._connections: dict[tuple, dict] = {}
        self._pending: list[ThreatEvent] = []
        self._last_check: float = 0.0
        self._threshold: int = _DEFAULT_THRESHOLD
        self._timeout: int = _DEFAULT_TIMEOUT

    # ------------------------------------------------------------------
    # BaseRule interface
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Reset all state and read config thresholds."""
        self._connections.clear()
        self._pending.clear()
        self._last_check = 0.0
        try:
            from backend.api.dependencies import get_config_manager
            cfg = get_config_manager()
            self._threshold = int(cfg.get("slow_http_threshold", _DEFAULT_THRESHOLD))
            self._timeout = int(cfg.get("slow_http_connection_timeout", _DEFAULT_TIMEOUT))
        except Exception:  # noqa: BLE001
            self._threshold = _DEFAULT_THRESHOLD
            self._timeout = _DEFAULT_TIMEOUT
        logger.debug(
            "SlowHttpRule initialised (threshold=%d, timeout=%ds).",
            self._threshold,
            self._timeout,
        )

    def process_packet(self, packet: Packet) -> None:
        """
        Track TCP connection state for packets to ports 80/443.

        - SYN: create ConnState entry
        - Payload: update bytes/data timestamp; mark completed on \\r\\n\\r\\n
        - FIN/RST: remove connection
        - Periodically scan for stale incomplete entries and emit to _pending

        Never raises.

        Args:
            packet: Normalised packet from PacketDecoder.
        """
        try:
            if packet.protocol != "TCP":
                return
            if packet.dst_port not in _TARGET_PORTS:
                return

            conn_key = (packet.src_ip, packet.src_port, packet.dst_port)
            flags = (packet.flags or "").upper()
            now_mono = time.monotonic()

            # SYN (new connection, not SYN-ACK)
            if "S" in flags and "A" not in flags:
                self._connections[conn_key] = {
                    "opened_at": now_mono,
                    "last_data_at": now_mono,
                    "completed": False,
                    "bytes_seen": 0,
                }

            # FIN or RST — clean up
            elif "F" in flags or "R" in flags:
                self._connections.pop(conn_key, None)

            # Payload-bearing packet
            elif packet.payload and len(packet.payload) > 0:
                state = self._connections.get(conn_key)
                if state is None:
                    # Missed SYN; create partial entry so we can track it
                    state = {
                        "opened_at": now_mono,
                        "last_data_at": now_mono,
                        "completed": False,
                        "bytes_seen": 0,
                    }
                    self._connections[conn_key] = state
                state["last_data_at"] = now_mono
                state["bytes_seen"] += len(packet.payload)
                if not state["completed"] and b"\r\n\r\n" in packet.payload:
                    state["completed"] = True

            # Periodic scan — run at most once per _timeout seconds
            if now_mono - self._last_check >= self._timeout:
                self._last_check = now_mono
                self._scan_stale(packet.src_ip, now_mono)

        except Exception:  # noqa: BLE001
            # process_packet must never raise (Requirement 7.6)
            logger.debug("SlowHttpRule.process_packet: suppressed exception", exc_info=True)

    def evaluate(self) -> Optional[ThreatEvent]:
        """
        Return and consume the first pending ThreatEvent, or None.

        Never raises.
        """
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
        Generate a plain-English explanation for a Slow HTTP ThreatEvent.

        Args:
            event: The ThreatEvent to explain.

        Returns:
            Populated Explanation object.
        """
        count = event.evidence.get("concurrent_connections", event.packet_count)
        threshold = event.evidence.get("threshold", self._threshold)
        timeout = event.evidence.get("connection_timeout_seconds", self._timeout)
        ports = event.evidence.get("target_ports", sorted(_TARGET_PORTS))
        action = "Blocked." if event.blocked else "Monitoring."

        text = (
            f"Detected {count} slow HTTP connections from {event.source_ip} on port(s) "
            f"{ports}. Each connection has been open for over {timeout}s without completing "
            f"an HTTP request (threshold: {threshold}). {action}"
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
        self._connections.clear()
        self._pending.clear()
        self._last_check = 0.0
        logger.debug("SlowHttpRule cleaned up.")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _scan_stale(self, triggering_src: str, now_mono: float) -> None:
        """
        Scan _connections for stale incomplete low-data-rate entries.

        Groups stale connections by src_ip and emits a ThreatEvent for any
        source IP whose stale count meets or exceeds _threshold.

        Called at most once per _timeout seconds from process_packet.
        """
        # Group stale connection keys by src_ip
        stale_by_src: dict[str, list[tuple]] = {}
        for conn_key, state in self._connections.items():
            src_ip = conn_key[0]
            if (
                not state["completed"]
                and (now_mono - state["opened_at"]) > self._timeout
                and state["bytes_seen"] < _LOW_DATA_BYTES
            ):
                stale_by_src.setdefault(src_ip, []).append(conn_key)

        for src_ip, stale_keys in stale_by_src.items():
            count = len(stale_keys)
            if count < self._threshold:
                continue

            # Avoid emitting duplicate pending events for same IP
            if any(e.source_ip == src_ip for e in self._pending):
                continue

            dst_ports = sorted({k[2] for k in stale_keys})
            severity = "High" if count >= 2 * self._threshold else "Medium"
            confidence = min(int(round(min(count / self._threshold, 2.0) / 2.0 * 95)), 95)

            evidence = {
                "concurrent_connections": count,
                "threshold": self._threshold,
                "connection_timeout_seconds": self._timeout,
                "target_ports": dst_ports,
            }

            self._pending.append(ThreatEvent(
                event_id=str(uuid.uuid4()),
                timestamp=_utc_now(),
                attack_type=self.attack_type,
                source_ip=src_ip,
                destination_ip=None,
                source_port=None,
                destination_port=dst_ports[0] if dst_ports else None,
                protocol="TCP",
                rule_name=self.rule_name,
                severity=severity,
                confidence=confidence,
                packet_count=count,
                evidence=evidence,
            ))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
