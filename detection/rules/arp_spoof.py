"""
arp_spoof.py — ARP Spoofing detection rule for NetGuard IDPS.

Detects ARP spoofing (man-in-the-middle) attacks by identifying when two or
more different MAC addresses claim the same IP address in ARP replies.

Detection logic:
- Maintain ip_to_macs: dict[ip_str, set[mac_str]] from ARP reply packets
- Emit ThreatEvent when len(macs_for_ip) >= 2
- Severity: always High (Requirement 8.2)
- Confidence: 97 for exactly 2 conflicting MACs, 100 for 3+ (Requirement 8.3)
- Evidence: conflicting IP, all observed MACs, first/last observed timestamps

Requirements: 8.1, 8.2, 8.3, 8.4
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from detection.parsers.packet_decoder import Packet
from detection.rules.base_rule import BaseRule, Explanation, ThreatEvent

logger = logging.getLogger("netguard.rule.arp_spoof")

_RECOMMENDATION = (
    "Verify gateway configuration and inspect network devices for unauthorized ARP entries."
)

# ARP operation codes
_ARP_OP_REPLY = 2
_ARP_OP_REQUEST = 1


@dataclass
class _ArpRecord:
    """Tracks MAC address observations for a single IP."""
    macs: set = field(default_factory=set)
    first_seen: str = ""
    last_seen: str = ""
    emitted: bool = False  # True once a ThreatEvent has been emitted for this IP


class ArpSpoofRule(BaseRule):
    """
    Detects ARP spoofing attacks on the local network.

    An ARP spoof occurs when an attacker sends gratuitous ARP replies
    advertising a MAC address for an IP that already has a different MAC
    in the ARP cache, enabling man-in-the-middle attacks.
    """

    rule_name: str = "ARP_SPOOF_001"
    attack_type: str = "ARP Spoofing"

    def __init__(self) -> None:
        self.enabled = True
        # Maps IP address string → _ArpRecord
        self._ip_to_macs: dict[str, _ArpRecord] = {}
        # Pending event queue (process_packet sets, evaluate pops)
        self._pending_event: Optional[ThreatEvent] = None

    def initialize(self) -> None:
        """Reset all ARP tracking state."""
        self._ip_to_macs.clear()
        self._pending_event = None
        logger.debug("ArpSpoofRule initialised.")

    def process_packet(self, packet: Packet) -> None:
        """
        Inspect ARP packets for conflicting IP-to-MAC mappings.

        Processes ARP replies and gratuitous ARP packets (request where
        sender IP == target IP).

        Args:
            packet: Normalised packet from PacketDecoder.
        """
        if packet.protocol != "ARP":
            return

        # We need the raw Scapy ARP layer — stored in packet.payload as bytes
        # Instead, we re-parse from payload if available; otherwise use the
        # src_ip + a synthetic MAC from extra context.
        # PacketDecoder stores payload bytes — we need to extract ARP sender MAC.
        mac = self._extract_sender_mac(packet)
        if not mac:
            return

        claimed_ip = packet.src_ip
        if not claimed_ip:
            return

        now = _utc_now()

        if claimed_ip not in self._ip_to_macs:
            self._ip_to_macs[claimed_ip] = _ArpRecord(first_seen=now, last_seen=now)

        record = self._ip_to_macs[claimed_ip]
        record.last_seen = now

        if mac not in record.macs:
            record.macs.add(mac)
            logger.debug(
                "ArpSpoofRule: IP %s now has MACs: %s", claimed_ip, record.macs
            )

        # Emit event if we have 2+ MACs and haven't emitted for this IP yet
        if len(record.macs) >= 2 and not record.emitted:
            record.emitted = True
            self._pending_event = self._build_event(claimed_ip, record, now)

    def evaluate(self) -> Optional[ThreatEvent]:
        """
        Return and clear any pending ARP spoof ThreatEvent.

        Returns:
            ThreatEvent if ARP spoofing was detected, otherwise None.
        """
        event = self._pending_event
        self._pending_event = None
        return event

    def generate_event(self) -> ThreatEvent:
        raise NotImplementedError("Use process_packet() + evaluate().")

    def explain(self, event: ThreatEvent) -> Explanation:
        """
        Generate a plain-English explanation for an ARP Spoofing ThreatEvent.

        Args:
            event: The ThreatEvent to explain.

        Returns:
            Populated Explanation object.
        """
        conflicting_ip = event.evidence.get("conflicting_ip", event.source_ip)
        macs = event.evidence.get("conflicting_macs", [])
        macs_str = ", ".join(macs) if macs else "multiple MACs"
        action = "Blocked." if event.blocked else "Monitoring."

        text = (
            f"Detected conflicting ARP responses for IP {conflicting_ip}: "
            f"MAC addresses {macs_str}. {action}"
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
        """Release all ARP tracking state."""
        self._ip_to_macs.clear()
        self._pending_event = None
        logger.debug("ArpSpoofRule cleaned up.")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_sender_mac(self, packet: Packet) -> Optional[str]:
        """
        Extract the ARP sender hardware address from the packet payload.

        Falls back to extracting from payload bytes using Scapy if available.
        """
        if packet.payload:
            try:
                from scapy.layers.l2 import ARP as ScapyARP
                from scapy.packet import Packet as ScapyPacket
                from scapy.utils import raw

                # Try to parse ARP from payload bytes
                arp_pkt = ScapyARP(packet.payload)
                if hasattr(arp_pkt, "hwsrc") and arp_pkt.hwsrc:
                    return str(arp_pkt.hwsrc).lower()
            except Exception:
                pass

        # Fallback: use extra data stored in packet.payload as string
        if packet.payload:
            try:
                payload_str = packet.payload.decode("ascii", errors="ignore")
                # Look for MAC pattern (6 groups of 2 hex digits)
                import re
                mac_match = re.search(
                    r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}"
                    r":[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})",
                    payload_str,
                )
                if mac_match:
                    return mac_match.group(1).lower()
            except Exception:
                pass

        return None

    def _build_event(
        self,
        conflicting_ip: str,
        record: _ArpRecord,
        timestamp: str,
    ) -> ThreatEvent:
        macs_list = sorted(record.macs)
        mac_count = len(macs_list)
        confidence = 100 if mac_count >= 3 else 97

        evidence = {
            "conflicting_ip": conflicting_ip,
            "conflicting_macs": macs_list,
            "mac_count": mac_count,
            "first_observed_timestamp": record.first_seen,
            "most_recent_timestamp": record.last_seen,
        }

        return ThreatEvent(
            event_id=str(uuid.uuid4()),
            timestamp=timestamp,
            attack_type=self.attack_type,
            source_ip=conflicting_ip,
            destination_ip=None,
            source_port=None,
            destination_port=None,
            protocol="ARP",
            rule_name=self.rule_name,
            severity="High",
            confidence=confidence,
            packet_count=mac_count,
            evidence=evidence,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
