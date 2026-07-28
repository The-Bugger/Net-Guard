"""
arp_spoof.py — ARP Spoofing detection rule for NetGuard IDPS.

Detects ARP spoofing (man-in-the-middle) attacks by identifying when two or
more different MAC addresses claim the same IP address in ARP replies.

Detection logic:
- Maintain _ip_to_macs: dict[str, set[str]] — maps each IP to observed MAC addresses
- Emit ThreatEvent when len(macs_for_ip) >= 2
- Severity: always High (Requirement 8.2)
- Confidence: 97 for exactly 2 conflicting MACs, 100 for 3+ (Requirement 8.3)
- Evidence: conflicting_ip, conflicting_macs (list), first_observed_timestamp,
  most_recent_timestamp (Requirement 8.4)

The Packet dataclass exposes hw_src (populated by PacketDecoder from
arp_layer.hwsrc), so no payload re-parsing is needed here.

Requirements: 8.1, 8.2, 8.3, 8.4
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from detection.parsers.packet_decoder import Packet
from detection.rules.base_rule import BaseRule, Explanation, ThreatEvent

logger = logging.getLogger("netguard.rule.arp_spoof")

_RECOMMENDATION = (
    "Verify gateway configuration and inspect network devices for unauthorized ARP entries."
)


class ArpSpoofRule(BaseRule):
    """
    Detects ARP spoofing attacks on the local network.

    An ARP spoof occurs when an attacker sends gratuitous ARP replies or
    requests advertising a MAC address for an IP that already has a different
    MAC recorded, enabling man-in-the-middle attacks.

    Relies on `packet.hw_src` set by PacketDecoder from arp_layer.hwsrc.
    """

    rule_name: str = "ARP_SPOOF_001"
    attack_type: str = "ARP Spoofing"

    def __init__(self) -> None:
        super().__init__()
        # Maps IP address string → set of observed MAC address strings
        self._ip_to_macs: dict[str, set[str]] = {}
        # Timestamp of the first ARP packet observed per IP
        self._ip_first_seen: dict[str, str] = {}
        # Timestamp of the most recent ARP packet per IP
        self._ip_last_seen: dict[str, str] = {}
        # Pending events produced in process_packet, consumed by evaluate()
        self._pending: list[dict] = []
        # Track which IPs have already had an event emitted to avoid duplicates
        self._emitted: set[str] = set()

    # ------------------------------------------------------------------
    # BaseRule interface
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Reset all ARP tracking state."""
        self._ip_to_macs.clear()
        self._ip_first_seen.clear()
        self._ip_last_seen.clear()
        self._pending.clear()
        self._emitted.clear()
        logger.debug("ArpSpoofRule initialised.")

    def process_packet(self, packet: Packet) -> None:
        """
        Inspect ARP packets for conflicting IP-to-MAC mappings.

        Uses packet.hw_src (set by PacketDecoder from arp_layer.hwsrc) to
        track which MAC addresses have claimed each IP address.

        Args:
            packet: Normalised packet from PacketDecoder.
        """
        if packet.protocol != "ARP":
            return

        mac = packet.hw_src
        if not mac:
            return

        claimed_ip = packet.src_ip
        if not claimed_ip:
            return

        now = _utc_now()

        # Initialise tracking structures for new IP
        if claimed_ip not in self._ip_to_macs:
            self._ip_to_macs[claimed_ip] = set()
            self._ip_first_seen[claimed_ip] = now

        self._ip_last_seen[claimed_ip] = now
        macs = self._ip_to_macs[claimed_ip]

        if mac not in macs:
            macs.add(mac)
            logger.debug(
                "ArpSpoofRule: IP %s now has MACs: %s", claimed_ip, macs
            )

        # Queue a pending event if threshold reached and not yet emitted
        if len(macs) >= 2 and claimed_ip not in self._emitted:
            self._emitted.add(claimed_ip)
            self._pending.append({
                "ip": claimed_ip,
                "macs": set(macs),  # snapshot
                "timestamp": now,
            })

    def evaluate(self) -> Optional[ThreatEvent]:
        """
        Return and clear the next pending ARP spoof ThreatEvent, if any.

        Returns:
            ThreatEvent if ARP spoofing was detected, otherwise None.
        """
        if not self._pending:
            return None

        item = self._pending.pop(0)
        return self._build_event(item["ip"], item["macs"], item["timestamp"])

    def generate_event(self) -> ThreatEvent:
        """Not called directly — use process_packet() + evaluate()."""
        raise NotImplementedError("Use process_packet() + evaluate() instead.")

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
        self._ip_first_seen.clear()
        self._ip_last_seen.clear()
        self._pending.clear()
        self._emitted.clear()
        logger.debug("ArpSpoofRule cleaned up.")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_event(
        self,
        conflicting_ip: str,
        macs: set[str],
        timestamp: str,
    ) -> ThreatEvent:
        """Construct a ThreatEvent from the observed IP/MAC conflict."""
        macs_list = sorted(macs)
        mac_count = len(macs_list)
        confidence = 100 if mac_count >= 3 else 97

        evidence = {
            "conflicting_ip": conflicting_ip,
            "conflicting_macs": macs_list,
            "mac_count": mac_count,
            "first_observed_timestamp": self._ip_first_seen.get(conflicting_ip, timestamp),
            "most_recent_timestamp": self._ip_last_seen.get(conflicting_ip, timestamp),
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
