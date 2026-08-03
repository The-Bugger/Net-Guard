"""
test_arp_spoof.py — Unit tests for ArpSpoofRule.

Covers trigger logic (≥2 MACs for the same IP), confidence tiers (97 for
exactly 2 MACs, 100 for ≥3 MACs), required evidence fields, and the
invariant that severity is always "High".

Requirements: 8.1, 8.2, 8.3, 8.4
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from detection.parsers.packet_decoder import Packet
from detection.rules.arp_spoof import ArpSpoofRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts_now() -> str:
    """Return current UTC time as ISO-8601 string (matching the rule's format)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_arp_packet(
    src_ip: str = "192.168.1.1",
    mac: str = "aa:bb:cc:dd:ee:ff",
    timestamp: str | None = None,
) -> Packet:
    """Build a single ARP reply Packet with the given source IP and MAC address."""
    return Packet(
        src_ip=src_ip,
        dst_ip="192.168.1.254",
        src_port=None,
        dst_port=None,
        protocol="ARP",
        flags=None,
        timestamp=timestamp or _ts_now(),
        length=42,
        payload=None,
        hw_src=mac,
        arp_op=2,
    )


def _feed(rule: ArpSpoofRule, packets: list[Packet]) -> None:
    """Process a list of packets through the rule."""
    for pkt in packets:
        rule.process_packet(pkt)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def rule() -> ArpSpoofRule:
    """Fresh ArpSpoofRule, fully initialised."""
    r = ArpSpoofRule()
    r.initialize()
    return r


# ---------------------------------------------------------------------------
# Trigger tests (Requirement 8.1)
# ---------------------------------------------------------------------------

class TestTriggerCondition:
    """Rule must emit a ThreatEvent when ≥2 different MACs claim the same IP."""

    def test_single_mac_no_event(self, rule):
        """Only one MAC for an IP must produce no event."""
        rule.process_packet(make_arp_packet(src_ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01"))
        assert rule.evaluate() is None

    def test_same_mac_twice_no_event(self, rule):
        """Repeated packets from the same MAC for the same IP must not trigger."""
        for _ in range(5):
            rule.process_packet(make_arp_packet(src_ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01"))
        assert rule.evaluate() is None

    def test_two_different_macs_triggers_event(self, rule):
        """Two different MACs for the same IP must produce a ThreatEvent (Req 8.1)."""
        rule.process_packet(make_arp_packet(src_ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01"))
        rule.process_packet(make_arp_packet(src_ip="10.0.0.1", mac="ff:ee:dd:cc:bb:02"))
        event = rule.evaluate()

        assert event is not None
        assert event.attack_type == "ARP Spoofing"
        assert event.rule_name == "ARP_SPOOF_001"

    def test_three_different_macs_triggers_event(self, rule):
        """Three different MACs for the same IP must also produce a ThreatEvent."""
        rule.process_packet(make_arp_packet(src_ip="10.0.0.2", mac="aa:00:00:00:00:01"))
        rule.process_packet(make_arp_packet(src_ip="10.0.0.2", mac="bb:00:00:00:00:02"))
        rule.process_packet(make_arp_packet(src_ip="10.0.0.2", mac="cc:00:00:00:00:03"))
        event = rule.evaluate()

        assert event is not None

    def test_different_ips_no_cross_contamination(self, rule):
        """Two MACs for different IPs must not trigger an event for either IP."""
        rule.process_packet(make_arp_packet(src_ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01"))
        rule.process_packet(make_arp_packet(src_ip="10.0.0.2", mac="ff:ee:dd:cc:bb:02"))
        assert rule.evaluate() is None

    def test_non_arp_packets_ignored(self, rule):
        """Non-ARP packets must be ignored even at high volume."""
        tcp_pkt = Packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=80,
            protocol="TCP",
            flags="S",
            timestamp=_ts_now(),
            length=60,
            payload=None,
            hw_src="aa:bb:cc:dd:ee:01",
        )
        for _ in range(10):
            rule.process_packet(tcp_pkt)
        assert rule.evaluate() is None

    def test_arp_packet_with_no_hw_src_ignored(self, rule):
        """ARP packet with hw_src=None must not contribute to MAC tracking."""
        pkt = make_arp_packet(src_ip="10.0.0.1", mac=None)
        rule.process_packet(pkt)
        rule.process_packet(make_arp_packet(src_ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01"))
        assert rule.evaluate() is None

    def test_event_source_ip_matches_conflicting_ip(self, rule):
        """event.source_ip must be the IP with conflicting MACs."""
        rule.process_packet(make_arp_packet(src_ip="192.168.5.10", mac="aa:00:00:00:00:01"))
        rule.process_packet(make_arp_packet(src_ip="192.168.5.10", mac="bb:00:00:00:00:02"))
        event = rule.evaluate()

        assert event is not None
        assert event.source_ip == "192.168.5.10"


# ---------------------------------------------------------------------------
# Severity tests (Requirement 8.2)
# ---------------------------------------------------------------------------

class TestSeverityAlwaysHigh:
    """Severity must always be 'High' regardless of MAC count (Requirement 8.2)."""

    def test_severity_high_for_two_macs(self, rule):
        """Exactly 2 MACs → severity must be 'High'."""
        rule.process_packet(make_arp_packet(src_ip="10.1.1.1", mac="aa:00:00:00:00:01"))
        rule.process_packet(make_arp_packet(src_ip="10.1.1.1", mac="bb:00:00:00:00:02"))
        event = rule.evaluate()

        assert event is not None
        assert event.severity == "High"

    def test_severity_high_for_three_macs(self, rule):
        """3 MACs → severity must still be 'High'."""
        rule.process_packet(make_arp_packet(src_ip="10.1.1.2", mac="aa:00:00:00:00:01"))
        rule.process_packet(make_arp_packet(src_ip="10.1.1.2", mac="bb:00:00:00:00:02"))
        rule.process_packet(make_arp_packet(src_ip="10.1.1.2", mac="cc:00:00:00:00:03"))
        event = rule.evaluate()

        assert event is not None
        assert event.severity == "High"

    def test_severity_high_for_many_macs(self, rule):
        """5+ MACs → severity must still be 'High'."""
        ip = "10.1.1.3"
        for i in range(5):
            rule.process_packet(make_arp_packet(src_ip=ip, mac=f"aa:00:00:00:00:{i+1:02x}"))
        event = rule.evaluate()

        assert event is not None
        assert event.severity == "High"


# ---------------------------------------------------------------------------
# Confidence tier tests (Requirement 8.3)
# ---------------------------------------------------------------------------

class TestConfidenceTiers:
    """Confidence: 97 for exactly 2 MACs, 100 for ≥3 MACs (Requirement 8.3)."""

    def test_confidence_97_for_exactly_two_macs(self, rule):
        """Exactly 2 MACs → confidence must be 97."""
        rule.process_packet(make_arp_packet(src_ip="10.2.0.1", mac="aa:00:00:00:00:01"))
        rule.process_packet(make_arp_packet(src_ip="10.2.0.1", mac="bb:00:00:00:00:02"))
        event = rule.evaluate()

        assert event is not None
        assert event.confidence == 97

    def test_confidence_100_for_three_macs(self, rule):
        """Exactly 3 MACs → confidence must be 100."""
        rule.process_packet(make_arp_packet(src_ip="10.2.0.2", mac="aa:00:00:00:00:01"))
        rule.process_packet(make_arp_packet(src_ip="10.2.0.2", mac="bb:00:00:00:00:02"))
        rule.process_packet(make_arp_packet(src_ip="10.2.0.2", mac="cc:00:00:00:00:03"))
        event = rule.evaluate()

        assert event is not None
        assert event.confidence == 100

    def test_confidence_100_for_more_than_three_macs(self, rule):
        """4+ MACs → confidence must be 100."""
        ip = "10.2.0.3"
        for i in range(4):
            rule.process_packet(make_arp_packet(src_ip=ip, mac=f"dd:00:00:00:00:{i+1:02x}"))
        event = rule.evaluate()

        assert event is not None
        assert event.confidence == 100

    def test_confidence_transitions_97_to_100_on_third_mac(self, rule):
        """
        When a 3rd MAC arrives before evaluate() is called, the pending event
        must be updated to confidence=100.
        """
        ip = "10.2.0.4"
        rule.process_packet(make_arp_packet(src_ip=ip, mac="aa:00:00:00:00:01"))
        rule.process_packet(make_arp_packet(src_ip=ip, mac="bb:00:00:00:00:02"))
        # 3rd MAC before any evaluate()
        rule.process_packet(make_arp_packet(src_ip=ip, mac="cc:00:00:00:00:03"))

        event = rule.evaluate()

        assert event is not None
        assert event.confidence == 100


# ---------------------------------------------------------------------------
# Evidence fields tests (Requirement 8.4)
# ---------------------------------------------------------------------------

class TestEvidenceFields:
    """Evidence dict must contain all required keys (Requirement 8.4)."""

    def _get_event_two_macs(self, rule: ArpSpoofRule):
        rule.process_packet(make_arp_packet(src_ip="10.3.0.1", mac="aa:00:00:00:00:01"))
        rule.process_packet(make_arp_packet(src_ip="10.3.0.1", mac="bb:00:00:00:00:02"))
        return rule.evaluate()

    def test_evidence_has_conflicting_ip(self, rule):
        """evidence['conflicting_ip'] must be present."""
        event = self._get_event_two_macs(rule)
        assert event is not None
        assert "conflicting_ip" in event.evidence

    def test_evidence_conflicting_ip_value(self, rule):
        """evidence['conflicting_ip'] must equal the IP with conflicting MACs."""
        event = self._get_event_two_macs(rule)
        assert event is not None
        assert event.evidence["conflicting_ip"] == "10.3.0.1"

    def test_evidence_has_conflicting_macs(self, rule):
        """evidence['conflicting_macs'] must be present."""
        event = self._get_event_two_macs(rule)
        assert event is not None
        assert "conflicting_macs" in event.evidence

    def test_evidence_conflicting_macs_is_list(self, rule):
        """evidence['conflicting_macs'] must be a list."""
        event = self._get_event_two_macs(rule)
        assert event is not None
        assert isinstance(event.evidence["conflicting_macs"], list)

    def test_evidence_conflicting_macs_contains_both_macs(self, rule):
        """evidence['conflicting_macs'] must contain both observed MACs."""
        mac1 = "aa:00:00:00:00:01"
        mac2 = "bb:00:00:00:00:02"
        rule.process_packet(make_arp_packet(src_ip="10.3.0.2", mac=mac1))
        rule.process_packet(make_arp_packet(src_ip="10.3.0.2", mac=mac2))
        event = rule.evaluate()

        assert event is not None
        macs = event.evidence["conflicting_macs"]
        assert mac1 in macs
        assert mac2 in macs

    def test_evidence_has_first_observed_timestamp(self, rule):
        """evidence['first_observed_timestamp'] must be present."""
        event = self._get_event_two_macs(rule)
        assert event is not None
        assert "first_observed_timestamp" in event.evidence

    def test_evidence_first_observed_timestamp_is_iso8601(self, rule):
        """evidence['first_observed_timestamp'] must be a non-empty ISO-8601 string."""
        event = self._get_event_two_macs(rule)
        assert event is not None
        ts = event.evidence["first_observed_timestamp"]
        assert isinstance(ts, str)
        assert "T" in ts
        assert ts.endswith("Z")

    def test_evidence_has_most_recent_timestamp(self, rule):
        """evidence['most_recent_timestamp'] must be present."""
        event = self._get_event_two_macs(rule)
        assert event is not None
        assert "most_recent_timestamp" in event.evidence

    def test_evidence_most_recent_timestamp_is_iso8601(self, rule):
        """evidence['most_recent_timestamp'] must be a non-empty ISO-8601 string."""
        event = self._get_event_two_macs(rule)
        assert event is not None
        ts = event.evidence["most_recent_timestamp"]
        assert isinstance(ts, str)
        assert "T" in ts
        assert ts.endswith("Z")

    def test_evidence_conflicting_macs_count_matches_mac_count_field(self, rule):
        """len(evidence['conflicting_macs']) must equal evidence['mac_count']."""
        ip = "10.3.0.3"
        rule.process_packet(make_arp_packet(src_ip=ip, mac="aa:00:00:00:00:01"))
        rule.process_packet(make_arp_packet(src_ip=ip, mac="bb:00:00:00:00:02"))
        rule.process_packet(make_arp_packet(src_ip=ip, mac="cc:00:00:00:00:03"))
        event = rule.evaluate()

        assert event is not None
        ev = event.evidence
        assert len(ev["conflicting_macs"]) == ev["mac_count"]


# ---------------------------------------------------------------------------
# ThreatEvent core fields
# ---------------------------------------------------------------------------

class TestThreatEventFields:
    """Core ThreatEvent fields must be correctly populated."""

    def test_event_protocol_is_arp(self, rule):
        """event.protocol must be 'ARP'."""
        rule.process_packet(make_arp_packet(src_ip="10.4.0.1", mac="aa:00:00:00:00:01"))
        rule.process_packet(make_arp_packet(src_ip="10.4.0.1", mac="bb:00:00:00:00:02"))
        event = rule.evaluate()

        assert event is not None
        assert event.protocol == "ARP"

    def test_event_has_unique_id(self, rule):
        """event.event_id must be a non-empty string (UUID)."""
        rule.process_packet(make_arp_packet(src_ip="10.4.0.2", mac="aa:00:00:00:00:01"))
        rule.process_packet(make_arp_packet(src_ip="10.4.0.2", mac="bb:00:00:00:00:02"))
        event = rule.evaluate()

        assert event is not None
        assert isinstance(event.event_id, str)
        assert len(event.event_id) > 0

    def test_event_timestamp_is_iso8601(self, rule):
        """event.timestamp must be a non-empty ISO-8601 string."""
        rule.process_packet(make_arp_packet(src_ip="10.4.0.3", mac="aa:00:00:00:00:01"))
        rule.process_packet(make_arp_packet(src_ip="10.4.0.3", mac="bb:00:00:00:00:02"))
        event = rule.evaluate()

        assert event is not None
        assert isinstance(event.timestamp, str)
        assert "T" in event.timestamp
        assert event.timestamp.endswith("Z")

    def test_event_packet_count_equals_mac_count(self, rule):
        """event.packet_count must equal the number of distinct MACs observed."""
        ip = "10.4.0.4"
        rule.process_packet(make_arp_packet(src_ip=ip, mac="aa:00:00:00:00:01"))
        rule.process_packet(make_arp_packet(src_ip=ip, mac="bb:00:00:00:00:02"))
        rule.process_packet(make_arp_packet(src_ip=ip, mac="cc:00:00:00:00:03"))
        event = rule.evaluate()

        assert event is not None
        assert event.packet_count == 3

    def test_no_second_event_for_same_ip(self, rule):
        """Once an event is emitted for an IP, a second evaluate() returns None."""
        rule.process_packet(make_arp_packet(src_ip="10.4.0.5", mac="aa:00:00:00:00:01"))
        rule.process_packet(make_arp_packet(src_ip="10.4.0.5", mac="bb:00:00:00:00:02"))

        event1 = rule.evaluate()
        assert event1 is not None

        event2 = rule.evaluate()
        assert event2 is None

    def test_independent_events_for_different_ips(self, rule):
        """Two different IPs each with 2 MACs must each produce their own event."""
        rule.process_packet(make_arp_packet(src_ip="10.5.0.1", mac="aa:00:00:00:00:01"))
        rule.process_packet(make_arp_packet(src_ip="10.5.0.1", mac="bb:00:00:00:00:02"))
        rule.process_packet(make_arp_packet(src_ip="10.5.0.2", mac="cc:00:00:00:00:03"))
        rule.process_packet(make_arp_packet(src_ip="10.5.0.2", mac="dd:00:00:00:00:04"))

        event1 = rule.evaluate()
        event2 = rule.evaluate()

        assert event1 is not None
        assert event2 is not None
        assert {event1.source_ip, event2.source_ip} == {"10.5.0.1", "10.5.0.2"}
