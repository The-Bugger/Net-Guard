"""
test_icmp_flood_rule.py — Unit tests for IcmpFloodRule.

Covers:
(a) Below threshold → None
(b) At threshold → ThreatEvent with severity Medium
(c) Broadcast dst → Critical + smurf_pattern=True
(d) process_packet never raises on malformed packet

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.7
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from detection.parsers.packet_decoder import Packet
from detection.rules.icmp_flood import IcmpFloodRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_icmp_packet(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.1",
    icmp_type: int = 8,
) -> Packet:
    """Build a minimal ICMP Packet."""
    return Packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=None,
        dst_port=None,
        protocol="ICMP",
        flags=None,
        timestamp=_ts(),
        length=64,
        payload=None,
        icmp_type=icmp_type,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def rule() -> IcmpFloodRule:
    """Fresh IcmpFloodRule with low threshold for fast testing."""
    r = IcmpFloodRule()
    r.initialize()
    # Override to small values so tests don't send 100 packets
    r._threshold = 5
    r._window = 10.0
    return r


# ---------------------------------------------------------------------------
# (a) Below threshold → None
# ---------------------------------------------------------------------------

class TestBelowThreshold:
    def test_no_packets_returns_none(self, rule):
        assert rule.evaluate() is None

    def test_one_packet_below_threshold_returns_none(self, rule):
        rule.process_packet(make_icmp_packet())
        assert rule.evaluate() is None

    def test_threshold_minus_one_returns_none(self, rule):
        for _ in range(rule._threshold - 1):
            rule.process_packet(make_icmp_packet())
        assert rule.evaluate() is None

    def test_non_icmp_packet_ignored(self, rule):
        tcp_pkt = Packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1234, dst_port=80,
            protocol="TCP", flags="S",
            timestamp=_ts(), length=60, payload=None,
        )
        for _ in range(rule._threshold + 1):
            rule.process_packet(tcp_pkt)
        assert rule.evaluate() is None

    def test_icmp_echo_reply_ignored(self, rule):
        """icmp_type=0 (Echo Reply) must not count toward flood."""
        for _ in range(rule._threshold + 1):
            rule.process_packet(make_icmp_packet(icmp_type=0))
        assert rule.evaluate() is None


# ---------------------------------------------------------------------------
# (b) At threshold → ThreatEvent with severity Medium
# ---------------------------------------------------------------------------

class TestAtThreshold:
    def test_at_threshold_returns_event(self, rule):
        for _ in range(rule._threshold):
            rule.process_packet(make_icmp_packet())
        event = rule.evaluate()
        assert event is not None

    def test_at_threshold_severity_medium(self, rule):
        """count == threshold < 2×threshold → Medium."""
        for _ in range(rule._threshold):
            rule.process_packet(make_icmp_packet())
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "Medium"

    def test_event_attack_type(self, rule):
        for _ in range(rule._threshold):
            rule.process_packet(make_icmp_packet())
        event = rule.evaluate()
        assert event is not None
        assert event.attack_type == "ICMP Flood"
        assert event.rule_name == "ICMP_FLOOD_001"
        assert event.protocol == "ICMP"

    def test_evidence_fields_present(self, rule):
        for _ in range(rule._threshold):
            rule.process_packet(make_icmp_packet())
        event = rule.evaluate()
        assert event is not None
        ev = event.evidence
        assert "icmp_packet_count" in ev
        assert "time_window_seconds" in ev
        assert "threshold" in ev
        assert "smurf_pattern" in ev
        assert "sample_dst_ips" in ev

    def test_smurf_pattern_false_for_normal_flood(self, rule):
        for _ in range(rule._threshold):
            rule.process_packet(make_icmp_packet())
        event = rule.evaluate()
        assert event is not None
        assert event.evidence["smurf_pattern"] is False

    def test_second_evaluate_returns_none(self, rule):
        """After the first event is consumed, no duplicate is emitted."""
        for _ in range(rule._threshold):
            rule.process_packet(make_icmp_packet())
        event1 = rule.evaluate()
        assert event1 is not None
        assert rule.evaluate() is None

    def test_severity_high_at_two_times_threshold(self, rule):
        """count >= 2×threshold and < 4×threshold → High."""
        for _ in range(rule._threshold * 2):
            rule.process_packet(make_icmp_packet())
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "High"

    def test_severity_critical_at_four_times_threshold(self, rule):
        """count >= 4×threshold → Critical."""
        for _ in range(rule._threshold * 4):
            rule.process_packet(make_icmp_packet())
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "Critical"


# ---------------------------------------------------------------------------
# (c) Broadcast dst → Critical + smurf_pattern=True
# ---------------------------------------------------------------------------

class TestSmurfDetection:
    def test_broadcast_255_suffix_triggers_critical(self, rule):
        """dst ending in .255 → Critical + smurf_pattern=True."""
        rule.process_packet(make_icmp_packet(dst_ip="192.168.1.255"))
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "Critical"
        assert event.evidence["smurf_pattern"] is True

    def test_global_broadcast_triggers_critical(self, rule):
        """dst == '255.255.255.255' → Critical + smurf_pattern=True."""
        rule.process_packet(make_icmp_packet(dst_ip="255.255.255.255"))
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "Critical"
        assert event.evidence["smurf_pattern"] is True

    def test_smurf_triggers_below_threshold(self, rule):
        """Smurf fires on even a single broadcast packet (no threshold required)."""
        rule.process_packet(make_icmp_packet(dst_ip="10.0.0.255"))
        event = rule.evaluate()
        assert event is not None
        assert event.evidence["smurf_pattern"] is True

    def test_unicast_dst_not_smurf(self, rule):
        """A normal unicast destination must not set smurf_pattern=True."""
        for _ in range(rule._threshold):
            rule.process_packet(make_icmp_packet(dst_ip="10.0.0.1"))
        event = rule.evaluate()
        assert event is not None
        assert event.evidence["smurf_pattern"] is False

    def test_sample_dst_ips_populated(self, rule):
        rule.process_packet(make_icmp_packet(src_ip="1.2.3.4", dst_ip="192.168.0.255"))
        event = rule.evaluate()
        assert event is not None
        assert len(event.evidence["sample_dst_ips"]) >= 1


# ---------------------------------------------------------------------------
# (d) process_packet never raises on malformed packet
# ---------------------------------------------------------------------------

class TestNoRaiseOnMalformed:
    def test_none_icmp_type(self, rule):
        """packet.icmp_type=None must not raise."""
        pkt = make_icmp_packet(icmp_type=None)
        rule.process_packet(pkt)  # must not raise

    def test_empty_src_ip(self, rule):
        """Empty src_ip must not raise."""
        pkt = make_icmp_packet(src_ip="")
        rule.process_packet(pkt)

    def test_none_dst_ip(self, rule):
        """dst_ip=None on an ICMP packet must not raise."""
        pkt = Packet(
            src_ip="1.2.3.4", dst_ip=None,
            src_port=None, dst_port=None,
            protocol="ICMP", flags=None,
            timestamp=_ts(), length=64, payload=None,
            icmp_type=8,
        )
        rule.process_packet(pkt)  # must not raise

    def test_evaluate_on_fresh_rule_never_raises(self):
        """evaluate() on a brand-new (uninitialised) rule must not raise."""
        r = IcmpFloodRule()
        # do NOT call initialize() — simulate misconfigured engine
        result = r.evaluate()
        assert result is None


# ---------------------------------------------------------------------------
# Explain
# ---------------------------------------------------------------------------

class TestExplain:
    def test_explain_text_under_500_chars(self, rule):
        for _ in range(rule._threshold):
            rule.process_packet(make_icmp_packet())
        event = rule.evaluate()
        assert event is not None
        explanation = rule.explain(event)
        assert len(explanation.plain_english_text) <= 500

    def test_explain_smurf_mentions_broadcast(self, rule):
        rule.process_packet(make_icmp_packet(dst_ip="10.255.255.255"))
        event = rule.evaluate()
        assert event is not None
        explanation = rule.explain(event)
        assert "broadcast" in explanation.plain_english_text.lower() or "smurf" in explanation.plain_english_text.lower()

    def test_explain_returns_explanation_object(self, rule):
        from detection.rules.base_rule import Explanation
        for _ in range(rule._threshold):
            rule.process_packet(make_icmp_packet())
        event = rule.evaluate()
        assert event is not None
        result = rule.explain(event)
        assert isinstance(result, Explanation)


# ---------------------------------------------------------------------------
# cleanup / initialize
# ---------------------------------------------------------------------------

class TestLifecycle:
    def test_cleanup_clears_state(self, rule):
        for _ in range(rule._threshold):
            rule.process_packet(make_icmp_packet())
        rule.cleanup()
        assert rule.evaluate() is None
        assert not rule._flow
        assert not rule._emitted

    def test_initialize_clears_state(self, rule):
        for _ in range(rule._threshold):
            rule.process_packet(make_icmp_packet())
        rule.initialize()
        assert rule.evaluate() is None
