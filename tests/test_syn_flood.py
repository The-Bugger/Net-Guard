"""
test_syn_flood.py — Unit tests for SynFloodRule.

Covers threshold detection, severity tiers, confidence formula,
evidence field population, sample timestamp capping, and cooldown
suppression/escalation logic.

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7
"""

from __future__ import annotations

import time
from datetime import datetime, timezone, timedelta

import pytest

from detection.parsers.packet_decoder import Packet
from detection.rules.syn_flood import SynFloodRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts_now() -> str:
    """Return current UTC time as ISO-8601 string used by the rule."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts_future(seconds: int) -> str:
    """Return a UTC ISO-8601 string <seconds> seconds in the future."""
    dt = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_syn_packet(
    src_ip: str = "1.2.3.4",
    dst_ip: str = "10.0.0.1",
    count: int = 1,
    flags: str = "S",
    timestamp: str | None = None,
) -> list[Packet]:
    """Build a list of TCP packets with the given flags (default pure SYN)."""
    ts = timestamp or _ts_now()
    pkts = []
    for _ in range(count):
        pkts.append(
            Packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=12345,
                dst_port=80,
                protocol="TCP",
                flags=flags,
                timestamp=ts,
                length=60,
                payload=None,
            )
        )
    return pkts


def _feed(rule: SynFloodRule, packets: list[Packet]) -> None:
    """Process every packet through the rule."""
    for pkt in packets:
        rule.process_packet(pkt)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def rule() -> SynFloodRule:
    """Fresh SynFloodRule with threshold=100 and a large window to avoid expiry."""
    r = SynFloodRule(threshold=100, window_seconds=3600, cooldown_seconds=10)
    r.initialize()
    return r


# ---------------------------------------------------------------------------
# Threshold tests (Requirements 4.1, 4.6)
# ---------------------------------------------------------------------------

class TestThresholdDetection:
    """Requirement 4.1 — events are emitted only when threshold is reached."""

    def test_below_threshold_no_event(self, rule):
        """Sending fewer than threshold SYN packets must produce no event."""
        _feed(rule, make_syn_packet(count=99))
        assert rule.evaluate() is None

    def test_at_threshold_emits_event(self, rule):
        """Exactly threshold SYN packets must produce a ThreatEvent."""
        _feed(rule, make_syn_packet(count=100))
        event = rule.evaluate()

        assert event is not None
        assert event.attack_type == "SYN Flood"
        assert event.rule_name == "SYN_FLOOD_001"

    def test_above_threshold_emits_event(self, rule):
        """More than threshold SYN packets must also produce a ThreatEvent."""
        _feed(rule, make_syn_packet(count=150))
        event = rule.evaluate()

        assert event is not None
        assert event.attack_type == "SYN Flood"


# ---------------------------------------------------------------------------
# Packet filtering tests (Requirements 4.1, 4.6)
# ---------------------------------------------------------------------------

class TestPacketFiltering:
    """Only pure-SYN packets should be counted (Requirement 4.1)."""

    def test_non_syn_packet_ignored(self, rule):
        """TCP packets with ACK-only flag must not be counted."""
        _feed(rule, make_syn_packet(count=200, flags="A"))
        assert rule.evaluate() is None

    def test_syn_ack_ignored(self, rule):
        """TCP SYN-ACK packets must not be counted."""
        _feed(rule, make_syn_packet(count=200, flags="SA"))
        assert rule.evaluate() is None

    def test_non_tcp_ignored(self, rule):
        """UDP packets must not be counted even with high volume."""
        udp_pkts = [
            Packet(
                src_ip="1.2.3.4",
                dst_ip="10.0.0.1",
                src_port=12345,
                dst_port=80,
                protocol="UDP",
                flags=None,
                timestamp=_ts_now(),
                length=60,
                payload=None,
            )
            for _ in range(200)
        ]
        _feed(rule, udp_pkts)
        assert rule.evaluate() is None


# ---------------------------------------------------------------------------
# Severity tests (Requirements 4.2, 4.3, 4.4)
# ---------------------------------------------------------------------------

class TestSeverityTiers:
    """Severity is determined by SYN count: Medium/High/Critical (Req 4.2-4.4)."""

    def test_severity_medium(self):
        """Count in [100, 199] must produce severity='Medium'."""
        rule = SynFloodRule(threshold=100, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_syn_packet(count=150))
        event = rule.evaluate()

        assert event is not None
        assert event.severity == "Medium"

    def test_severity_high(self):
        """Count in [200, 399] must produce severity='High'."""
        rule = SynFloodRule(threshold=100, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_syn_packet(count=300))
        event = rule.evaluate()

        assert event is not None
        assert event.severity == "High"

    def test_severity_critical(self):
        """Count >= 400 must produce severity='Critical'."""
        rule = SynFloodRule(threshold=100, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_syn_packet(count=400))
        event = rule.evaluate()

        assert event is not None
        assert event.severity == "Critical"

    def test_severity_exactly_100(self):
        """Boundary at exactly 100 (threshold) is 'Medium'."""
        rule = SynFloodRule(threshold=100, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_syn_packet(count=100))
        event = rule.evaluate()

        assert event is not None
        assert event.severity == "Medium"

    def test_severity_exactly_200(self):
        """Boundary at exactly 200 transitions to 'High'."""
        rule = SynFloodRule(threshold=100, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_syn_packet(count=200))
        event = rule.evaluate()

        assert event is not None
        assert event.severity == "High"

    def test_severity_exactly_400(self):
        """Boundary at exactly 400 transitions to 'Critical'."""
        rule = SynFloodRule(threshold=100, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_syn_packet(count=400))
        event = rule.evaluate()

        assert event is not None
        assert event.severity == "Critical"


# ---------------------------------------------------------------------------
# Confidence formula test (Requirement 4.5)
# ---------------------------------------------------------------------------

class TestConfidenceFormula:
    """Confidence = round(min(count/threshold, 2.0) / 2.0 * 100) (Req 4.5)."""

    def test_confidence_at_threshold(self, rule):
        """At exactly threshold confidence should be 50."""
        _feed(rule, make_syn_packet(count=100))
        event = rule.evaluate()

        assert event is not None
        expected = round(min(100 / 100, 2.0) / 2.0 * 100)
        assert event.confidence == expected

    def test_confidence_at_double_threshold(self, rule):
        """At 2× threshold confidence should be 100 (capped)."""
        _feed(rule, make_syn_packet(count=200))
        event = rule.evaluate()

        assert event is not None
        expected = round(min(200 / 100, 2.0) / 2.0 * 100)
        assert event.confidence == expected
        assert event.confidence == 100

    def test_confidence_formula(self, rule):
        """Verify the formula for an arbitrary count above threshold."""
        count = 150
        threshold = 100
        _feed(rule, make_syn_packet(count=count))
        event = rule.evaluate()

        assert event is not None
        expected = round(min(count / threshold, 2.0) / 2.0 * 100)
        assert event.confidence == expected

    def test_confidence_above_double_threshold_capped(self, rule):
        """Counts beyond 2× threshold must not exceed 100 confidence."""
        _feed(rule, make_syn_packet(count=500))
        event = rule.evaluate()

        assert event is not None
        assert event.confidence == 100


# ---------------------------------------------------------------------------
# Evidence fields test (Requirement 4.6)
# ---------------------------------------------------------------------------

class TestEvidenceFields:
    """Evidence dict must contain required keys (Requirement 4.6)."""

    def test_evidence_fields(self, rule):
        """Evidence must contain source_ip, syn_packet_count, time_window_seconds,
        destination_ips, and sample_timestamps."""
        _feed(rule, make_syn_packet(count=100))
        event = rule.evaluate()

        assert event is not None
        ev = event.evidence

        assert "source_ip" in ev
        assert "syn_packet_count" in ev
        assert "time_window_seconds" in ev
        assert "destination_ips" in ev
        assert "sample_timestamps" in ev

    def test_evidence_source_ip_matches(self, rule):
        """evidence['source_ip'] must match the attacking IP."""
        _feed(rule, make_syn_packet(src_ip="5.5.5.5", count=100))
        event = rule.evaluate()

        assert event is not None
        assert event.evidence["source_ip"] == "5.5.5.5"

    def test_evidence_packet_count_matches(self, rule):
        """evidence['syn_packet_count'] must equal the actual count processed."""
        _feed(rule, make_syn_packet(count=120))
        event = rule.evaluate()

        assert event is not None
        assert event.evidence["syn_packet_count"] == 120

    def test_evidence_destination_ips_is_list(self, rule):
        """evidence['destination_ips'] must be a list."""
        _feed(rule, make_syn_packet(count=100))
        event = rule.evaluate()

        assert event is not None
        assert isinstance(event.evidence["destination_ips"], list)

    def test_evidence_sample_timestamps_is_list(self, rule):
        """evidence['sample_timestamps'] must be a list."""
        _feed(rule, make_syn_packet(count=100))
        event = rule.evaluate()

        assert event is not None
        assert isinstance(event.evidence["sample_timestamps"], list)


# ---------------------------------------------------------------------------
# Sample timestamps cap test (Requirement 4.6)
# ---------------------------------------------------------------------------

class TestSampleTimestamps:
    """sample_timestamps must have at most 5 entries (Requirement 4.6)."""

    def test_sample_timestamps_max_5(self, rule):
        """Even with many packets, sample_timestamps has at most 5 entries."""
        _feed(rule, make_syn_packet(count=200))
        event = rule.evaluate()

        assert event is not None
        assert len(event.evidence["sample_timestamps"]) <= 5

    def test_sample_timestamps_few_packets(self, rule):
        """With exactly 3 packets at threshold, sample has <= 5 entries."""
        # Use a low threshold to trigger with few packets
        low_rule = SynFloodRule(threshold=3, window_seconds=3600, cooldown_seconds=10)
        low_rule.initialize()
        _feed(low_rule, make_syn_packet(count=3))
        event = low_rule.evaluate()

        assert event is not None
        assert len(event.evidence["sample_timestamps"]) <= 5


# ---------------------------------------------------------------------------
# Cooldown tests (Requirements 4.7)
# ---------------------------------------------------------------------------

class TestCooldown:
    """Cooldown suppresses duplicate events; higher severity always emitted (Req 4.7)."""

    def test_cooldown_suppresses_duplicate(self, rule):
        """Second evaluate() for same IP/severity within cooldown window returns None."""
        _feed(rule, make_syn_packet(count=150))

        # First call should emit (Medium)
        event1 = rule.evaluate()
        assert event1 is not None
        assert event1.severity == "Medium"

        # Second call within cooldown window for same count/severity → suppressed
        event2 = rule.evaluate()
        assert event2 is None

    def test_cooldown_allows_higher_severity(self):
        """Higher severity event within cooldown must still be emitted."""
        # Start with medium (100–199): use threshold=100, send 150 → Medium
        rule = SynFloodRule(threshold=100, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()

        _feed(rule, make_syn_packet(count=150))
        event1 = rule.evaluate()
        assert event1 is not None
        assert event1.severity == "Medium"

        # Now add more packets to push count into High range (200-399)
        # Feed 50 more SYN packets to bring total to 200
        _feed(rule, make_syn_packet(count=50))
        event2 = rule.evaluate()

        # Should emit because High > Medium
        assert event2 is not None
        assert event2.severity == "High"

    def test_cooldown_suppresses_same_severity_different_call(self, rule):
        """Multiple consecutive evaluate() calls at same severity all suppressed after first."""
        _feed(rule, make_syn_packet(count=150))

        event1 = rule.evaluate()
        assert event1 is not None  # first one fires

        # All subsequent calls within cooldown → None
        for _ in range(3):
            assert rule.evaluate() is None

    def test_cooldown_different_ips_independent(self):
        """Cooldown for one source IP must not affect detection for a different source IP."""
        rule = SynFloodRule(threshold=100, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()

        _feed(rule, make_syn_packet(src_ip="1.1.1.1", count=150))
        event1 = rule.evaluate()
        assert event1 is not None
        assert event1.source_ip == "1.1.1.1"

        _feed(rule, make_syn_packet(src_ip="2.2.2.2", count=150))
        event2 = rule.evaluate()
        assert event2 is not None
        assert event2.source_ip == "2.2.2.2"


# ---------------------------------------------------------------------------
# Source IP and destination IP in event (Requirements 4.1, 4.6)
# ---------------------------------------------------------------------------

class TestEventFields:
    """Core ThreatEvent fields must be correctly populated."""

    def test_event_source_ip(self, rule):
        """event.source_ip must match the attacking source IP."""
        _feed(rule, make_syn_packet(src_ip="9.8.7.6", count=100))
        event = rule.evaluate()

        assert event is not None
        assert event.source_ip == "9.8.7.6"

    def test_event_protocol_is_tcp(self, rule):
        """event.protocol must be 'TCP' for SYN flood."""
        _feed(rule, make_syn_packet(count=100))
        event = rule.evaluate()

        assert event is not None
        assert event.protocol == "TCP"

    def test_event_packet_count_matches(self, rule):
        """event.packet_count must reflect the number of SYN packets processed."""
        _feed(rule, make_syn_packet(count=120))
        event = rule.evaluate()

        assert event is not None
        assert event.packet_count == 120

    def test_event_has_unique_id(self, rule):
        """event.event_id must be a non-empty string."""
        _feed(rule, make_syn_packet(count=100))
        event = rule.evaluate()

        assert event is not None
        assert isinstance(event.event_id, str)
        assert len(event.event_id) > 0

    def test_event_timestamp_is_set(self, rule):
        """event.timestamp must be a non-empty ISO-8601 string."""
        _feed(rule, make_syn_packet(count=100))
        event = rule.evaluate()

        assert event is not None
        assert isinstance(event.timestamp, str)
        assert "T" in event.timestamp  # ISO-8601 format check


# ---------------------------------------------------------------------------
# Window sliding / expiry test
# ---------------------------------------------------------------------------

class TestWindowSliding:
    """Packets outside the sliding window are not counted (Requirement 4.1)."""

    def test_old_packets_expired_from_window(self):
        """Packets with timestamps older than window_seconds must be discarded."""
        rule = SynFloodRule(threshold=100, window_seconds=5, cooldown_seconds=10)
        rule.initialize()

        # Build packets with a timestamp well in the past (60s ago)
        past_dt = datetime.now(timezone.utc) - timedelta(seconds=60)
        past_ts = past_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        old_packets = [
            Packet(
                src_ip="1.2.3.4",
                dst_ip="10.0.0.1",
                src_port=12345,
                dst_port=80,
                protocol="TCP",
                flags="S",
                timestamp=past_ts,
                length=60,
                payload=None,
            )
            for _ in range(200)
        ]
        _feed(rule, old_packets)

        # All old packets should have been expired; no event
        assert rule.evaluate() is None

    def test_recent_packets_within_window_counted(self):
        """Packets with current timestamps within window must be counted normally."""
        rule = SynFloodRule(threshold=100, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()

        _feed(rule, make_syn_packet(count=100))
        assert rule.evaluate() is not None
