"""
test_port_scan.py — Unit tests for PortScanRule.

Tests cover Requirements 5.1–5.6:
  5.1  Track unique destination ports per source IP in a sliding window
  5.2  Emit ThreatEvent when unique port count >= threshold
  5.3  Severity tiers: 20–39 → Medium, 40–79 → High, ≥80 → Critical
  5.4  Confidence formula: round(min(count/threshold, 2.0) / 2.0 * 100)
  5.5  Evidence includes scanned_ports (capped at 20), unique_port_count, etc.
  5.6  Cooldown: suppress duplicate events for same IP within cooldown period
"""

from __future__ import annotations

import time

import pytest

from detection.parsers.packet_decoder import Packet
from detection.rules.port_scan import PortScanRule, _scan_confidence, _scan_severity


# ---------------------------------------------------------------------------
# Helper factory
# ---------------------------------------------------------------------------

def make_tcp_packet(src_ip: str, dst_port: int, dst_ip: str = "10.0.0.1") -> Packet:
    """Build a minimal TCP SYN packet for port scan testing."""
    return Packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=5000,
        dst_port=dst_port,
        protocol="TCP",
        flags="S",
        timestamp="2024-01-01T00:00:00Z",
        length=60,
        payload=None,
    )


def make_udp_packet(src_ip: str, dst_port: int, dst_ip: str = "10.0.0.1") -> Packet:
    """Build a minimal UDP packet for testing non-TCP protocol handling."""
    return Packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=5000,
        dst_port=dst_port,
        protocol="UDP",
        flags=None,
        timestamp="2024-01-01T00:00:00Z",
        length=40,
        payload=None,
    )


def make_icmp_packet(src_ip: str = "192.168.1.1") -> Packet:
    """Build an ICMP packet (no dst_port) to test non-TCP/UDP filtering."""
    return Packet(
        src_ip=src_ip,
        dst_ip="10.0.0.1",
        src_port=None,
        dst_port=None,
        protocol="ICMP",
        flags=None,
        timestamp="2024-01-01T00:00:00Z",
        length=28,
        payload=None,
    )


def make_arp_packet(src_ip: str = "192.168.1.1") -> Packet:
    """Build an ARP packet (no dst_port) to test non-TCP/UDP filtering."""
    return Packet(
        src_ip=src_ip,
        dst_ip="192.168.1.255",
        src_port=None,
        dst_port=None,
        protocol="ARP",
        flags=None,
        timestamp="2024-01-01T00:00:00Z",
        length=42,
        payload=None,
    )


def feed_unique_ports(rule: PortScanRule, src_ip: str, count: int, start_port: int = 1) -> None:
    """Feed `count` unique TCP packets from src_ip to ports [start_port, start_port+count)."""
    for port in range(start_port, start_port + count):
        rule.process_packet(make_tcp_packet(src_ip, port))


# ---------------------------------------------------------------------------
# Threshold / emission tests (Req 5.1, 5.2)
# ---------------------------------------------------------------------------

class TestThresholdBehavior:
    """Tests related to threshold-based event emission."""

    def test_below_threshold_no_event(self):
        """Scanning fewer than threshold unique ports produces no event."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", 19)
        event = rule.evaluate()
        assert event is None

    def test_at_threshold_emits_event(self):
        """Exactly threshold unique ports triggers a ThreatEvent."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", 20)
        event = rule.evaluate()
        assert event is not None
        assert event.attack_type == "Port Scan"
        assert event.rule_name == "PORT_SCAN_001"
        assert event.source_ip == "192.168.1.10"

    def test_above_threshold_emits_event(self):
        """More than threshold unique ports also triggers a ThreatEvent."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", 25)
        event = rule.evaluate()
        assert event is not None
        assert event.attack_type == "Port Scan"

    def test_zero_packets_no_event(self):
        """Evaluating with no packets produces no event."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        assert rule.evaluate() is None


# ---------------------------------------------------------------------------
# Deduplication / counting tests (Req 5.1)
# ---------------------------------------------------------------------------

class TestPortCounting:
    """Tests for unique port counting semantics."""

    def test_same_port_not_counted_twice(self):
        """Sending the same dst_port multiple times counts as only one unique port."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        src = "10.0.0.5"
        # Send port 80 nineteen times — should still be just 1 unique port
        for _ in range(19):
            rule.process_packet(make_tcp_packet(src, 80))
        event = rule.evaluate()
        assert event is None  # only 1 unique port, not 19

    def test_same_port_repeated_with_different_ports_counts_correctly(self):
        """Mix of repeated and unique ports — only unique ones count toward threshold."""
        rule = PortScanRule(threshold=5, window_seconds=60)
        src = "10.0.0.5"
        # Send port 80 ten times and 4 other unique ports
        for _ in range(10):
            rule.process_packet(make_tcp_packet(src, 80))
        for port in [81, 82, 83, 84]:
            rule.process_packet(make_tcp_packet(src, port))
        # 5 unique ports total (80, 81, 82, 83, 84) — at threshold
        event = rule.evaluate()
        assert event is not None

    def test_different_source_ips_tracked_independently(self):
        """Two source IPs scanning the same ports are tracked independently."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.1", 19)
        feed_unique_ports(rule, "192.168.1.2", 19)
        # Neither has hit 20 unique ports individually
        event = rule.evaluate()
        assert event is None


# ---------------------------------------------------------------------------
# Severity tests (Req 5.3)
# ---------------------------------------------------------------------------

class TestSeverityTiers:
    """Tests for severity classification based on unique port count."""

    def test_severity_medium_at_lower_bound(self):
        """20 unique ports → Medium severity (lowest tier)."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", 20)
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "Medium"

    def test_severity_medium(self):
        """30 unique ports → Medium severity."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", 30)
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "Medium"

    def test_severity_medium_at_upper_bound(self):
        """39 unique ports → still Medium severity."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", 39)
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "Medium"

    def test_severity_high_at_lower_bound(self):
        """40 unique ports → High severity."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", 40)
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "High"

    def test_severity_high(self):
        """60 unique ports → High severity."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", 60)
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "High"

    def test_severity_high_at_upper_bound(self):
        """79 unique ports → still High severity."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", 79)
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "High"

    def test_severity_critical(self):
        """80 unique ports → Critical severity."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", 80)
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "Critical"

    def test_severity_critical_well_above(self):
        """100 unique ports → Critical severity."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", 100)
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "Critical"


# ---------------------------------------------------------------------------
# Confidence formula tests (Req 5.4)
# ---------------------------------------------------------------------------

class TestConfidenceFormula:
    """Tests verifying the confidence calculation matches the spec formula."""

    def test_confidence_formula_at_threshold(self):
        """At exactly threshold, confidence = round(1.0/2.0*100) = 50."""
        threshold = 20
        count = 20
        expected = _scan_confidence(count, threshold)
        rule = PortScanRule(threshold=threshold, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", count)
        event = rule.evaluate()
        assert event is not None
        assert event.confidence == expected
        assert event.confidence == 50

    def test_confidence_formula_at_double_threshold(self):
        """At 2x threshold, confidence = round(2.0/2.0*100) = 100 (capped)."""
        threshold = 20
        count = 40
        expected = _scan_confidence(count, threshold)
        rule = PortScanRule(threshold=threshold, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", count)
        event = rule.evaluate()
        assert event is not None
        assert event.confidence == expected
        assert event.confidence == 100

    def test_confidence_capped_at_100(self):
        """Confidence never exceeds 100 regardless of port count."""
        threshold = 20
        count = 200  # 10x threshold — still capped at 100
        rule = PortScanRule(threshold=threshold, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", count)
        event = rule.evaluate()
        assert event is not None
        assert event.confidence <= 100

    def test_confidence_formula_matches_event(self):
        """Directly computed formula matches the value stored in the event."""
        threshold = 20
        for count in [20, 25, 30, 40, 80, 100]:
            rule = PortScanRule(threshold=threshold, window_seconds=60)
            feed_unique_ports(rule, "192.168.1.10", count)
            event = rule.evaluate()
            assert event is not None
            expected = _scan_confidence(count, threshold)
            assert event.confidence == expected, (
                f"count={count}: expected confidence={expected}, got {event.confidence}"
            )


# ---------------------------------------------------------------------------
# Evidence structure tests (Req 5.5)
# ---------------------------------------------------------------------------

class TestEvidenceFields:
    """Tests that the evidence dict contains all required fields."""

    def setup_method(self):
        """Create a triggered rule + event for all evidence tests."""
        self.rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(self.rule, "192.168.1.50", 25)
        self.event = self.rule.evaluate()
        assert self.event is not None

    def test_evidence_contains_source_ip(self):
        """Evidence includes the source_ip field."""
        assert "source_ip" in self.event.evidence
        assert self.event.evidence["source_ip"] == "192.168.1.50"

    def test_evidence_contains_scanned_ports(self):
        """Evidence includes a scanned_ports list."""
        assert "scanned_ports" in self.event.evidence
        assert isinstance(self.event.evidence["scanned_ports"], list)

    def test_evidence_contains_unique_port_count(self):
        """Evidence includes the unique_port_count."""
        assert "unique_port_count" in self.event.evidence
        assert self.event.evidence["unique_port_count"] == 25

    def test_evidence_contains_time_window_seconds(self):
        """Evidence includes the time_window_seconds."""
        assert "time_window_seconds" in self.event.evidence
        assert self.event.evidence["time_window_seconds"] == 60

    def test_evidence_contains_confidence_score(self):
        """Evidence includes a confidence_score matching event.confidence."""
        assert "confidence_score" in self.event.evidence
        assert self.event.evidence["confidence_score"] == self.event.confidence

    def test_evidence_all_required_fields_present(self):
        """All five required evidence fields are present together."""
        required = {"source_ip", "scanned_ports", "unique_port_count",
                    "time_window_seconds", "confidence_score"}
        assert required.issubset(set(self.event.evidence.keys()))


# ---------------------------------------------------------------------------
# Scanned ports cap tests (Req 5.5)
# ---------------------------------------------------------------------------

class TestScannedPortsCap:
    """Tests that scanned_ports in evidence is capped at 20 entries."""

    def test_scanned_ports_capped_at_20(self):
        """Even with 100+ unique ports, evidence['scanned_ports'] has ≤ 20 entries."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "10.0.0.2", 100)
        event = rule.evaluate()
        assert event is not None
        assert len(event.evidence["scanned_ports"]) <= 20

    def test_scanned_ports_exactly_20_when_scan_is_large(self):
        """With 50 unique ports scanned, evidence['scanned_ports'] has exactly 20 entries."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "10.0.0.2", 50)
        event = rule.evaluate()
        assert event is not None
        assert len(event.evidence["scanned_ports"]) == 20

    def test_scanned_ports_under_cap_are_not_truncated(self):
        """When fewer than 20 unique ports scanned, all are included in evidence."""
        rule = PortScanRule(threshold=5, window_seconds=60)
        feed_unique_ports(rule, "10.0.0.3", 8)  # 8 unique ports, below cap
        event = rule.evaluate()
        assert event is not None
        assert len(event.evidence["scanned_ports"]) == 8


# ---------------------------------------------------------------------------
# Cooldown tests (Req 5.6)
# ---------------------------------------------------------------------------

class TestCooldown:
    """Tests for the cooldown mechanism that suppresses duplicate events."""

    def test_cooldown_suppresses_duplicate_same_severity(self):
        """Same-severity re-emission within cooldown window returns None."""
        rule = PortScanRule(threshold=20, window_seconds=60, cooldown_seconds=30)
        feed_unique_ports(rule, "172.16.0.1", 25)
        # First evaluation triggers the event
        first = rule.evaluate()
        assert first is not None
        # Second evaluation — still in cooldown, same severity → None
        event = rule.evaluate()
        assert event is None

    def test_cooldown_expires_allows_new_event(self):
        """After cooldown expires, a new event is emitted."""
        rule = PortScanRule(threshold=20, window_seconds=60, cooldown_seconds=0)
        feed_unique_ports(rule, "172.16.0.1", 25)
        first = rule.evaluate()
        assert first is not None
        # With cooldown=0 seconds, the next call should re-emit
        second = rule.evaluate()
        assert second is not None

    def test_higher_severity_bypasses_cooldown(self):
        """A higher-severity event is emitted even within cooldown."""
        rule = PortScanRule(threshold=20, window_seconds=60, cooldown_seconds=30)
        src = "172.16.0.2"
        # First: Medium severity (20–39 ports)
        feed_unique_ports(rule, src, 25)
        first = rule.evaluate()
        assert first is not None
        assert first.severity == "Medium"
        # Now escalate to Critical (80+ ports) within cooldown
        feed_unique_ports(rule, src, 60, start_port=200)  # pushes total to 85
        second = rule.evaluate()
        assert second is not None
        assert second.severity in ("High", "Critical")


# ---------------------------------------------------------------------------
# Non-TCP/UDP protocol tests (Req 5.1)
# ---------------------------------------------------------------------------

class TestProtocolFiltering:
    """Tests that non-TCP/UDP packets are ignored by the rule."""

    def test_non_tcp_udp_icmp_ignored(self):
        """ICMP packets do not contribute to port scan counting."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        for _ in range(100):
            rule.process_packet(make_icmp_packet("192.168.5.5"))
        event = rule.evaluate()
        assert event is None

    def test_non_tcp_udp_arp_ignored(self):
        """ARP packets do not contribute to port scan counting."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        for _ in range(100):
            rule.process_packet(make_arp_packet("192.168.5.5"))
        event = rule.evaluate()
        assert event is None

    def test_udp_packets_are_counted(self):
        """UDP packets ARE counted — the rule tracks TCP and UDP."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        for port in range(1, 21):
            rule.process_packet(make_udp_packet("10.10.10.1", port))
        event = rule.evaluate()
        assert event is not None

    def test_mixed_icmp_and_tcp_only_tcp_counts(self):
        """Mixed stream: only TCP packets count, ICMP does not."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        # 19 TCP ports + 100 ICMP packets — should NOT trigger
        feed_unique_ports(rule, "192.168.5.5", 19)
        for _ in range(100):
            rule.process_packet(make_icmp_packet("192.168.5.5"))
        event = rule.evaluate()
        assert event is None


# ---------------------------------------------------------------------------
# State / lifecycle tests
# ---------------------------------------------------------------------------

class TestRuleLifecycle:
    """Tests for rule initialization and cleanup."""

    def test_initialize_resets_state(self):
        """Calling initialize() clears all accumulated flow state."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", 20)
        rule.initialize()
        event = rule.evaluate()
        assert event is None

    def test_cleanup_resets_state(self):
        """Calling cleanup() clears all accumulated flow state."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "192.168.1.10", 20)
        rule.cleanup()
        event = rule.evaluate()
        assert event is None

    def test_rule_name_and_attack_type(self):
        """Rule metadata is correctly set on the instance."""
        rule = PortScanRule()
        assert rule.rule_name == "PORT_SCAN_001"
        assert rule.attack_type == "Port Scan"

    def test_default_threshold_is_20(self):
        """Default threshold is 20 unique ports."""
        rule = PortScanRule()
        assert rule.threshold == 20

    def test_packet_count_in_event_equals_unique_port_count(self):
        """event.packet_count reflects the number of unique ports detected."""
        rule = PortScanRule(threshold=20, window_seconds=60)
        feed_unique_ports(rule, "10.1.1.1", 30)
        event = rule.evaluate()
        assert event is not None
        assert event.packet_count == 30


# ---------------------------------------------------------------------------
# Standalone helper function tests
# ---------------------------------------------------------------------------

class TestHelperFunctions:
    """Unit tests for module-level helper functions."""

    def test_scan_severity_medium_lower(self):
        assert _scan_severity(20) == "Medium"

    def test_scan_severity_medium_upper(self):
        assert _scan_severity(39) == "Medium"

    def test_scan_severity_high_lower(self):
        assert _scan_severity(40) == "High"

    def test_scan_severity_high_upper(self):
        assert _scan_severity(79) == "High"

    def test_scan_severity_critical(self):
        assert _scan_severity(80) == "Critical"

    def test_scan_severity_critical_large(self):
        assert _scan_severity(1000) == "Critical"

    def test_scan_confidence_at_threshold(self):
        # count == threshold → ratio 1.0 → 1.0/2.0*100 = 50
        assert _scan_confidence(20, 20) == 50

    def test_scan_confidence_at_double_threshold(self):
        # count == 2*threshold → ratio 2.0 (capped) → 100
        assert _scan_confidence(40, 20) == 100

    def test_scan_confidence_beyond_double_threshold(self):
        # ratio capped at 2.0 → still 100
        assert _scan_confidence(200, 20) == 100

    def test_scan_confidence_zero_threshold_returns_100(self):
        # Guard against division by zero
        assert _scan_confidence(5, 0) == 100
