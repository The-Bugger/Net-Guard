"""
test_brute_force.py — Unit tests for BruteForceRule.

Covers threshold boundary, severity tiers, confidence formula,
service identification (SSH/HTTP/FTP/Unknown), evidence field population,
and cooldown suppression/escalation logic.

Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

from detection.parsers.packet_decoder import Packet
from detection.rules.brute_force import BruteForceRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts_now() -> str:
    """Return current UTC time as ISO-8601 string used by the rule."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts_past(seconds: int) -> str:
    """Return a UTC ISO-8601 string <seconds> seconds in the past."""
    dt = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_auth_packet(
    src_ip: str = "1.2.3.4",
    dst_ip: str = "10.0.0.1",
    dst_port: int = 22,
    count: int = 1,
    protocol: str = "TCP",
    timestamp: str | None = None,
) -> list[Packet]:
    """Build a list of packets directed at a given destination port."""
    ts = timestamp or _ts_now()
    return [
        Packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=54321,
            dst_port=dst_port,
            protocol=protocol,
            flags=None,
            timestamp=ts,
            length=60,
            payload=None,
        )
        for _ in range(count)
    ]


def _feed(rule: BruteForceRule, packets: list[Packet]) -> None:
    """Process every packet through the rule."""
    for pkt in packets:
        rule.process_packet(pkt)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def rule() -> BruteForceRule:
    """Fresh BruteForceRule with threshold=10 and a large window to avoid expiry."""
    r = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=10)
    r.initialize()
    return r


# ---------------------------------------------------------------------------
# Threshold tests (Requirement 7.1)
# ---------------------------------------------------------------------------

class TestThresholdBoundary:
    """Events are emitted only when failure count >= threshold (Req 7.1)."""

    def test_below_threshold_no_event(self, rule):
        """Sending fewer than threshold packets must produce no event."""
        _feed(rule, make_auth_packet(count=9))
        assert rule.evaluate() is None

    def test_at_threshold_emits_event(self, rule):
        """Exactly threshold packets must produce a ThreatEvent."""
        _feed(rule, make_auth_packet(count=10))
        event = rule.evaluate()

        assert event is not None
        assert event.attack_type == "Brute Force"
        assert event.rule_name == "BRUTE_FORCE_001"

    def test_above_threshold_emits_event(self, rule):
        """More than threshold packets must also produce a ThreatEvent."""
        _feed(rule, make_auth_packet(count=25))
        event = rule.evaluate()

        assert event is not None
        assert event.attack_type == "Brute Force"

    def test_custom_threshold_respected(self):
        """A custom threshold value should be used for detection."""
        rule = BruteForceRule(threshold=5, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()

        _feed(rule, make_auth_packet(count=4))
        assert rule.evaluate() is None

        _feed(rule, make_auth_packet(count=1))
        assert rule.evaluate() is not None


# ---------------------------------------------------------------------------
# Packet filtering tests (Requirement 7.1)
# ---------------------------------------------------------------------------

class TestPacketFiltering:
    """Only TCP packets to auth ports should be counted."""

    def test_non_tcp_ignored(self, rule):
        """UDP packets to auth ports must not be counted."""
        _feed(rule, make_auth_packet(count=50, dst_port=22, protocol="UDP"))
        assert rule.evaluate() is None

    def test_non_auth_port_ignored(self, rule):
        """TCP packets to a non-auth port (e.g. 9999) must not be counted."""
        _feed(rule, make_auth_packet(count=50, dst_port=9999))
        assert rule.evaluate() is None

    def test_auth_port_22_counted(self, rule):
        """TCP packets to port 22 (SSH) must be counted."""
        _feed(rule, make_auth_packet(count=10, dst_port=22))
        assert rule.evaluate() is not None

    def test_auth_port_80_counted(self, rule):
        """TCP packets to port 80 (HTTP) must be counted."""
        _feed(rule, make_auth_packet(count=10, dst_port=80))
        assert rule.evaluate() is not None

    def test_auth_port_443_counted(self, rule):
        """TCP packets to port 443 (HTTPS) must be counted."""
        _feed(rule, make_auth_packet(count=10, dst_port=443))
        assert rule.evaluate() is not None

    def test_auth_port_21_counted(self, rule):
        """TCP packets to port 21 (FTP) must be counted."""
        _feed(rule, make_auth_packet(count=10, dst_port=21))
        assert rule.evaluate() is not None


# ---------------------------------------------------------------------------
# Severity tier tests (Requirements 7.2, 7.3, 7.4)
# ---------------------------------------------------------------------------

class TestSeverityTiers:
    """Severity tiers: 10–19 → Medium, 20–39 → High, ≥40 → Critical (Req 7.2–7.4)."""

    def test_severity_medium_lower_bound(self):
        """Count=10 (threshold boundary) must produce severity='Medium'."""
        rule = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_auth_packet(count=10))
        event = rule.evaluate()

        assert event is not None
        assert event.severity == "Medium"

    def test_severity_medium_upper_bound(self):
        """Count=19 must still produce severity='Medium'."""
        rule = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_auth_packet(count=19))
        event = rule.evaluate()

        assert event is not None
        assert event.severity == "Medium"

    def test_severity_high_lower_bound(self):
        """Count=20 must produce severity='High'."""
        rule = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_auth_packet(count=20))
        event = rule.evaluate()

        assert event is not None
        assert event.severity == "High"

    def test_severity_high_upper_bound(self):
        """Count=39 must produce severity='High'."""
        rule = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_auth_packet(count=39))
        event = rule.evaluate()

        assert event is not None
        assert event.severity == "High"

    def test_severity_critical_lower_bound(self):
        """Count=40 must produce severity='Critical'."""
        rule = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_auth_packet(count=40))
        event = rule.evaluate()

        assert event is not None
        assert event.severity == "Critical"

    def test_severity_critical_above_40(self):
        """Count=100 must still produce severity='Critical'."""
        rule = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_auth_packet(count=100))
        event = rule.evaluate()

        assert event is not None
        assert event.severity == "Critical"


# ---------------------------------------------------------------------------
# Confidence formula tests (Requirement 7.5)
# ---------------------------------------------------------------------------

class TestConfidenceFormula:
    """Confidence = round(min(count/threshold, 2.0) / 2.0 * 100) capped at 100 (Req 7.5)."""

    def test_confidence_at_threshold(self, rule):
        """At exactly threshold (10) confidence should be 50."""
        _feed(rule, make_auth_packet(count=10))
        event = rule.evaluate()

        assert event is not None
        expected = round(min(10 / 10, 2.0) / 2.0 * 100)
        assert event.confidence == expected
        assert event.confidence == 50

    def test_confidence_at_double_threshold(self, rule):
        """At 2× threshold (20) confidence should be 100."""
        _feed(rule, make_auth_packet(count=20))
        event = rule.evaluate()

        assert event is not None
        expected = round(min(20 / 10, 2.0) / 2.0 * 100)
        assert event.confidence == expected
        assert event.confidence == 100

    def test_confidence_between_threshold_and_double(self, rule):
        """At 1.5× threshold (15) confidence should be 75."""
        _feed(rule, make_auth_packet(count=15))
        event = rule.evaluate()

        assert event is not None
        expected = round(min(15 / 10, 2.0) / 2.0 * 100)
        assert event.confidence == expected
        assert event.confidence == 75

    def test_confidence_capped_at_100(self, rule):
        """Counts far beyond 2× threshold must not push confidence above 100."""
        _feed(rule, make_auth_packet(count=200))
        event = rule.evaluate()

        assert event is not None
        assert event.confidence == 100

    def test_confidence_formula_arbitrary_count(self, rule):
        """Verify the formula for count=12 with threshold=10."""
        count = 12
        threshold = 10
        _feed(rule, make_auth_packet(count=count))
        event = rule.evaluate()

        assert event is not None
        expected = round(min(count / threshold, 2.0) / 2.0 * 100)
        assert event.confidence == expected


# ---------------------------------------------------------------------------
# Service identification tests (Requirement 7.5)
# ---------------------------------------------------------------------------

class TestServiceIdentification:
    """Target service is identified from destination port (Req 7.5)."""

    def test_port_22_identified_as_ssh(self):
        """TCP port 22 must map to target_service='SSH'."""
        rule = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_auth_packet(count=10, dst_port=22))
        event = rule.evaluate()

        assert event is not None
        assert event.evidence["target_service"] == "SSH"

    def test_port_80_identified_as_http(self):
        """TCP port 80 must map to target_service='HTTP'."""
        rule = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_auth_packet(count=10, dst_port=80))
        event = rule.evaluate()

        assert event is not None
        assert event.evidence["target_service"] == "HTTP"

    def test_port_443_identified_as_http(self):
        """TCP port 443 must map to target_service='HTTP'."""
        rule = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_auth_packet(count=10, dst_port=443))
        event = rule.evaluate()

        assert event is not None
        assert event.evidence["target_service"] == "HTTP"

    def test_port_21_identified_as_ftp(self):
        """TCP port 21 must map to target_service='FTP'."""
        rule = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_auth_packet(count=10, dst_port=21))
        event = rule.evaluate()

        assert event is not None
        assert event.evidence["target_service"] == "FTP"

    def test_service_ports_class_attribute(self):
        """BruteForceRule.SERVICE_PORTS must contain the four documented mappings."""
        sp = BruteForceRule.SERVICE_PORTS
        assert sp[22] == "SSH"
        assert sp[80] == "HTTP"
        assert sp[443] == "HTTP"
        assert sp[21] == "FTP"


# ---------------------------------------------------------------------------
# Evidence field tests (Requirement 7.6)
# ---------------------------------------------------------------------------

class TestEvidenceFields:
    """Evidence dict must contain required keys (Requirement 7.6)."""

    def test_evidence_required_keys_present(self, rule):
        """Evidence must contain source_ip, failure_count, time_window_seconds,
        and target_service."""
        _feed(rule, make_auth_packet(count=10))
        event = rule.evaluate()

        assert event is not None
        ev = event.evidence
        assert "source_ip" in ev
        assert "failure_count" in ev
        assert "time_window_seconds" in ev
        assert "target_service" in ev

    def test_evidence_source_ip_matches(self, rule):
        """evidence['source_ip'] must match the attacking source IP."""
        _feed(rule, make_auth_packet(src_ip="5.5.5.5", count=10))
        event = rule.evaluate()

        assert event is not None
        assert event.evidence["source_ip"] == "5.5.5.5"

    def test_evidence_failure_count_matches(self, rule):
        """evidence['failure_count'] must equal the actual packet count processed."""
        _feed(rule, make_auth_packet(count=15))
        event = rule.evaluate()

        assert event is not None
        assert event.evidence["failure_count"] == 15

    def test_evidence_time_window_seconds_matches_config(self):
        """evidence['time_window_seconds'] must reflect the configured window."""
        rule = BruteForceRule(threshold=10, window_seconds=120, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_auth_packet(count=10))
        event = rule.evaluate()

        assert event is not None
        assert event.evidence["time_window_seconds"] == 120

    def test_evidence_target_service_is_string(self, rule):
        """evidence['target_service'] must be a non-empty string."""
        _feed(rule, make_auth_packet(count=10, dst_port=22))
        event = rule.evaluate()

        assert event is not None
        assert isinstance(event.evidence["target_service"], str)
        assert len(event.evidence["target_service"]) > 0


# ---------------------------------------------------------------------------
# Core event field tests (Requirements 7.1, 7.6)
# ---------------------------------------------------------------------------

class TestEventFields:
    """Core ThreatEvent fields must be correctly populated."""

    def test_event_source_ip_matches(self, rule):
        """event.source_ip must match the attacking source IP."""
        _feed(rule, make_auth_packet(src_ip="9.8.7.6", count=10))
        event = rule.evaluate()

        assert event is not None
        assert event.source_ip == "9.8.7.6"

    def test_event_protocol_is_tcp(self, rule):
        """event.protocol must be 'TCP' for brute force."""
        _feed(rule, make_auth_packet(count=10))
        event = rule.evaluate()

        assert event is not None
        assert event.protocol == "TCP"

    def test_event_packet_count_matches(self, rule):
        """event.packet_count must equal the number of auth packets processed."""
        _feed(rule, make_auth_packet(count=12))
        event = rule.evaluate()

        assert event is not None
        assert event.packet_count == 12

    def test_event_has_unique_id(self, rule):
        """event.event_id must be a non-empty string."""
        _feed(rule, make_auth_packet(count=10))
        event = rule.evaluate()

        assert event is not None
        assert isinstance(event.event_id, str)
        assert len(event.event_id) > 0

    def test_event_timestamp_is_iso8601(self, rule):
        """event.timestamp must be a non-empty ISO-8601 string."""
        _feed(rule, make_auth_packet(count=10))
        event = rule.evaluate()

        assert event is not None
        assert isinstance(event.timestamp, str)
        assert "T" in event.timestamp

    def test_event_destination_port_set(self, rule):
        """event.destination_port must reflect the targeted port."""
        _feed(rule, make_auth_packet(count=10, dst_port=22))
        event = rule.evaluate()

        assert event is not None
        assert event.destination_port == 22


# ---------------------------------------------------------------------------
# Window sliding / expiry tests (Requirement 7.1)
# ---------------------------------------------------------------------------

class TestWindowSliding:
    """Packets outside the sliding window are not counted (Requirement 7.1)."""

    def test_old_packets_expired_from_window(self):
        """Packets with timestamps older than window_seconds must be discarded."""
        rule = BruteForceRule(threshold=10, window_seconds=5, cooldown_seconds=10)
        rule.initialize()

        past_ts = _ts_past(60)
        old_packets = make_auth_packet(count=50, dst_port=22, timestamp=past_ts)
        _feed(rule, old_packets)

        assert rule.evaluate() is None

    def test_recent_packets_within_window_counted(self):
        """Packets with current timestamps within window must be counted normally."""
        rule = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_auth_packet(count=10))
        assert rule.evaluate() is not None


# ---------------------------------------------------------------------------
# Cooldown tests (Requirement 7.1)
# ---------------------------------------------------------------------------

class TestCooldown:
    """Cooldown suppresses duplicate events; higher severity must still be emitted."""

    def test_cooldown_suppresses_duplicate(self, rule):
        """Second evaluate() for same IP/severity within cooldown window returns None."""
        _feed(rule, make_auth_packet(count=15))

        event1 = rule.evaluate()
        assert event1 is not None
        assert event1.severity == "Medium"

        event2 = rule.evaluate()
        assert event2 is None

    def test_cooldown_allows_escalation_to_higher_severity(self):
        """Higher severity event within cooldown must still be emitted."""
        rule = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=30)
        rule.initialize()

        # First batch: 15 packets → Medium
        _feed(rule, make_auth_packet(count=15))
        event1 = rule.evaluate()
        assert event1 is not None
        assert event1.severity == "Medium"

        # Add more packets to push count to 20 → High
        _feed(rule, make_auth_packet(count=5))
        event2 = rule.evaluate()

        assert event2 is not None
        assert event2.severity == "High"

    def test_cooldown_different_ips_are_independent(self):
        """Cooldown for one source IP must not affect detection for a different source IP."""
        rule = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=30)
        rule.initialize()

        _feed(rule, make_auth_packet(src_ip="1.1.1.1", count=15))
        event1 = rule.evaluate()
        assert event1 is not None
        assert event1.source_ip == "1.1.1.1"

        _feed(rule, make_auth_packet(src_ip="2.2.2.2", count=15))
        event2 = rule.evaluate()
        assert event2 is not None
        assert event2.source_ip == "2.2.2.2"

    def test_cooldown_suppresses_same_severity_multiple_calls(self, rule):
        """All consecutive evaluate() calls at same severity are suppressed after first."""
        _feed(rule, make_auth_packet(count=15))

        first = rule.evaluate()
        assert first is not None

        for _ in range(3):
            assert rule.evaluate() is None


# ---------------------------------------------------------------------------
# Initialize / cleanup tests
# ---------------------------------------------------------------------------

class TestInitializeAndCleanup:
    """initialize() and cleanup() reset all internal state."""

    def test_initialize_resets_state(self):
        """After initialize(), no event should be emitted for previously seen packets."""
        rule = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_auth_packet(count=10))
        assert rule.evaluate() is not None

        rule.initialize()
        assert rule.evaluate() is None

    def test_cleanup_clears_flows(self):
        """After cleanup(), flows are empty and no event is emitted."""
        rule = BruteForceRule(threshold=10, window_seconds=3600, cooldown_seconds=10)
        rule.initialize()
        _feed(rule, make_auth_packet(count=10))

        rule.cleanup()
        assert len(rule._flows) == 0
        assert rule.evaluate() is None
