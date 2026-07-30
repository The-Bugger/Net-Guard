"""
test_brute_force.py — Unit tests for BruteForceRule.

Covers threshold detection, severity tiers, confidence formula,
service identification (SSH/HTTP/FTP/Unknown), evidence fields,
and cooldown behaviour.

Requirements: 7.1–7.6
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime, timezone

import pytest

from detection.parsers.packet_decoder import Packet
from detection.rules.brute_force import BruteForceRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_tcp_packet(
    src_ip: str = "10.0.0.1",
    dst_port: int = 22,
    timestamp: str | None = None,
) -> Packet:
    return Packet(
        src_ip=src_ip,
        dst_ip="192.168.1.1",
        src_port=54321,
        dst_port=dst_port,
        protocol="TCP",
        flags="S",
        timestamp=timestamp or _ts_now(),
        length=60,
        payload=None,
        hw_src=None,
    )


def _feed(rule: BruteForceRule, count: int, src_ip: str = "10.0.0.1",
          dst_port: int = 22) -> None:
    for _ in range(count):
        rule.process_packet(make_tcp_packet(src_ip=src_ip, dst_port=dst_port))


@pytest.fixture
def rule() -> BruteForceRule:
    r = BruteForceRule(threshold=10, window_seconds=60, cooldown_seconds=10)
    r.initialize()
    return r


# ---------------------------------------------------------------------------
# Threshold detection (Requirement 7.1)
# ---------------------------------------------------------------------------

class TestThreshold:
    def test_below_threshold_no_event(self, rule):
        _feed(rule, 9)
        assert rule.evaluate() is None

    def test_at_threshold_emits_event(self, rule):
        _feed(rule, 10)
        assert rule.evaluate() is not None

    def test_above_threshold_emits_event(self, rule):
        _feed(rule, 15)
        assert rule.evaluate() is not None

    def test_attack_type_and_rule_name(self, rule):
        _feed(rule, 10)
        event = rule.evaluate()
        assert event.attack_type == "Brute Force"
        assert event.rule_name == "BRUTE_FORCE_001"

    def test_non_tcp_ignored(self, rule):
        """Non-TCP packets must not count toward failure tracking."""
        pkt = Packet(
            src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=None, dst_port=None,
            protocol="UDP", flags=None,
            timestamp=_ts_now(), length=60, payload=None, hw_src=None,
        )
        for _ in range(15):
            rule.process_packet(pkt)
        assert rule.evaluate() is None

    def test_non_auth_port_ignored(self, rule):
        """TCP to an irrelevant port must not count."""
        for _ in range(15):
            rule.process_packet(make_tcp_packet(dst_port=8080))
        assert rule.evaluate() is None

    def test_missing_dst_port_ignored(self, rule):
        pkt = Packet(
            src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=54321, dst_port=None,
            protocol="TCP", flags="S",
            timestamp=_ts_now(), length=60, payload=None, hw_src=None,
        )
        for _ in range(15):
            rule.process_packet(pkt)
        assert rule.evaluate() is None


# ---------------------------------------------------------------------------
# Severity tiers (Requirements 7.2–7.4)
# ---------------------------------------------------------------------------

class TestSeverityTiers:
    """Medium 10-19, High 20-39, Critical ≥40."""

    def _event_for_count(self, count: int, port: int = 22) -> object:
        rule = BruteForceRule(threshold=10, window_seconds=60)
        rule.initialize()
        _feed(rule, count, dst_port=port)
        return rule.evaluate()

    def test_severity_medium_at_10(self):
        assert self._event_for_count(10).severity == "Medium"

    def test_severity_medium_at_19(self):
        assert self._event_for_count(19).severity == "Medium"

    def test_severity_high_at_20(self):
        assert self._event_for_count(20).severity == "High"

    def test_severity_high_at_39(self):
        assert self._event_for_count(39).severity == "High"

    def test_severity_critical_at_40(self):
        assert self._event_for_count(40).severity == "Critical"

    def test_severity_critical_at_100(self):
        assert self._event_for_count(100).severity == "Critical"


# ---------------------------------------------------------------------------
# Confidence formula (Requirement 7.6)
# ---------------------------------------------------------------------------

class TestConfidenceFormula:
    """round(min(count/threshold, 2.0) / 2.0 * 100), capped at 100."""

    def _confidence_for(self, count: int, threshold: int = 10) -> int:
        rule = BruteForceRule(threshold=threshold, window_seconds=60)
        rule.initialize()
        _feed(rule, count)
        return rule.evaluate().confidence

    def test_confidence_at_threshold(self):
        # count=10, threshold=10 → min(1.0,2.0)/2.0*100 = 50
        assert self._confidence_for(10, 10) == 50

    def test_confidence_at_double_threshold(self):
        # count=20, threshold=10 → min(2.0,2.0)/2.0*100 = 100
        assert self._confidence_for(20, 10) == 100

    def test_confidence_above_double_capped(self):
        assert self._confidence_for(50, 10) == 100

    def test_confidence_at_15_threshold_10(self):
        # round(min(1.5,2.0)/2.0*100) = round(75) = 75
        assert self._confidence_for(15, 10) == 75

    def test_confidence_always_in_range(self):
        for count in [10, 15, 20, 25, 40, 100]:
            c = self._confidence_for(count)
            assert 0 <= c <= 100


# ---------------------------------------------------------------------------
# Service identification (Requirement 7.5)
# ---------------------------------------------------------------------------

class TestServiceIdentification:
    def _event_for_port(self, dst_port: int) -> object:
        rule = BruteForceRule(threshold=10, window_seconds=60)
        rule.initialize()
        _feed(rule, 10, dst_port=dst_port)
        return rule.evaluate()

    def test_ssh_service(self):
        event = self._event_for_port(22)
        assert event is not None
        assert event.evidence["target_service"] == "SSH"

    def test_http_port_80(self):
        event = self._event_for_port(80)
        assert event is not None
        assert event.evidence["target_service"] == "HTTP"

    def test_http_port_443(self):
        event = self._event_for_port(443)
        assert event is not None
        assert event.evidence["target_service"] == "HTTP"

    def test_ftp_service(self):
        event = self._event_for_port(21)
        assert event is not None
        assert event.evidence["target_service"] == "FTP"


# ---------------------------------------------------------------------------
# Evidence fields (Requirement 7.5)
# ---------------------------------------------------------------------------

class TestEvidenceFields:
    def test_required_keys_present(self, rule):
        _feed(rule, 12)
        event = rule.evaluate()
        assert event is not None
        ev = event.evidence
        for key in ("source_ip", "failure_count", "time_window_seconds", "target_service"):
            assert key in ev, f"Evidence missing '{key}'"

    def test_source_ip_matches(self, rule):
        _feed(rule, 10, src_ip="10.5.5.5")
        event = rule.evaluate()
        assert event is not None
        assert event.evidence["source_ip"] == "10.5.5.5"

    def test_failure_count_matches(self, rule):
        _feed(rule, 13)
        event = rule.evaluate()
        assert event is not None
        assert event.evidence["failure_count"] == 13

    def test_time_window_seconds_matches(self):
        rule = BruteForceRule(threshold=10, window_seconds=30)
        rule.initialize()
        _feed(rule, 10)
        event = rule.evaluate()
        assert event is not None
        assert event.evidence["time_window_seconds"] == 30

    def test_packet_count_matches_failure_count(self, rule):
        _feed(rule, 11)
        event = rule.evaluate()
        assert event is not None
        assert event.packet_count == event.evidence["failure_count"]


# ---------------------------------------------------------------------------
# Cooldown (Requirement 9.2 applied to BruteForce)
# ---------------------------------------------------------------------------

class TestCooldown:
    def test_second_evaluate_no_escalation_returns_none(self, rule):
        """Within cooldown, same or lower severity is suppressed."""
        _feed(rule, 10)
        event1 = rule.evaluate()
        assert event1 is not None
        # Feed more but same severity bracket — still within cooldown
        _feed(rule, 5)
        event2 = rule.evaluate()
        assert event2 is None

    def test_different_ips_independent(self):
        rule = BruteForceRule(threshold=10, window_seconds=60)
        rule.initialize()
        _feed(rule, 10, src_ip="10.0.0.1")
        _feed(rule, 10, src_ip="10.0.0.2")
        events = [rule.evaluate(), rule.evaluate()]
        ips = {e.source_ip for e in events if e is not None}
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips

    def test_source_ip_on_event(self, rule):
        _feed(rule, 10, src_ip="172.16.0.99")
        event = rule.evaluate()
        assert event is not None
        assert event.source_ip == "172.16.0.99"
