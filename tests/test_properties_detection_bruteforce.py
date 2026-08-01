"""
test_properties_detection_bruteforce.py — Property-based tests for Brute Force detection.

Covers Properties 15–18 from the design document.

Properties tested in this file:
  Property 15: Brute Force Threshold Triggers ThreatEvent
  Property 16: Severity Tiers (Medium/High/Critical)
  Property 17: Confidence Formula Always in [0, 100]
  Property 18: Evidence Dict Contains All Required Fields

Requirements: 7.1–7.6
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime, timezone

import pytest
from hypothesis import given, settings, strategies as st, assume

from detection.parsers.packet_decoder import Packet
from detection.rules.brute_force import BruteForceRule


# ---------------------------------------------------------------------------
# Shared strategies and helpers
# ---------------------------------------------------------------------------

def _now_ts() -> str:
    """Return current UTC time as ISO-8601 string (same format used by the rule)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Strategy for valid IPv4 addresses (simple fixed pool)
_ipv4 = st.sampled_from([
    "10.0.0.1",
    "10.0.0.2",
    "192.168.1.1",
    "192.168.1.100",
    "172.16.0.1",
])

# Ports tracked by BruteForce rule (SSH, HTTP, FTP)
_AUTH_PORTS = [22, 80, 443, 21]

# Port → service mapping as specified
_PORT_TO_SERVICE = {
    22: "SSH",
    80: "HTTP",
    443: "HTTP",
    21: "FTP",
}


def _make_tcp_packet(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    timestamp: str | None = None,
) -> Packet:
    """Build a minimal TCP packet targeting an auth port."""
    return Packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=12345,
        dst_port=dst_port,
        protocol="TCP",
        flags="S",
        timestamp=timestamp or _now_ts(),
        length=64,
        payload=None,
    )


def _flood_rule(
    rule: BruteForceRule,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    count: int,
) -> None:
    """
    Feed `count` TCP packets from src_ip to dst_port into the rule,
    all with the current timestamp so they fall within the window.
    """
    ts = _now_ts()
    for _ in range(count):
        pkt = _make_tcp_packet(src_ip, dst_ip, dst_port, timestamp=ts)
        rule.process_packet(pkt)


# ---------------------------------------------------------------------------
# Property 15: Threshold Triggers ThreatEvent
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 15
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    dst_port=st.sampled_from(_AUTH_PORTS),
    threshold=st.integers(min_value=1, max_value=20),
    extra=st.integers(min_value=0, max_value=10),
)
@settings(max_examples=100, deadline=5000)
def test_property_15_threshold_met_emits_threat_event(
    src_ip, dst_ip, dst_port, threshold, extra
):
    """
    Property 15: failure_count >= threshold triggers a ThreatEvent with
    attack_type "Brute Force" and rule_name "BRUTE_FORCE_001".

    For any source IP whose connection-attempt count to an auth port (22, 80,
    443, 21) equals or exceeds the configured threshold within the sliding
    window, evaluate() SHALL return a ThreatEvent with:
        - attack_type == "Brute Force"
        - rule_name  == "BRUTE_FORCE_001"
        - source_ip  == src_ip

    Validates: Requirements 7.1, 7.2
    """
    failure_count = threshold + extra  # always >= threshold
    rule = BruteForceRule(threshold=threshold, window_seconds=60, cooldown_seconds=0)
    _flood_rule(rule, src_ip, dst_ip, dst_port, failure_count)

    event = rule.evaluate()

    assert event is not None, (
        f"Expected ThreatEvent when failure_count={failure_count} >= threshold={threshold}, "
        f"but got None"
    )
    assert event.attack_type == "Brute Force", (
        f"Expected attack_type='Brute Force', got '{event.attack_type}'"
    )
    assert event.rule_name == "BRUTE_FORCE_001", (
        f"Expected rule_name='BRUTE_FORCE_001', got '{event.rule_name}'"
    )
    assert event.source_ip == src_ip, (
        f"Expected source_ip='{src_ip}', got '{event.source_ip}'"
    )


# Feature: netguard-idps, Property 15
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    dst_port=st.sampled_from(_AUTH_PORTS),
    threshold=st.integers(min_value=2, max_value=30),
    shortfall=st.integers(min_value=1, max_value=1),
)
@settings(max_examples=100, deadline=5000)
def test_property_15_below_threshold_no_event(
    src_ip, dst_ip, dst_port, threshold, shortfall
):
    """
    Property 15 (complementary): failure_count < threshold => no ThreatEvent.

    Validates: Requirements 7.1
    """
    failure_count = threshold - shortfall  # always < threshold, >= 1
    assume(failure_count >= 1)

    rule = BruteForceRule(threshold=threshold, window_seconds=60, cooldown_seconds=0)
    _flood_rule(rule, src_ip, dst_ip, dst_port, failure_count)

    event = rule.evaluate()

    assert event is None, (
        f"Expected no ThreatEvent when failure_count={failure_count} < threshold={threshold}, "
        f"but got event: {event}"
    )


# Feature: netguard-idps, Property 15
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    non_auth_port=st.integers(min_value=1024, max_value=65535).filter(
        lambda p: p not in {22, 21, 80, 443}
    ),
    threshold=st.integers(min_value=1, max_value=10),
    count=st.integers(min_value=50, max_value=100),
)
@settings(max_examples=100, deadline=5000)
def test_property_15_non_auth_ports_ignored(
    src_ip, dst_ip, non_auth_port, threshold, count
):
    """
    Property 15 (non-auth ports): Packets to non-auth ports are not tracked
    and therefore never trigger a ThreatEvent regardless of count.

    Validates: Requirements 7.1
    """
    rule = BruteForceRule(threshold=threshold, window_seconds=60, cooldown_seconds=0)
    ts = _now_ts()
    for _ in range(count):
        pkt = Packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=12345,
            dst_port=non_auth_port,
            protocol="TCP",
            flags="S",
            timestamp=ts,
            length=64,
        )
        rule.process_packet(pkt)

    event = rule.evaluate()

    assert event is None, (
        f"Expected no ThreatEvent for non-auth port {non_auth_port} "
        f"(count={count}, threshold={threshold}), but got event: {event}"
    )


# ---------------------------------------------------------------------------
# Property 16: Severity Tiers (Medium/High/Critical)
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 16
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    dst_port=st.sampled_from(_AUTH_PORTS),
    # Medium tier: 10 <= count <= 19 with default threshold=10
    count=st.integers(min_value=10, max_value=19),
)
@settings(max_examples=100, deadline=5000)
def test_property_16_severity_medium_tier(src_ip, dst_ip, dst_port, count):
    """
    Property 16: Severity Tier — Medium (10 ≤ failure_count ≤ 19).

    For any failure_count in [10, 19] with default threshold=10,
    the ThreatEvent severity SHALL be "Medium".

    Validates: Requirements 7.3
    """
    rule = BruteForceRule(threshold=10, window_seconds=60, cooldown_seconds=0)
    _flood_rule(rule, src_ip, dst_ip, dst_port, count)

    event = rule.evaluate()

    assert event is not None, (
        f"Expected ThreatEvent for failure_count={count} >= threshold=10, but got None"
    )
    assert event.severity == "Medium", (
        f"Expected severity='Medium' for count={count} (tier 10-19), "
        f"got '{event.severity}'"
    )


# Feature: netguard-idps, Property 16
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    dst_port=st.sampled_from(_AUTH_PORTS),
    # High tier: 20 <= count <= 39
    count=st.integers(min_value=20, max_value=39),
)
@settings(max_examples=100, deadline=5000)
def test_property_16_severity_high_tier(src_ip, dst_ip, dst_port, count):
    """
    Property 16: Severity Tier — High (20 ≤ failure_count ≤ 39).

    For any failure_count in [20, 39] with default threshold=10,
    the ThreatEvent severity SHALL be "High".

    Validates: Requirements 7.3
    """
    rule = BruteForceRule(threshold=10, window_seconds=60, cooldown_seconds=0)
    _flood_rule(rule, src_ip, dst_ip, dst_port, count)

    event = rule.evaluate()

    assert event is not None, (
        f"Expected ThreatEvent for failure_count={count} >= threshold=10, but got None"
    )
    assert event.severity == "High", (
        f"Expected severity='High' for count={count} (tier 20-39), "
        f"got '{event.severity}'"
    )


# Feature: netguard-idps, Property 16
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    dst_port=st.sampled_from(_AUTH_PORTS),
    # Critical tier: count >= 40
    count=st.integers(min_value=40, max_value=100),
)
@settings(max_examples=100, deadline=5000)
def test_property_16_severity_critical_tier(src_ip, dst_ip, dst_port, count):
    """
    Property 16: Severity Tier — Critical (failure_count ≥ 40).

    For any failure_count >= 40 with default threshold=10,
    the ThreatEvent severity SHALL be "Critical".

    Validates: Requirements 7.3
    """
    rule = BruteForceRule(threshold=10, window_seconds=60, cooldown_seconds=0)
    _flood_rule(rule, src_ip, dst_ip, dst_port, count)

    event = rule.evaluate()

    assert event is not None, (
        f"Expected ThreatEvent for failure_count={count} >= threshold=10, but got None"
    )
    assert event.severity == "Critical", (
        f"Expected severity='Critical' for count={count} (tier >=40), "
        f"got '{event.severity}'"
    )


# Feature: netguard-idps, Property 16
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    dst_port=st.sampled_from(_AUTH_PORTS),
    threshold=st.integers(min_value=1, max_value=10),
    count=st.integers(min_value=10, max_value=100),
)
@settings(max_examples=100, deadline=5000)
def test_property_16_severity_is_always_valid(src_ip, dst_ip, dst_port, threshold, count):
    """
    Property 16: Severity is always one of the expected tier values.

    For any failure_count >= threshold, severity SHALL be one of
    "Medium", "High", or "Critical".

    Validates: Requirements 7.3
    """
    assume(count >= threshold)

    rule = BruteForceRule(threshold=threshold, window_seconds=60, cooldown_seconds=0)
    _flood_rule(rule, src_ip, dst_ip, dst_port, count)

    event = rule.evaluate()

    assert event is not None, (
        f"Expected ThreatEvent for count={count} >= threshold={threshold}, but got None"
    )
    assert event.severity in ("Medium", "High", "Critical"), (
        f"Expected severity in (Medium, High, Critical), got '{event.severity}'"
    )


# ---------------------------------------------------------------------------
# Property 17: Confidence Formula Always in [0, 100]
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 17
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    dst_port=st.sampled_from(_AUTH_PORTS),
    threshold=st.integers(min_value=1, max_value=20),
    count=st.integers(min_value=1, max_value=100),
)
@settings(max_examples=100, deadline=5000)
def test_property_17_confidence_always_in_range(src_ip, dst_ip, dst_port, threshold, count):
    """
    Property 17: Confidence formula result always in [0, 100].

    For any failure_count >= threshold, the ThreatEvent confidence score
    SHALL be an integer in the closed interval [0, 100].

    Formula: round(min(failure_count/threshold, 2.0) / 2.0 * 100), capped at 100.

    Validates: Requirements 7.4
    """
    assume(count >= threshold)

    rule = BruteForceRule(threshold=threshold, window_seconds=60, cooldown_seconds=0)
    _flood_rule(rule, src_ip, dst_ip, dst_port, count)

    event = rule.evaluate()

    assert event is not None, (
        f"Expected ThreatEvent for count={count} >= threshold={threshold}, but got None"
    )
    assert isinstance(event.confidence, int), (
        f"Expected confidence to be int, got {type(event.confidence)}"
    )
    assert 0 <= event.confidence <= 100, (
        f"Expected confidence in [0, 100], got {event.confidence} "
        f"(count={count}, threshold={threshold})"
    )


# Feature: netguard-idps, Property 17
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    dst_port=st.sampled_from(_AUTH_PORTS),
    threshold=st.integers(min_value=1, max_value=20),
    count=st.integers(min_value=1, max_value=100),
)
@settings(max_examples=100, deadline=5000)
def test_property_17_confidence_matches_formula(src_ip, dst_ip, dst_port, threshold, count):
    """
    Property 17: Confidence value matches the defined formula.

    confidence = round(min(failure_count / threshold, 2.0) / 2.0 * 100), capped at 100.

    Validates: Requirements 7.4
    """
    assume(count >= threshold)

    rule = BruteForceRule(threshold=threshold, window_seconds=60, cooldown_seconds=0)
    _flood_rule(rule, src_ip, dst_ip, dst_port, count)

    event = rule.evaluate()
    assert event is not None

    expected = min(int(round(min(count / threshold, 2.0) / 2.0 * 100)), 100)

    assert event.confidence == expected, (
        f"Expected confidence={expected} for count={count}, threshold={threshold}, "
        f"got {event.confidence}"
    )


# Feature: netguard-idps, Property 17
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    dst_port=st.sampled_from(_AUTH_PORTS),
    threshold=st.integers(min_value=1, max_value=10),
    # count exactly 2x threshold should give confidence = 100
    multiplier=st.integers(min_value=2, max_value=10),
)
@settings(max_examples=100, deadline=5000)
def test_property_17_confidence_capped_at_100(src_ip, dst_ip, dst_port, threshold, multiplier):
    """
    Property 17: Confidence is capped at 100.

    When failure_count >= 2 * threshold, the formula yields exactly 100.

    Validates: Requirements 7.4
    """
    count = threshold * multiplier  # >= 2 * threshold when multiplier >= 2

    rule = BruteForceRule(threshold=threshold, window_seconds=60, cooldown_seconds=0)
    _flood_rule(rule, src_ip, dst_ip, dst_port, count)

    event = rule.evaluate()
    assert event is not None

    assert event.confidence == 100, (
        f"Expected confidence=100 for count={count} >= 2*threshold={2*threshold}, "
        f"got {event.confidence}"
    )


# ---------------------------------------------------------------------------
# Property 18: Evidence Dict Contains All Required Fields
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 18
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    dst_port=st.sampled_from(_AUTH_PORTS),
    threshold=st.integers(min_value=1, max_value=10),
    extra=st.integers(min_value=0, max_value=10),
)
@settings(max_examples=100, deadline=5000)
def test_property_18_evidence_contains_required_fields(
    src_ip, dst_ip, dst_port, threshold, extra
):
    """
    Property 18: Evidence dict contains all required fields including target_service.

    For any ThreatEvent emitted by BruteForceRule, the evidence dictionary
    SHALL contain all of: source_ip, failure_count, time_window_seconds,
    and target_service.

    Validates: Requirements 7.5, 7.6
    """
    count = threshold + extra
    rule = BruteForceRule(threshold=threshold, window_seconds=60, cooldown_seconds=0)
    _flood_rule(rule, src_ip, dst_ip, dst_port, count)

    event = rule.evaluate()

    assert event is not None, (
        f"Expected ThreatEvent for count={count} >= threshold={threshold}, but got None"
    )

    evidence = event.evidence
    assert isinstance(evidence, dict), (
        f"Expected evidence to be dict, got {type(evidence)}"
    )

    required_fields = {"source_ip", "failure_count", "time_window_seconds", "target_service"}
    missing_fields = required_fields - set(evidence.keys())
    assert not missing_fields, (
        f"Evidence missing required fields: {missing_fields}. "
        f"Present fields: {set(evidence.keys())}"
    )


# Feature: netguard-idps, Property 18
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    dst_port=st.sampled_from(_AUTH_PORTS),
    threshold=st.integers(min_value=1, max_value=10),
    extra=st.integers(min_value=0, max_value=10),
)
@settings(max_examples=100, deadline=5000)
def test_property_18_evidence_target_service_correct(
    src_ip, dst_ip, dst_port, threshold, extra
):
    """
    Property 18: target_service in evidence reflects the destination port.

    Port 22  → "SSH"
    Port 80  → "HTTP"
    Port 443 → "HTTP"
    Port 21  → "FTP"
    Unknown  → "Unknown"

    Validates: Requirements 7.5
    """
    count = threshold + extra
    rule = BruteForceRule(threshold=threshold, window_seconds=60, cooldown_seconds=0)
    _flood_rule(rule, src_ip, dst_ip, dst_port, count)

    event = rule.evaluate()
    assert event is not None

    expected_service = _PORT_TO_SERVICE.get(dst_port, "Unknown")
    actual_service = event.evidence.get("target_service")

    assert actual_service == expected_service, (
        f"Expected target_service='{expected_service}' for port {dst_port}, "
        f"got '{actual_service}'"
    )


# Feature: netguard-idps, Property 18
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    dst_port=st.sampled_from(_AUTH_PORTS),
    threshold=st.integers(min_value=1, max_value=10),
    extra=st.integers(min_value=0, max_value=10),
)
@settings(max_examples=100, deadline=5000)
def test_property_18_evidence_field_values_are_valid(
    src_ip, dst_ip, dst_port, threshold, extra
):
    """
    Property 18: Evidence field values are semantically valid.

    - source_ip matches the packet source IP
    - failure_count is a positive integer >= threshold
    - time_window_seconds is a positive integer
    - target_service is one of "SSH", "HTTP", "FTP", "Unknown"

    Validates: Requirements 7.5, 7.6
    """
    count = threshold + extra
    rule = BruteForceRule(threshold=threshold, window_seconds=60, cooldown_seconds=0)
    _flood_rule(rule, src_ip, dst_ip, dst_port, count)

    event = rule.evaluate()
    assert event is not None

    evidence = event.evidence

    assert evidence["source_ip"] == src_ip, (
        f"Expected evidence['source_ip']='{src_ip}', got '{evidence['source_ip']}'"
    )
    assert isinstance(evidence["failure_count"], int), (
        f"Expected failure_count to be int, got {type(evidence['failure_count'])}"
    )
    assert evidence["failure_count"] >= threshold, (
        f"Expected failure_count >= threshold={threshold}, "
        f"got {evidence['failure_count']}"
    )
    assert isinstance(evidence["time_window_seconds"], int), (
        f"Expected time_window_seconds to be int, got {type(evidence['time_window_seconds'])}"
    )
    assert evidence["time_window_seconds"] > 0, (
        f"Expected time_window_seconds > 0, got {evidence['time_window_seconds']}"
    )
    assert evidence["target_service"] in ("SSH", "HTTP", "FTP", "Unknown"), (
        f"Expected target_service in (SSH, HTTP, FTP, Unknown), "
        f"got '{evidence['target_service']}'"
    )
