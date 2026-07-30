"""
test_properties_detection_bruteforce.py — Property-based tests for BruteForceRule.

Properties tested:
  Property 15: failure_count ≥ threshold → ThreatEvent with "Brute Force" / "BRUTE_FORCE_001"
  Property 16: Severity tiers — Medium 10–19, High 20–39, Critical ≥40
  Property 17: Confidence formula result always in [0, 100]
  Property 18: Evidence dict contains all required fields including target_service

Requirements: 7.1–7.6
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime, timezone

from hypothesis import given, settings, strategies as st, assume

from detection.parsers.packet_decoder import Packet
from detection.rules.brute_force import BruteForceRule, SERVICE_PORTS

# ---------------------------------------------------------------------------
# Helpers / strategies
# ---------------------------------------------------------------------------

def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_AUTH_PORTS = list(SERVICE_PORTS.keys())  # [21, 22, 80, 443]

_ipv4 = st.sampled_from([
    "10.0.0.1", "10.0.0.2", "192.168.1.1", "192.168.1.100", "172.16.0.1",
])


def _make_tcp_packet(src_ip: str, dst_port: int) -> Packet:
    return Packet(
        src_ip=src_ip,
        dst_ip="192.168.1.1",
        src_port=54321,
        dst_port=dst_port,
        protocol="TCP",
        flags="S",
        timestamp=_now_ts(),
        length=60,
        payload=None,
        hw_src=None,
    )


def _feed(rule: BruteForceRule, count: int, src_ip: str, dst_port: int) -> None:
    for _ in range(count):
        rule.process_packet(_make_tcp_packet(src_ip, dst_port))


# ---------------------------------------------------------------------------
# Property 15: failure_count ≥ threshold → ThreatEvent
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 15
@given(
    src_ip=_ipv4,
    threshold=st.integers(min_value=1, max_value=20),
    excess=st.integers(min_value=0, max_value=30),
    dst_port=st.sampled_from(_AUTH_PORTS),
)
@settings(max_examples=100, deadline=2000)
def test_property_15_threshold_triggers_event(src_ip, threshold, excess, dst_port):
    """
    Property 15: When failure_count ≥ threshold within the window, the rule SHALL
    emit a ThreatEvent with attack_type "Brute Force" and rule_name "BRUTE_FORCE_001".

    Validates: Requirements 7.1
    """
    count = threshold + excess
    rule = BruteForceRule(threshold=threshold, window_seconds=60)
    rule.initialize()
    _feed(rule, count, src_ip, dst_port)
    event = rule.evaluate()

    assert event is not None, (
        f"Expected ThreatEvent for count={count} >= threshold={threshold}, got None"
    )
    assert event.attack_type == "Brute Force", (
        f"Expected attack_type='Brute Force', got '{event.attack_type}'"
    )
    assert event.rule_name == "BRUTE_FORCE_001", (
        f"Expected rule_name='BRUTE_FORCE_001', got '{event.rule_name}'"
    )


# Feature: netguard-idps, Property 15
@given(
    src_ip=_ipv4,
    threshold=st.integers(min_value=2, max_value=20),
    dst_port=st.sampled_from(_AUTH_PORTS),
)
@settings(max_examples=50, deadline=2000)
def test_property_15_below_threshold_no_event(src_ip, threshold, dst_port):
    """
    Property 15: failure_count < threshold → no ThreatEvent.

    Validates: Requirements 7.1
    """
    count = threshold - 1
    rule = BruteForceRule(threshold=threshold, window_seconds=60)
    rule.initialize()
    _feed(rule, count, src_ip, dst_port)
    event = rule.evaluate()

    assert event is None, (
        f"Expected no ThreatEvent for count={count} < threshold={threshold}, "
        f"got: {event}"
    )


# ---------------------------------------------------------------------------
# Property 16: Severity tiers
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 16
@given(
    src_ip=_ipv4,
    count=st.integers(min_value=10, max_value=19),
    dst_port=st.sampled_from(_AUTH_PORTS),
)
@settings(max_examples=60, deadline=2000)
def test_property_16_severity_medium_10_to_19(src_ip, count, dst_port):
    """
    Property 16: failure_count in [10, 19] → severity "Medium".

    Validates: Requirements 7.2
    """
    rule = BruteForceRule(threshold=10, window_seconds=60)
    rule.initialize()
    _feed(rule, count, src_ip, dst_port)
    event = rule.evaluate()

    assert event is not None
    assert event.severity == "Medium", (
        f"Expected 'Medium' for count={count}, got '{event.severity}'"
    )


# Feature: netguard-idps, Property 16
@given(
    src_ip=_ipv4,
    count=st.integers(min_value=20, max_value=39),
    dst_port=st.sampled_from(_AUTH_PORTS),
)
@settings(max_examples=60, deadline=2000)
def test_property_16_severity_high_20_to_39(src_ip, count, dst_port):
    """
    Property 16: failure_count in [20, 39] → severity "High".

    Validates: Requirements 7.3
    """
    rule = BruteForceRule(threshold=10, window_seconds=60)
    rule.initialize()
    _feed(rule, count, src_ip, dst_port)
    event = rule.evaluate()

    assert event is not None
    assert event.severity == "High", (
        f"Expected 'High' for count={count}, got '{event.severity}'"
    )


# Feature: netguard-idps, Property 16
@given(
    src_ip=_ipv4,
    count=st.integers(min_value=40, max_value=100),
    dst_port=st.sampled_from(_AUTH_PORTS),
)
@settings(max_examples=60, deadline=2000)
def test_property_16_severity_critical_40_plus(src_ip, count, dst_port):
    """
    Property 16: failure_count ≥ 40 → severity "Critical".

    Validates: Requirements 7.4
    """
    rule = BruteForceRule(threshold=10, window_seconds=60)
    rule.initialize()
    _feed(rule, count, src_ip, dst_port)
    event = rule.evaluate()

    assert event is not None
    assert event.severity == "Critical", (
        f"Expected 'Critical' for count={count}, got '{event.severity}'"
    )


# ---------------------------------------------------------------------------
# Property 17: Confidence always in [0, 100]
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 17
@given(
    src_ip=_ipv4,
    threshold=st.integers(min_value=1, max_value=20),
    excess=st.integers(min_value=0, max_value=80),
    dst_port=st.sampled_from(_AUTH_PORTS),
)
@settings(max_examples=100, deadline=2000)
def test_property_17_confidence_always_in_range(src_ip, threshold, excess, dst_port):
    """
    Property 17: Confidence score is always an integer in [0, 100].

    Validates: Requirements 7.6
    """
    count = threshold + excess
    rule = BruteForceRule(threshold=threshold, window_seconds=60)
    rule.initialize()
    _feed(rule, count, src_ip, dst_port)
    event = rule.evaluate()

    assert event is not None
    assert isinstance(event.confidence, int), (
        f"Expected confidence to be int, got {type(event.confidence)}"
    )
    assert 0 <= event.confidence <= 100, (
        f"Expected confidence in [0,100], got {event.confidence}"
    )


# Feature: netguard-idps, Property 17
@given(
    threshold=st.integers(min_value=1, max_value=20),
    count=st.integers(min_value=1, max_value=100),
)
@settings(max_examples=100, deadline=2000)
def test_property_17_confidence_formula_correct(threshold, count):
    """
    Property 17: Confidence matches formula round(min(count/T,2.0)/2.0*100) capped at 100.

    Validates: Requirements 7.6
    """
    assume(count >= threshold)

    rule = BruteForceRule(threshold=threshold, window_seconds=60)
    rule.initialize()
    _feed(rule, count, "10.0.0.1", 22)
    event = rule.evaluate()

    assert event is not None
    expected = min(int(round(min(count / threshold, 2.0) / 2.0 * 100)), 100)
    assert event.confidence == expected, (
        f"count={count}, threshold={threshold}: "
        f"expected confidence={expected}, got {event.confidence}"
    )


# ---------------------------------------------------------------------------
# Property 18: Evidence contains all required fields including target_service
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 18
@given(
    src_ip=_ipv4,
    threshold=st.integers(min_value=1, max_value=10),
    excess=st.integers(min_value=0, max_value=20),
    dst_port=st.sampled_from(_AUTH_PORTS),
)
@settings(max_examples=100, deadline=2000)
def test_property_18_evidence_required_fields(src_ip, threshold, excess, dst_port):
    """
    Property 18: Evidence dict contains all required fields:
    source_ip, failure_count, time_window_seconds, target_service.

    Validates: Requirements 7.5
    """
    count = threshold + excess
    rule = BruteForceRule(threshold=threshold, window_seconds=60)
    rule.initialize()
    _feed(rule, count, src_ip, dst_port)
    event = rule.evaluate()

    assert event is not None
    ev = event.evidence

    required = {"source_ip", "failure_count", "time_window_seconds", "target_service"}
    missing = required - set(ev.keys())
    assert not missing, f"Evidence missing fields: {missing}. Got: {set(ev.keys())}"


# Feature: netguard-idps, Property 18
@given(
    src_ip=_ipv4,
    dst_port=st.sampled_from(_AUTH_PORTS),
    threshold=st.integers(min_value=1, max_value=10),
    excess=st.integers(min_value=0, max_value=10),
)
@settings(max_examples=100, deadline=2000)
def test_property_18_target_service_is_valid_string(src_ip, dst_port, threshold, excess):
    """
    Property 18: evidence['target_service'] must be a non-empty string.
    For known auth ports it must match the expected service name.

    Validates: Requirements 7.5
    """
    count = threshold + excess
    rule = BruteForceRule(threshold=threshold, window_seconds=60)
    rule.initialize()
    _feed(rule, count, src_ip, dst_port)
    event = rule.evaluate()

    assert event is not None
    service = event.evidence.get("target_service")
    assert isinstance(service, str) and service, (
        f"Expected non-empty string for target_service, got: {service!r}"
    )

    expected_service = SERVICE_PORTS.get(dst_port, "Unknown")
    assert service == expected_service, (
        f"For dst_port={dst_port} expected service='{expected_service}', "
        f"got '{service}'"
    )
