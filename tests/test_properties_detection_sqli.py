"""
test_properties_detection_sqli.py — Property-based tests for SQL Injection detection.

Properties tested:
  Property 12: Any matching payload → ThreatEvent with "SQL Injection" / "SQL_INJECTION_001"
  Property 13: First occurrence from IP → High; repeat from same IP → Critical
  Property 14: Confidence always 100; evidence contains all required fields

Requirements: 6.1–6.6
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime, timezone

from hypothesis import given, settings, strategies as st

from detection.parsers.packet_decoder import Packet
from detection.rules.sql_injection import SqlInjectionRule

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# The five canonical patterns from Requirement 6.1
_SQL_PATTERNS = ["' OR", "UNION SELECT", "DROP TABLE", "--", "xp_cmdshell"]

_ipv4 = st.sampled_from([
    "10.0.0.1", "10.0.0.2", "192.168.1.1", "192.168.1.50", "172.16.0.5",
])


def _make_http_packet(src_ip: str, payload: str, dst_port: int = 80) -> Packet:
    """Build a TCP packet with the given HTTP payload string."""
    return Packet(
        src_ip=src_ip,
        dst_ip="10.0.0.254",
        src_port=54321,
        dst_port=dst_port,
        protocol="TCP",
        flags="PA",
        timestamp=_now_ts(),
        length=len(payload) + 54,
        payload=payload.encode("utf-8"),
        hw_src=None,
    )


def _http_request(path: str = "/search", pattern: str = "' OR 1=1") -> str:
    """Minimal HTTP/1.1 GET request with a SQL pattern in the URL."""
    return f"GET {path}?q={pattern} HTTP/1.1\r\nHost: example.com\r\n\r\n"


# ---------------------------------------------------------------------------
# Property 12: Any matching payload → ThreatEvent with correct type/rule
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 12
@given(
    src_ip=_ipv4,
    pattern=st.sampled_from(_SQL_PATTERNS),
    dst_port=st.sampled_from([80, 443]),
)
@settings(max_examples=50, deadline=2000)
def test_property_12_matching_payload_triggers_event(src_ip, pattern, dst_port):
    """
    Property 12: Any HTTP packet whose payload contains a SQL injection pattern
    SHALL emit a ThreatEvent with attack_type "SQL Injection" and
    rule_name "SQL_INJECTION_001".

    Validates: Requirements 6.1, 6.6
    """
    rule = SqlInjectionRule()
    rule.initialize()
    pkt = _make_http_packet(src_ip, _http_request(pattern=pattern), dst_port)
    rule.process_packet(pkt)
    event = rule.evaluate()

    assert event is not None, (
        f"Expected ThreatEvent for pattern '{pattern}' on port {dst_port}, got None"
    )
    assert event.attack_type == "SQL Injection", (
        f"Expected attack_type='SQL Injection', got '{event.attack_type}'"
    )
    assert event.rule_name == "SQL_INJECTION_001", (
        f"Expected rule_name='SQL_INJECTION_001', got '{event.rule_name}'"
    )


# Feature: netguard-idps, Property 12
@given(src_ip=_ipv4, dst_port=st.sampled_from([80, 443]))
@settings(max_examples=50, deadline=2000)
def test_property_12_case_insensitive_matching(src_ip, dst_port):
    """
    Property 12: Pattern matching is case-insensitive — upper/lower/mixed all trigger.

    Validates: Requirements 6.1
    """
    rule = SqlInjectionRule()
    rule.initialize()
    # "union select" lowercased — must still match
    pkt = _make_http_packet(src_ip, _http_request(pattern="union select 1,2,3"), dst_port)
    rule.process_packet(pkt)
    event = rule.evaluate()

    assert event is not None, "Expected ThreatEvent for lowercase 'union select'"
    assert event.attack_type == "SQL Injection"


# Feature: netguard-idps, Property 12
@given(src_ip=_ipv4, dst_port=st.sampled_from([80, 443]))
@settings(max_examples=30, deadline=2000)
def test_property_12_clean_payload_no_event(src_ip, dst_port):
    """
    Property 12: HTTP packet with no SQL pattern must NOT trigger an event.

    Validates: Requirements 6.1
    """
    rule = SqlInjectionRule()
    rule.initialize()
    pkt = _make_http_packet(src_ip, _http_request(path="/search", pattern="hello+world"), dst_port)
    rule.process_packet(pkt)
    event = rule.evaluate()

    assert event is None, (
        f"Expected no ThreatEvent for clean payload, got: {event}"
    )


# ---------------------------------------------------------------------------
# Property 13: First → High; repeat from same IP → Critical
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 13
@given(
    src_ip=_ipv4,
    pattern=st.sampled_from(_SQL_PATTERNS),
)
@settings(max_examples=50, deadline=2000)
def test_property_13_first_occurrence_is_high(src_ip, pattern):
    """
    Property 13: First SQL injection detection from a source IP → severity "High".

    Validates: Requirements 6.2
    """
    rule = SqlInjectionRule()
    rule.initialize()
    pkt = _make_http_packet(src_ip, _http_request(pattern=pattern))
    rule.process_packet(pkt)
    event = rule.evaluate()

    assert event is not None
    assert event.severity == "High", (
        f"Expected severity='High' for first occurrence from {src_ip}, "
        f"got '{event.severity}'"
    )


# Feature: netguard-idps, Property 13
@given(
    src_ip=_ipv4,
    pattern1=st.sampled_from(_SQL_PATTERNS),
    pattern2=st.sampled_from(_SQL_PATTERNS),
)
@settings(max_examples=50, deadline=2000)
def test_property_13_repeat_from_same_ip_is_critical(src_ip, pattern1, pattern2):
    """
    Property 13: Second+ SQL injection from same IP → severity "Critical".

    Validates: Requirements 6.3
    """
    rule = SqlInjectionRule()
    rule.initialize()

    # First hit
    rule.process_packet(_make_http_packet(src_ip, _http_request(pattern=pattern1)))
    event1 = rule.evaluate()
    assert event1 is not None
    assert event1.severity == "High"

    # Second hit from same IP
    rule.process_packet(_make_http_packet(src_ip, _http_request(pattern=pattern2)))
    event2 = rule.evaluate()
    assert event2 is not None, (
        f"Expected ThreatEvent on second hit from {src_ip}, got None"
    )
    assert event2.severity == "Critical", (
        f"Expected severity='Critical' for repeat hit from {src_ip}, "
        f"got '{event2.severity}'"
    )


# Feature: netguard-idps, Property 13
@given(
    src_ip1=st.just("10.1.0.1"),
    src_ip2=st.just("10.1.0.2"),
    pattern=st.sampled_from(_SQL_PATTERNS),
)
@settings(max_examples=30, deadline=2000)
def test_property_13_different_ips_are_independent(src_ip1, src_ip2, pattern):
    """
    Property 13: Severity escalation is per-source-IP — different IPs are independent.

    Validates: Requirements 6.2, 6.3
    """
    rule = SqlInjectionRule()
    rule.initialize()

    # Trigger from ip1 first, then ip2
    rule.process_packet(_make_http_packet(src_ip1, _http_request(pattern=pattern)))
    rule.evaluate()  # consume

    rule.process_packet(_make_http_packet(src_ip2, _http_request(pattern=pattern)))
    event2 = rule.evaluate()

    assert event2 is not None
    assert event2.severity == "High", (
        f"Expected first hit from {src_ip2} to be 'High' (IP-independent), "
        f"got '{event2.severity}'"
    )


# ---------------------------------------------------------------------------
# Property 14: Confidence always 100; evidence contains all required fields
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 14
@given(
    src_ip=_ipv4,
    pattern=st.sampled_from(_SQL_PATTERNS),
    dst_port=st.sampled_from([80, 443]),
)
@settings(max_examples=50, deadline=2000)
def test_property_14_confidence_always_100(src_ip, pattern, dst_port):
    """
    Property 14: Confidence score is always 100 for SQL injection detections.

    A single matching payload constitutes definitive evidence.

    Validates: Requirements 6.5
    """
    rule = SqlInjectionRule()
    rule.initialize()
    pkt = _make_http_packet(src_ip, _http_request(pattern=pattern), dst_port)
    rule.process_packet(pkt)
    event = rule.evaluate()

    assert event is not None
    assert event.confidence == 100, (
        f"Expected confidence=100, got {event.confidence}"
    )


# Feature: netguard-idps, Property 14
@given(
    src_ip=_ipv4,
    pattern=st.sampled_from(_SQL_PATTERNS),
    dst_port=st.sampled_from([80, 443]),
)
@settings(max_examples=50, deadline=2000)
def test_property_14_evidence_contains_required_fields(src_ip, pattern, dst_port):
    """
    Property 14: Evidence dict contains all required fields:
    source_ip, destination_ip, http_method, request_url, matched_pattern.

    Validates: Requirements 6.4
    """
    rule = SqlInjectionRule()
    rule.initialize()
    pkt = _make_http_packet(src_ip, _http_request(pattern=pattern), dst_port)
    rule.process_packet(pkt)
    event = rule.evaluate()

    assert event is not None
    ev = event.evidence

    required = {"source_ip", "destination_ip", "http_method", "request_url", "matched_pattern"}
    missing = required - set(ev.keys())
    assert not missing, f"Evidence missing fields: {missing}. Present: {set(ev.keys())}"


# Feature: netguard-idps, Property 14
@given(
    src_ip=_ipv4,
    pattern=st.sampled_from(_SQL_PATTERNS),
)
@settings(max_examples=50, deadline=2000)
def test_property_14_evidence_matched_pattern_is_canonical(src_ip, pattern):
    """
    Property 14: evidence['matched_pattern'] must be one of the five canonical
    pattern strings defined in Requirement 6.1.

    Validates: Requirements 6.4
    """
    rule = SqlInjectionRule()
    rule.initialize()
    pkt = _make_http_packet(src_ip, _http_request(pattern=pattern))
    rule.process_packet(pkt)
    event = rule.evaluate()

    assert event is not None
    assert event.evidence["matched_pattern"] in _SQL_PATTERNS, (
        f"Expected matched_pattern in {_SQL_PATTERNS}, "
        f"got '{event.evidence['matched_pattern']}'"
    )
