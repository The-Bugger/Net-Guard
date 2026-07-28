"""
test_properties_detection_sqli.py — Property-based tests for SQL Injection detection.

Covers Properties 12–14 from the design document.

Properties tested in this file:
  Property 12: SQL Injection Pattern Detection
  Property 13: SQL Injection Severity Escalation
  Property 14: SQL Injection Confidence and Evidence

Requirements: 6.1–6.6
"""

from __future__ import annotations

import sys
import os
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime, timezone

import pytest
from hypothesis import given, settings, strategies as st, assume

from detection.parsers.packet_decoder import Packet
from detection.rules.sql_injection import SqlInjectionRule


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

# SQL injection patterns as defined in Requirement 6.1
_SQL_PATTERNS = [
    "' OR",
    "UNION SELECT",
    "DROP TABLE",
    "--",
    "xp_cmdshell",
]

# HTTP ports (80, 443)
_http_ports = st.sampled_from([80, 443])

# Non-HTTP ports that should be ignored (not 8080/8443 as those are included in _HTTP_PORTS)
_non_http_ports = st.sampled_from([21, 22, 23, 25, 53, 110, 143, 3306, 5432, 9000])


def _make_http_packet(
    src_ip: str,
    dst_ip: str,
    payload_str: str,
    dst_port: int = 80,
    timestamp: str | None = None,
) -> Packet:
    """Build a minimal TCP packet that looks like an HTTP request."""
    return Packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=5000,
        dst_port=dst_port,
        protocol="TCP",
        flags="PA",
        timestamp=timestamp or _now_ts(),
        length=len(payload_str.encode()),
        payload=payload_str.encode(),
    )


def _generate_http_request_with_pattern(pattern: str, method: str = "GET") -> str:
    """Generate an HTTP request containing the specified SQL injection pattern."""
    if method == "GET":
        # Add space before pattern to ensure word boundary matching
        return f"GET /search?q=test {pattern} HTTP/1.1\r\nHost: example.com\r\n\r\n"
    else:
        return f"POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Length: {len(pattern) + 14}\r\n\r\nusername=admin {pattern}"


def _generate_clean_http_request(method: str = "GET") -> str:
    """Generate a clean HTTP request with no SQL injection patterns."""
    if method == "GET":
        return "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    else:
        return "POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 20\r\n\r\nusername=alice&pass=s3cr3t"


# ---------------------------------------------------------------------------
# Property 12: SQL Injection Pattern Detection
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 12
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    pattern=st.sampled_from(_SQL_PATTERNS),
    dst_port=_http_ports,
    method=st.sampled_from(["GET", "POST"]),
)
@settings(max_examples=100, deadline=2000)
def test_property_12_sql_injection_pattern_detection(src_ip, dst_ip, pattern, dst_port, method):
    """
    Property 12: SQL Injection Pattern Detection

    For any HTTP packet (destination port 80 or 443) whose payload contains at least
    one of the SQL injection patterns (' OR, UNION SELECT, DROP TABLE, --, xp_cmdshell)
    in a case-insensitive match within the URL path, query string, or request body,
    the Detection_Engine SHALL emit a ThreatEvent with attack_type "SQL Injection"
    and rule_name "SQL_INJECTION_001".

    Validates: Requirements 6.1, 6.6
    """
    # Generate HTTP request with the SQL injection pattern
    payload_str = _generate_http_request_with_pattern(pattern, method)
    
    rule = SqlInjectionRule()
    packet = _make_http_packet(src_ip, dst_ip, payload_str, dst_port)
    
    rule.process_packet(packet)
    event = rule.evaluate()
    
    assert event is not None, (
        f"Expected ThreatEvent for SQL injection pattern '{pattern}' in {method} request "
        f"on port {dst_port}, but got None"
    )
    assert event.attack_type == "SQL Injection", (
        f"Expected attack_type='SQL Injection', got '{event.attack_type}'"
    )
    assert event.rule_name == "SQL_INJECTION_001", (
        f"Expected rule_name='SQL_INJECTION_001', got '{event.rule_name}'"
    )
    assert event.source_ip == src_ip, (
        f"Expected source_ip='{src_ip}', got '{event.source_ip}'"
    )
    assert event.destination_ip == dst_ip, (
        f"Expected destination_ip='{dst_ip}', got '{event.destination_ip}'"
    )


# Feature: netguard-idps, Property 12
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    pattern=st.sampled_from(_SQL_PATTERNS),
    case_fn=st.sampled_from([str.lower, str.upper, str.title]),
)
@settings(max_examples=100, deadline=2000)
def test_property_12_sql_injection_case_insensitive(src_ip, dst_ip, pattern, case_fn):
    """
    Property 12: SQL Injection Pattern Detection (Case Insensitivity)

    For any HTTP packet containing a SQL injection pattern in any case
    (lowercase, uppercase, mixed case), the Detection_Engine SHALL detect it.

    Validates: Requirements 6.1
    """
    # Apply case transformation
    case_variant = case_fn(pattern)
    
    rule = SqlInjectionRule()
    payload_str = _generate_http_request_with_pattern(case_variant)
    packet = _make_http_packet(src_ip, dst_ip, payload_str, 80)
    
    rule.process_packet(packet)
    event = rule.evaluate()
    
    assert event is not None, (
        f"Expected ThreatEvent for case variant '{case_variant}' of pattern '{pattern}', "
        f"but got None"
    )
    assert event.attack_type == "SQL Injection"


# Feature: netguard-idps, Property 12
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    dst_port=_non_http_ports,
    pattern=st.sampled_from(_SQL_PATTERNS),
)
@settings(max_examples=100, deadline=2000)
def test_property_12_sql_injection_non_http_ports_ignored(src_ip, dst_ip, dst_port, pattern):
    """
    Property 12: SQL Injection Pattern Detection (Non-HTTP Ports)

    For any packet with a SQL injection pattern but destination port NOT 80 or 443,
    the Detection_Engine SHALL NOT emit a ThreatEvent.

    Validates: Requirements 6.1
    """
    payload_str = _generate_http_request_with_pattern(pattern)
    
    rule = SqlInjectionRule()
    packet = _make_http_packet(src_ip, dst_ip, payload_str, dst_port)
    
    rule.process_packet(packet)
    event = rule.evaluate()
    
    assert event is None, (
        f"Expected no ThreatEvent for SQL injection on non-HTTP port {dst_port}, "
        f"but got event: {event}"
    )


# Feature: netguard-idps, Property 12
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    dst_port=_http_ports,
)
@settings(max_examples=100, deadline=2000)
def test_property_12_sql_injection_clean_traffic_no_event(src_ip, dst_ip, dst_port):
    """
    Property 12: SQL Injection Pattern Detection (Clean Traffic)

    For any HTTP packet with no SQL injection patterns, the Detection_Engine
    SHALL NOT emit a ThreatEvent.

    Validates: Requirements 6.1, 6.6
    """
    payload_str = _generate_clean_http_request()
    
    rule = SqlInjectionRule()
    packet = _make_http_packet(src_ip, dst_ip, payload_str, dst_port)
    
    rule.process_packet(packet)
    event = rule.evaluate()
    
    assert event is None, (
        f"Expected no ThreatEvent for clean HTTP traffic, but got event: {event}"
    )


# ---------------------------------------------------------------------------
# Property 13: SQL Injection Severity Escalation
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 13
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    pattern=st.sampled_from(_SQL_PATTERNS),
    dst_port=_http_ports,
)
@settings(max_examples=100, deadline=2000)
def test_property_13_sql_injection_first_detection_high_severity(src_ip, dst_ip, pattern, dst_port):
    """
    Property 13: SQL Injection Severity Escalation (First Detection)

    For any SQL injection ThreatEvent from a source IP that has not previously
    triggered SQL_INJECTION_001 since application start, the Detection_Engine
    SHALL assign severity "High".

    Validates: Requirements 6.2
    """
    payload_str = _generate_http_request_with_pattern(pattern)
    
    rule = SqlInjectionRule()
    packet = _make_http_packet(src_ip, dst_ip, payload_str, dst_port)
    
    rule.process_packet(packet)
    event = rule.evaluate()
    
    assert event is not None, f"Expected ThreatEvent for first detection, but got None"
    assert event.severity == "High", (
        f"Expected severity='High' for first detection from {src_ip}, "
        f"got '{event.severity}'"
    )


# Feature: netguard-idps, Property 13
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    pattern1=st.sampled_from(_SQL_PATTERNS),
    pattern2=st.sampled_from(_SQL_PATTERNS),
    dst_port=_http_ports,
)
@settings(max_examples=100, deadline=2000)
def test_property_13_sql_injection_repeat_detection_critical_severity(
    src_ip, dst_ip, pattern1, pattern2, dst_port
):
    """
    Property 13: SQL Injection Severity Escalation (Repeat Detection)

    For any SQL injection ThreatEvent from a source IP that has previously
    triggered SQL_INJECTION_001 one or more times since application start,
    the Detection_Engine SHALL assign severity "Critical".

    Validates: Requirements 6.3
    """
    rule = SqlInjectionRule()
    
    # First detection
    payload1 = _generate_http_request_with_pattern(pattern1)
    packet1 = _make_http_packet(src_ip, dst_ip, payload1, dst_port)
    rule.process_packet(packet1)
    event1 = rule.evaluate()
    
    assert event1 is not None
    assert event1.severity == "High", (
        f"Expected severity='High' for first detection, got '{event1.severity}'"
    )
    
    # Second detection from same IP
    payload2 = _generate_http_request_with_pattern(pattern2)
    packet2 = _make_http_packet(src_ip, dst_ip, payload2, dst_port)
    rule.process_packet(packet2)
    event2 = rule.evaluate()
    
    assert event2 is not None, (
        f"Expected ThreatEvent for repeat detection from {src_ip}, but got None"
    )
    assert event2.severity == "Critical", (
        f"Expected severity='Critical' for repeat detection from {src_ip}, "
        f"got '{event2.severity}'"
    )


# Feature: netguard-idps, Property 13
@given(
    src_ip1=_ipv4,
    src_ip2=_ipv4,
    dst_ip=_ipv4,
    pattern=st.sampled_from(_SQL_PATTERNS),
    dst_port=_http_ports,
)
@settings(max_examples=100, deadline=2000)
def test_property_13_sql_injection_independent_ips(src_ip1, src_ip2, dst_ip, pattern, dst_port):
    """
    Property 13: SQL Injection Severity Escalation (Independent IPs)

    For any two different source IPs, each first detection SHALL return severity "High"
    independently; the history of one IP SHALL NOT affect the severity of another IP.

    Validates: Requirements 6.2, 6.3
    """
    assume(src_ip1 != src_ip2)
    
    rule = SqlInjectionRule()
    payload = _generate_http_request_with_pattern(pattern)
    
    # First IP - first detection
    packet1 = _make_http_packet(src_ip1, dst_ip, payload, dst_port)
    rule.process_packet(packet1)
    event1 = rule.evaluate()
    
    assert event1 is not None
    assert event1.severity == "High", (
        f"Expected severity='High' for first detection from {src_ip1}, "
        f"got '{event1.severity}'"
    )
    
    # Second IP - first detection
    packet2 = _make_http_packet(src_ip2, dst_ip, payload, dst_port)
    rule.process_packet(packet2)
    event2 = rule.evaluate()
    
    assert event2 is not None
    assert event2.severity == "High", (
        f"Expected severity='High' for first detection from {src_ip2}, "
        f"got '{event2.severity}' (should be independent of {src_ip1})"
    )


# ---------------------------------------------------------------------------
# Property 14: SQL Injection Confidence and Evidence
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 14
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    pattern=st.sampled_from(_SQL_PATTERNS),
    dst_port=_http_ports,
    method=st.sampled_from(["GET", "POST"]),
)
@settings(max_examples=100, deadline=2000)
def test_property_14_sql_injection_confidence_always_100(src_ip, dst_ip, pattern, dst_port, method):
    """
    Property 14: SQL Injection Confidence and Evidence (Confidence Score)

    For any SQL injection ThreatEvent, the Detection_Engine SHALL assign
    confidence score 100.

    Validates: Requirements 6.5
    """
    payload_str = _generate_http_request_with_pattern(pattern, method)
    
    rule = SqlInjectionRule()
    packet = _make_http_packet(src_ip, dst_ip, payload_str, dst_port)
    
    rule.process_packet(packet)
    event = rule.evaluate()
    
    assert event is not None, f"Expected ThreatEvent, but got None"
    assert event.confidence == 100, (
        f"Expected confidence=100 for SQL injection detection, got {event.confidence}"
    )


# Feature: netguard-idps, Property 14
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    pattern=st.sampled_from(_SQL_PATTERNS),
    dst_port=_http_ports,
)
@settings(max_examples=100, deadline=2000)
def test_property_14_sql_injection_evidence_completeness(src_ip, dst_ip, pattern, dst_port):
    """
    Property 14: SQL Injection Confidence and Evidence (Evidence Fields)

    For any SQL injection ThreatEvent, the evidence dictionary SHALL contain
    all required fields: source_ip, destination_ip, http_method, request_url,
    and matched_pattern.

    Validates: Requirements 6.4
    """
    payload_str = _generate_http_request_with_pattern(pattern)
    
    rule = SqlInjectionRule()
    packet = _make_http_packet(src_ip, dst_ip, payload_str, dst_port)
    
    rule.process_packet(packet)
    event = rule.evaluate()
    
    assert event is not None, f"Expected ThreatEvent, but got None"
    
    evidence = event.evidence
    assert isinstance(evidence, dict), f"Expected evidence to be dict, got {type(evidence)}"
    
    # Check all required fields are present
    required_fields = {
        "source_ip",
        "destination_ip",
        "http_method",
        "request_url",
        "matched_pattern",
    }
    missing_fields = required_fields - set(evidence.keys())
    assert not missing_fields, (
        f"Evidence missing required fields: {missing_fields}. "
        f"Present fields: {set(evidence.keys())}"
    )
    
    # Validate field values
    assert evidence["source_ip"] == src_ip, (
        f"Expected evidence['source_ip']='{src_ip}', got '{evidence['source_ip']}'"
    )
    assert evidence["destination_ip"] == dst_ip, (
        f"Expected evidence['destination_ip']='{dst_ip}', got '{evidence['destination_ip']}'"
    )
    assert evidence["http_method"] in ["GET", "POST", "UNKNOWN"], (
        f"Expected valid http_method, got '{evidence['http_method']}'"
    )
    assert evidence["request_url"] != "", (
        "Expected non-empty request_url"
    )
    assert evidence["matched_pattern"] != "", (
        "Expected non-empty matched_pattern"
    )
    # Verify the matched pattern is one of the defined SQL patterns
    assert any(
        pattern.lower() in evidence["matched_pattern"].lower()
        for pattern in _SQL_PATTERNS
    ), (
        f"Expected matched_pattern to be one of {_SQL_PATTERNS}, "
        f"got '{evidence['matched_pattern']}'"
    )


# Feature: netguard-idps, Property 14
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    pattern1=st.sampled_from(_SQL_PATTERNS),
    pattern2=st.sampled_from(_SQL_PATTERNS),
    dst_port=_http_ports,
)
@settings(max_examples=100, deadline=2000)
def test_property_14_sql_injection_confidence_remains_100_on_repeat(
    src_ip, dst_ip, pattern1, pattern2, dst_port
):
    """
    Property 14: SQL Injection Confidence and Evidence (Confidence on Repeat)

    For any SQL injection ThreatEvent, even on repeated detections (Critical severity),
    the confidence score SHALL remain 100.

    Validates: Requirements 6.5
    """
    rule = SqlInjectionRule()
    
    # First detection
    payload1 = _generate_http_request_with_pattern(pattern1)
    packet1 = _make_http_packet(src_ip, dst_ip, payload1, dst_port)
    rule.process_packet(packet1)
    event1 = rule.evaluate()
    
    assert event1 is not None
    assert event1.confidence == 100, (
        f"Expected confidence=100 for first detection, got {event1.confidence}"
    )
    
    # Second detection from same IP (should be Critical severity)
    payload2 = _generate_http_request_with_pattern(pattern2)
    packet2 = _make_http_packet(src_ip, dst_ip, payload2, dst_port)
    rule.process_packet(packet2)
    event2 = rule.evaluate()
    
    assert event2 is not None
    assert event2.severity == "Critical", (
        f"Expected severity='Critical' for repeat, got '{event2.severity}'"
    )
    assert event2.confidence == 100, (
        f"Expected confidence=100 for repeat detection (Critical), got {event2.confidence}"
    )


# Feature: netguard-idps, Property 14
@given(
    src_ip=_ipv4,
    dst_ip=_ipv4,
    pattern=st.sampled_from(_SQL_PATTERNS),
    dst_port=_http_ports,
)
@settings(max_examples=100, deadline=2000)
def test_property_14_sql_injection_event_source_matches_evidence(src_ip, dst_ip, pattern, dst_port):
    """
    Property 14: SQL Injection Confidence and Evidence (Event-Evidence Consistency)

    For any SQL injection ThreatEvent, the event.source_ip SHALL match
    evidence['source_ip'], and event.destination_ip SHALL match
    evidence['destination_ip'].

    Validates: Requirements 6.4
    """
    payload_str = _generate_http_request_with_pattern(pattern)
    
    rule = SqlInjectionRule()
    packet = _make_http_packet(src_ip, dst_ip, payload_str, dst_port)
    
    rule.process_packet(packet)
    event = rule.evaluate()
    
    assert event is not None, f"Expected ThreatEvent, but got None"
    
    assert event.source_ip == event.evidence["source_ip"], (
        f"Event source_ip '{event.source_ip}' does not match "
        f"evidence source_ip '{event.evidence['source_ip']}'"
    )
    assert event.destination_ip == event.evidence["destination_ip"], (
        f"Event destination_ip '{event.destination_ip}' does not match "
        f"evidence destination_ip '{event.evidence['destination_ip']}'"
    )
