"""
test_properties_detection.py — Property-based tests for NetGuard detection rules.

Covers Properties 4–11 (SYN Flood and Port Scan) from the design document.

Properties tested in this file:
  Property 4:  SYN Flood detection threshold
  Property 5:  SYN Flood severity tiers
  Property 6:  SYN Flood confidence formula
  Property 7:  SYN Flood evidence completeness
  Property 8:  Port Scan detection threshold
  Property 9:  Port Scan severity tiers
  Property 10: Port Scan confidence formula
  Property 11: Port Scan evidence completeness

Requirements: 4.1–4.6, 5.1–5.5
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
from detection.rules.syn_flood import SynFloodRule, _syn_confidence, _syn_severity
from detection.rules.port_scan import PortScanRule, _scan_confidence, _scan_severity


# ---------------------------------------------------------------------------
# Shared strategies and helpers
# ---------------------------------------------------------------------------

# Strategy for valid IPv4 addresses (full 4-octet addresses)
_ipv4 = st.from_regex(
    r"^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.16\.\d{1,3}\.\d{1,3})$",
    fullmatch=True,
)

# Strategy for valid TCP/UDP destination ports (1–65535)
_port = st.integers(min_value=1, max_value=65535)

# Strategy for protocol
_tcp_udp = st.sampled_from(["TCP", "UDP"])


def _now_ts() -> str:
    """Return current UTC time as ISO-8601 string (same format used by the rule)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_packet(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    protocol: str = "TCP",
    timestamp: str | None = None,
) -> Packet:
    """Build a minimal Packet for port scan testing."""
    return Packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=5000,
        dst_port=dst_port,
        protocol=protocol,
        flags="S" if protocol == "TCP" else None,
        timestamp=timestamp or _now_ts(),
        length=60,
        payload=None,
    )


def _feed_unique_ports(
    rule: PortScanRule,
    src_ip: str,
    ports: list[int],
    dst_ip: str = "10.0.0.1",
    protocol: str = "TCP",
) -> None:
    """Feed packets for a distinct set of destination ports from src_ip."""
    for port in ports:
        rule.process_packet(_make_packet(src_ip, dst_ip, port, protocol))


# ---------------------------------------------------------------------------
# SYN Flood helpers
# ---------------------------------------------------------------------------

def make_syn(src: str = "1.2.3.4", dst: str = "10.0.0.1") -> Packet:
    """Build a minimal TCP SYN packet for SYN flood testing."""
    return Packet(
        src_ip=src,
        dst_ip=dst,
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        flags="S",
        timestamp=_now_ts(),
        length=60,
        payload=None,
    )


def _feed_syn_packets(rule: SynFloodRule, count: int, src: str = "1.2.3.4") -> None:
    """Feed `count` SYN packets from `src` into `rule`."""
    pkt = make_syn(src=src)
    for _ in range(count):
        rule.process_packet(pkt)


# ---------------------------------------------------------------------------
# Property 4: SYN Flood Detection Threshold
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 4
@given(
    threshold=st.integers(min_value=1, max_value=50),
    excess=st.integers(min_value=0, max_value=200),
)
@settings(max_examples=100, deadline=None)
def test_property_4_syn_flood_detection_threshold(threshold, excess):
    """
    Property 4: SYN Flood Detection Threshold

    For any count >= threshold, SynFloodRule SHALL emit a ThreatEvent with
    attack_type="SYN Flood" and rule_name="SYN_FLOOD_001".

    Validates: Requirements 4.1
    """
    count = threshold + excess  # always >= threshold

    rule = SynFloodRule(threshold=threshold, window_seconds=3600)
    _feed_syn_packets(rule, count)

    event = rule.evaluate()

    assert event is not None, (
        f"Expected ThreatEvent for count={count} with threshold={threshold}"
    )
    assert event.attack_type == "SYN Flood", (
        f"Expected attack_type='SYN Flood', got '{event.attack_type}'"
    )
    assert event.rule_name == "SYN_FLOOD_001", (
        f"Expected rule_name='SYN_FLOOD_001', got '{event.rule_name}'"
    )


# ---------------------------------------------------------------------------
# Property 5: SYN Flood Severity Tiers
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 5
@given(count=st.integers(min_value=100, max_value=600))
@settings(max_examples=100, deadline=None)
def test_property_5_syn_flood_severity_tiers(count):
    """
    Property 5: SYN Flood Severity Tiers

    For any SYN flood ThreatEvent with SYN packet count C, the Detection_Engine
    SHALL assign:
      - severity "Medium"   when 100 <= C < 200
      - severity "High"     when 200 <= C < 400
      - severity "Critical" when C >= 400

    Validates: Requirements 4.2, 4.3, 4.4
    """
    rule = SynFloodRule(threshold=1, window_seconds=3600)
    _feed_syn_packets(rule, count)

    event = rule.evaluate()

    assert event is not None, f"Expected ThreatEvent for count={count}"

    if 100 <= count < 200:
        assert event.severity == "Medium", (
            f"count={count} should be Medium, got '{event.severity}'"
        )
    elif 200 <= count < 400:
        assert event.severity == "High", (
            f"count={count} should be High, got '{event.severity}'"
        )
    else:
        # count >= 400
        assert event.severity == "Critical", (
            f"count={count} should be Critical, got '{event.severity}'"
        )


# ---------------------------------------------------------------------------
# Property 6: SYN Flood Confidence Formula
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 6
@given(
    count=st.integers(min_value=1, max_value=500),
    threshold=st.integers(min_value=1, max_value=100),
)
@settings(max_examples=100, deadline=None)
def test_property_6_syn_flood_confidence_formula(count, threshold):
    """
    Property 6: SYN Flood Confidence Formula

    For any SYN flood ThreatEvent with packet count C and threshold T, the
    confidence SHALL be round(min(C/T, 2.0) / 2.0 * 100) capped at 100,
    and the result SHALL always be an integer in [0, 100].

    Validates: Requirements 4.5
    """
    expected = round(min(count / threshold, 2.0) / 2.0 * 100)
    expected = min(expected, 100)

    result = _syn_confidence(count, threshold)

    assert isinstance(result, int), f"Confidence must be int, got {type(result)}"
    assert 0 <= result <= 100, f"Confidence {result} out of [0, 100] range"
    assert result == expected, (
        f"count={count}, threshold={threshold}: expected {expected}, got {result}"
    )


# ---------------------------------------------------------------------------
# Property 7: SYN Flood Evidence Completeness
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 7
@given(count=st.integers(min_value=1, max_value=200))
@settings(max_examples=100, deadline=None)
def test_property_7_syn_flood_evidence_completeness(count):
    """
    Property 7: SYN Flood Evidence Completeness

    For any SYN flood ThreatEvent, the evidence dictionary SHALL contain all
    required keys: source_ip, syn_packet_count, time_window_seconds,
    destination_ips, and sample_timestamps.

    Validates: Requirements 4.6
    """
    rule = SynFloodRule(threshold=1, window_seconds=3600)
    _feed_syn_packets(rule, count)

    event = rule.evaluate()

    assert event is not None, f"Expected ThreatEvent for count={count}"

    evidence = event.evidence
    assert isinstance(evidence, dict), "evidence must be a dict"

    required_keys = {
        "source_ip",
        "syn_packet_count",
        "time_window_seconds",
        "destination_ips",
        "sample_timestamps",
    }
    missing = required_keys - set(evidence.keys())
    assert not missing, f"Evidence missing required keys: {missing}"


# ---------------------------------------------------------------------------
# Property 8: Port Scan Detection Threshold
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 8
@given(
    threshold=st.integers(min_value=1, max_value=50),
    extra=st.integers(min_value=0, max_value=50),
    src_ip=_ipv4,
)
@settings(max_examples=100, deadline=None)
def test_property_8_port_scan_detection_threshold(threshold, extra, src_ip):
    """
    Property 8: Port Scan Detection Threshold

    For any source IP address, when the Flow_Tracker records connection attempts
    to a unique destination port count >= the configured threshold within the
    configured sliding time window, the Detection_Engine SHALL emit a ThreatEvent
    with attack_type="Port Scan" and rule_name="PORT_SCAN_001".

    Validates: Requirements 5.1
    """
    unique_count = threshold + extra  # always >= threshold

    # Build a set of unique destination ports of size `unique_count`.
    # We cap at 1000 to avoid huge port numbers while ensuring uniqueness.
    assume(unique_count <= 1000)
    ports = list(range(1, unique_count + 1))

    rule = PortScanRule(threshold=threshold, window_seconds=3600)
    _feed_unique_ports(rule, src_ip, ports)

    event = rule.evaluate()

    assert event is not None, (
        f"Expected ThreatEvent for {unique_count} unique ports with threshold={threshold}"
    )
    assert event.attack_type == "Port Scan"
    assert event.rule_name == "PORT_SCAN_001"
    assert event.source_ip == src_ip


# ---------------------------------------------------------------------------
# Property 9: Port Scan Severity Tiers
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 9
@given(
    unique_count=st.integers(min_value=20, max_value=500),
    threshold=st.integers(min_value=1, max_value=20),
    src_ip=_ipv4,
)
@settings(max_examples=100, deadline=None)
def test_property_9_port_scan_severity_tiers(unique_count, threshold, src_ip):
    """
    Property 9: Port Scan Severity Tiers

    For any port scan ThreatEvent with unique destination port count P, the
    Detection_Engine SHALL assign:
      - severity "Medium" when 20 <= P < 40
      - severity "High"   when 40 <= P < 80
      - severity "Critical" when P >= 80

    Validates: Requirements 5.2, 5.3, 5.4
    """
    # Ensure we produce a detectable scan (unique_count >= threshold)
    assume(unique_count >= threshold)
    # Limit port range to avoid generating lists that are too large
    assume(unique_count <= 1000)

    ports = list(range(1, unique_count + 1))

    rule = PortScanRule(threshold=threshold, window_seconds=3600)
    _feed_unique_ports(rule, src_ip, ports)

    event = rule.evaluate()

    assert event is not None, (
        f"Expected ThreatEvent for unique_count={unique_count}, threshold={threshold}"
    )

    # Verify severity tier boundaries
    if 20 <= unique_count < 40:
        assert event.severity == "Medium", (
            f"unique_count={unique_count} should be Medium, got {event.severity}"
        )
    elif 40 <= unique_count < 80:
        assert event.severity == "High", (
            f"unique_count={unique_count} should be High, got {event.severity}"
        )
    else:
        # unique_count >= 80
        assert event.severity == "Critical", (
            f"unique_count={unique_count} should be Critical, got {event.severity}"
        )


# ---------------------------------------------------------------------------
# Property 10: Port Scan Confidence Formula
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 10
@given(
    unique_count=st.integers(min_value=1, max_value=500),
    threshold=st.integers(min_value=1, max_value=100),
)
@settings(max_examples=100, deadline=None)
def test_property_10_port_scan_confidence_formula(unique_count, threshold):
    """
    Property 10: Port Scan Confidence Formula

    For any port scan ThreatEvent with unique port count P and configured
    threshold T, the Detection_Engine SHALL calculate confidence as:
        round(min(P / T, 2.0) / 2.0 * 100)
    capped at 100, ensuring the result is always an integer in [0, 100].

    Validates: Requirements 5.5
    """
    # Verify the formula directly
    expected = round(min(unique_count / threshold, 2.0) / 2.0 * 100)
    expected = min(expected, 100)

    result = _scan_confidence(unique_count, threshold)

    # Must be an integer in [0, 100]
    assert isinstance(result, int), f"Confidence must be int, got {type(result)}"
    assert 0 <= result <= 100, f"Confidence {result} out of [0, 100] range"

    # Must match the formula
    assert result == expected, (
        f"unique_count={unique_count}, threshold={threshold}: "
        f"expected {expected}, got {result}"
    )


@given(
    unique_count=st.integers(min_value=1, max_value=500),
    threshold=st.integers(min_value=1, max_value=50),
    src_ip=_ipv4,
)
@settings(max_examples=100, deadline=None)
def test_property_10_confidence_in_event_is_in_range(unique_count, threshold, src_ip):
    """
    Property 10 (end-to-end): Confidence value in emitted ThreatEvent is always
    an integer in [0, 100], matching the formula.

    Validates: Requirements 5.5
    """
    assume(unique_count >= threshold)
    assume(unique_count <= 1000)

    ports = list(range(1, unique_count + 1))

    rule = PortScanRule(threshold=threshold, window_seconds=3600)
    _feed_unique_ports(rule, src_ip, ports)

    event = rule.evaluate()
    assert event is not None

    assert isinstance(event.confidence, int)
    assert 0 <= event.confidence <= 100

    expected = _scan_confidence(unique_count, threshold)
    assert event.confidence == expected


# ---------------------------------------------------------------------------
# Property 11: Port Scan Evidence Completeness
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 11
@given(
    unique_count=st.integers(min_value=20, max_value=200),
    threshold=st.integers(min_value=1, max_value=20),
    src_ip=_ipv4,
    window=st.integers(min_value=10, max_value=3600),
)
@settings(max_examples=100, deadline=None)
def test_property_11_port_scan_evidence_completeness(unique_count, threshold, src_ip, window):
    """
    Property 11: Port Scan Evidence Completeness

    For any port scan ThreatEvent, the evidence dictionary SHALL contain all
    required fields: source_ip, scanned_ports, unique_port_count,
    time_window_seconds, and confidence_score.

    Validates: Requirements 5.5
    """
    assume(unique_count >= threshold)
    assume(unique_count <= 1000)

    ports = list(range(1, unique_count + 1))

    rule = PortScanRule(threshold=threshold, window_seconds=window)
    _feed_unique_ports(rule, src_ip, ports)

    event = rule.evaluate()
    assert event is not None, (
        f"Expected ThreatEvent for unique_count={unique_count}, threshold={threshold}"
    )

    evidence = event.evidence
    assert isinstance(evidence, dict), "evidence must be a dict"

    # All five required fields must be present
    required_fields = {
        "source_ip",
        "scanned_ports",
        "unique_port_count",
        "time_window_seconds",
        "confidence_score",
    }
    missing = required_fields - set(evidence.keys())
    assert not missing, f"Evidence missing required fields: {missing}"

    # Validate field types and values
    assert evidence["source_ip"] == src_ip, (
        f"source_ip mismatch: expected {src_ip}, got {evidence['source_ip']}"
    )

    assert isinstance(evidence["scanned_ports"], list), (
        "scanned_ports must be a list"
    )
    # scanned_ports is capped at 20 entries per Requirement 5.5
    assert len(evidence["scanned_ports"]) <= 20, (
        f"scanned_ports capped at 20 entries, got {len(evidence['scanned_ports'])}"
    )
    # All entries must be integers
    assert all(isinstance(p, int) for p in evidence["scanned_ports"]), (
        "All entries in scanned_ports must be integers"
    )

    assert isinstance(evidence["unique_port_count"], int), (
        "unique_port_count must be an int"
    )
    assert evidence["unique_port_count"] == unique_count, (
        f"unique_port_count mismatch: expected {unique_count}, "
        f"got {evidence['unique_port_count']}"
    )

    assert isinstance(evidence["time_window_seconds"], int), (
        "time_window_seconds must be an int"
    )
    assert evidence["time_window_seconds"] == window, (
        f"time_window_seconds mismatch: expected {window}, "
        f"got {evidence['time_window_seconds']}"
    )

    assert isinstance(evidence["confidence_score"], int), (
        "confidence_score must be an int"
    )
    assert 0 <= evidence["confidence_score"] <= 100, (
        f"confidence_score {evidence['confidence_score']} out of [0, 100]"
    )
    assert evidence["confidence_score"] == event.confidence, (
        "confidence_score in evidence must match event.confidence"
    )
