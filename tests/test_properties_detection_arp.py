"""
test_properties_detection_arp.py — Property-based tests for ARP Spoofing detection.

Covers Properties 19–22 from the design document.

Properties tested in this file:
  Property 19: 2+ MACs for same IP → ThreatEvent with "ARP Spoofing" and "ARP_SPOOF_001"
  Property 20: Severity always "High" regardless of MAC count
  Property 21: Confidence 97 for exactly 2 MACs, 100 for ≥3 MACs
  Property 22: Evidence contains conflicting_ip, conflicting_macs,
               first_observed_timestamp, most_recent_timestamp

Requirements: 8.1–8.4
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime, timezone

from hypothesis import given, settings, strategies as st, assume

from detection.parsers.packet_decoder import Packet
from detection.rules.arp_spoof import ArpSpoofRule


# ---------------------------------------------------------------------------
# Shared strategies and helpers
# ---------------------------------------------------------------------------

def _now_ts() -> str:
    """Return current UTC time as ISO-8601 string (same format used by the rule)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Strategy for valid IPv4 addresses (fixed pool to keep tests focused)
_ipv4 = st.sampled_from([
    "10.0.0.1",
    "10.0.0.2",
    "192.168.1.1",
    "192.168.1.100",
    "172.16.0.1",
])

# Strategy for MAC address octets
_hex_octet = st.integers(min_value=0, max_value=255).map(lambda x: f"{x:02x}")

# Strategy for full MAC addresses
_mac = st.builds(
    lambda a, b, c, d, e, f: f"{a}:{b}:{c}:{d}:{e}:{f}",
    _hex_octet, _hex_octet, _hex_octet, _hex_octet, _hex_octet, _hex_octet,
)

# Strategy for lists of 2 distinct MACs (exactly 2)
_two_distinct_macs = st.lists(
    _mac, min_size=2, max_size=2, unique=True
)

# Strategy for lists of ≥3 distinct MACs
_three_or_more_distinct_macs = st.lists(
    _mac, min_size=3, max_size=5, unique=True
)


def _make_arp_packet(
    src_ip: str,
    hw_src: str,
    timestamp: str | None = None,
) -> Packet:
    """Build a minimal ARP reply packet with the given src_ip and hw_src MAC."""
    return Packet(
        src_ip=src_ip,
        dst_ip="0.0.0.0",
        src_port=None,
        dst_port=None,
        protocol="ARP",
        flags=None,
        timestamp=timestamp or _now_ts(),
        length=28,
        payload=None,
        hw_src=hw_src,
        arp_op=2,
    )


def _feed_arp_packets(rule: ArpSpoofRule, src_ip: str, macs: list[str]) -> None:
    """Feed one ARP packet per MAC address for the given IP into the rule."""
    for mac in macs:
        rule.process_packet(_make_arp_packet(src_ip, mac))


# ---------------------------------------------------------------------------
# Property 19: 2+ MACs for same IP triggers ThreatEvent
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 19
@given(
    src_ip=_ipv4,
    macs=_two_distinct_macs,
)
@settings(max_examples=100, deadline=2000)
def test_property_19_two_macs_triggers_arp_spoof_event(src_ip, macs):
    """
    Property 19: 2+ MACs for same IP → ThreatEvent with "ARP Spoofing" and "ARP_SPOOF_001"

    For any ARP traffic where two or more distinct MAC addresses claim the same
    IP address, the Detection_Engine SHALL emit a ThreatEvent with
    attack_type "ARP Spoofing" and rule_name "ARP_SPOOF_001".

    Validates: Requirements 8.1
    """
    rule = ArpSpoofRule()
    _feed_arp_packets(rule, src_ip, macs)
    event = rule.evaluate()

    assert event is not None, (
        f"Expected ThreatEvent when {len(macs)} MACs claim IP {src_ip}, but got None"
    )
    assert event.attack_type == "ARP Spoofing", (
        f"Expected attack_type='ARP Spoofing', got '{event.attack_type}'"
    )
    assert event.rule_name == "ARP_SPOOF_001", (
        f"Expected rule_name='ARP_SPOOF_001', got '{event.rule_name}'"
    )


# Feature: netguard-idps, Property 19
@given(
    src_ip=_ipv4,
    macs=_three_or_more_distinct_macs,
)
@settings(max_examples=100, deadline=2000)
def test_property_19_three_or_more_macs_triggers_arp_spoof_event(src_ip, macs):
    """
    Property 19: 3+ MACs for same IP → ThreatEvent with "ARP Spoofing" and "ARP_SPOOF_001"

    For any ARP traffic where three or more distinct MAC addresses claim the same
    IP address, the Detection_Engine SHALL emit a ThreatEvent with
    attack_type "ARP Spoofing" and rule_name "ARP_SPOOF_001".

    Validates: Requirements 8.1
    """
    rule = ArpSpoofRule()
    _feed_arp_packets(rule, src_ip, macs)
    event = rule.evaluate()

    assert event is not None, (
        f"Expected ThreatEvent when {len(macs)} MACs claim IP {src_ip}, but got None"
    )
    assert event.attack_type == "ARP Spoofing", (
        f"Expected attack_type='ARP Spoofing', got '{event.attack_type}'"
    )
    assert event.rule_name == "ARP_SPOOF_001", (
        f"Expected rule_name='ARP_SPOOF_001', got '{event.rule_name}'"
    )


# Feature: netguard-idps, Property 19
@given(
    src_ip=_ipv4,
    mac=_mac,
)
@settings(max_examples=100, deadline=2000)
def test_property_19_single_mac_no_event(src_ip, mac):
    """
    Property 19: Single MAC for an IP → no ThreatEvent

    When only one distinct MAC address is seen for an IP, no ARP spoofing
    event should be emitted.

    Validates: Requirements 8.1
    """
    rule = ArpSpoofRule()
    # Send the same MAC multiple times — still just 1 unique MAC
    for _ in range(3):
        rule.process_packet(_make_arp_packet(src_ip, mac))
    event = rule.evaluate()

    assert event is None, (
        f"Expected no ThreatEvent for single MAC {mac} on IP {src_ip}, "
        f"but got event: {event}"
    )


# ---------------------------------------------------------------------------
# Property 20: Severity always "High" regardless of MAC count
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 20
@given(
    src_ip=_ipv4,
    macs=_two_distinct_macs,
)
@settings(max_examples=100, deadline=2000)
def test_property_20_severity_high_for_exactly_two_macs(src_ip, macs):
    """
    Property 20: Severity always "High" regardless of MAC count (2 MACs)

    For any ARP spoofing ThreatEvent triggered by exactly 2 conflicting MACs,
    the Detection_Engine SHALL assign severity "High".

    Validates: Requirements 8.2
    """
    rule = ArpSpoofRule()
    _feed_arp_packets(rule, src_ip, macs)
    event = rule.evaluate()

    assert event is not None, "Expected ThreatEvent for 2 conflicting MACs"
    assert event.severity == "High", (
        f"Expected severity='High' for 2 conflicting MACs, got '{event.severity}'"
    )


# Feature: netguard-idps, Property 20
@given(
    src_ip=_ipv4,
    macs=_three_or_more_distinct_macs,
)
@settings(max_examples=100, deadline=2000)
def test_property_20_severity_high_for_three_or_more_macs(src_ip, macs):
    """
    Property 20: Severity always "High" regardless of MAC count (3+ MACs)

    For any ARP spoofing ThreatEvent triggered by 3 or more conflicting MACs,
    the Detection_Engine SHALL still assign severity "High" (not escalated).

    Validates: Requirements 8.2
    """
    rule = ArpSpoofRule()
    _feed_arp_packets(rule, src_ip, macs)
    event = rule.evaluate()

    assert event is not None, f"Expected ThreatEvent for {len(macs)} conflicting MACs"
    assert event.severity == "High", (
        f"Expected severity='High' for {len(macs)} conflicting MACs, "
        f"got '{event.severity}'"
    )


# ---------------------------------------------------------------------------
# Property 21: Confidence 97 for exactly 2 MACs, 100 for ≥3 MACs
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 21
@given(
    src_ip=_ipv4,
    macs=_two_distinct_macs,
)
@settings(max_examples=100, deadline=2000)
def test_property_21_confidence_97_for_exactly_two_macs(src_ip, macs):
    """
    Property 21: Confidence 97 for exactly 2 MACs

    For any ARP spoofing ThreatEvent triggered by exactly 2 conflicting MAC
    addresses, the Detection_Engine SHALL assign confidence score 97.

    Validates: Requirements 8.3
    """
    rule = ArpSpoofRule()
    _feed_arp_packets(rule, src_ip, macs)
    event = rule.evaluate()

    assert event is not None, "Expected ThreatEvent for exactly 2 conflicting MACs"
    assert event.confidence == 97, (
        f"Expected confidence=97 for exactly 2 conflicting MACs, "
        f"got {event.confidence}"
    )


# Feature: netguard-idps, Property 21
@given(
    src_ip=_ipv4,
    macs=_three_or_more_distinct_macs,
)
@settings(max_examples=100, deadline=2000)
def test_property_21_confidence_100_for_three_or_more_macs(src_ip, macs):
    """
    Property 21: Confidence 100 for ≥3 MACs

    For any ARP spoofing ThreatEvent triggered by 3 or more conflicting MAC
    addresses, the Detection_Engine SHALL assign confidence score 100.

    Validates: Requirements 8.3
    """
    rule = ArpSpoofRule()
    _feed_arp_packets(rule, src_ip, macs)
    event = rule.evaluate()

    assert event is not None, f"Expected ThreatEvent for {len(macs)} conflicting MACs"
    assert event.confidence == 100, (
        f"Expected confidence=100 for {len(macs)} conflicting MACs "
        f"(≥3), got {event.confidence}"
    )


# Feature: netguard-idps, Property 21
@given(
    src_ip=_ipv4,
    extra_mac=_mac,
    base_macs=_two_distinct_macs,
)
@settings(max_examples=100, deadline=2000)
def test_property_21_confidence_transitions_from_97_to_100(src_ip, extra_mac, base_macs):
    """
    Property 21: Confidence transitions from 97 to 100 when 3rd MAC arrives

    When a 3rd distinct MAC address is observed before evaluate() is called,
    the resulting event SHALL have confidence 100.

    Validates: Requirements 8.3
    """
    assume(extra_mac not in base_macs)

    rule = ArpSpoofRule()
    # Feed 2 MACs first, then a 3rd before evaluate()
    _feed_arp_packets(rule, src_ip, base_macs)
    rule.process_packet(_make_arp_packet(src_ip, extra_mac))
    event = rule.evaluate()

    assert event is not None, "Expected ThreatEvent for 3 conflicting MACs"
    assert event.confidence == 100, (
        f"Expected confidence=100 after 3rd MAC arrived, got {event.confidence}"
    )


# ---------------------------------------------------------------------------
# Property 22: Evidence contains required fields
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 22
@given(
    src_ip=_ipv4,
    macs=_two_distinct_macs,
)
@settings(max_examples=100, deadline=2000)
def test_property_22_evidence_contains_required_fields_two_macs(src_ip, macs):
    """
    Property 22: Evidence contains conflicting_ip, conflicting_macs,
                 first_observed_timestamp, most_recent_timestamp (2 MACs)

    For any ARP spoofing ThreatEvent, the evidence dictionary SHALL contain all
    four required fields: conflicting_ip, conflicting_macs,
    first_observed_timestamp, and most_recent_timestamp.

    Validates: Requirements 8.4
    """
    rule = ArpSpoofRule()
    _feed_arp_packets(rule, src_ip, macs)
    event = rule.evaluate()

    assert event is not None, "Expected ThreatEvent for 2 conflicting MACs"

    evidence = event.evidence
    assert isinstance(evidence, dict), (
        f"Expected evidence to be dict, got {type(evidence)}"
    )

    required_fields = {
        "conflicting_ip",
        "conflicting_macs",
        "first_observed_timestamp",
        "most_recent_timestamp",
    }
    missing_fields = required_fields - set(evidence.keys())
    assert not missing_fields, (
        f"Evidence missing required fields: {missing_fields}. "
        f"Present fields: {set(evidence.keys())}"
    )


# Feature: netguard-idps, Property 22
@given(
    src_ip=_ipv4,
    macs=_three_or_more_distinct_macs,
)
@settings(max_examples=100, deadline=2000)
def test_property_22_evidence_contains_required_fields_three_or_more_macs(src_ip, macs):
    """
    Property 22: Evidence contains required fields for ≥3 MACs

    For any ARP spoofing ThreatEvent triggered by 3 or more conflicting MACs,
    the evidence dictionary SHALL contain all four required fields.

    Validates: Requirements 8.4
    """
    rule = ArpSpoofRule()
    _feed_arp_packets(rule, src_ip, macs)
    event = rule.evaluate()

    assert event is not None, f"Expected ThreatEvent for {len(macs)} conflicting MACs"

    evidence = event.evidence
    required_fields = {
        "conflicting_ip",
        "conflicting_macs",
        "first_observed_timestamp",
        "most_recent_timestamp",
    }
    missing_fields = required_fields - set(evidence.keys())
    assert not missing_fields, (
        f"Evidence missing required fields: {missing_fields}. "
        f"Present fields: {set(evidence.keys())}"
    )


# Feature: netguard-idps, Property 22
@given(
    src_ip=_ipv4,
    macs=_two_distinct_macs,
)
@settings(max_examples=100, deadline=2000)
def test_property_22_evidence_field_values_are_correct(src_ip, macs):
    """
    Property 22: Evidence field values are semantically correct

    The conflicting_ip SHALL match the src_ip, conflicting_macs SHALL be a
    non-empty list containing all observed MACs, and both timestamp fields
    SHALL be non-empty ISO-8601 strings.

    Validates: Requirements 8.4
    """
    rule = ArpSpoofRule()
    _feed_arp_packets(rule, src_ip, macs)
    event = rule.evaluate()

    assert event is not None, "Expected ThreatEvent for 2 conflicting MACs"

    evidence = event.evidence

    # conflicting_ip must match the IP that had conflicting MACs
    assert evidence["conflicting_ip"] == src_ip, (
        f"Expected conflicting_ip='{src_ip}', got '{evidence['conflicting_ip']}'"
    )

    # conflicting_macs must be a non-empty list
    assert isinstance(evidence["conflicting_macs"], list), (
        f"Expected conflicting_macs to be a list, got {type(evidence['conflicting_macs'])}"
    )
    assert len(evidence["conflicting_macs"]) >= 2, (
        f"Expected at least 2 entries in conflicting_macs, "
        f"got {len(evidence['conflicting_macs'])}"
    )

    # All input MACs must be present in the evidence
    for mac in macs:
        assert mac in evidence["conflicting_macs"], (
            f"MAC '{mac}' not found in evidence conflicting_macs: "
            f"{evidence['conflicting_macs']}"
        )

    # Timestamps must be non-empty strings
    assert isinstance(evidence["first_observed_timestamp"], str), (
        f"Expected first_observed_timestamp to be str, "
        f"got {type(evidence['first_observed_timestamp'])}"
    )
    assert len(evidence["first_observed_timestamp"]) > 0, (
        "Expected non-empty first_observed_timestamp"
    )

    assert isinstance(evidence["most_recent_timestamp"], str), (
        f"Expected most_recent_timestamp to be str, "
        f"got {type(evidence['most_recent_timestamp'])}"
    )
    assert len(evidence["most_recent_timestamp"]) > 0, (
        "Expected non-empty most_recent_timestamp"
    )
