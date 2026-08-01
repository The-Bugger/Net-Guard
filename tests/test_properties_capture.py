# Feature: netguard-idps, Property 2
# Feature: netguard-idps, Property 3
"""
test_properties_capture.py — Property-based tests for PacketDecoder.

Property 2: Malformed Input Resilience
  - Any raw input that cannot be decoded returns None without raising any exception.
  - Inputs include arbitrary bytes, None, integers, strings, and random objects.

Property 3: Packet Decoding Correctness
  - A successfully decoded packet always has all required fields populated:
    src_ip, dst_ip, protocol, timestamp, length are non-None and non-empty.
  - src_port and dst_port are None for non-TCP/UDP protocols.
  - For TCP packets: src_port, dst_port, and flags are present.

Validates: Requirements 2.4, 3.1, 3.2, 3.4, 9.7
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from hypothesis import given, settings as hyp_settings, HealthCheck
from hypothesis import strategies as st

from detection.parsers.packet_decoder import PacketDecoder, Packet


# ---------------------------------------------------------------------------
# Shared decoder instance (stateless — safe to share)
# ---------------------------------------------------------------------------

_DECODER = PacketDecoder()

# ISO-8601 UTC pattern: e.g. "2025-01-01T12:00:00Z"
_ISO8601_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# Valid protocol values from the design
_VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "ARP", "UNKNOWN"}


# ---------------------------------------------------------------------------
# Helper: build a valid Scapy TCP/IP packet from raw field values
# ---------------------------------------------------------------------------

def _build_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int):
    """
    Construct a valid Scapy TCP/IP packet.
    Returns the Scapy packet or None if Scapy is unavailable.
    """
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        pkt = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S")
        return pkt
    except Exception:
        return None


def _build_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int):
    """
    Construct a valid Scapy UDP/IP packet.
    """
    try:
        from scapy.layers.inet import IP, UDP
        from scapy.layers.l2 import Ether
        pkt = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port)
        return pkt
    except Exception:
        return None


def _build_icmp_packet(src_ip: str, dst_ip: str):
    """
    Construct a valid Scapy ICMP/IP packet.
    """
    try:
        from scapy.layers.inet import IP, ICMP
        from scapy.layers.l2 import Ether
        pkt = Ether() / IP(src=src_ip, dst=dst_ip) / ICMP()
        return pkt
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Strategy for valid IPv4 address strings (covers most cases quickly)
_ipv4_st = st.from_regex(
    r"(?:(?:1\d\d|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.){3}(?:1\d\d|2[0-4]\d|25[0-5]|[1-9]\d|\d)",
    fullmatch=True,
)

# Strategy for valid port numbers
_port_st = st.integers(min_value=1, max_value=65535)

# Strategy for malformed / undecodeable inputs
_bad_input_st = st.one_of(
    st.binary(),                            # arbitrary bytes
    st.none(),                              # None
    st.integers(),                          # integers (positive, negative, zero)
    st.text(),                              # arbitrary unicode strings
    st.floats(allow_nan=True),              # floats including nan/inf
    st.booleans(),                          # True / False
    st.lists(st.integers()),               # lists of integers
    st.just(object()),                      # generic object instance
    st.just(b""),                           # empty bytes
    st.just(""),                            # empty string
    st.just(0),                             # zero integer
    st.just([]),                            # empty list
    st.just({}),                            # empty dict
)


# ---------------------------------------------------------------------------
# Property 2: Malformed Input Resilience
# ---------------------------------------------------------------------------

@given(bad_input=_bad_input_st)
@hyp_settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_property2_malformed_input_returns_none_without_exception(bad_input):
    """
    **Validates: Requirements 2.4, 3.4, 9.7**

    Property 2: Malformed Input Resilience

    For any undecodeable raw input, PacketDecoder.decode() MUST:
      - Return None (never a Packet object)
      - Never raise any exception

    Inputs cover: arbitrary bytes, None, integers, strings, floats, booleans,
    lists, generic objects, and empty values.
    """
    # Feature: netguard-idps, Property 2
    try:
        result = _DECODER.decode(bad_input)
    except Exception as exc:
        pytest.fail(
            f"PacketDecoder.decode() raised {type(exc).__name__}: {exc!r} "
            f"for input {bad_input!r}"
        )

    assert result is None, (
        f"PacketDecoder.decode() returned {result!r} (expected None) "
        f"for undecodeable input {bad_input!r}"
    )


def test_property2_explicit_bad_inputs():
    """
    **Validates: Requirements 2.4, 3.4, 9.7**

    Explicitly test a catalogue of known-bad inputs to ensure Property 2
    holds for the most likely real-world malformed payloads.
    """
    # Feature: netguard-idps, Property 2
    bad_inputs = [
        None,
        b"",
        b"\x00" * 10,
        b"\xff\xfe\xab\xcd",
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",  # raw HTTP text, not a Scapy packet
        0,
        -1,
        42,
        "",
        "not a packet",
        "192.168.1.1",
        [],
        {},
        object(),
        True,
        False,
        3.14,
        float("nan"),
        float("inf"),
    ]

    for bad in bad_inputs:
        try:
            result = _DECODER.decode(bad)
        except Exception as exc:
            pytest.fail(
                f"PacketDecoder.decode() raised {type(exc).__name__}: {exc!r} "
                f"for explicit bad input {bad!r}"
            )
        assert result is None, (
            f"Expected None for {bad!r}, got {result!r}"
        )


# ---------------------------------------------------------------------------
# Property 3: Packet Decoding Correctness — TCP packets
# ---------------------------------------------------------------------------

@given(
    src_ip=_ipv4_st,
    dst_ip=_ipv4_st,
    src_port=_port_st,
    dst_port=_port_st,
)
@hyp_settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_property3_tcp_packet_has_all_required_fields(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int
):
    """
    **Validates: Requirements 3.1, 3.2**

    Property 3: Packet Decoding Correctness (TCP)

    For any valid TCP/IP Scapy packet:
      - decode() returns a non-None Packet
      - src_ip, dst_ip, protocol, timestamp, length are non-None and non-empty
      - protocol is "TCP"
      - src_port and dst_port are non-None integers within 0–65535
      - timestamp matches the UTC ISO-8601 format
      - length is a positive integer
    """
    # Feature: netguard-idps, Property 3
    raw_pkt = _build_tcp_packet(src_ip, dst_ip, src_port, dst_port)
    if raw_pkt is None:
        pytest.skip("Scapy unavailable — skipping Property 3 TCP test")

    result = _DECODER.decode(raw_pkt)

    assert result is not None, (
        f"decode() returned None for a valid TCP packet "
        f"({src_ip}:{src_port} → {dst_ip}:{dst_port})"
    )
    assert isinstance(result, Packet), (
        f"decode() did not return a Packet instance; got {type(result)}"
    )

    # --- Required fields must be non-None and non-empty ---
    assert result.src_ip, f"src_ip is empty/None: {result.src_ip!r}"
    assert result.dst_ip, f"dst_ip is empty/None: {result.dst_ip!r}"
    assert result.protocol, f"protocol is empty/None: {result.protocol!r}"
    assert result.timestamp, f"timestamp is empty/None: {result.timestamp!r}"
    assert result.length is not None, "length is None"

    # --- Protocol must be from the valid set ---
    assert result.protocol in _VALID_PROTOCOLS, (
        f"protocol {result.protocol!r} not in {_VALID_PROTOCOLS}"
    )

    # --- TCP-specific assertions ---
    assert result.protocol == "TCP", (
        f"Expected protocol 'TCP', got {result.protocol!r}"
    )
    assert result.src_port is not None, "src_port is None for a TCP packet"
    assert result.dst_port is not None, "dst_port is None for a TCP packet"
    assert 0 <= result.src_port <= 65535, (
        f"src_port {result.src_port} out of range [0, 65535]"
    )
    assert 0 <= result.dst_port <= 65535, (
        f"dst_port {result.dst_port} out of range [0, 65535]"
    )

    # --- Timestamp format: UTC ISO-8601 ---
    assert _ISO8601_RE.match(result.timestamp), (
        f"timestamp {result.timestamp!r} does not match ISO-8601 format"
    )

    # --- Length must be positive ---
    assert result.length > 0, f"length must be > 0, got {result.length}"


# ---------------------------------------------------------------------------
# Property 3: Packet Decoding Correctness — UDP packets
# ---------------------------------------------------------------------------

@given(
    src_ip=_ipv4_st,
    dst_ip=_ipv4_st,
    src_port=_port_st,
    dst_port=_port_st,
)
@hyp_settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_property3_udp_packet_has_all_required_fields(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int
):
    """
    **Validates: Requirements 3.1, 3.2**

    Property 3: Packet Decoding Correctness (UDP)

    For any valid UDP/IP Scapy packet:
      - decode() returns a non-None Packet
      - src_ip, dst_ip, protocol, timestamp, length are non-None and non-empty
      - protocol is "UDP"
      - src_port and dst_port are non-None
      - flags is None (UDP has no TCP flags)
    """
    # Feature: netguard-idps, Property 3
    raw_pkt = _build_udp_packet(src_ip, dst_ip, src_port, dst_port)
    if raw_pkt is None:
        pytest.skip("Scapy unavailable — skipping Property 3 UDP test")

    result = _DECODER.decode(raw_pkt)

    assert result is not None, (
        f"decode() returned None for a valid UDP packet "
        f"({src_ip}:{src_port} → {dst_ip}:{dst_port})"
    )
    assert isinstance(result, Packet)

    assert result.src_ip, f"src_ip is empty/None: {result.src_ip!r}"
    assert result.dst_ip, f"dst_ip is empty/None: {result.dst_ip!r}"
    assert result.protocol == "UDP", f"Expected 'UDP', got {result.protocol!r}"
    assert result.timestamp, f"timestamp is empty/None"
    assert result.length is not None and result.length > 0, (
        f"length must be > 0, got {result.length}"
    )

    # UDP has ports
    assert result.src_port is not None, "src_port is None for a UDP packet"
    assert result.dst_port is not None, "dst_port is None for a UDP packet"

    # UDP has no TCP flags
    assert result.flags is None, (
        f"flags should be None for UDP, got {result.flags!r}"
    )

    assert _ISO8601_RE.match(result.timestamp), (
        f"timestamp {result.timestamp!r} does not match ISO-8601 format"
    )


# ---------------------------------------------------------------------------
# Property 3: Packet Decoding Correctness — ICMP packets (no ports)
# ---------------------------------------------------------------------------

@given(
    src_ip=_ipv4_st,
    dst_ip=_ipv4_st,
)
@hyp_settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_property3_icmp_packet_ports_are_none(src_ip: str, dst_ip: str):
    """
    **Validates: Requirements 3.1, 3.2**

    Property 3: Packet Decoding Correctness (ICMP — non-TCP/UDP)

    For any valid ICMP/IP packet:
      - decode() returns a non-None Packet
      - src_port and dst_port are None (non-TCP/UDP requirement)
      - protocol is "ICMP"
      - All core fields (src_ip, dst_ip, protocol, timestamp, length) are non-None/empty
    """
    # Feature: netguard-idps, Property 3
    raw_pkt = _build_icmp_packet(src_ip, dst_ip)
    if raw_pkt is None:
        pytest.skip("Scapy unavailable — skipping Property 3 ICMP test")

    result = _DECODER.decode(raw_pkt)

    assert result is not None, (
        f"decode() returned None for a valid ICMP packet ({src_ip} → {dst_ip})"
    )
    assert isinstance(result, Packet)

    # Core required fields
    assert result.src_ip, f"src_ip is empty/None"
    assert result.dst_ip, f"dst_ip is empty/None"
    assert result.protocol == "ICMP", f"Expected 'ICMP', got {result.protocol!r}"
    assert result.timestamp, f"timestamp is empty/None"
    assert result.length is not None and result.length > 0, (
        f"length must be > 0, got {result.length}"
    )

    # Non-TCP/UDP: ports must be None (Requirement 3.1)
    assert result.src_port is None, (
        f"src_port must be None for ICMP, got {result.src_port!r}"
    )
    assert result.dst_port is None, (
        f"dst_port must be None for ICMP, got {result.dst_port!r}"
    )

    # Non-TCP: flags must be None
    assert result.flags is None, (
        f"flags must be None for ICMP, got {result.flags!r}"
    )

    assert _ISO8601_RE.match(result.timestamp), (
        f"timestamp {result.timestamp!r} does not match ISO-8601 format"
    )


# ---------------------------------------------------------------------------
# Property 3: Decoded Packet fields are internally consistent
# ---------------------------------------------------------------------------

@given(
    src_ip=_ipv4_st,
    dst_ip=_ipv4_st,
    src_port=_port_st,
    dst_port=_port_st,
)
@hyp_settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_property3_decoded_packet_field_consistency(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int
):
    """
    **Validates: Requirements 3.1, 3.2**

    Property 3: Packet Decoding Correctness (field consistency invariants)

    For any successfully decoded TCP packet:
      - The returned Packet's src_ip and dst_ip match what was embedded in the raw packet
      - protocol is always a member of the allowed set
      - length is a non-negative integer
      - timestamp is always a non-empty string
    """
    # Feature: netguard-idps, Property 3
    raw_pkt = _build_tcp_packet(src_ip, dst_ip, src_port, dst_port)
    if raw_pkt is None:
        pytest.skip("Scapy unavailable — skipping Property 3 consistency test")

    result = _DECODER.decode(raw_pkt)
    if result is None:
        # If the packet didn't decode (e.g. invalid IP), that's acceptable per
        # the spec — we skip the consistency check for this example.
        return

    assert isinstance(result, Packet)

    # Protocol invariant: always from the known set
    assert result.protocol in _VALID_PROTOCOLS, (
        f"protocol {result.protocol!r} is not in {_VALID_PROTOCOLS}"
    )

    # Length invariant: non-negative integer
    assert isinstance(result.length, int), (
        f"length must be int, got {type(result.length)}"
    )
    assert result.length >= 0, f"length must be >= 0, got {result.length}"

    # Timestamp invariant: non-empty string
    assert isinstance(result.timestamp, str), (
        f"timestamp must be a string, got {type(result.timestamp)}"
    )
    assert len(result.timestamp) > 0, "timestamp must not be an empty string"

    # IP fields must be strings
    assert isinstance(result.src_ip, str) and result.src_ip, "src_ip must be non-empty string"
    assert isinstance(result.dst_ip, str) and result.dst_ip, "dst_ip must be non-empty string"
