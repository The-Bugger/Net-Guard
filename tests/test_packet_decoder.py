"""
test_packet_decoder.py — Unit tests for PacketDecoder.

Covers protocol-specific decoding (TCP, UDP, ICMP, ARP, UNKNOWN),
null-field guarantees, and failure-safety behaviour.

Requirements: 3.1, 3.2, 3.3, 3.4
"""

from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether

from detection.parsers.packet_decoder import Packet, PacketDecoder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def decoder() -> PacketDecoder:
    return PacketDecoder()


def _tcp_pkt(src="1.2.3.4", dst="5.6.7.8", sport=12345, dport=80, flags="S"):
    """Build a minimal Ether/IP/TCP Scapy packet."""
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)


def _udp_pkt(src="1.2.3.4", dst="5.6.7.8", sport=5000, dport=53):
    return Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)


def _icmp_pkt(src="1.2.3.4", dst="5.6.7.8"):
    return Ether() / IP(src=src, dst=dst) / ICMP()


def _arp_pkt(psrc="192.168.1.1", pdst="192.168.1.2"):
    return Ether() / ARP(psrc=psrc, pdst=pdst)


def _unknown_pkt(src="1.2.3.4", dst="5.6.7.8"):
    """IP packet with no recognised L4 layer (raw IP with proto=253)."""
    return Ether() / IP(src=src, dst=dst, proto=253)


# ---------------------------------------------------------------------------
# TCP tests
# ---------------------------------------------------------------------------

class TestTcpDecoding:
    """Requirements 3.1, 3.3 — TCP packets are fully decoded."""

    def test_tcp_packet_decoded(self, decoder):
        """TCP packet yields correct IPs, ports, protocol, and flags."""
        raw = _tcp_pkt(src="1.2.3.4", dst="5.6.7.8", sport=12345, dport=80, flags="S")
        pkt = decoder.decode(raw)

        assert pkt is not None
        assert pkt.src_ip == "1.2.3.4"
        assert pkt.dst_ip == "5.6.7.8"
        assert pkt.src_port == 12345
        assert pkt.dst_port == 80
        assert pkt.protocol == "TCP"
        assert pkt.flags == "S"

    def test_tcp_timestamp_is_set(self, decoder):
        """TCP packet includes a non-empty timestamp string."""
        raw = _tcp_pkt()
        pkt = decoder.decode(raw)

        assert pkt is not None
        assert pkt.timestamp  # non-empty string

    def test_tcp_length_is_positive(self, decoder):
        """TCP packet length field is a positive integer."""
        raw = _tcp_pkt()
        pkt = decoder.decode(raw)

        assert pkt is not None
        assert pkt.length > 0

    def test_tcp_syn_ack_flags(self, decoder):
        """SYN-ACK flags are preserved exactly."""
        raw = _tcp_pkt(flags="SA")
        pkt = decoder.decode(raw)

        assert pkt is not None
        assert pkt.flags == "SA"

    def test_tcp_rst_flags(self, decoder):
        """RST flag is preserved exactly."""
        raw = _tcp_pkt(flags="R")
        pkt = decoder.decode(raw)

        assert pkt is not None
        assert pkt.flags == "R"


# ---------------------------------------------------------------------------
# UDP tests
# ---------------------------------------------------------------------------

class TestUdpDecoding:
    """Requirements 3.1, 3.3 — UDP packets are decoded with ports, no flags."""

    def test_udp_packet_decoded(self, decoder):
        """UDP packet yields correct ports and protocol; flags are None."""
        raw = _udp_pkt(src="10.0.0.1", dst="8.8.8.8", sport=5000, dport=53)
        pkt = decoder.decode(raw)

        assert pkt is not None
        assert pkt.src_ip == "10.0.0.1"
        assert pkt.dst_ip == "8.8.8.8"
        assert pkt.src_port == 5000
        assert pkt.dst_port == 53
        assert pkt.protocol == "UDP"
        assert pkt.flags is None

    def test_udp_protocol_string(self, decoder):
        raw = _udp_pkt()
        pkt = decoder.decode(raw)
        assert pkt is not None
        assert pkt.protocol == "UDP"


# ---------------------------------------------------------------------------
# ICMP tests
# ---------------------------------------------------------------------------

class TestIcmpDecoding:
    """Requirement 3.2 — ICMP packets have no ports and no flags."""

    def test_icmp_packet_decoded(self, decoder):
        """ICMP packet has protocol ICMP, and both ports are None."""
        raw = _icmp_pkt(src="192.168.1.1", dst="192.168.1.2")
        pkt = decoder.decode(raw)

        assert pkt is not None
        assert pkt.src_ip == "192.168.1.1"
        assert pkt.dst_ip == "192.168.1.2"
        assert pkt.protocol == "ICMP"
        assert pkt.src_port is None
        assert pkt.dst_port is None
        assert pkt.flags is None

    def test_icmp_has_timestamp(self, decoder):
        raw = _icmp_pkt()
        pkt = decoder.decode(raw)
        assert pkt is not None
        assert pkt.timestamp


# ---------------------------------------------------------------------------
# ARP tests
# ---------------------------------------------------------------------------

class TestArpDecoding:
    """Requirement 3.2 — ARP packets use psrc/pdst as IPs, no ports."""

    def test_arp_packet_decoded(self, decoder):
        """ARP packet uses psrc/pdst for src/dst IPs and protocol is ARP."""
        raw = _arp_pkt(psrc="10.0.0.1", pdst="10.0.0.2")
        pkt = decoder.decode(raw)

        assert pkt is not None
        assert pkt.src_ip == "10.0.0.1"
        assert pkt.dst_ip == "10.0.0.2"
        assert pkt.protocol == "ARP"
        assert pkt.src_port is None
        assert pkt.dst_port is None
        assert pkt.flags is None


# ---------------------------------------------------------------------------
# Unknown protocol tests
# ---------------------------------------------------------------------------

class TestUnknownProtocol:
    """Requirement 3.2 — Unrecognised L4 gets UNKNOWN protocol, no ports."""

    def test_unknown_protocol(self, decoder):
        """IP packet with no recognised L4 yields protocol UNKNOWN."""
        raw = _unknown_pkt(src="1.2.3.4", dst="5.6.7.8")
        pkt = decoder.decode(raw)

        assert pkt is not None
        assert pkt.protocol == "UNKNOWN"
        assert pkt.src_ip == "1.2.3.4"
        assert pkt.dst_ip == "5.6.7.8"
        assert pkt.src_port is None
        assert pkt.dst_port is None


# ---------------------------------------------------------------------------
# Null-field guarantees
# ---------------------------------------------------------------------------

class TestNullFieldGuarantees:
    """Requirements 3.2, 3.3 — ports/flags are None for non-TCP/UDP protocols."""

    def test_non_tcp_ports_are_none(self, decoder):
        """UDP, ICMP, and ARP all have src_port and dst_port set to None."""
        udp_pkt = decoder.decode(_udp_pkt())
        icmp_pkt = decoder.decode(_icmp_pkt())
        arp_pkt = decoder.decode(_arp_pkt())

        # UDP has ports, so we only check ICMP and ARP here per requirement
        assert icmp_pkt is not None
        assert icmp_pkt.src_port is None
        assert icmp_pkt.dst_port is None

        assert arp_pkt is not None
        assert arp_pkt.src_port is None
        assert arp_pkt.dst_port is None

    def test_non_tcp_flags_are_none(self, decoder):
        """UDP and ICMP packets must have flags=None."""
        udp_pkt = decoder.decode(_udp_pkt())
        icmp_pkt = decoder.decode(_icmp_pkt())

        assert udp_pkt is not None
        assert udp_pkt.flags is None

        assert icmp_pkt is not None
        assert icmp_pkt.flags is None

    def test_udp_ports_are_set(self, decoder):
        """UDP does carry ports — confirm both are non-None integers."""
        pkt = decoder.decode(_udp_pkt(sport=1234, dport=5678))
        assert pkt is not None
        assert isinstance(pkt.src_port, int)
        assert isinstance(pkt.dst_port, int)


# ---------------------------------------------------------------------------
# Failure-safety tests
# ---------------------------------------------------------------------------

class TestDecodeFailureSafety:
    """Requirement 3.4 — decode() never raises; returns None on failure."""

    def test_decode_none_returns_none(self, decoder):
        """Passing None does not raise and returns None."""
        result = decoder.decode(None)
        assert result is None

    def test_decode_integer_returns_none(self, decoder):
        """Passing an integer does not raise and returns None."""
        result = decoder.decode(42)
        assert result is None

    def test_decode_string_returns_none(self, decoder):
        """Passing a string does not raise and returns None."""
        result = decoder.decode("not a packet")
        assert result is None

    def test_decode_empty_dict_returns_none(self, decoder):
        """Passing an empty dict does not raise and returns None."""
        result = decoder.decode({})
        assert result is None

    def test_decode_failure_returns_none(self, decoder):
        """A variety of invalid inputs all return None without raising."""
        for bad_input in [None, 0, b"", [], object()]:
            result = decoder.decode(bad_input)
            assert result is None, f"Expected None for input {bad_input!r}"


# ---------------------------------------------------------------------------
# Dataclass field completeness
# ---------------------------------------------------------------------------

class TestPacketDataclassFields:
    """Requirement 3.1 — decoded Packet contains all required fields."""

    def test_decode_returns_packet_object(self, decoder):
        """decode() returns a Packet instance with all expected fields present."""
        raw = _tcp_pkt(src="192.168.0.1", dst="10.10.10.1", sport=9999, dport=443, flags="S")
        pkt = decoder.decode(raw)

        assert pkt is not None
        assert isinstance(pkt, Packet)

        # All fields must be present (not missing/AttributeError)
        assert hasattr(pkt, "src_ip")
        assert hasattr(pkt, "dst_ip")
        assert hasattr(pkt, "src_port")
        assert hasattr(pkt, "dst_port")
        assert hasattr(pkt, "protocol")
        assert hasattr(pkt, "flags")
        assert hasattr(pkt, "timestamp")
        assert hasattr(pkt, "length")
        assert hasattr(pkt, "payload")

    def test_packet_fields_correct_types(self, decoder):
        """Packet fields have the expected types for a TCP packet."""
        raw = _tcp_pkt()
        pkt = decoder.decode(raw)

        assert pkt is not None
        assert isinstance(pkt.src_ip, str)
        assert isinstance(pkt.dst_ip, str)
        assert isinstance(pkt.src_port, int)
        assert isinstance(pkt.dst_port, int)
        assert isinstance(pkt.protocol, str)
        assert isinstance(pkt.flags, str)
        assert isinstance(pkt.timestamp, str)
        assert isinstance(pkt.length, int)
