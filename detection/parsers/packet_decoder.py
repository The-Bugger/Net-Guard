"""Packet decoder — converts raw Scapy packets into normalised Packet dataclass objects."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("netguard.packet_decoder")
_error_logger = logging.getLogger("netguard.errors")


@dataclass
class Packet:
    """
    Normalised internal packet object produced by PacketDecoder.

    All detection rules operate on this structure; raw Scapy types never
    leak into detection logic.
    """
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str          # TCP | UDP | ICMP | ARP | UNKNOWN
    flags: Optional[str]   # TCP flags string, e.g. 'S', 'SA'; None for non-TCP
    timestamp: str         # UTC ISO-8601
    length: int
    payload: Optional[bytes] = field(default=None, repr=False)
    hw_src: Optional[str] = field(default=None)    # ARP sender MAC; None for non-ARP
    arp_op: Optional[int] = field(default=None)    # ARP opcode: 1=request, 2=reply
    icmp_type: Optional[int] = field(default=None) # ICMP type; None for non-ICMP


class PacketDecoder:
    """Converts raw Scapy packets into normalised Packet objects."""

    def decode(self, raw_pkt) -> Optional[Packet]:
        """Return a normalised Packet, or None on failure. Never raises."""
        try:
            return self._decode(raw_pkt)
        except Exception as exc:  # noqa: BLE001
            _error_logger.warning("PacketDecoder: failed to decode packet — %s: %s", type(exc).__name__, exc)
            return None

    def _decode(self, raw_pkt) -> Optional[Packet]:
        """Internal decode — may raise; outer decode() catches all exceptions."""
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.inet6 import IPv6
            from scapy.layers.l2 import ARP, Ether
        except ImportError:
            logger.error("Scapy is not installed — packet decoding unavailable.")
            return None

        timestamp = _packet_timestamp(raw_pkt)
        src_ip: str = ""
        dst_ip: str = ""
        length: int = len(raw_pkt)

        if raw_pkt.haslayer(IP):
            ip_layer = raw_pkt[IP]
            src_ip, dst_ip = ip_layer.src, ip_layer.dst
        elif raw_pkt.haslayer(IPv6):
            ip6_layer = raw_pkt[IPv6]
            src_ip, dst_ip = ip6_layer.src, ip6_layer.dst
        elif raw_pkt.haslayer(ARP):
            arp_layer = raw_pkt[ARP]
            src_ip = arp_layer.psrc or ""
            dst_ip = arp_layer.pdst or ""
            hw_src = str(arp_layer.hwsrc).lower() if arp_layer.hwsrc else None
            arp_op = int(arp_layer.op) if arp_layer.op is not None else None
            return Packet(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=None, dst_port=None,
                protocol="ARP", flags=None,
                timestamp=timestamp, length=length,
                payload=_extract_payload(raw_pkt),
                hw_src=hw_src, arp_op=arp_op,
            )
        else:
            return None

        if not src_ip or not dst_ip:
            return None

        if raw_pkt.haslayer(TCP):
            tcp = raw_pkt[TCP]
            return Packet(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=tcp.sport, dst_port=tcp.dport,
                protocol="TCP", flags=_tcp_flags_string(tcp.flags),
                timestamp=timestamp, length=length,
                payload=_extract_payload(tcp),
            )

        if raw_pkt.haslayer(UDP):
            udp = raw_pkt[UDP]
            return Packet(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=udp.sport, dst_port=udp.dport,
                protocol="UDP", flags=None,
                timestamp=timestamp, length=length,
                payload=_extract_payload(udp),
            )

        if raw_pkt.haslayer(ICMP):
            return Packet(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=None, dst_port=None,
                protocol="ICMP", flags=None,
                timestamp=timestamp, length=length,
                payload=None,
                icmp_type=int(raw_pkt[ICMP].type) if raw_pkt.haslayer(ICMP) else None,
            )

        return Packet(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=None, dst_port=None,
            protocol="UNKNOWN", flags=None,
            timestamp=timestamp, length=length,
            payload=None,
        )


def _tcp_flags_string(flags) -> str:
    """Convert Scapy TCP flags to a string (e.g. 'S', 'SA'). Returns '' on error."""
    try:
        return str(flags)
    except Exception:  # noqa: BLE001
        return ""


def _extract_payload(layer) -> Optional[bytes]:
    """Safely extract raw payload bytes from a Scapy layer. Returns None if unavailable."""
    try:
        from scapy.packet import Raw
        if layer.haslayer(Raw):
            return bytes(layer[Raw].load)
        if hasattr(layer, "load"):
            return bytes(layer.load)
        return bytes(layer.payload) if layer.payload else None
    except Exception:  # noqa: BLE001
        return None


def _packet_timestamp(raw_pkt) -> str:
    """
    Return the packet's capture timestamp as UTC ISO-8601.

    Uses pkt.time (UNIX float set by libpcap) when available; falls back to now.
    """
    try:
        t = getattr(raw_pkt, "time", None)
        if t and t > 0:
            return datetime.fromtimestamp(float(t), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:  # noqa: BLE001
        pass
    return _utc_now()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
