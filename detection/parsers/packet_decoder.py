"""
packet_decoder.py — Packet Decoder for NetGuard IDPS.

Converts raw Scapy packets into normalized internal Packet dataclass objects.
Every detection rule operates on the uniform Packet structure produced here.

Design guarantees:
- Returns None (never raises) on any decode failure
- Completes within 10 ms per packet
- Sets src_port / dst_port to None for non-TCP/UDP protocols
- Sets flags to None for non-TCP protocols
- Sets protocol to "UNKNOWN" for unrecognised L4 protocols
- Logs decode failures (exception class + message) to logs/errors.log

Requirements: 3.1, 3.2, 3.3, 3.4
"""



from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# Module-level logger — inherits from netguard root, used for debug/info
logger = logging.getLogger("netguard.packet_decoder")

# Dedicated error logger — wired to logs/errors.log by setup_logging() in log_service
_error_logger = logging.getLogger("netguard.errors")


# ---------------------------------------------------------------------------
# Normalised packet dataclass
# ---------------------------------------------------------------------------

@dataclass
class Packet:
    """
    Normalised internal packet object produced by PacketDecoder.

    All detection rules operate exclusively on this structure so that the
    raw Scapy layer types never leak into detection logic.
    """

    src_ip: str
    """Source IP address (IPv4 or IPv6 string)."""

    dst_ip: str
    """Destination IP address (IPv4 or IPv6 string)."""

    src_port: Optional[int]
    """Source port number, or None for non-TCP/UDP protocols."""

    dst_port: Optional[int]
    """Destination port number, or None for non-TCP/UDP protocols."""

    protocol: str
    """Protocol string: TCP | UDP | ICMP | ARP | UNKNOWN."""

    flags: Optional[str]
    """TCP flag string (e.g. 'S' for SYN), or None for non-TCP."""

    timestamp: str
    """UTC ISO-8601 timestamp of capture time."""

    length: int
    """Total packet length in bytes."""

    payload: Optional[bytes] = field(default=None, repr=False)
    """Raw payload bytes for deep inspection (e.g. SQL injection)."""

    hw_src: Optional[str] = field(default=None)
    """ARP sender hardware (MAC) address, e.g. 'aa:bb:cc:dd:ee:ff'. None for non-ARP packets."""

    arp_op: Optional[int] = field(default=None)
    """ARP opcode: 1=request, 2=reply. None for non-ARP packets."""


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

class PacketDecoder:
    """
    Converts raw Scapy packets into normalised Packet objects.

    Usage::

        decoder = PacketDecoder()
        pkt = decoder.decode(raw_scapy_packet)
        if pkt is not None:
            detection_engine.process(pkt)
    """

    def decode(self, raw_pkt) -> Optional[Packet]:
        """
        Decode a raw Scapy packet into a normalised Packet object.

        Args:
            raw_pkt: A raw Scapy packet object.

        Returns:
            A normalised Packet, or None if the packet could not be decoded.
            Never raises an exception to the caller (Requirement 3.4).
        """
        try:
            return self._decode(raw_pkt)
        except Exception as exc:  # noqa: BLE001
            # Requirement 3.4: log exception class and message to logs/errors.log
            _error_logger.warning(
                "PacketDecoder: failed to decode packet — %s: %s",
                type(exc).__name__,
                exc,
            )
            return None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _decode(self, raw_pkt) -> Optional[Packet]:
        """Internal decode — may raise; outer decode() catches all exceptions."""
        # Scapy imports deferred to avoid import overhead at module level
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.inet6 import IPv6
            from scapy.layers.l2 import ARP, Ether
        except ImportError:
            logger.error("Scapy is not installed — packet decoding unavailable.")
            return None

        # Use packet capture time if available; fall back to utcnow
        timestamp = _packet_timestamp(raw_pkt)

        # ── IP layer ──────────────────────────────────────────────────────
        src_ip: str = ""
        dst_ip: str = ""
        length: int = len(raw_pkt)

        if raw_pkt.haslayer(IP):
            ip_layer = raw_pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
        elif raw_pkt.haslayer(IPv6):
            ip6_layer = raw_pkt[IPv6]
            src_ip = ip6_layer.src
            dst_ip = ip6_layer.dst
        elif raw_pkt.haslayer(ARP):
            arp_layer = raw_pkt[ARP]
            # For ARP, use psrc/pdst as "IPs"
            src_ip = arp_layer.psrc or ""
            dst_ip = arp_layer.pdst or ""
            # Extract sender hardware (MAC) address for ARP spoof detection
            hw_src = str(arp_layer.hwsrc).lower() if arp_layer.hwsrc else None
            arp_op = int(arp_layer.op) if arp_layer.op is not None else None
            return Packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=None,
                dst_port=None,
                protocol="ARP",
                flags=None,
                timestamp=timestamp,
                length=length,
                payload=_extract_payload(raw_pkt),
                hw_src=hw_src,
                arp_op=arp_op,
            )
        else:
            # No recognisable IP layer — cannot build a meaningful Packet
            return None

        if not src_ip or not dst_ip:
            return None

        # ── Transport layer ───────────────────────────────────────────────
        if raw_pkt.haslayer(TCP):
            tcp = raw_pkt[TCP]
            return Packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=tcp.sport,
                dst_port=tcp.dport,
                protocol="TCP",
                flags=_tcp_flags_string(tcp.flags),
                timestamp=timestamp,
                length=length,
                payload=_extract_payload(tcp),
            )

        if raw_pkt.haslayer(UDP):
            udp = raw_pkt[UDP]
            return Packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=udp.sport,
                dst_port=udp.dport,
                protocol="UDP",
                flags=None,
                timestamp=timestamp,
                length=length,
                payload=_extract_payload(udp),
            )

        if raw_pkt.haslayer(ICMP):
            return Packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=None,
                dst_port=None,
                protocol="ICMP",
                flags=None,
                timestamp=timestamp,
                length=length,
                payload=None,
            )

        # Requirement 3.2: Unknown transport — still pass through with UNKNOWN label
        # and populate all available fields
        return Packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=None,
            dst_port=None,
            protocol="UNKNOWN",
            flags=None,
            timestamp=timestamp,
            length=length,
            payload=None,
        )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _tcp_flags_string(flags) -> str:
    """
    Convert a Scapy TCP flags object to a human-readable string.

    Examples: 'S' (SYN), 'SA' (SYN-ACK), 'FA' (FIN-ACK), 'R' (RST).
    Returns an empty string on unexpected error rather than raising.
    """
    try:
        return str(flags)
    except Exception:  # noqa: BLE001
        return ""


def _extract_payload(layer) -> Optional[bytes]:
    """
    Safely extract raw payload bytes from a Scapy layer.

    Tries the Raw sub-layer first (most reliable), then falls back to
    checking for a .load attribute or the layer's own .payload bytes.
    Returns None if nothing is extractable.
    """
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
    Return the packet's capture timestamp as a UTC ISO-8601 string.

    Uses pkt.time (a UNIX float set by Scapy's libpcap integration) when
    available and non-zero; otherwise falls back to the current UTC time.
    """
    try:
        t = getattr(raw_pkt, "time", None)
        if t and t > 0:
            return datetime.fromtimestamp(float(t), tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
    except Exception:  # noqa: BLE001
        pass
    return _utc_now()


def _utc_now() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
