"""
detection/parsers/__init__.py

Exports the canonical Packet dataclass and PacketDecoder used across the
entire detection pipeline.  Import from here rather than from the submodule
directly to keep the public API stable.
"""

from detection.parsers.packet_decoder import Packet, PacketDecoder

__all__ = ["Packet", "PacketDecoder"]
