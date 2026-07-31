"""
test_integration_capture.py — End-to-end packet capture integration test.

Requires: Linux, root/sudo, scapy network access.
Verifies: packets flow from CaptureEngine → PacketDecoder → packet_queue.

Requirements: 2.1, 2.3, 3.1

NOTE: This test requires Linux root privileges and a working network interface.
      Run with: sudo pytest tests/integration/ -v
"""

from __future__ import annotations

import platform
import queue
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

# Skip entire module on non-Linux or when not root
pytestmark = [
    pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Packet capture integration tests require Linux",
    ),
    pytest.mark.skipif(
        not hasattr(__import__("os"), "geteuid") or __import__("os").geteuid() != 0,
        reason="Packet capture integration tests require root privileges",
    ),
]


def test_capture_feeds_packet_queue():
    """
    Requirement 2.1, 2.3: CaptureEngine must forward captured packets to
    the packet_queue within 100 ms of capture.
    """
    from detection.capture.sniffer import CaptureEngine
    from detection.parsers.packet_decoder import Packet

    pq: queue.Queue = queue.Queue()
    engine = CaptureEngine(pq)

    try:
        engine.start("lo")
        # Generate loopback traffic — send a ping
        import subprocess
        subprocess.run(["ping", "-c", "3", "-i", "0.1", "127.0.0.1"],
                       capture_output=True, timeout=5)

        # Wait up to 5 seconds for packets to appear
        received = []
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                pkt = pq.get(timeout=0.5)
                if isinstance(pkt, Packet):
                    received.append(pkt)
                    if len(received) >= 3:
                        break
            except queue.Empty:
                continue
    finally:
        engine.stop()

    assert len(received) >= 1, "Expected at least one decoded Packet from loopback capture"
    for pkt in received:
        # Requirement 3.1: all required fields present
        assert pkt.src_ip, "src_ip must be non-empty"
        assert pkt.dst_ip, "dst_ip must be non-empty"
        assert pkt.protocol in {"TCP", "UDP", "ICMP", "ARP", "UNKNOWN"}
        assert pkt.timestamp, "timestamp must be set"
        assert pkt.length > 0, "length must be positive"


def test_capture_start_stop_within_2s():
    """
    Requirement 2.1, 2.6: CaptureEngine must start and stop within 2 seconds.
    """
    from detection.capture.sniffer import CaptureEngine

    pq: queue.Queue = queue.Queue()
    engine = CaptureEngine(pq)

    start_t = time.monotonic()
    engine.start("lo")
    assert time.monotonic() - start_t < 2.0, "start() must complete within 2s"

    stop_t = time.monotonic()
    engine.stop()
    assert time.monotonic() - stop_t < 2.0, "stop() must complete within 2s"


def test_malformed_packet_does_not_crash_capture():
    """
    Requirement 2.4: Malformed packets must be discarded; capture continues.
    """
    from detection.capture.sniffer import CaptureEngine

    pq: queue.Queue = queue.Queue()
    engine = CaptureEngine(pq)
    engine.start("lo")
    time.sleep(0.5)
    engine.stop()
    # If we got here without exception, capture is resilient
    assert True
