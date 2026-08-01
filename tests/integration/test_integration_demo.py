"""
test_integration_demo.py — Attack demo → detection integration test.

Requires: Linux, root/sudo, scapy, hping3/nmap/hydra/arpspoof.
Verifies: Each attack type triggers a ThreatEvent within a timeout window.

Requirements: Detection requirements 4–8 (SYN Flood, Port Scan, SQL Injection,
              Brute Force, ARP Spoofing)

NOTE: Run with: sudo pytest tests/integration/ -v
      Some tests require external tools (hping3, nmap, hydra, arpspoof).
"""

from __future__ import annotations

import platform
import queue
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

pytestmark = [
    pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Demo integration tests require Linux",
    ),
    pytest.mark.skipif(
        __import__("os").geteuid() != 0,
        reason="Demo integration tests require root privileges",
    ),
]

DETECTION_TIMEOUT = 15  # seconds to wait for a ThreatEvent


def _tool_available(name: str) -> bool:
    """Check if an external tool is available in PATH."""
    result = subprocess.run(["which", name], capture_output=True)
    return result.returncode == 0


def _make_detection_engine(pq: queue.Queue, collected: list):
    """Build a minimal DetectionEngine wired to collect events."""
    from backend.services.detection_service import DetectionEngine

    def on_event(event):
        collected.append(event)

    engine = DetectionEngine(
        packet_queue=pq,
        on_event=on_event,
    )
    return engine


def _make_capture_engine(pq: queue.Queue):
    from detection.capture.sniffer import CaptureEngine
    return CaptureEngine(pq)


@pytest.mark.skipif(not _tool_available("hping3"), reason="hping3 not available")
def test_syn_flood_detected():
    """
    Requirement 4.1: SYN flood attack triggers SYN_FLOOD_001 detection.
    """
    pq: queue.Queue = queue.Queue()
    collected = []

    capture = _make_capture_engine(pq)
    engine = _make_detection_engine(pq, collected)

    capture.start("lo")
    engine.start()

    try:
        subprocess.Popen(
            ["hping3", "-S", "--flood", "-p", "80", "-c", "500", "127.0.0.1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + DETECTION_TIMEOUT
        while time.monotonic() < deadline:
            syn_events = [e for e in collected if e.attack_type == "SYN Flood"]
            if syn_events:
                break
            time.sleep(0.5)
    finally:
        engine.stop()
        capture.stop()

    syn_events = [e for e in collected if e.attack_type == "SYN Flood"]
    assert syn_events, "SYN Flood attack must trigger SYN_FLOOD_001 detection"
    assert syn_events[0].rule_name == "SYN_FLOOD_001"


@pytest.mark.skipif(not _tool_available("nmap"), reason="nmap not available")
def test_port_scan_detected():
    """
    Requirement 5.1: Port scan triggers PORT_SCAN_001 detection.
    """
    pq: queue.Queue = queue.Queue()
    collected = []

    capture = _make_capture_engine(pq)
    engine = _make_detection_engine(pq, collected)

    capture.start("lo")
    engine.start()

    try:
        subprocess.Popen(
            ["nmap", "-sS", "-p", "1-200", "--min-rate", "500", "127.0.0.1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + DETECTION_TIMEOUT
        while time.monotonic() < deadline:
            scan_events = [e for e in collected if e.attack_type == "Port Scan"]
            if scan_events:
                break
            time.sleep(0.5)
    finally:
        engine.stop()
        capture.stop()

    scan_events = [e for e in collected if e.attack_type == "Port Scan"]
    assert scan_events, "Port scan must trigger PORT_SCAN_001 detection"


def test_sql_injection_detected():
    """
    Requirement 6.1: SQL injection payload in HTTP traffic triggers SQL_INJECTION_001.
    Uses scapy to craft packets directly — no external tool required.
    """
    from detection.rules.sql_injection import SqlInjectionRule
    from detection.parsers.packet_decoder import Packet
    from datetime import datetime, timezone

    rule = SqlInjectionRule()
    rule.initialize()

    payload = b"GET /search?q=UNION SELECT 1,2,3 HTTP/1.1\r\nHost: localhost\r\n\r\n"
    pkt = Packet(
        src_ip="10.0.0.1",
        dst_ip="127.0.0.1",
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        flags="PA",
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        length=len(payload) + 54,
        payload=payload,
        hw_src=None,
    )

    rule.process_packet(pkt)
    event = rule.evaluate()

    assert event is not None, "SQL injection payload must trigger SQL_INJECTION_001"
    assert event.attack_type == "SQL Injection"
    assert event.rule_name == "SQL_INJECTION_001"
    assert event.confidence == 100


def test_arp_spoofing_detected():
    """
    Requirement 8.1: Conflicting ARP MACs trigger ARP_SPOOF_001 detection.
    Uses the rule directly (no external tool required for this test).
    """
    from detection.rules.arp_spoof import ArpSpoofRule
    from detection.parsers.packet_decoder import Packet
    from datetime import datetime, timezone

    rule = ArpSpoofRule()
    rule.initialize()

    def _arp_pkt(mac: str) -> Packet:
        return Packet(
            src_ip="192.168.1.1",
            dst_ip="0.0.0.0",
            src_port=None,
            dst_port=None,
            protocol="ARP",
            flags=None,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            length=28,
            payload=None,
            hw_src=mac,
        )

    rule.process_packet(_arp_pkt("aa:bb:cc:dd:ee:ff"))
    rule.process_packet(_arp_pkt("11:22:33:44:55:66"))
    event = rule.evaluate()

    assert event is not None, "Conflicting ARP MACs must trigger ARP_SPOOF_001"
    assert event.attack_type == "ARP Spoofing"
    assert event.rule_name == "ARP_SPOOF_001"
    assert event.severity == "High"
