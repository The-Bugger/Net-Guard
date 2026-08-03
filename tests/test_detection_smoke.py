"""Quick smoke test for all 5 detection rules."""
from datetime import datetime, timezone
from detection.parsers.packet_decoder import Packet
from detection.rules.syn_flood import SynFloodRule
from detection.rules.port_scan import PortScanRule
from detection.rules.sql_injection import SqlInjectionRule
from detection.rules.brute_force import BruteForceRule
from detection.rules.arp_spoof import ArpSpoofRule


def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_pkt(**kwargs):
    defaults = dict(
        src_ip="10.0.0.1", dst_ip="192.168.1.1", src_port=5000, dst_port=80,
        protocol="TCP", flags="S", timestamp=ts(), length=60, payload=None,
    )
    defaults.update(kwargs)
    return Packet(**defaults)


def test_syn_flood():
    rule = SynFloodRule(threshold=10, window_seconds=10)
    rule.initialize()
    for _ in range(15):
        rule.process_packet(make_pkt())
    event = rule.evaluate()
    assert event is not None
    assert event.attack_type == "SYN Flood"
    assert event.rule_name == "SYN_FLOOD_001"
    assert event.confidence > 0
    assert event.severity in {"Low", "Medium", "High", "Critical"}
    print(f"  SYN Flood: severity={event.severity}, confidence={event.confidence} OK")


def test_port_scan():
    rule = PortScanRule(threshold=5, window_seconds=10)
    rule.initialize()
    for i in range(8):
        rule.process_packet(make_pkt(dst_port=100 + i))
    event = rule.evaluate()
    assert event is not None
    assert event.attack_type == "Port Scan"
    assert event.rule_name == "PORT_SCAN_001"
    print(f"  Port Scan: severity={event.severity}, confidence={event.confidence} OK")


def test_sql_injection():
    rule = SqlInjectionRule()
    rule.initialize()
    payload = b"GET /login?id=%27%20OR%20%271%27%3D%271 HTTP/1.1\r\nHost: localhost\r\n\r\n"
    # Use a simple payload with the literal pattern
    payload2 = b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=x'%20OR%20'1'='1"
    pkt = make_pkt(dst_port=80, flags="", payload=b"GET /search?q=UNION SELECT 1,2,3 HTTP/1.1\r\nHost: x\r\n\r\n")
    rule.process_packet(pkt)
    event = rule.evaluate()
    assert event is not None
    assert event.attack_type == "SQL Injection"
    assert event.confidence == 100
    print(f"  SQL Injection: severity={event.severity}, confidence={event.confidence} OK")


def test_brute_force():
    rule = BruteForceRule(threshold=5, window_seconds=60)
    rule.initialize()
    for _ in range(8):
        rule.process_packet(make_pkt(dst_port=22, protocol="TCP", flags="S"))
    event = rule.evaluate()
    assert event is not None
    assert event.attack_type == "Brute Force"
    assert event.rule_name == "BRUTE_FORCE_001"
    print(f"  Brute Force: severity={event.severity}, confidence={event.confidence} OK")


def test_arp_spoof():
    rule = ArpSpoofRule()
    rule.initialize()
    from detection.parsers.packet_decoder import Packet
    def _arp(mac):
        return Packet(
            src_ip="192.168.1.1", dst_ip="0.0.0.0",
            src_port=None, dst_port=None, protocol="ARP", flags=None,
            timestamp=ts(), length=28, payload=None, hw_src=mac, arp_op=2,
        )
    rule.process_packet(_arp("aa:bb:cc:dd:ee:ff"))
    rule.process_packet(_arp("11:22:33:44:55:66"))
    event = rule.evaluate()
    assert event is not None
    assert event.attack_type == "ARP Spoofing"
    assert event.severity == "High"
    assert event.confidence == 97
    print(f"  ARP Spoofing: severity={event.severity}, confidence={event.confidence} OK")


def test_explainability():
    from backend.services.explain_service import ExplainabilityEngine
    from detection.rules.base_rule import ThreatEvent
    engine = ExplainabilityEngine()
    event = ThreatEvent(
        event_id="test-001", timestamp=ts(), attack_type="SYN Flood",
        source_ip="10.0.0.1", destination_ip="192.168.1.1",
        source_port=None, destination_port=80, protocol="TCP",
        rule_name="SYN_FLOOD_001", severity="High", confidence=95,
        packet_count=200, evidence={"syn_packet_count": 200, "time_window_seconds": 3,
                                     "threshold": 100, "destination_ips": ["192.168.1.1"],
                                     "sample_timestamps": [ts()]},
    )
    explanation = engine.explain(event)
    assert explanation.plain_english_text
    assert len(explanation.plain_english_text) <= 500
    assert explanation.confidence_score == 95
    assert explanation.severity == "High"
    assert explanation.recommendation
    print(f"  Explainability: text='{explanation.plain_english_text[:60]}...' OK")


if __name__ == "__main__":
    print("Running detection smoke tests...")
    test_syn_flood()
    test_port_scan()
    test_sql_injection()
    test_brute_force()
    test_arp_spoof()
    test_explainability()
    print("\nAll smoke tests PASSED!")
