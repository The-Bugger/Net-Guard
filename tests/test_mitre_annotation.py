"""
test_mitre_annotation.py — Unit tests for DetectionEngine.annotate_mitre (Task 13.3, Req 9.8).

Validates: Requirements 9.8
"""

import queue
import pytest
from backend.services.detection_service import DetectionEngine
from detection.rules.base_rule import ThreatEvent


def _make_event(rule_name: str = "", attack_type: str = "Unknown") -> ThreatEvent:
    return ThreatEvent(
        event_id="test-id",
        timestamp="2024-01-01T00:00:00Z",
        attack_type=attack_type,
        source_ip="1.2.3.4",
        destination_ip=None,
        source_port=None,
        destination_port=None,
        protocol="TCP",
        rule_name=rule_name,
        severity="High",
        confidence=90,
        packet_count=1,
        evidence={},
    )


@pytest.fixture
def engine():
    return DetectionEngine(packet_queue=queue.Queue())


class TestAnnotateMitre:
    def test_known_rule_name_key(self, engine):
        e = _make_event(rule_name="port_scan")
        engine.annotate_mitre(e)
        assert e.mitre_tactic == "Reconnaissance"
        assert e.mitre_technique == "T1595"

    def test_known_attack_type_fallback(self, engine):
        """Built-in rules use display-name attack_type; rule_name is the rule ID."""
        e = _make_event(rule_name="PORT_SCAN_001", attack_type="Port Scan")
        engine.annotate_mitre(e)
        # No entry for "PORT_SCAN_001" key, falls back to attack_type "Port Scan"
        assert e.mitre_tactic == "Reconnaissance"
        assert e.mitre_technique == "T1595"

    def test_unknown_falls_back_to_Unknown(self, engine):
        e = _make_event(rule_name="mystery_rule", attack_type="Alien Attack")
        engine.annotate_mitre(e)
        assert e.mitre_tactic == "Unknown"
        assert e.mitre_technique == "Unknown"

    def test_evidence_dict_populated(self, engine):
        e = _make_event(rule_name="syn_flood")
        engine.annotate_mitre(e)
        assert e.evidence["mitre_tactic"] == "Impact"
        assert e.evidence["mitre_technique"] == "T1499"

    def test_all_required_rule_name_keys_present(self, engine):
        required = {
            "port_scan":         ("Reconnaissance", "T1595"),
            "syn_flood":         ("Impact", "T1499"),
            "brute_force":       ("Credential Access", "T1110"),
            "sql_injection":     ("Initial Access", "T1190"),
            "xss":               ("Initial Access", "T1189"),
            "dns_amplification": ("Impact", "T1498"),
            "http_flood":        ("Impact", "T1499"),
            "ssh_attack":        ("Lateral Movement", "T1021"),
            "data_exfiltration": ("Exfiltration", "T1041"),
            "malware_beacon":    ("Command and Control", "T1071"),
        }
        for rule_name, (tactic, technique) in required.items():
            e = _make_event(rule_name=rule_name)
            engine.annotate_mitre(e)
            assert e.mitre_tactic == tactic, f"{rule_name}: expected tactic {tactic!r}"
            assert e.mitre_technique == technique, f"{rule_name}: expected technique {technique!r}"
