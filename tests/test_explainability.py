"""
test_explainability.py — Unit tests for ExplainabilityEngine.

Tests all 5 attack-type templates, fallback, whitelist annotation,
recommendation mapping, confidence clamping, and severity validation.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from unittest.mock import MagicMock

from backend.services.explain_service import ExplainabilityEngine
from conftest import make_threat_event


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine():
    return ExplainabilityEngine(whitelist_manager=None)


@pytest.fixture
def wl_engine():
    wl = MagicMock()
    wl.is_whitelisted.return_value = True
    return ExplainabilityEngine(whitelist_manager=wl)


# ---------------------------------------------------------------------------
# Attack-type template tests
# ---------------------------------------------------------------------------

class TestAttackTypeTemplates:

    def test_syn_flood_template(self, engine):
        event = make_threat_event(
            attack_type="SYN Flood",
            evidence={"syn_packet_count": 250, "time_window_seconds": 3, "threshold": 100},
        )
        exp = engine.explain(event)
        assert "SYN" in exp.plain_english_text
        assert "250" in exp.plain_english_text
        assert exp.attack_name == "SYN Flood"

    def test_port_scan_template(self, engine):
        event = make_threat_event(
            attack_type="Port Scan",
            rule_name="PORT_SCAN_001",
            evidence={"unique_port_count": 50, "time_window_seconds": 10},
        )
        exp = engine.explain(event)
        assert "50" in exp.plain_english_text
        assert "port" in exp.plain_english_text.lower()

    def test_sql_injection_template(self, engine):
        event = make_threat_event(
            attack_type="SQL Injection",
            rule_name="SQL_INJECTION_001",
            evidence={"matched_pattern": "OR 1=1", "destination_ip": "10.0.0.1"},
        )
        exp = engine.explain(event)
        assert "OR 1=1" in exp.plain_english_text
        assert "SQL" in exp.plain_english_text

    def test_brute_force_template(self, engine):
        event = make_threat_event(
            attack_type="Brute Force",
            rule_name="BRUTE_FORCE_001",
            evidence={"failure_count": 20, "time_window_seconds": 60, "target_service": "SSH"},
        )
        exp = engine.explain(event)
        assert "20" in exp.plain_english_text
        assert "SSH" in exp.plain_english_text

    def test_arp_spoof_template(self, engine):
        event = make_threat_event(
            attack_type="ARP Spoofing",
            rule_name="ARP_SPOOF_001",
            evidence={
                "conflicting_ip": "192.168.1.1",
                "conflicting_macs": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
            },
        )
        exp = engine.explain(event)
        assert "ARP" in exp.plain_english_text
        assert "aa:bb:cc:dd:ee:ff" in exp.plain_english_text

    def test_unknown_attack_type_fallback(self, engine):
        event = make_threat_event(attack_type="Unknown Attack", rule_name="UNKNOWN_001")
        exp = engine.explain(event)
        assert exp.plain_english_text  # non-empty
        assert "Security event" in exp.plain_english_text or event.source_ip in exp.plain_english_text


# ---------------------------------------------------------------------------
# Whitelist annotation
# ---------------------------------------------------------------------------

class TestWhitelistAnnotation:

    def test_whitelist_annotation_appended(self, wl_engine):
        event = make_threat_event()
        exp = wl_engine.explain(event)
        assert "Whitelisted" in exp.plain_english_text
        assert "monitoring only" in exp.plain_english_text

    def test_no_annotation_when_not_whitelisted(self, engine):
        event = make_threat_event()
        exp = engine.explain(event)
        assert "Whitelisted" not in exp.plain_english_text


# ---------------------------------------------------------------------------
# Recommendation mapping
# ---------------------------------------------------------------------------

class TestRecommendation:

    @pytest.mark.parametrize("attack_type,keyword", [
        ("SYN Flood", "source host"),
        ("Port Scan", "firewall"),
        ("SQL Injection", "input sanitization"),
        ("Brute Force", "account lockout"),
        ("ARP Spoofing", "gateway"),
    ])
    def test_recommendation_for_attack_type(self, engine, attack_type, keyword):
        event = make_threat_event(attack_type=attack_type)
        exp = engine.explain(event)
        assert keyword in exp.recommendation.lower()

    def test_unknown_attack_default_recommendation(self, engine):
        event = make_threat_event(attack_type="CustomAttack")
        exp = engine.explain(event)
        assert "security team" in exp.recommendation.lower()


# ---------------------------------------------------------------------------
# Fallback explanation
# ---------------------------------------------------------------------------

class TestFallback:

    def test_fallback_on_broken_event(self, engine):
        """An event with attributes that cause internal errors → safe fallback."""
        event = make_threat_event()
        # Break the event so _build_text raises
        object.__setattr__(event, "evidence", None)
        exp = engine.explain(event)
        assert exp.plain_english_text
        assert "security event" in exp.plain_english_text.lower()


# ---------------------------------------------------------------------------
# Constraints
# ---------------------------------------------------------------------------

class TestConstraints:

    def test_text_max_500_chars(self, engine):
        # Create event with very long evidence to force long text
        event = make_threat_event(
            attack_type="SQL Injection",
            evidence={"matched_pattern": "A" * 600, "destination_ip": "10.0.0.1"},
        )
        exp = engine.explain(event)
        assert len(exp.plain_english_text) <= 500

    def test_confidence_clamped_low(self, engine):
        event = make_threat_event(confidence=-50)
        exp = engine.explain(event)
        assert exp.confidence_score == 0

    def test_confidence_clamped_high(self, engine):
        event = make_threat_event(confidence=999)
        exp = engine.explain(event)
        assert exp.confidence_score == 100

    def test_confidence_normal(self, engine):
        event = make_threat_event(confidence=75)
        exp = engine.explain(event)
        assert exp.confidence_score == 75

    @pytest.mark.parametrize("severity", ["Low", "Medium", "High", "Critical"])
    def test_valid_severity_passes_through(self, engine, severity):
        event = make_threat_event(severity=severity)
        exp = engine.explain(event)
        assert exp.severity == severity

    def test_invalid_severity_defaults_to_high(self, engine):
        event = make_threat_event(severity="INVALID")
        exp = engine.explain(event)
        assert exp.severity == "High"

    def test_text_never_empty(self, engine):
        event = make_threat_event()
        exp = engine.explain(event)
        assert exp.plain_english_text.strip()
