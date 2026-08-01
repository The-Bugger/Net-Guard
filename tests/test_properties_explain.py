"""
test_properties_explain.py — Property-based tests for ExplainabilityEngine.

Properties 26–30: text ≤500 chars, confidence 0–100, severity enum,
recommendation match, whitelist phrase.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from unittest.mock import MagicMock
from hypothesis import given, settings as hsettings, strategies as st

from backend.services.explain_service import ExplainabilityEngine
from conftest import make_threat_event


_VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}
_ATTACK_TYPES = ["SYN Flood", "Port Scan", "SQL Injection", "Brute Force", "ARP Spoofing"]


# ---------------------------------------------------------------------------
# Property 26: plain_english_text ≤ 500 chars
# ---------------------------------------------------------------------------

class TestProperty26TextLength:

    @hsettings(max_examples=50)
    @given(
        attack=st.sampled_from(_ATTACK_TYPES + ["Unknown", "Custom"]),
        extra_text=st.text(min_size=0, max_size=600),
    )
    def test_text_never_exceeds_500(self, attack, extra_text):
        engine = ExplainabilityEngine()
        event = make_threat_event(
            attack_type=attack,
            evidence={"matched_pattern": extra_text, "syn_packet_count": 999,
                      "unique_port_count": 999, "failure_count": 999,
                      "conflicting_ip": "1.2.3.4",
                      "conflicting_macs": [extra_text[:17]],
                      "time_window_seconds": 3, "threshold": 100,
                      "destination_ip": "10.0.0.1", "target_service": "SSH"},
        )
        exp = engine.explain(event)
        assert len(exp.plain_english_text) <= 500


# ---------------------------------------------------------------------------
# Property 27: confidence_score in [0, 100]
# ---------------------------------------------------------------------------

class TestProperty27Confidence:

    @hsettings(max_examples=50)
    @given(confidence=st.integers(min_value=-1000, max_value=1000))
    def test_confidence_clamped(self, confidence):
        engine = ExplainabilityEngine()
        event = make_threat_event(confidence=confidence)
        exp = engine.explain(event)
        assert 0 <= exp.confidence_score <= 100


# ---------------------------------------------------------------------------
# Property 28: severity always valid enum
# ---------------------------------------------------------------------------

class TestProperty28Severity:

    @hsettings(max_examples=50)
    @given(severity=st.text(min_size=0, max_size=30))
    def test_severity_always_valid(self, severity):
        engine = ExplainabilityEngine()
        event = make_threat_event(severity=severity if severity else "High")
        exp = engine.explain(event)
        assert exp.severity in _VALID_SEVERITIES


# ---------------------------------------------------------------------------
# Property 29: recommendation matches attack type
# ---------------------------------------------------------------------------

class TestProperty29Recommendation:

    @pytest.mark.parametrize("attack,keyword", [
        ("SYN Flood", "source"),
        ("Port Scan", "firewall"),
        ("SQL Injection", "sanitization"),
        ("Brute Force", "lockout"),
        ("ARP Spoofing", "gateway"),
    ])
    def test_recommendation_contains_keyword(self, attack, keyword):
        engine = ExplainabilityEngine()
        event = make_threat_event(attack_type=attack)
        exp = engine.explain(event)
        assert keyword.lower() in exp.recommendation.lower()


# ---------------------------------------------------------------------------
# Property 30: whitelist annotation
# ---------------------------------------------------------------------------

class TestProperty30Whitelist:

    @hsettings(max_examples=30)
    @given(attack=st.sampled_from(_ATTACK_TYPES))
    def test_whitelist_annotation_present(self, attack):
        wl = MagicMock()
        wl.is_whitelisted.return_value = True
        engine = ExplainabilityEngine(whitelist_manager=wl)
        event = make_threat_event(attack_type=attack)
        exp = engine.explain(event)
        text_lower = exp.plain_english_text.lower()
        assert "whitelist" in text_lower

    @hsettings(max_examples=30)
    @given(attack=st.sampled_from(_ATTACK_TYPES))
    def test_no_whitelist_annotation_when_not_whitelisted(self, attack):
        engine = ExplainabilityEngine()
        event = make_threat_event(attack_type=attack)
        exp = engine.explain(event)
        assert "Whitelisted device" not in exp.plain_english_text
