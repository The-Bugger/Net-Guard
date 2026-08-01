"""
test_properties_engine.py — Property-based tests for DetectionEngine.

Properties 23–25: UUID uniqueness, cooldown enforcement, rule exception handling.
"""

from __future__ import annotations

import sys
import uuid
import queue
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from unittest.mock import MagicMock, patch
from hypothesis import given, settings as hsettings, strategies as st

from backend.services.detection_service import DetectionEngine
from detection.rules.base_rule import ThreatEvent
from detection.parsers.packet_decoder import Packet
from conftest import make_threat_event, make_packet


# ---------------------------------------------------------------------------
# Property 23: UUID uniqueness
# ---------------------------------------------------------------------------

class TestUUIDUniqueness:

    @hsettings(max_examples=20)
    @given(n=st.integers(min_value=2, max_value=50))
    def test_all_event_ids_unique(self, n):
        events = [make_threat_event() for _ in range(n)]
        ids = [e.event_id for e in events]
        assert len(set(ids)) == len(ids), "Duplicate event IDs found"

    @hsettings(max_examples=20)
    @given(n=st.integers(min_value=1, max_value=20))
    def test_event_ids_are_valid_uuid4(self, n):
        for _ in range(n):
            event = make_threat_event()
            parsed = uuid.UUID(event.event_id, version=4)
            assert str(parsed) == event.event_id


# ---------------------------------------------------------------------------
# Property 24: Cooldown enforcement
# ---------------------------------------------------------------------------

class TestCooldownEnforcement:

    def test_first_event_always_emits(self):
        q = queue.Queue()
        engine = DetectionEngine(packet_queue=q)
        event = make_threat_event(source_ip="10.0.0.1", severity="High")
        assert engine._should_emit(event) is True

    def test_same_severity_suppressed_within_cooldown(self):
        q = queue.Queue()
        engine = DetectionEngine(packet_queue=q)
        event1 = make_threat_event(source_ip="10.0.0.1", severity="High", rule_name="SYN_FLOOD_001")
        # Simulate cooldown entry
        engine._cooldown[("10.0.0.1", "SYN_FLOOD_001")] = ("High", time.monotonic())
        event2 = make_threat_event(source_ip="10.0.0.1", severity="High", rule_name="SYN_FLOOD_001")
        assert engine._should_emit(event2) is False

    def test_higher_severity_passes_cooldown(self):
        q = queue.Queue()
        engine = DetectionEngine(packet_queue=q)
        engine._cooldown[("10.0.0.1", "SYN_FLOOD_001")] = ("Medium", time.monotonic())
        event = make_threat_event(source_ip="10.0.0.1", severity="High", rule_name="SYN_FLOOD_001")
        assert engine._should_emit(event) is True

    def test_lower_severity_suppressed(self):
        q = queue.Queue()
        engine = DetectionEngine(packet_queue=q)
        engine._cooldown[("10.0.0.1", "SYN_FLOOD_001")] = ("Critical", time.monotonic())
        event = make_threat_event(source_ip="10.0.0.1", severity="High", rule_name="SYN_FLOOD_001")
        assert engine._should_emit(event) is False

    def test_expired_cooldown_allows_emit(self):
        q = queue.Queue()
        engine = DetectionEngine(packet_queue=q)
        # Cooldown set 20 seconds ago (> 10s cooldown)
        engine._cooldown[("10.0.0.1", "SYN_FLOOD_001")] = ("High", time.monotonic() - 20)
        event = make_threat_event(source_ip="10.0.0.1", severity="High", rule_name="SYN_FLOOD_001")
        assert engine._should_emit(event) is True

    @hsettings(max_examples=30)
    @given(
        severity1=st.sampled_from(["Low", "Medium", "High", "Critical"]),
        severity2=st.sampled_from(["Low", "Medium", "High", "Critical"]),
    )
    def test_cooldown_severity_ordering(self, severity1, severity2):
        sev_order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
        q = queue.Queue()
        engine = DetectionEngine(packet_queue=q)
        engine._cooldown[("10.0.0.1", "R1")] = (severity1, time.monotonic())
        event = make_threat_event(source_ip="10.0.0.1", severity=severity2, rule_name="R1")
        result = engine._should_emit(event)
        if sev_order[severity2] > sev_order[severity1]:
            assert result is True
        else:
            assert result is False


# ---------------------------------------------------------------------------
# Property 25: Rule exception handling
# ---------------------------------------------------------------------------

class TestRuleExceptionHandling:

    def test_rule_exception_disables_rule(self):
        q = queue.Queue()
        engine = DetectionEngine(packet_queue=q)

        mock_rule = MagicMock()
        mock_rule.rule_name = "BAD_RULE"
        mock_rule.enabled = True
        mock_rule.evaluate.side_effect = RuntimeError("Rule crashed")
        engine._rules = [mock_rule]
        engine._disabled_rules = set()

        packet = make_packet()
        engine._dispatch(packet)

        assert "BAD_RULE" in engine._disabled_rules

    def test_disabled_rule_not_evaluated(self):
        q = queue.Queue()
        engine = DetectionEngine(packet_queue=q)

        mock_rule = MagicMock()
        mock_rule.rule_name = "BAD_RULE"
        mock_rule.enabled = True
        engine._rules = [mock_rule]
        engine._disabled_rules = {"BAD_RULE"}

        packet = make_packet()
        engine._dispatch(packet)

        mock_rule.process_packet.assert_not_called()

    def test_other_rules_continue_after_exception(self):
        q = queue.Queue()
        engine = DetectionEngine(packet_queue=q)

        bad_rule = MagicMock()
        bad_rule.rule_name = "BAD_RULE"
        bad_rule.enabled = True
        bad_rule.evaluate.side_effect = RuntimeError("crash")

        good_rule = MagicMock()
        good_rule.rule_name = "GOOD_RULE"
        good_rule.enabled = True
        good_rule.evaluate.return_value = None

        engine._rules = [bad_rule, good_rule]
        engine._disabled_rules = set()

        packet = make_packet()
        engine._dispatch(packet)

        good_rule.process_packet.assert_called_once()
        good_rule.evaluate.assert_called_once()
