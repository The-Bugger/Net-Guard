"""
test_threading.py — Unit tests for DetectionEngine threading behavior.

Covers:
- Queue communication: packets flow from packet_queue → _detection_loop → on_event callback
- Graceful shutdown via threading.Event stop signal (stop() exits cleanly)
- Rule exception → rule disabled, other rules continue (Req 9.5 / 9.7)

No real Scapy, iptables, or network I/O is used.
Requirements: 9.3, 9.7
"""

from __future__ import annotations

import queue
import threading
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from backend.services.detection_service import DetectionEngine, _STOP_SENTINEL
from detection.parsers.packet_decoder import Packet
from detection.rules.base_rule import ThreatEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_packet(src_ip: str = "10.0.0.1") -> Packet:
    return Packet(
        src_ip=src_ip,
        dst_ip="192.168.1.1",
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        flags="S",
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        length=64,
        payload=None,
    )


def _make_event(source_ip: str = "10.0.0.1", severity: str = "High") -> ThreatEvent:
    return ThreatEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        attack_type="SYN Flood",
        source_ip=source_ip,
        destination_ip="192.168.1.1",
        source_port=None,
        destination_port=None,
        protocol="TCP",
        rule_name="SYN_FLOOD_001",
        severity=severity,
        confidence=90,
        packet_count=150,
        evidence={},
    )


def _engine_with_mock_rules(pq: queue.Queue, collected: list, rule_mocks=None):
    """
    Build a DetectionEngine whose rule list is replaced post-construction.
    on_event appends events to `collected`.
    """
    eng = DetectionEngine(packet_queue=pq, on_event=lambda e: collected.append(e))
    # Patch _build_rules so start() uses our mock rules
    if rule_mocks is not None:
        eng._build_rules = lambda: rule_mocks  # type: ignore[method-assign]
    else:
        eng._build_rules = lambda: []  # type: ignore[method-assign]
    return eng


# ---------------------------------------------------------------------------
# 1. Queue communication
# ---------------------------------------------------------------------------

class TestQueueCommunication:
    """Packets placed on packet_queue reach the on_event callback."""

    def test_packet_triggers_event(self):
        """A packet that causes a rule to fire should reach the callback."""
        pq: queue.Queue = queue.Queue()
        collected: list[ThreatEvent] = []

        mock_rule = MagicMock()
        mock_rule.rule_name = "SYN_FLOOD_001"
        mock_rule.enabled = True
        mock_rule.initialize.return_value = None
        mock_rule.process_packet.return_value = None
        mock_rule.evaluate.return_value = _make_event()
        mock_rule.cleanup.return_value = None

        eng = _engine_with_mock_rules(pq, collected, rule_mocks=[mock_rule])
        eng.start()

        pq.put(_make_packet())
        # Give the thread time to process
        deadline = time.monotonic() + 2.0
        while not collected and time.monotonic() < deadline:
            time.sleep(0.02)

        eng.stop()
        assert len(collected) == 1
        assert collected[0].attack_type == "SYN Flood"

    def test_non_packet_items_ignored(self):
        """Items that are not Packet instances are silently discarded."""
        pq: queue.Queue = queue.Queue()
        collected: list = []

        mock_rule = MagicMock()
        mock_rule.rule_name = "TEST_RULE"
        mock_rule.enabled = True
        mock_rule.initialize.return_value = None
        mock_rule.evaluate.return_value = None
        mock_rule.cleanup.return_value = None

        eng = _engine_with_mock_rules(pq, collected, rule_mocks=[mock_rule])
        eng.start()

        pq.put("not a packet")
        pq.put(42)
        pq.put({"some": "dict"})
        time.sleep(0.1)

        eng.stop()
        assert len(collected) == 0

    def test_multiple_packets_all_processed(self):
        """Every packet in the queue gets dispatched."""
        pq: queue.Queue = queue.Queue()
        collected: list[ThreatEvent] = []

        # Each call to evaluate() must return an event with a unique source_ip so
        # the cooldown dict (src_ip, rule_name) doesn't suppress later events.
        counter = [0]

        def _fresh_event():
            counter[0] += 1
            return _make_event(source_ip=f"10.0.0.{counter[0]}")

        mock_rule = MagicMock()
        mock_rule.rule_name = "SYN_FLOOD_001"
        mock_rule.enabled = True
        mock_rule.initialize.return_value = None
        mock_rule.process_packet.return_value = None
        mock_rule.evaluate.side_effect = _fresh_event
        mock_rule.cleanup.return_value = None

        eng = _engine_with_mock_rules(pq, collected, rule_mocks=[mock_rule])
        eng.start()

        n = 5
        for i in range(n):
            pq.put(_make_packet(src_ip=f"10.0.0.{i + 1}"))

        deadline = time.monotonic() + 3.0
        while len(collected) < n and time.monotonic() < deadline:
            time.sleep(0.02)

        eng.stop()
        assert len(collected) == n

    def test_no_event_when_rule_returns_none(self):
        """No callback invocation when evaluate() returns None."""
        pq: queue.Queue = queue.Queue()
        collected: list = []

        mock_rule = MagicMock()
        mock_rule.rule_name = "QUIET_RULE"
        mock_rule.enabled = True
        mock_rule.initialize.return_value = None
        mock_rule.process_packet.return_value = None
        mock_rule.evaluate.return_value = None
        mock_rule.cleanup.return_value = None

        eng = _engine_with_mock_rules(pq, collected, rule_mocks=[mock_rule])
        eng.start()

        pq.put(_make_packet())
        time.sleep(0.15)

        eng.stop()
        assert len(collected) == 0


# ---------------------------------------------------------------------------
# 2. Graceful shutdown
# ---------------------------------------------------------------------------

class TestGracefulShutdown:
    """stop() signals the loop to exit and joins the thread."""

    def test_stop_while_idle(self):
        """stop() on an idle engine returns without blocking."""
        pq: queue.Queue = queue.Queue()
        eng = _engine_with_mock_rules(pq, [])
        eng.start()
        assert eng.is_running

        eng.stop()
        assert not eng.is_running

    def test_stop_drains_sentinel(self):
        """After stop(), the Detection_Thread is no longer alive."""
        pq: queue.Queue = queue.Queue()
        eng = _engine_with_mock_rules(pq, [])
        eng.start()

        thread_ref = eng._thread
        eng.stop()

        assert thread_ref is not None
        assert not thread_ref.is_alive()

    def test_stop_before_start_is_safe(self):
        """Calling stop() before start() should not raise."""
        pq: queue.Queue = queue.Queue()
        eng = _engine_with_mock_rules(pq, [])
        eng.stop()  # no exception

    def test_start_twice_is_idempotent(self):
        """A second start() while running is a no-op."""
        pq: queue.Queue = queue.Queue()
        eng = _engine_with_mock_rules(pq, [])
        eng.start()
        thread1 = eng._thread
        eng.start()  # should log warning and return
        thread2 = eng._thread

        assert thread1 is thread2  # same thread
        eng.stop()

    def test_stop_event_causes_loop_exit(self):
        """Setting _stop_event directly causes the loop to exit on the next iteration."""
        pq: queue.Queue = queue.Queue()
        eng = _engine_with_mock_rules(pq, [])
        eng.start()

        # Manually set the stop event — the loop polls every 1 s via queue timeout
        eng._stop_event.set()

        thread = eng._thread
        thread.join(timeout=3.0)
        assert not thread.is_alive()
        eng._thread = None  # prevent double-join in teardown


# ---------------------------------------------------------------------------
# 3. Rule exception → rule disabled, others continue
# ---------------------------------------------------------------------------

class TestRuleExceptionHandling:
    """Requirement 9.5: a rule that raises should be disabled; others keep running."""

    def test_crashing_rule_disabled_good_rule_continues(self):
        """If rule A raises, it gets disabled and rule B still fires."""
        pq: queue.Queue = queue.Queue()
        collected: list[ThreatEvent] = []

        bad_rule = MagicMock()
        bad_rule.rule_name = "BAD_RULE"
        bad_rule.enabled = True
        bad_rule.initialize.return_value = None
        bad_rule.process_packet.side_effect = RuntimeError("boom")
        bad_rule.cleanup.return_value = None

        good_rule = MagicMock()
        good_rule.rule_name = "GOOD_RULE"
        good_rule.enabled = True
        good_rule.initialize.return_value = None
        good_rule.process_packet.return_value = None
        good_rule.evaluate.return_value = _make_event(source_ip="10.1.1.1")
        good_rule.cleanup.return_value = None

        eng = _engine_with_mock_rules(pq, collected, rule_mocks=[bad_rule, good_rule])
        eng.start()

        pq.put(_make_packet())
        deadline = time.monotonic() + 2.0
        while not collected and time.monotonic() < deadline:
            time.sleep(0.02)

        eng.stop()

        assert "BAD_RULE" in eng.disabled_rule_names
        assert len(collected) >= 1

    def test_disabled_rule_not_called_again(self):
        """Once a rule is in _disabled_rules, process_packet is not called again."""
        pq: queue.Queue = queue.Queue()
        collected: list = []

        bad_rule = MagicMock()
        bad_rule.rule_name = "CRASHER"
        bad_rule.enabled = True
        bad_rule.initialize.return_value = None
        bad_rule.process_packet.side_effect = RuntimeError("first failure")
        bad_rule.cleanup.return_value = None

        eng = _engine_with_mock_rules(pq, collected, rule_mocks=[bad_rule])
        eng.start()

        # Send two packets
        pq.put(_make_packet(src_ip="10.0.0.1"))
        time.sleep(0.15)
        call_count_after_first = bad_rule.process_packet.call_count

        pq.put(_make_packet(src_ip="10.0.0.2"))
        time.sleep(0.15)
        call_count_after_second = bad_rule.process_packet.call_count

        eng.stop()

        # Rule called once (first packet), NOT called again after being disabled
        assert call_count_after_first == 1
        assert call_count_after_second == 1  # unchanged

    def test_evaluate_exception_also_disables_rule(self):
        """Exception in evaluate() (not just process_packet) disables the rule."""
        pq: queue.Queue = queue.Queue()
        collected: list = []

        bad_rule = MagicMock()
        bad_rule.rule_name = "BAD_EVAL"
        bad_rule.enabled = True
        bad_rule.initialize.return_value = None
        bad_rule.process_packet.return_value = None
        bad_rule.evaluate.side_effect = ValueError("bad evaluate")
        bad_rule.cleanup.return_value = None

        eng = _engine_with_mock_rules(pq, collected, rule_mocks=[bad_rule])
        eng.start()

        pq.put(_make_packet())
        time.sleep(0.15)

        eng.stop()

        assert "BAD_EVAL" in eng.disabled_rule_names


# ---------------------------------------------------------------------------
# 4. Cooldown enforcement (threading-observable)
# ---------------------------------------------------------------------------

class TestCooldownViaCommunication:
    """Cooldown: same (ip, rule) within 10 s → only first event emitted."""

    def test_same_ip_rule_within_cooldown_suppressed(self):
        """Two packets from same IP/rule within 10 s → only 1 event."""
        pq: queue.Queue = queue.Queue()
        collected: list[ThreatEvent] = []

        event = _make_event(source_ip="10.9.9.9", severity="High")

        mock_rule = MagicMock()
        mock_rule.rule_name = "SYN_FLOOD_001"
        mock_rule.enabled = True
        mock_rule.initialize.return_value = None
        mock_rule.process_packet.return_value = None
        # Always returns the same event (same ip + rule → cooldown)
        mock_rule.evaluate.return_value = event
        mock_rule.cleanup.return_value = None

        eng = _engine_with_mock_rules(pq, collected, rule_mocks=[mock_rule])
        eng.start()

        pq.put(_make_packet(src_ip="10.9.9.9"))
        time.sleep(0.15)
        pq.put(_make_packet(src_ip="10.9.9.9"))
        time.sleep(0.15)

        eng.stop()
        # Cooldown suppresses the second event
        assert len(collected) == 1
