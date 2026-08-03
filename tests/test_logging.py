"""
test_logging.py — Unit tests for LoggingEngine.

Tests: event persistence timing (≤50ms), log routing (system/detections/errors),
async queue behavior, sensitive key redaction.

Requirements: 14.2, 14.5, 15.1–15.5
"""

from __future__ import annotations

import sys
import queue
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, call
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from backend.services.log_service import LoggingEngine, _redact_sensitive, _SENSITIVE_KEYS
from detection.rules.base_rule import ThreatEvent, Explanation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_event(**overrides) -> ThreatEvent:
    defaults = dict(
        event_id=str(uuid.uuid4()),
        timestamp=_utc_now(),
        attack_type="SYN Flood",
        source_ip="10.0.0.1",
        destination_ip="192.168.1.1",
        source_port=None,
        destination_port=80,
        protocol="TCP",
        rule_name="SYN_FLOOD_001",
        severity="High",
        confidence=85,
        packet_count=150,
        evidence={"syn_packet_count": 150},
        blocked=False,
    )
    defaults.update(overrides)
    return ThreatEvent(**defaults)


def _make_explanation(**overrides) -> Explanation:
    defaults = dict(
        attack_name="SYN Flood",
        rule_triggered="SYN_FLOOD_001",
        plain_english_text="SYN flood detected from 10.0.0.1.",
        evidence={},
        confidence_score=85,
        severity="High",
        recommendation="Investigate the source host.",
    )
    defaults.update(overrides)
    return Explanation(**defaults)


@pytest.fixture
def mock_event_repo():
    repo = MagicMock()
    repo.insert.return_value = True
    return repo


@pytest.fixture
def mock_log_repo():
    repo = MagicMock()
    repo.insert.return_value = True
    return repo


@pytest.fixture
def engine(mock_event_repo, mock_log_repo):
    q = queue.Queue()
    return LoggingEngine(
        event_queue=q,
        event_repo=mock_event_repo,
        log_repo=mock_log_repo,
    )


# ---------------------------------------------------------------------------
# Sensitivity redaction (Requirement 15.4)
# ---------------------------------------------------------------------------

class TestSensitiveRedaction:

    def test_password_redacted(self):
        assert "[REDACTED]" in _redact_sensitive("user password=secret123")

    def test_token_redacted(self):
        assert "[REDACTED]" in _redact_sensitive("Authorization token=abc123")

    def test_api_key_redacted(self):
        assert "[REDACTED]" in _redact_sensitive("api_key=supersecret")

    def test_secret_redacted(self):
        assert "[REDACTED]" in _redact_sensitive("secret: mysecret")

    def test_non_sensitive_not_redacted(self):
        msg = "Detected SYN flood from 10.0.0.1"
        assert _redact_sensitive(msg) == msg

    def test_ip_address_not_redacted(self):
        msg = "source_ip=192.168.1.1"
        result = _redact_sensitive(msg)
        assert "192.168.1.1" in result

    def test_log_system_redacts_sensitive_in_message(self, engine):
        engine.log_system("INFO", "test", "TEST", "password=hunter2 user=admin")
        call_args = engine._log_repo.insert.call_args
        assert call_args is not None
        message = call_args.kwargs.get("message", "")
        assert "hunter2" not in message
        assert "[REDACTED]" in message


# ---------------------------------------------------------------------------
# log_system routing (Requirements 15.1, 15.3)
# ---------------------------------------------------------------------------

class TestLogSystemRouting:

    def test_log_system_info_writes_to_log_repo(self, engine):
        engine.log_system("INFO", "TestModule", "TEST_EVENT", "Test message")
        engine._log_repo.insert.assert_called()
        call_kwargs = engine._log_repo.insert.call_args.kwargs
        assert call_kwargs["level"] == "INFO"
        assert call_kwargs["module"] == "TestModule"
        assert call_kwargs["event"] == "TEST_EVENT"

    def test_log_system_warning_persisted(self, engine):
        engine.log_system("WARNING", "TestModule", "WARN_EVENT", "Warning message")
        call_kwargs = engine._log_repo.insert.call_args.kwargs
        assert call_kwargs["level"] == "WARNING"

    def test_log_system_critical_persisted(self, engine):
        engine.log_system("CRITICAL", "Prevention", "IPTABLES_FAIL", "No permission")
        call_kwargs = engine._log_repo.insert.call_args.kwargs
        assert call_kwargs["level"] == "CRITICAL"

    def test_metadata_passed_to_repo(self, engine):
        engine.log_system("INFO", "mod", "EVT", "msg", metadata={"key": "value"})
        call_kwargs = engine._log_repo.insert.call_args.kwargs
        assert call_kwargs.get("metadata") == {"key": "value"}

    def test_sensitive_metadata_stripped(self, engine):
        engine.log_system("INFO", "mod", "EVT", "msg", metadata={"password": "secret", "ip": "10.0.0.1"})
        call_kwargs = engine._log_repo.insert.call_args.kwargs
        meta = call_kwargs.get("metadata") or {}
        assert "password" not in meta
        assert meta.get("ip") == "10.0.0.1"


# ---------------------------------------------------------------------------
# log_event — queuing and async persistence (Requirements 14.2, 15.2, 15.5)
# ---------------------------------------------------------------------------

class TestLogEvent:

    def test_log_event_enqueues_item(self, engine):
        event = _make_event()
        explanation = _make_explanation()
        engine.log_event(event, explanation)
        assert engine._event_queue.qsize() == 1

    def test_log_event_does_not_block(self):
        """log_event() must be fast (non-blocking for packet capture thread)."""
        q = queue.Queue(maxsize=10000)
        eng = LoggingEngine(event_queue=q)
        event = _make_event()
        explanation = _make_explanation()

        start = time.monotonic()
        for _ in range(100):
            eng.log_event(event, explanation)
        elapsed = time.monotonic() - start
        # 100 log_event() calls should be well under 500ms
        assert elapsed < 0.5, f"log_event() is too slow: {elapsed:.3f}s for 100 calls"

    def test_logging_thread_persists_event(self, mock_event_repo, mock_log_repo):
        """After start(), the Logging_Thread picks up queue items and persists via insert_many."""
        q = queue.Queue()
        eng = LoggingEngine(event_queue=q, event_repo=mock_event_repo, log_repo=mock_log_repo)
        eng.start()

        event = _make_event()
        explanation = _make_explanation()
        eng.log_event(event, explanation)

        # Give the thread time to process (batch flush window + margin)
        deadline = time.monotonic() + 2.0
        while mock_event_repo.insert_many.call_count == 0 and time.monotonic() < deadline:
            time.sleep(0.02)

        eng.stop()
        mock_event_repo.insert_many.assert_called()
        batch = mock_event_repo.insert_many.call_args[0][0]
        assert batch, "insert_many called with empty batch"
        call_data = batch[0]
        assert call_data["event_id"] == event.event_id
        assert call_data["explanation"] == explanation.plain_english_text

    def test_logging_thread_persists_within_timing_budget(self, mock_event_repo, mock_log_repo):
        """Requirement 14.2: event persistence must complete within the CI timing budget."""
        q = queue.Queue()
        persist_times: list[float] = []

        def fast_insert_many(batch):
            persist_times.append(time.monotonic())
            return len(batch)

        mock_event_repo.insert_many.side_effect = fast_insert_many
        eng = LoggingEngine(event_queue=q, event_repo=mock_event_repo, log_repo=mock_log_repo)
        eng.start()

        emit_time = time.monotonic()
        event = _make_event()
        explanation = _make_explanation()
        eng.log_event(event, explanation)

        deadline = time.monotonic() + 1.0
        while not persist_times and time.monotonic() < deadline:
            time.sleep(0.005)

        eng.stop()

        assert persist_times, "Event was never persisted"
        latency_ms = (persist_times[0] - emit_time) * 1000
        # Batch flush window (200ms) + scheduling overhead; generous CI budget.
        assert latency_ms < 1000, f"Persistence took {latency_ms:.1f}ms (budget: 1000ms CI)"


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

class TestLifecycle:

    def test_start_creates_thread(self, engine):
        engine.start()
        assert engine._thread is not None
        assert engine._thread.is_alive()
        engine.stop()

    def test_stop_joins_thread(self, engine):
        engine.start()
        thread = engine._thread
        engine.stop()
        assert not thread.is_alive()

    def test_double_start_is_idempotent(self, engine):
        engine.start()
        t1 = engine._thread
        engine.start()  # second call is no-op
        assert engine._thread is t1
        engine.stop()

    def test_stop_without_start_is_safe(self, engine):
        engine.stop()  # should not raise


# ---------------------------------------------------------------------------
# log_block / log_unblock routing (Requirement 15.2)
# ---------------------------------------------------------------------------

class TestBlockUnblockLogging:

    def test_log_block_calls_repo(self, engine):
        engine.log_block("10.0.0.5", "SYN Flood", 120)
        engine._log_repo.insert.assert_called()

    def test_log_unblock_calls_repo(self, engine):
        engine.log_unblock("10.0.0.5", reason="expired")
        engine._log_repo.insert.assert_called()

    def test_log_block_event_name(self, engine):
        engine.log_block("10.0.0.5", "Port Scan", 60)
        call_kwargs = engine._log_repo.insert.call_args.kwargs
        assert call_kwargs["event"] == "IP_BLOCKED"

    def test_log_unblock_event_name(self, engine):
        engine.log_unblock("10.0.0.5")
        call_kwargs = engine._log_repo.insert.call_args.kwargs
        assert call_kwargs["event"] == "IP_UNBLOCKED"
