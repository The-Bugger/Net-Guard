"""
test_prevention.py — Unit tests for PreventionEngine.

Tests block/unblock with mocked subprocess, whitelist bypass,
duplicate block extension, iptables failure, and privilege check.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from unittest.mock import MagicMock, patch, call

from backend.services.prevention_service import PreventionEngine
from conftest import make_threat_event
from detection.rules.base_rule import Explanation


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_block_repo():
    repo = MagicMock()
    repo.get_active.return_value = None
    repo.insert.return_value = True
    repo.set_inactive.return_value = True
    repo.extend_expiry.return_value = True
    return repo


@pytest.fixture
def mock_whitelist():
    wl = MagicMock()
    wl.is_whitelisted.return_value = False
    return wl


@pytest.fixture
def mock_log_engine():
    return MagicMock()


@pytest.fixture
def mock_emit():
    return MagicMock()


@pytest.fixture
def engine(mock_block_repo, mock_whitelist, mock_log_engine, mock_emit):
    return PreventionEngine(
        block_repo=mock_block_repo,
        whitelist_manager=mock_whitelist,
        log_engine=mock_log_engine,
        block_duration=120,
        socketio_emit=mock_emit,
    )


def _make_explanation():
    return Explanation(
        attack_name="SYN Flood",
        rule_triggered="SYN_FLOOD_001",
        plain_english_text="Test explanation.",
        evidence={},
        confidence_score=85,
        severity="High",
        recommendation="Block immediately.",
    )


# ---------------------------------------------------------------------------
# Block IP
# ---------------------------------------------------------------------------

class TestBlockIP:

    @patch("backend.services.prevention_service.subprocess")
    def test_block_ip_success(self, mock_sub, engine, mock_block_repo):
        mock_sub.run.return_value = MagicMock(returncode=0)
        result = engine.block_ip("10.0.0.5", "SYN Flood", "evt-001", allow_private_block=True)
        assert result is True
        mock_block_repo.insert.assert_called_once()
        record = mock_block_repo.insert.call_args[0][0]
        assert record["ip_address"] == "10.0.0.5"
        assert record["reason"] == "SYN Flood"

    @patch("backend.services.prevention_service.subprocess")
    def test_block_ip_calls_iptables(self, mock_sub, engine):
        mock_sub.run.return_value = MagicMock(returncode=0)
        engine.block_ip("10.0.0.5", "SYN Flood", "evt-001", allow_private_block=True)
        args = mock_sub.run.call_args[0][0]
        assert "iptables" in args
        assert "10.0.0.5" in args

    @patch("backend.services.prevention_service.subprocess")
    def test_block_ip_emits_socketio(self, mock_sub, engine, mock_emit):
        mock_sub.run.return_value = MagicMock(returncode=0)
        engine.block_ip("10.0.0.5", "SYN Flood", "evt-001", allow_private_block=True)
        mock_emit.assert_called_once()
        event_name, data = mock_emit.call_args[0]
        assert event_name == "ip_blocked"
        assert data["ip"] == "10.0.0.5"


# ---------------------------------------------------------------------------
# Unblock IP
# ---------------------------------------------------------------------------

class TestUnblockIP:

    @patch("backend.services.prevention_service.subprocess")
    def test_unblock_ip_success(self, mock_sub, engine, mock_block_repo):
        mock_sub.run.return_value = MagicMock(returncode=0)
        result = engine.unblock_ip("10.0.0.5")
        assert result is True
        mock_block_repo.set_inactive.assert_called_once_with("10.0.0.5")


# ---------------------------------------------------------------------------
# Whitelist bypass
# ---------------------------------------------------------------------------

class TestWhitelistBypass:

    @patch("backend.services.prevention_service.subprocess")
    def test_whitelisted_ip_not_blocked(self, mock_sub, engine, mock_whitelist, mock_block_repo):
        mock_whitelist.is_whitelisted.return_value = True
        event = make_threat_event(source_ip="192.168.1.1")
        explanation = _make_explanation()
        engine.handle_event(event, explanation)
        mock_sub.run.assert_not_called()
        mock_block_repo.insert.assert_not_called()

    @patch("backend.services.prevention_service.subprocess")
    def test_non_whitelisted_ip_blocked(self, mock_sub, engine, mock_whitelist):
        mock_whitelist.is_whitelisted.return_value = False
        mock_sub.run.return_value = MagicMock(returncode=0)
        event = make_threat_event(source_ip="203.0.113.5")
        explanation = _make_explanation()
        engine.handle_event(event, explanation)
        assert mock_sub.run.called


# ---------------------------------------------------------------------------
# Duplicate block → extend expiry
# ---------------------------------------------------------------------------

class TestDuplicateBlock:

    @patch("backend.services.prevention_service.subprocess")
    def test_duplicate_extends_expiry(self, mock_sub, engine, mock_block_repo):
        mock_block_repo.get_active.return_value = {
            "ip_address": "10.0.0.5",
            "expires_at": "2026-07-29T12:00:00Z",
        }
        result = engine.block_ip("10.0.0.5", "SYN Flood", "evt-002", allow_private_block=True)
        assert result is True
        mock_block_repo.extend_expiry.assert_called_once()
        # Should NOT call iptables again
        mock_sub.run.assert_not_called()
        # Should NOT insert a new record
        mock_block_repo.insert.assert_not_called()


# ---------------------------------------------------------------------------
# iptables failure
# ---------------------------------------------------------------------------

class TestIptablesFailure:

    @patch("backend.services.prevention_service.subprocess")
    def test_block_returns_false_on_failure(self, mock_sub, engine):
        mock_sub.run.return_value = MagicMock(
            returncode=1, stderr=b"Permission denied"
        )
        result = engine.block_ip("10.0.0.5", "SYN Flood", "evt-003", allow_private_block=True)
        assert result is False

    @patch("backend.services.prevention_service.subprocess")
    def test_unblock_returns_false_on_failure(self, mock_sub, engine, mock_block_repo):
        mock_sub.run.return_value = MagicMock(
            returncode=1, stderr=b"No chain"
        )
        result = engine.unblock_ip("10.0.0.5")
        assert result is False
        # DB should still be marked inactive even on iptables failure
        mock_block_repo.set_inactive.assert_called_once()


# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------

class TestPrivilegeCheck:

    @patch("backend.services.prevention_service.subprocess")
    def test_verify_privileges_passes(self, mock_sub, engine):
        mock_sub.run.return_value = MagicMock(returncode=0)
        engine.verify_privileges()  # should not raise

    @patch("backend.services.prevention_service.subprocess")
    def test_verify_privileges_raises_on_failure(self, mock_sub, engine):
        mock_sub.run.return_value = MagicMock(
            returncode=1, stderr=b"permission denied"
        )
        with pytest.raises(RuntimeError, match="insufficient privileges"):
            engine.verify_privileges()


# ---------------------------------------------------------------------------
# Block duration
# ---------------------------------------------------------------------------

class TestBlockDuration:

    def test_set_block_duration(self, engine):
        engine.set_block_duration(300)
        assert engine._block_duration == 300

    def test_set_block_duration_clamped_low(self, engine):
        engine.set_block_duration(0)
        assert engine._block_duration >= 1

    def test_set_block_duration_clamped_high(self, engine):
        engine.set_block_duration(99999)
        assert engine._block_duration <= 3600
