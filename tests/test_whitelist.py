"""
test_whitelist.py — Unit tests for WhitelistManager.

Tests add/remove/list, in-memory sync, invalid IP rejection,
DB atomicity, and thread safety.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
import threading
from unittest.mock import MagicMock

from backend.services.whitelist_service import WhitelistManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_repo():
    repo = MagicMock()
    repo.insert.return_value = True
    repo.delete.return_value = True
    repo.get_all.return_value = []
    return repo


@pytest.fixture
def manager(mock_repo):
    return WhitelistManager(mock_repo)


# ---------------------------------------------------------------------------
# Add / Remove / List
# ---------------------------------------------------------------------------

class TestAddRemoveList:

    def test_add_ip(self, manager, mock_repo):
        manager.add("192.168.1.1", description="Gateway")
        mock_repo.insert.assert_called_once()
        assert manager.is_whitelisted("192.168.1.1")

    def test_add_ipv6(self, manager, mock_repo):
        manager.add("::1", description="Loopback v6")
        assert manager.is_whitelisted("::1")

    def test_remove_ip(self, manager, mock_repo):
        manager.add("10.0.0.1")
        result = manager.remove("10.0.0.1")
        assert result is True
        assert not manager.is_whitelisted("10.0.0.1")
        mock_repo.delete.assert_called_once_with("10.0.0.1")

    def test_remove_nonexistent(self, manager, mock_repo):
        mock_repo.delete.return_value = False
        result = manager.remove("10.0.0.99")
        assert result is False

    def test_get_all_delegates_to_repo(self, manager, mock_repo):
        mock_repo.get_all.return_value = [
            {"ip_address": "192.168.1.1", "description": "GW", "created_at": "2026-01-01", "created_by": "admin"}
        ]
        result = manager.get_all()
        assert len(result) == 1
        assert result[0]["ip_address"] == "192.168.1.1"

    def test_is_whitelisted_false_by_default(self, manager):
        assert not manager.is_whitelisted("1.2.3.4")


# ---------------------------------------------------------------------------
# Sync from DB
# ---------------------------------------------------------------------------

class TestSyncFromDB:

    def test_sync_rebuilds_set(self, manager, mock_repo):
        mock_repo.get_all.return_value = [
            {"ip_address": "10.0.0.1"},
            {"ip_address": "10.0.0.2"},
        ]
        manager.sync_from_db()
        assert manager.is_whitelisted("10.0.0.1")
        assert manager.is_whitelisted("10.0.0.2")
        assert not manager.is_whitelisted("10.0.0.3")

    def test_sync_replaces_previous(self, manager, mock_repo):
        manager.add("192.168.1.1")
        mock_repo.get_all.return_value = [{"ip_address": "10.0.0.1"}]
        manager.sync_from_db()
        assert not manager.is_whitelisted("192.168.1.1")
        assert manager.is_whitelisted("10.0.0.1")

    def test_sync_handles_exception(self, manager, mock_repo):
        manager.add("10.0.0.1")
        mock_repo.get_all.side_effect = RuntimeError("DB down")
        manager.sync_from_db()  # should not raise
        # In-memory set should remain unchanged on failure
        assert manager.is_whitelisted("10.0.0.1")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestValidation:

    def test_add_invalid_ip_raises(self, manager):
        with pytest.raises(ValueError, match="Invalid IP"):
            manager.add("not-an-ip")

    def test_add_empty_string_raises(self, manager):
        with pytest.raises(ValueError):
            manager.add("")


# ---------------------------------------------------------------------------
# DB failure
# ---------------------------------------------------------------------------

class TestDBFailure:

    def test_add_raises_on_insert_failure(self, manager, mock_repo):
        mock_repo.insert.return_value = False
        with pytest.raises(RuntimeError, match="Failed to add"):
            manager.add("192.168.1.1")


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

class TestThreadSafety:

    def test_concurrent_add_remove(self, mock_repo):
        mgr = WhitelistManager(mock_repo)
        errors = []

        def add_ips():
            try:
                for i in range(50):
                    mgr.add(f"10.0.0.{i % 256}")
            except Exception as e:
                errors.append(e)

        def remove_ips():
            try:
                for i in range(50):
                    mgr.remove(f"10.0.0.{i % 256}")
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=add_ips)
        t2 = threading.Thread(target=remove_ips)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)
        assert not errors, f"Thread errors: {errors}"
