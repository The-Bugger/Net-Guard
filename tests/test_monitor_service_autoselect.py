"""
test_monitor_service_autoselect.py — Unit tests for Task 5.

Verifies _pick_default_interface() (module-level helper) and the auto-select
path in start_monitoring().

Requirements: 2.3
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import backend.services.monitor_service as _mod
from backend.services.monitor_service import MonitorService, MonitoringState, _pick_default_interface

# Patch target: psutil is imported locally inside _pick_default_interface and
# get_interfaces, so we patch the global psutil module directly.
_PATCH_STATS = "psutil.net_if_stats"


def _make_service():
    """Build a minimal MonitorService."""
    capture = MagicMock()
    detection = MagicMock(is_running=False)
    state = MonitoringState()
    svc = MonitorService(capture, detection, state)
    return svc, capture, state


def _stats(**kwargs):
    """Build a {name: MagicMock(isup=bool)} stats dict."""
    return {name: MagicMock(isup=up) for name, up in kwargs.items()}


# ---------------------------------------------------------------------------
# _pick_default_interface (module-level function)
# ---------------------------------------------------------------------------

class TestPickDefaultInterface:

    def test_skips_loopback_picks_first_up(self):
        stats = _stats(lo=True, eth0=True, wlan0=True)
        with patch(_PATCH_STATS, return_value=stats):
            assert _pick_default_interface() == "eth0"

    def test_skips_down_interfaces(self):
        stats = _stats(eth0=False, wlan0=True)
        with patch(_PATCH_STATS, return_value=stats):
            assert _pick_default_interface() == "wlan0"

    def test_returns_empty_when_only_loopback(self):
        stats = _stats(lo=True)
        with patch(_PATCH_STATS, return_value=stats):
            assert _pick_default_interface() == ""

    def test_returns_empty_when_all_down(self):
        stats = _stats(eth0=False, wlan0=False)
        with patch(_PATCH_STATS, return_value=stats):
            assert _pick_default_interface() == ""

    def test_returns_empty_on_psutil_error(self):
        with patch(_PATCH_STATS, side_effect=Exception("no psutil")):
            assert _pick_default_interface() == ""


# ---------------------------------------------------------------------------
# start_monitoring auto-select path
# ---------------------------------------------------------------------------

class TestStartMonitoringAutoSelect:

    def _start(self, interface, net_stats):
        svc, capture, state = _make_service()
        with patch(_PATCH_STATS, return_value=net_stats):
            svc.start_monitoring(interface)
        return capture, state

    def test_none_triggers_auto_select(self):
        stats = _stats(lo=True, eth0=True)
        capture, state = self._start(None, stats)
        capture.start.assert_called_once_with("eth0")
        assert state.interface == "eth0"
        assert state.active is True

    def test_empty_string_triggers_auto_select(self):
        stats = _stats(lo=True, wlan0=True)
        capture, state = self._start("", stats)
        capture.start.assert_called_once_with("wlan0")
        assert state.interface == "wlan0"

    def test_explicit_interface_skips_auto_select(self):
        stats = _stats(lo=True, eth0=True, wlan0=True)
        capture, state = self._start("wlan0", stats)
        capture.start.assert_called_once_with("wlan0")

    def test_raises_when_no_active_interface_available(self):
        import pytest
        stats = _stats(lo=True)
        svc, _, _ = _make_service()
        with patch(_PATCH_STATS, return_value=stats):
            with pytest.raises(ValueError, match="NO_INTERFACE"):
                svc.start_monitoring(None)
