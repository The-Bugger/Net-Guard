"""
tests/test_prevention_service.py — Unit tests for the prevention engine private-IP guard.

Covers Requirement 3.1–3.5: private-IP pre-check in PreventionEngine.block_ip().
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from backend.services.prevention_service import PreventionEngine, _is_private, _is_own_address


# ---------------------------------------------------------------------------
# _is_private helper
# ---------------------------------------------------------------------------

class TestIsPrivate:
    def test_loopback(self):
        ok, name = _is_private("127.0.0.1")
        assert ok is True
        assert "127" in name

    def test_rfc1918_10(self):
        ok, _ = _is_private("10.0.0.1")
        assert ok is True

    def test_rfc1918_172(self):
        ok, _ = _is_private("172.16.5.1")
        assert ok is True

    def test_rfc1918_192(self):
        ok, _ = _is_private("192.168.1.100")
        assert ok is True

    def test_link_local(self):
        ok, _ = _is_private("169.254.1.1")
        assert ok is True

    def test_multicast(self):
        ok, _ = _is_private("224.0.0.1")
        assert ok is True

    def test_ipv6_loopback(self):
        ok, _ = _is_private("::1")
        assert ok is True

    def test_ipv6_link_local(self):
        ok, _ = _is_private("fe80::1")
        assert ok is True

    def test_public_ip(self):
        ok, _ = _is_private("8.8.8.8")
        assert ok is False

    def test_public_ip_203(self):
        ok, _ = _is_private("203.0.113.5")
        assert ok is False

    def test_invalid_ip_returns_false(self):
        ok, _ = _is_private("not-an-ip")
        assert ok is False


# ---------------------------------------------------------------------------
# PreventionEngine.block_ip — private-IP guard
# ---------------------------------------------------------------------------

def _make_engine():
    block_repo = MagicMock()
    block_repo.get_active.return_value = None
    whitelist_mgr = MagicMock()
    whitelist_mgr.is_whitelisted.return_value = False
    return PreventionEngine(block_repo, whitelist_mgr)


class TestBlockIpPrivateGuard:
    def test_loopback_refused(self):
        engine = _make_engine()
        assert engine.block_ip("127.0.0.1", "test", "evt-1") is False

    def test_rfc1918_192_refused(self):
        engine = _make_engine()
        assert engine.block_ip("192.168.1.1", "test", "evt-2") is False

    def test_rfc1918_10_refused(self):
        engine = _make_engine()
        assert engine.block_ip("10.0.0.1", "test", "evt-3") is False

    def test_public_ip_reaches_iptables(self):
        """Public IP must pass the guard and attempt the iptables call."""
        engine = _make_engine()
        with patch.object(engine, "_run_iptables", return_value=True):
            result = engine.block_ip("8.8.8.8", "test", "evt-4")
        assert result is True

    def test_allow_private_block_bypasses_guard(self):
        """allow_private_block=True must skip the private-IP check."""
        engine = _make_engine()
        with patch.object(engine, "_run_iptables", return_value=True):
            result = engine.block_ip("127.0.0.1", "test", "evt-5", allow_private_block=True)
        assert result is True

    def test_own_address_refused(self):
        """An IP matching a local interface address must be refused."""
        engine = _make_engine()
        with patch(
            "backend.services.prevention_service._is_own_address",
            return_value=True,
        ):
            result = engine.block_ip("1.2.3.4", "test", "evt-6")
        assert result is False

    def test_own_address_bypass_with_allow(self):
        """allow_private_block=True also bypasses the own-address check."""
        engine = _make_engine()
        with patch(
            "backend.services.prevention_service._is_own_address",
            return_value=True,
        ):
            with patch.object(engine, "_run_iptables", return_value=True):
                result = engine.block_ip("1.2.3.4", "test", "evt-7", allow_private_block=True)
        assert result is True
