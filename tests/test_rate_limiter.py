"""
test_rate_limiter.py — Unit tests for RateLimiter._client_ip() proxy trust logic.

Covers:
    (a) TRUST_PROXY_HEADERS unset (default false) → X-Forwarded-For ignored
    (b) TRUST_PROXY_HEADERS=true → X-Forwarded-For leftmost IP is used

Requirements: 2.1, 2.2, 2.3
"""

from __future__ import annotations

import sys
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from conftest_app import make_test_app
from backend.middleware.rate_limiter import RateLimiter


# ---------------------------------------------------------------------------
# (a) TRUST_PROXY_HEADERS unset → X-Forwarded-For is ignored
# ---------------------------------------------------------------------------

class TestTrustProxyHeadersDisabled:
    def test_xff_ignored_when_trust_not_set(self, monkeypatch):
        """X-Forwarded-For must not override remote_addr when TRUST_PROXY_HEADERS is unset."""
        monkeypatch.delenv("TRUST_PROXY_HEADERS", raising=False)
        app, _ = make_test_app()
        limiter = RateLimiter()
        with app.test_request_context(
            "/api/v1/health",
            headers={"X-Forwarded-For": "9.9.9.9"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        ):
            ip = limiter._client_ip()
        assert ip == "127.0.0.1"
        assert ip != "9.9.9.9"

    def test_xff_ignored_when_trust_explicitly_false(self, monkeypatch):
        """X-Forwarded-For must not override remote_addr when TRUST_PROXY_HEADERS=false."""
        monkeypatch.setenv("TRUST_PROXY_HEADERS", "false")
        app, _ = make_test_app()
        limiter = RateLimiter()
        with app.test_request_context(
            "/api/v1/health",
            headers={"X-Forwarded-For": "10.0.0.1, 172.16.0.1"},
            environ_base={"REMOTE_ADDR": "192.168.1.5"},
        ):
            ip = limiter._client_ip()
        assert ip == "192.168.1.5"

    def test_returns_unknown_when_no_remote_addr_and_trust_off(self, monkeypatch):
        """Falls back to 'unknown' when remote_addr is absent and trust is off."""
        monkeypatch.delenv("TRUST_PROXY_HEADERS", raising=False)
        app, _ = make_test_app()
        limiter = RateLimiter()
        with app.test_request_context(
            "/api/v1/health",
            headers={"X-Forwarded-For": "9.9.9.9"},
            environ_base={"REMOTE_ADDR": ""},
        ):
            ip = limiter._client_ip()
        # remote_addr is "" which is falsy — must fall back to "unknown"
        assert ip == "unknown"


# ---------------------------------------------------------------------------
# (b) TRUST_PROXY_HEADERS=true → X-Forwarded-For leftmost IP is used
# ---------------------------------------------------------------------------

class TestTrustProxyHeadersEnabled:
    def test_xff_leftmost_returned_when_trust_enabled(self, monkeypatch):
        """Leftmost IP from X-Forwarded-For is returned when TRUST_PROXY_HEADERS=true."""
        monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
        app, _ = make_test_app()
        limiter = RateLimiter()
        with app.test_request_context(
            "/api/v1/health",
            headers={"X-Forwarded-For": "9.9.9.9, 10.0.0.1"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        ):
            ip = limiter._client_ip()
        assert ip == "9.9.9.9"

    def test_xff_single_ip_returned_when_trust_enabled(self, monkeypatch):
        """Single X-Forwarded-For IP is returned directly when TRUST_PROXY_HEADERS=true."""
        monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
        app, _ = make_test_app()
        limiter = RateLimiter()
        with app.test_request_context(
            "/api/v1/health",
            headers={"X-Forwarded-For": "203.0.113.5"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        ):
            ip = limiter._client_ip()
        assert ip == "203.0.113.5"

    def test_falls_back_to_remote_addr_when_xff_absent_and_trust_enabled(self, monkeypatch):
        """Falls back to remote_addr when X-Forwarded-For is absent even with trust enabled."""
        monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
        app, _ = make_test_app()
        limiter = RateLimiter()
        with app.test_request_context(
            "/api/v1/health",
            environ_base={"REMOTE_ADDR": "192.168.1.1"},
        ):
            ip = limiter._client_ip()
        assert ip == "192.168.1.1"
