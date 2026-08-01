"""
test_security_headers.py — Unit tests for add_security_headers() middleware.

Covers:
    (a) HTTP request → CSP present, HSTS absent, Permissions-Policy present
    (b) HTTPS request (is_secure=True) → HSTS present

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from conftest_app import make_test_app
_CSP_VALUE = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "connect-src 'self' ws: wss:; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'"
)


@pytest.fixture
def client():
    app, _ = make_test_app()
    with app.test_client() as c:
        yield c


class TestSecurityHeadersOverHttp:
    """(a) Plain HTTP: CSP and Permissions-Policy are present; HSTS is absent."""

    def test_csp_header_present(self, client):
        resp = client.get("/api/v1/health")
        assert "Content-Security-Policy" in resp.headers

    def test_csp_header_value(self, client):
        resp = client.get("/api/v1/health")
        assert resp.headers["Content-Security-Policy"] == _CSP_VALUE

    def test_permissions_policy_present(self, client):
        resp = client.get("/api/v1/health")
        assert resp.headers.get("Permissions-Policy") == "geolocation=(), microphone=(), camera=()"

    def test_hsts_absent_over_http(self, client):
        resp = client.get("/api/v1/health")
        assert "Strict-Transport-Security" not in resp.headers

    def test_existing_headers_still_present(self, client):
        resp = client.get("/api/v1/health")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("X-XSS-Protection") == "1; mode=block"
        assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


class TestSecurityHeadersOverHttps:
    """(b) HTTPS (is_secure=True): HSTS must be present."""

    def test_hsts_present_when_secure(self):
        """Call add_security_headers directly inside an HTTPS request context."""
        from flask import Flask
        from backend.middleware.security_headers import add_security_headers

        app = Flask(__name__)
        with app.test_request_context("https://localhost/"):
            resp = app.response_class(status=200)
            result = add_security_headers(resp)
            assert "Strict-Transport-Security" in result.headers

    def test_hsts_value_correct(self):
        """HSTS value matches the spec exactly."""
        from flask import Flask
        from backend.middleware.security_headers import add_security_headers

        app = Flask(__name__)
        with app.test_request_context("https://localhost/"):
            resp = app.response_class(status=200)
            result = add_security_headers(resp)
            assert result.headers["Strict-Transport-Security"] == "max-age=63072000; includeSubDomains"

    def test_hsts_absent_over_plain_http(self):
        """HSTS must be absent over plain HTTP."""
        from flask import Flask
        from backend.middleware.security_headers import add_security_headers

        app = Flask(__name__)
        with app.test_request_context("http://localhost/"):
            resp = app.response_class(status=200)
            result = add_security_headers(resp)
            assert "Strict-Transport-Security" not in result.headers
