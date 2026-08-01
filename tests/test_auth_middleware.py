"""
test_auth_middleware.py — Unit tests for the API key authentication middleware.

Covers:
    (a) NETGUARD_API_KEY not set → pass through (dev mode)
    (b) Correct X-API-Key header → pass
    (c) Wrong X-API-Key header → 401
    (d) Missing X-API-Key header → 401
    (e) SocketIO path → pass regardless of key
    (f) GET with REQUIRE_AUTH_FOR_READS=false → pass

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6
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

_TEST_KEY = "test-secret-api-key-32-chars-xx"


@pytest.fixture
def client(monkeypatch):
    """Test client with NETGUARD_API_KEY set."""
    monkeypatch.setenv("NETGUARD_API_KEY", _TEST_KEY)
    monkeypatch.delenv("REQUIRE_AUTH_FOR_READS", raising=False)
    app, _ = make_test_app()
    with app.test_client() as c:
        yield c


@pytest.fixture
def client_no_key(monkeypatch):
    """Test client with NETGUARD_API_KEY unset (dev mode)."""
    monkeypatch.delenv("NETGUARD_API_KEY", raising=False)
    monkeypatch.delenv("REQUIRE_AUTH_FOR_READS", raising=False)
    app, _ = make_test_app()
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# (a) No key configured → all requests pass (dev mode)
# ---------------------------------------------------------------------------

class TestNoKeyConfigured:
    def test_post_without_header_passes_when_no_key_set(self, client_no_key):
        # POST to block endpoint; no API key header, no env key → should reach route (not 401)
        resp = client_no_key.post("/api/v1/block", json={"ip": "1.2.3.4"})
        assert resp.status_code != 401

    def test_delete_without_header_passes_when_no_key_set(self, client_no_key):
        resp = client_no_key.delete("/api/v1/whitelist/1.2.3.4")
        assert resp.status_code != 401


# ---------------------------------------------------------------------------
# (b) Correct key → pass
# ---------------------------------------------------------------------------

class TestCorrectKey:
    def test_post_with_correct_key_passes(self, client):
        resp = client.post(
            "/api/v1/block",
            json={"ip": "1.2.3.4"},
            headers={"X-API-Key": _TEST_KEY},
        )
        assert resp.status_code != 401

    def test_put_with_correct_key_passes(self, client):
        resp = client.put(
            "/api/v1/settings",
            json={"syn_flood_threshold": 100},
            headers={"X-API-Key": _TEST_KEY},
        )
        assert resp.status_code != 401


# ---------------------------------------------------------------------------
# (c) Wrong key → 401
# ---------------------------------------------------------------------------

class TestWrongKey:
    def test_post_with_wrong_key_returns_401(self, client):
        resp = client.post(
            "/api/v1/block",
            json={"ip": "1.2.3.4"},
            headers={"X-API-Key": "wrong-key"},
        )
        assert resp.status_code == 401
        body = resp.get_json()
        assert body["success"] is False
        assert body["error_code"] == "UNAUTHORIZED"

    def test_delete_with_wrong_key_returns_401(self, client):
        resp = client.delete(
            "/api/v1/whitelist/1.2.3.4",
            headers={"X-API-Key": "not-the-key"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# (d) Missing header → 401
# ---------------------------------------------------------------------------

class TestMissingHeader:
    def test_post_without_header_returns_401(self, client):
        resp = client.post("/api/v1/block", json={"ip": "1.2.3.4"})
        assert resp.status_code == 401
        body = resp.get_json()
        assert body["success"] is False
        assert "X-API-Key" in body["error"]

    def test_patch_without_header_returns_401(self, client):
        resp = client.patch("/api/v1/settings", json={})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# (e) SocketIO path → pass regardless of key / method
# ---------------------------------------------------------------------------

class TestSocketIOPath:
    def test_socketio_get_passes_when_key_set(self, client):
        resp = client.get("/socket.io/?EIO=4&transport=polling")
        # SocketIO will respond with its own protocol error, not 401
        assert resp.status_code != 401

    def test_socketio_post_passes_when_key_set(self, client):
        resp = client.post("/socket.io/?EIO=4&transport=polling")
        assert resp.status_code != 401


# ---------------------------------------------------------------------------
# (f) GET with REQUIRE_AUTH_FOR_READS=false → pass (no auth enforced)
# ---------------------------------------------------------------------------

class TestGetPassesWithoutAuth:
    def test_get_health_passes_without_key(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code != 401

    def test_get_detections_passes_without_key(self, client):
        resp = client.get("/api/v1/detections")
        assert resp.status_code != 401


# ---------------------------------------------------------------------------
# (bonus) REQUIRE_AUTH_FOR_READS=true enforces auth on GET
# ---------------------------------------------------------------------------

class TestRequireAuthForReads:
    def test_get_returns_401_when_require_reads_enabled_and_no_key(self, monkeypatch):
        monkeypatch.setenv("NETGUARD_API_KEY", _TEST_KEY)
        monkeypatch.setenv("REQUIRE_AUTH_FOR_READS", "true")
        app, _ = make_test_app()
        with app.test_client() as c:
            resp = c.get("/api/v1/detections")
        assert resp.status_code == 401

    def test_get_passes_with_correct_key_when_require_reads_enabled(self, monkeypatch):
        monkeypatch.setenv("NETGUARD_API_KEY", _TEST_KEY)
        monkeypatch.setenv("REQUIRE_AUTH_FOR_READS", "true")
        app, _ = make_test_app()
        with app.test_client() as c:
            resp = c.get("/api/v1/detections", headers={"X-API-Key": _TEST_KEY})
        assert resp.status_code != 401
