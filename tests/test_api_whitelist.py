"""
test_api_whitelist.py — REST API tests for /whitelist endpoints.

Tests: add, delete, list, 404 for nonexistent, 422 for invalid IP.

Requirements: 12.2–12.6
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from conftest_app import make_test_app, _utc_now


@pytest.fixture
def client_mocks():
    app, mocks = make_test_app()
    with app.test_client() as client:
        yield client, mocks


# ---------------------------------------------------------------------------
# GET /api/v1/whitelist
# ---------------------------------------------------------------------------

class TestListWhitelist:

    def test_returns_empty_list(self, client_mocks):
        client, mocks = client_mocks
        mocks["whitelist_manager"].get_all.return_value = []
        resp = client.get("/api/v1/whitelist")
        assert resp.status_code == 200
        assert resp.get_json()["data"]["whitelist"] == []

    def test_returns_entries(self, client_mocks):
        client, mocks = client_mocks
        mocks["whitelist_manager"].get_all.return_value = [
            {
                "ip_address": "192.168.1.1",
                "description": "Gateway",
                "created_at": _utc_now(),
                "created_by": "admin",
            }
        ]
        resp = client.get("/api/v1/whitelist")
        assert resp.status_code == 200
        entries = resp.get_json()["data"]["whitelist"]
        assert len(entries) == 1
        assert entries[0]["ip_address"] == "192.168.1.1"


# ---------------------------------------------------------------------------
# POST /api/v1/whitelist
# ---------------------------------------------------------------------------

class TestAddWhitelist:

    def test_add_valid_ip_returns_201(self, client_mocks):
        client, mocks = client_mocks
        mocks["whitelist_manager"].add.return_value = None
        resp = client.post("/api/v1/whitelist", json={"ip": "10.0.0.1", "description": "Server"})
        assert resp.status_code == 201
        assert resp.get_json()["success"] is True
        mocks["whitelist_manager"].add.assert_called_once_with("10.0.0.1", description="Server")

    def test_add_ipv6_returns_201(self, client_mocks):
        client, mocks = client_mocks
        mocks["whitelist_manager"].add.return_value = None
        resp = client.post("/api/v1/whitelist", json={"ip": "::1"})
        assert resp.status_code == 201

    def test_add_missing_ip_returns_400(self, client_mocks):
        client, _ = client_mocks
        resp = client.post("/api/v1/whitelist", json={"description": "no ip"})
        assert resp.status_code == 400

    def test_add_invalid_ip_returns_422(self, client_mocks):
        client, _ = client_mocks
        resp = client.post("/api/v1/whitelist", json={"ip": "not-valid"})
        assert resp.status_code == 422
        assert resp.get_json()["error_code"] == "INVALID_IP"

    def test_add_no_body_returns_400(self, client_mocks):
        client, _ = client_mocks
        resp = client.post("/api/v1/whitelist")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# DELETE /api/v1/whitelist/<ip>
# ---------------------------------------------------------------------------

class TestDeleteWhitelist:

    def test_delete_existing_ip_returns_204(self, client_mocks):
        client, mocks = client_mocks
        mocks["whitelist_manager"].remove.return_value = True
        resp = client.delete("/api/v1/whitelist/10.0.0.1")
        assert resp.status_code == 204
        assert resp.data == b""

    def test_delete_nonexistent_ip_returns_404(self, client_mocks):
        client, mocks = client_mocks
        mocks["whitelist_manager"].remove.return_value = False
        resp = client.delete("/api/v1/whitelist/10.0.0.99")
        assert resp.status_code == 404
        assert resp.get_json()["error_code"] == "NOT_FOUND"

    def test_delete_invalid_ip_returns_422(self, client_mocks):
        client, _ = client_mocks
        resp = client.delete("/api/v1/whitelist/bad-ip")
        assert resp.status_code == 422
        assert resp.get_json()["error_code"] == "INVALID_IP"

    def test_delete_ipv6_returns_204(self, client_mocks):
        client, mocks = client_mocks
        mocks["whitelist_manager"].remove.return_value = True
        resp = client.delete("/api/v1/whitelist/::1")
        assert resp.status_code == 204
