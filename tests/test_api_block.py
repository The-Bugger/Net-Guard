"""
test_api_block.py — REST API tests for /block and /unblock endpoints.

Tests: manual block, unblock, blocked list, duplicate block, invalid IP.

Requirements: 11.7, 13.3, 13.4, 13.6
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from conftest_app import make_test_app, _utc_now, _utc_future


@pytest.fixture
def client_mocks():
    app, mocks = make_test_app()
    with app.test_client() as client:
        yield client, mocks


# ---------------------------------------------------------------------------
# POST /api/v1/block
# ---------------------------------------------------------------------------

class TestBlockIP:

    def test_block_valid_ip_returns_201(self, client_mocks):
        client, mocks = client_mocks
        mocks["prevention_engine"].block_ip.return_value = True
        resp = client.post("/api/v1/block", json={"ip": "10.0.0.5", "reason": "SYN Flood"})
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["success"] is True
        assert data["data"]["ip"] == "10.0.0.5"

    def test_block_missing_ip_returns_400(self, client_mocks):
        client, _ = client_mocks
        resp = client.post("/api/v1/block", json={"reason": "test"})
        assert resp.status_code == 400

    def test_block_invalid_ip_returns_422(self, client_mocks):
        client, _ = client_mocks
        resp = client.post("/api/v1/block", json={"ip": "not-an-ip"})
        assert resp.status_code == 422
        assert resp.get_json()["error_code"] == "INVALID_IP"

    def test_block_iptables_failure_returns_500(self, client_mocks):
        client, mocks = client_mocks
        mocks["prevention_engine"].block_ip.return_value = False
        resp = client.post("/api/v1/block", json={"ip": "10.0.0.5"})
        assert resp.status_code == 500

    def test_block_ipv6_accepted(self, client_mocks):
        client, mocks = client_mocks
        mocks["prevention_engine"].block_ip.return_value = True
        resp = client.post("/api/v1/block", json={"ip": "::1"})
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# POST /api/v1/unblock
# ---------------------------------------------------------------------------

class TestUnblockIP:

    def test_unblock_active_ip_returns_200(self, client_mocks):
        client, mocks = client_mocks
        mocks["block_repo"].is_blocked.return_value = True
        mocks["prevention_engine"].unblock_ip.return_value = True
        resp = client.post("/api/v1/unblock", json={"ip": "10.0.0.5"})
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_unblock_no_active_block_returns_404(self, client_mocks):
        client, mocks = client_mocks
        mocks["block_repo"].is_blocked.return_value = False
        resp = client.post("/api/v1/unblock", json={"ip": "10.0.0.99"})
        assert resp.status_code == 404

    def test_unblock_invalid_ip_returns_422(self, client_mocks):
        client, _ = client_mocks
        resp = client.post("/api/v1/unblock", json={"ip": "bad-ip"})
        assert resp.status_code == 422
        assert resp.get_json()["error_code"] == "INVALID_IP"

    def test_unblock_missing_ip_returns_400(self, client_mocks):
        client, _ = client_mocks
        resp = client.post("/api/v1/unblock", json={})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET /api/v1/blocked
# ---------------------------------------------------------------------------

class TestListBlocked:

    def test_returns_empty_list(self, client_mocks):
        client, mocks = client_mocks
        mocks["block_repo"].get_all_active.return_value = []
        resp = client.get("/api/v1/blocked")
        assert resp.status_code == 200
        assert resp.get_json()["data"]["blocked"] == []

    def test_returns_active_blocks(self, client_mocks):
        client, mocks = client_mocks
        mocks["block_repo"].get_all_active.return_value = [
            {
                "ip_address": "10.0.0.1",
                "blocked_at": _utc_now(),
                "expires_at": _utc_future(120),
                "reason": "SYN Flood",
                "active": True,
            }
        ]
        resp = client.get("/api/v1/blocked")
        assert resp.status_code == 200
        blocked = resp.get_json()["data"]["blocked"]
        assert len(blocked) == 1
        assert blocked[0]["ip_address"] == "10.0.0.1"
        assert "expires_in" in blocked[0]
