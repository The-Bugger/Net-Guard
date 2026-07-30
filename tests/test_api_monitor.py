"""
test_api_monitor.py — REST API tests for /monitor endpoints.

Tests: start/stop happy paths, ALREADY_MONITORING, NOT_MONITORING,
INVALID_INTERFACE, interfaces list.

Requirements: 2.1–2.9
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from conftest_app import make_test_app


@pytest.fixture
def client_mocks():
    app, mocks = make_test_app()
    with app.test_client() as client:
        yield client, mocks


# ---------------------------------------------------------------------------
# GET /api/v1/monitor/interfaces
# ---------------------------------------------------------------------------

class TestListInterfaces:

    def test_returns_200_with_list(self, client_mocks):
        client, mocks = client_mocks
        mocks["monitor_service"].get_interfaces.return_value = ["eth0", "lo", "wlan0"]
        resp = client.get("/api/v1/monitor/interfaces")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "eth0" in data["data"]["interfaces"]

    def test_returns_empty_list_gracefully(self, client_mocks):
        client, mocks = client_mocks
        mocks["monitor_service"].get_interfaces.return_value = []
        resp = client.get("/api/v1/monitor/interfaces")
        assert resp.status_code == 200
        assert resp.get_json()["data"]["interfaces"] == []


# ---------------------------------------------------------------------------
# POST /api/v1/monitor/start
# ---------------------------------------------------------------------------

class TestStartMonitoring:

    def test_start_success(self, client_mocks):
        client, mocks = client_mocks
        resp = client.post("/api/v1/monitor/start", json={"interface": "eth0"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        mocks["monitor_service"].start_monitoring.assert_called_once_with("eth0")

    def test_start_missing_interface_returns_400(self, client_mocks):
        client, _ = client_mocks
        resp = client.post("/api/v1/monitor/start", json={})
        assert resp.status_code == 400

    def test_start_empty_interface_returns_400(self, client_mocks):
        client, _ = client_mocks
        resp = client.post("/api/v1/monitor/start", json={"interface": "  "})
        assert resp.status_code == 400

    def test_already_monitoring_returns_409(self, client_mocks):
        client, mocks = client_mocks
        mocks["monitor_service"].start_monitoring.side_effect = RuntimeError("ALREADY_MONITORING")
        resp = client.post("/api/v1/monitor/start", json={"interface": "eth0"})
        assert resp.status_code == 409
        assert resp.get_json()["error_code"] == "ALREADY_MONITORING"

    def test_invalid_interface_returns_422(self, client_mocks):
        client, mocks = client_mocks
        mocks["monitor_service"].start_monitoring.side_effect = ValueError("INVALID_INTERFACE: noexist")
        resp = client.post("/api/v1/monitor/start", json={"interface": "noexist"})
        assert resp.status_code == 422
        assert resp.get_json()["error_code"] == "INVALID_INTERFACE"


# ---------------------------------------------------------------------------
# POST /api/v1/monitor/stop
# ---------------------------------------------------------------------------

class TestStopMonitoring:

    def test_stop_success(self, client_mocks):
        client, mocks = client_mocks
        resp = client.post("/api/v1/monitor/stop")
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True
        mocks["monitor_service"].stop_monitoring.assert_called_once()

    def test_not_monitoring_returns_409(self, client_mocks):
        client, mocks = client_mocks
        mocks["monitor_service"].stop_monitoring.side_effect = RuntimeError("NOT_MONITORING")
        resp = client.post("/api/v1/monitor/stop")
        assert resp.status_code == 409
        assert resp.get_json()["error_code"] == "NOT_MONITORING"
