"""
test_api_detections.py — REST API tests for /detections endpoints.

Tests: paginated list, filters, single event, 404 for unknown id.

Requirements: 13.3, 13.4, 13.8
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from conftest_app import make_test_app, _utc_now


def _make_event(**overrides):
    base = {
        "event_id": str(uuid.uuid4()),
        "timestamp": _utc_now(),
        "attack_type": "SYN Flood",
        "source_ip": "10.0.0.1",
        "destination_ip": "192.168.1.1",
        "protocol": "TCP",
        "rule_name": "SYN_FLOOD_001",
        "severity": "High",
        "confidence": 85,
        "packet_count": 150,
        "evidence": "{}",
        "explanation": "SYN flood detected",
        "recommendation": "Block IP",
        "blocked": False,
    }
    base.update(overrides)
    return base


@pytest.fixture
def client_mocks():
    app, mocks = make_test_app()
    with app.test_client() as client:
        yield client, mocks


# ---------------------------------------------------------------------------
# GET /api/v1/detections
# ---------------------------------------------------------------------------

class TestListDetections:

    def test_returns_200_with_empty_list(self, client_mocks):
        client, mocks = client_mocks
        mocks["event_repo"].get_all.return_value = []
        resp = client.get("/api/v1/detections")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["data"]["events"] == []

    def test_returns_events(self, client_mocks):
        client, mocks = client_mocks
        events = [_make_event(), _make_event()]
        mocks["event_repo"].get_all.return_value = events
        resp = client.get("/api/v1/detections")
        assert resp.status_code == 200
        assert len(resp.get_json()["data"]["events"]) == 2

    def test_filter_by_severity(self, client_mocks):
        client, mocks = client_mocks
        mocks["event_repo"].get_all.return_value = [_make_event(severity="High")]
        resp = client.get("/api/v1/detections?severity=High")
        assert resp.status_code == 200
        _, kwargs = mocks["event_repo"].get_all.call_args
        assert kwargs.get("filters", {}).get("severity") == "High"

    def test_invalid_severity_returns_422(self, client_mocks):
        client, _ = client_mocks
        resp = client.get("/api/v1/detections?severity=EXTREME")
        assert resp.status_code == 422

    def test_filter_by_attack_type(self, client_mocks):
        client, mocks = client_mocks
        mocks["event_repo"].get_all.return_value = []
        resp = client.get("/api/v1/detections?attack_type=Port+Scan")
        assert resp.status_code == 200
        _, kwargs = mocks["event_repo"].get_all.call_args
        assert kwargs.get("filters", {}).get("attack_type") == "Port Scan"

    def test_filter_by_source_ip(self, client_mocks):
        client, mocks = client_mocks
        mocks["event_repo"].get_all.return_value = []
        resp = client.get("/api/v1/detections?source_ip=10.0.0.1")
        assert resp.status_code == 200
        _, kwargs = mocks["event_repo"].get_all.call_args
        assert kwargs.get("filters", {}).get("source_ip") == "10.0.0.1"

    def test_invalid_source_ip_returns_422(self, client_mocks):
        client, _ = client_mocks
        resp = client.get("/api/v1/detections?source_ip=not-an-ip")
        assert resp.status_code == 422
        assert resp.get_json()["error_code"] == "INVALID_IP"

    def test_filter_by_date(self, client_mocks):
        client, mocks = client_mocks
        mocks["event_repo"].get_all.return_value = []
        resp = client.get("/api/v1/detections?date=2026-07-29")
        assert resp.status_code == 200
        _, kwargs = mocks["event_repo"].get_all.call_args
        assert kwargs.get("filters", {}).get("date") == "2026-07-29"


# ---------------------------------------------------------------------------
# GET /api/v1/detections/<event_id>
# ---------------------------------------------------------------------------

class TestGetDetection:

    def test_returns_event_by_id(self, client_mocks):
        client, mocks = client_mocks
        eid = str(uuid.uuid4())
        event = _make_event(event_id=eid)
        mocks["event_repo"].get_by_id.return_value = event
        resp = client.get(f"/api/v1/detections/{eid}")
        assert resp.status_code == 200
        assert resp.get_json()["data"]["event_id"] == eid

    def test_unknown_id_returns_404(self, client_mocks):
        client, mocks = client_mocks
        mocks["event_repo"].get_by_id.return_value = None
        resp = client.get("/api/v1/detections/nonexistent-id")
        assert resp.status_code == 404
        assert resp.get_json()["error_code"] == "NOT_FOUND"
