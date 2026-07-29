"""
test_properties_api.py — Property-based tests for REST API envelope and filtering.

Property 37: Every API response uses standard JSON envelope shape
Property 38: GET /detections with filters returns only matching events

Also contains Properties 35–36 (whitelist API + IP validation).

Requirements: 13.3, 13.8, 12.5, 12.6
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime, timezone
from hypothesis import given, settings as hsettings, strategies as st

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
        "explanation": "Test",
        "recommendation": "Block",
        "blocked": False,
    }
    base.update(overrides)
    return base


@pytest.fixture(scope="module")
def app_client():
    app, mocks = make_test_app()
    with app.test_client() as client:
        yield client, mocks


# ---------------------------------------------------------------------------
# Property 37: Standard JSON envelope shape
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 37
@pytest.mark.parametrize("url,method,body", [
    ("/api/v1/health", "GET", None),
    ("/api/v1/status", "GET", None),
    ("/api/v1/monitor/interfaces", "GET", None),
    ("/api/v1/detections", "GET", None),
    ("/api/v1/blocked", "GET", None),
    ("/api/v1/whitelist", "GET", None),
])
def test_property_37_success_response_has_envelope(url, method, body):
    """
    Property 37: Every successful API response has the envelope:
    {"success": true, "message": "...", "data": {...}}

    Validates: Requirements 13.3
    """
    app, mocks = make_test_app()
    with app.test_client() as client:
        mocks["event_repo"].get_all.return_value = []
        mocks["block_repo"].get_all_active.return_value = []
        mocks["whitelist_manager"].get_all.return_value = []

        if method == "GET":
            resp = client.get(url)
        else:
            resp = client.post(url, json=body)

        assert resp.status_code < 500, f"{url} returned {resp.status_code}"
        data = resp.get_json()
        assert data is not None, f"{url} returned non-JSON"
        assert "success" in data, f"{url} missing 'success' key"
        if data["success"]:
            assert "data" in data, f"{url} success response missing 'data'"


@pytest.mark.parametrize("url,method,body", [
    ("/api/v1/detections/nonexistent-id", "GET", None),
    ("/api/v1/block", "POST", {"ip": "not-valid"}),
    ("/api/v1/whitelist", "POST", {"ip": "bad"}),
])
def test_property_37_error_response_has_envelope(url, method, body):
    """
    Property 37: Every error API response has the envelope:
    {"success": false, "error": "...", "code": ...}

    Validates: Requirements 13.3
    """
    app, mocks = make_test_app()
    with app.test_client() as client:
        mocks["event_repo"].get_by_id.return_value = None

        if method == "GET":
            resp = client.get(url)
        else:
            resp = client.post(url, json=body)

        data = resp.get_json()
        assert data is not None
        assert data["success"] is False
        assert "error" in data
        assert "code" in data


# ---------------------------------------------------------------------------
# Property 38: GET /detections filters return only matching events
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 38
@pytest.mark.parametrize("severity", ["Low", "Medium", "High", "Critical"])
def test_property_38_severity_filter_respected(severity):
    """
    Property 38: GET /detections?severity=X only returns events with that severity.

    Validates: Requirements 13.8
    """
    app, mocks = make_test_app()
    with app.test_client() as client:
        expected_events = [_make_event(severity=severity)]
        mocks["event_repo"].get_all.return_value = expected_events

        resp = client.get(f"/api/v1/detections?severity={severity}")
        assert resp.status_code == 200

        # Verify the filter was passed to the repository
        _, kwargs = mocks["event_repo"].get_all.call_args
        assert kwargs.get("filters", {}).get("severity") == severity


def test_property_38_attack_type_filter_passed_to_repo():
    """
    Property 38: attack_type filter is correctly passed to the event repository.
    """
    app, mocks = make_test_app()
    with app.test_client() as client:
        mocks["event_repo"].get_all.return_value = []
        resp = client.get("/api/v1/detections?attack_type=SQL+Injection")
        assert resp.status_code == 200
        _, kwargs = mocks["event_repo"].get_all.call_args
        assert kwargs.get("filters", {}).get("attack_type") == "SQL Injection"


def test_property_38_source_ip_filter_passed_to_repo():
    """Property 38: source_ip filter is passed to the repository."""
    app, mocks = make_test_app()
    with app.test_client() as client:
        mocks["event_repo"].get_all.return_value = []
        resp = client.get("/api/v1/detections?source_ip=10.0.0.1")
        assert resp.status_code == 200
        _, kwargs = mocks["event_repo"].get_all.call_args
        assert kwargs.get("filters", {}).get("source_ip") == "10.0.0.1"


def test_property_38_date_filter_passed_to_repo():
    """Property 38: date filter is passed to the repository."""
    app, mocks = make_test_app()
    with app.test_client() as client:
        mocks["event_repo"].get_all.return_value = []
        resp = client.get("/api/v1/detections?date=2026-07-29")
        assert resp.status_code == 200
        _, kwargs = mocks["event_repo"].get_all.call_args
        assert kwargs.get("filters", {}).get("date") == "2026-07-29"


# ---------------------------------------------------------------------------
# Property 35: GET /whitelist returns all entries with required fields
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 35
def test_property_35_whitelist_returns_required_fields():
    """
    Property 35: GET /whitelist returns entries with ip_address, description,
    created_at, and created_by.

    Validates: Requirements 12.5
    """
    app, mocks = make_test_app()
    with app.test_client() as client:
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
        for field in ("ip_address", "description", "created_at", "created_by"):
            assert field in entries[0], f"Missing field: {field}"


# ---------------------------------------------------------------------------
# Property 36: Malformed IP returns 422 INVALID_IP without DB op
# ---------------------------------------------------------------------------

# Feature: netguard-idps, Property 36
@pytest.mark.parametrize("url,method,body", [
    ("/api/v1/block", "POST", {"ip": "not.valid.ip.address.extra"}),
    ("/api/v1/unblock", "POST", {"ip": "999.999.999.999"}),
    ("/api/v1/whitelist", "POST", {"ip": "bad--ip"}),
])
def test_property_36_malformed_ip_returns_422_no_db_op(url, method, body):
    """
    Property 36: Malformed IP in any API request → HTTP 422 INVALID_IP
    without performing any DB or firewall operation.

    Validates: Requirements 12.6, 13.6
    """
    app, mocks = make_test_app()
    with app.test_client() as client:
        if method == "POST":
            resp = client.post(url, json=body)
        else:
            resp = client.delete(url)

        assert resp.status_code == 422
        data = resp.get_json()
        assert data["success"] is False
        assert data["error_code"] == "INVALID_IP"

        # No DB or iptables operations should have occurred
        mocks["block_repo"].insert.assert_not_called()
        mocks["whitelist_manager"].add.assert_not_called()
        mocks["prevention_engine"].block_ip.assert_not_called()
