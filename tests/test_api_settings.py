"""
test_api_settings.py — REST API tests for PUT /settings.

Tests: valid update applied, invalid range returns 422 VALIDATION_ERROR
with field name, config persisted.

Requirements: 1.4, 1.5
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
# PUT /api/v1/settings
# ---------------------------------------------------------------------------

class TestUpdateSettings:

    def test_valid_update_returns_200(self, client_mocks):
        client, mocks = client_mocks
        mocks["config"].validate_settings.return_value = []
        resp = client.put("/api/v1/settings", json={"syn_flood_threshold": 150})
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True
        mocks["config"].update.assert_called_once_with({"syn_flood_threshold": 150})

    def test_invalid_field_returns_422(self, client_mocks):
        client, mocks = client_mocks
        mocks["config"].validate_settings.return_value = ["syn_flood_threshold"]
        resp = client.put("/api/v1/settings", json={"syn_flood_threshold": -99})
        assert resp.status_code == 422
        data = resp.get_json()
        assert data["error_code"] == "VALIDATION_ERROR"
        assert "syn_flood_threshold" in data["error"]

    def test_invalid_does_not_call_update(self, client_mocks):
        client, mocks = client_mocks
        mocks["config"].validate_settings.return_value = ["block_duration"]
        client.put("/api/v1/settings", json={"block_duration": 99999})
        mocks["config"].update.assert_not_called()

    def test_multiple_invalid_fields_returns_422(self, client_mocks):
        client, mocks = client_mocks
        mocks["config"].validate_settings.return_value = ["syn_flood_threshold", "block_duration"]
        resp = client.put("/api/v1/settings", json={
            "syn_flood_threshold": -1,
            "block_duration": 0
        })
        assert resp.status_code == 422
        error_text = resp.get_json()["error"]
        assert "syn_flood_threshold" in error_text
        assert "block_duration" in error_text

    def test_no_body_returns_400(self, client_mocks):
        client, _ = client_mocks
        resp = client.put("/api/v1/settings")
        assert resp.status_code == 400

    def test_empty_body_returns_400(self, client_mocks):
        client, _ = client_mocks
        resp = client.put("/api/v1/settings", json="not-a-dict")
        assert resp.status_code == 400

    def test_update_called_with_exact_payload(self, client_mocks):
        client, mocks = client_mocks
        mocks["config"].validate_settings.return_value = []
        payload = {"block_duration": 300, "dashboard_refresh_interval": 2}
        client.put("/api/v1/settings", json=payload)
        mocks["config"].update.assert_called_once_with(payload)
