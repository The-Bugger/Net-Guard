"""
test_rbac_enforcement.py — RBAC and settings-security regression tests.

Added with the audit fixes (C1, C2, H1, H5):

  H1  Mutation routes that previously lacked @require_role now enforce RBAC:
      anonymous callers → 401, viewers → 403, admin/analyst → allowed.
  C1  PUT /settings rejects unknown ``enterprise.*`` keys (e.g. ``jwt_secret``)
      and enforces admin-only sections inside the enterprise sub-dict — closing
      the privilege-escalation chain via arbitrary settings writes.
  H5  PreventionEngine.block_ip(duration=...) applies the per-call duration
      without mutating shared engine state (no TOCTOU with auto-blocks).
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from conftest_app import make_test_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_PROTECTED_MUTATIONS = [
    ("post", "/api/v1/block", {"ip": "1.2.3.4"}),
    ("post", "/api/v1/unblock", {"ip": "1.2.3.4"}),
    ("post", "/api/v1/whitelist", {"ip": "1.2.3.4"}),
    ("delete", "/api/v1/whitelist/1.2.3.4", None),
    ("post", "/api/v1/monitor/start", {"interface": "eth0"}),
    ("post", "/api/v1/monitor/stop", {}),
    ("post", "/api/v1/reset-data", {}),
    ("put", "/api/v1/settings", {"syn_flood_threshold": 150}),
    ("post", "/api/v1/detect", {"attack_type": "SYN Flood", "source_ip": "1.2.3.4",
                                "severity": "High", "rule": "SYN_FLOOD_001"}),
    ("get", "/api/v1/events/some-id/replay", None),
    ("post", "/api/v1/lan-devices/refresh", {}),
]


@pytest.fixture
def anon_client():
    """App with no authenticated principal — @require_role must 401."""
    app, mocks = make_test_app(auth_role=None)
    with app.test_client() as client:
        yield client, mocks


@pytest.fixture
def viewer_client():
    """App with an authenticated viewer — @require_role must 403."""
    app, mocks = make_test_app(auth_role="viewer")
    with app.test_client() as client:
        yield client, mocks


@pytest.fixture
def analyst_client():
    app, mocks = make_test_app(auth_role="analyst")
    with app.test_client() as client:
        yield client, mocks


@pytest.fixture
def admin_client():
    app, mocks = make_test_app(auth_role="admin")
    with app.test_client() as client:
        yield client, mocks


# ---------------------------------------------------------------------------
# H1 — anonymous callers are rejected (401) on every protected mutation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method,path,body", _PROTECTED_MUTATIONS)
class TestAnonymousRejected:
    def test_returns_401_without_user(self, anon_client, method, path, body):
        client, _ = anon_client
        resp = getattr(client, method)(path, json=body)
        assert resp.status_code == 401, f"{method.upper()} {path} → {resp.status_code}"
        data = resp.get_json()
        assert data is not None and data["success"] is False
        assert data["error"] == "UNAUTHORIZED"


# ---------------------------------------------------------------------------
# H1 — viewers cannot mutate (403)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method,path,body", _PROTECTED_MUTATIONS)
class TestViewerForbidden:
    def test_returns_403_for_viewer(self, viewer_client, method, path, body):
        client, _ = viewer_client
        resp = getattr(client, method)(path, json=body)
        assert resp.status_code == 403, f"{method.upper()} {path} → {resp.status_code}"
        data = resp.get_json()
        assert data is not None and data["error"] == "FORBIDDEN"


class TestPrivilegedRolesAllowed:
    """Admin and analyst reach the handler (no 401/403) on analyst-level routes."""

    @pytest.mark.parametrize("method,path,body", [
        ("post", "/api/v1/block", {"ip": "1.2.3.4"}),
        ("post", "/api/v1/unblock", {"ip": "1.2.3.4"}),
        ("post", "/api/v1/whitelist", {"ip": "1.2.3.4"}),
        ("delete", "/api/v1/whitelist/1.2.3.4", None),
        ("post", "/api/v1/monitor/start", {"interface": "eth0"}),
        ("post", "/api/v1/monitor/stop", {}),
        ("post", "/api/v1/lan-devices/refresh", {}),
    ])
    def test_analyst_not_forbidden(self, analyst_client, method, path, body):
        client, _ = analyst_client
        resp = getattr(client, method)(path, json=body)
        assert resp.status_code not in (401, 403), (
            f"{method.upper()} {path} → {resp.status_code}: {resp.get_json()}"
        )

    def test_reset_data_requires_admin(self, analyst_client):
        """reset-data is destructive — analysts are forbidden, admins allowed."""
        client, _ = analyst_client
        resp = client.post("/api/v1/reset-data", json={})
        assert resp.status_code == 403

    def test_reset_data_allowed_for_admin(self, admin_client):
        client, mocks = admin_client
        mocks["event_repo"].count.return_value = 0
        resp = client.post("/api/v1/reset-data", json={})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# C1 — enterprise settings allowlist and section RBAC
# ---------------------------------------------------------------------------

class TestEnterpriseSettingsGuard:

    def test_jwt_secret_write_rejected_even_for_admin(self, admin_client):
        """The escalation chain must be dead: unknown keys are refused outright."""
        client, _ = admin_client
        resp = client.put("/api/v1/settings", json={
            "enterprise": {"jwt_secret": "attacker-controlled-secret"},
        })
        assert resp.status_code == 422
        data = resp.get_json()
        assert data["error_code"] == "UNKNOWN_SETTING"
        assert "jwt_secret" in data["error"]

    def test_unknown_enterprise_key_rejected(self, admin_client):
        client, _ = admin_client
        resp = client.put("/api/v1/settings", json={
            "enterprise": {"totally.made_up": "x"},
        })
        assert resp.status_code == 422
        assert resp.get_json()["error_code"] == "UNKNOWN_SETTING"

    def test_enterprise_must_be_object(self, admin_client):
        client, _ = admin_client
        resp = client.put("/api/v1/settings", json={"enterprise": "oops"})
        assert resp.status_code == 400

    def test_security_section_requires_admin(self, analyst_client):
        client, _ = analyst_client
        resp = client.put("/api/v1/settings", json={
            "enterprise": {"security.mfa_required": "true"},
        })
        assert resp.status_code == 403
        assert resp.get_json()["error_code"] == "FORBIDDEN"

    def test_known_non_admin_enterprise_key_allowed_for_admin(self, admin_client):
        client, _ = admin_client
        resp = client.put("/api/v1/settings", json={
            "enterprise": {"appearance.theme": "light"},
        })
        assert resp.status_code == 200, resp.get_json()

    def test_viewer_cannot_write_settings_at_all(self, viewer_client):
        client, _ = viewer_client
        resp = client.put("/api/v1/settings", json={"syn_flood_threshold": 150})
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# H5 — block_ip duration override is per-call (no shared-state race)
# ---------------------------------------------------------------------------

def _expires_delta_seconds(record: dict) -> float:
    exp_dt = datetime.strptime(
        record["expires_at"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)
    return (exp_dt - datetime.now(timezone.utc)).total_seconds()


class TestBlockDurationPerCall:

    def _engine(self):
        from backend.services.prevention_service import PreventionEngine
        block_repo = MagicMock()
        block_repo.get_active.return_value = None
        block_repo.insert.return_value = True
        return PreventionEngine(block_repo, None, block_duration=120), block_repo

    def test_duration_override_used_without_mutating_shared_state(self):
        engine, block_repo = self._engine()
        with patch("backend.services.prevention_service.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert engine.block_ip("8.8.8.8", "test", "evt-1", duration=55) is True

        # Shared configured duration untouched (concurrent auto-blocks unaffected)
        assert engine._block_duration == 120

        # The persisted record expires in ~55 s, not the configured 120 s
        delta = _expires_delta_seconds(block_repo.insert.call_args[0][0])
        assert 40 <= delta <= 60, f"expected ~55 s expiry, got {delta:.0f} s"

    def test_default_duration_used_when_omitted(self):
        engine, block_repo = self._engine()
        with patch("backend.services.prevention_service.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert engine.block_ip("8.8.8.8", "test", "evt-2") is True
        delta = _expires_delta_seconds(block_repo.insert.call_args[0][0])
        assert 100 <= delta <= 120, f"expected ~120 s expiry, got {delta:.0f} s"

    def test_duration_clamped_to_maximum(self):
        engine, block_repo = self._engine()
        with patch("backend.services.prevention_service.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert engine.block_ip("8.8.8.8", "test", "evt-3", duration=999_999) is True
        delta = _expires_delta_seconds(block_repo.insert.call_args[0][0])
        assert 3590 <= delta <= 3600, f"expected ~3600 s expiry, got {delta:.0f} s"

    def test_non_integer_duration_raises_value_error(self):
        engine, _ = self._engine()
        with pytest.raises(ValueError):
            engine.block_ip("8.8.8.8", "test", "evt-4", duration="not-a-number")

    def test_route_rejects_non_integer_duration_with_422(self, admin_client):
        client, _ = admin_client
        resp = client.post("/api/v1/block", json={"ip": "1.2.3.4", "duration": "abc"})
        assert resp.status_code == 422
        assert resp.get_json()["error_code"] == "VALIDATION_ERROR"

    def test_route_does_not_touch_engine_block_duration(self, admin_client):
        """The route must no longer call set_block_duration (the old TOCTOU)."""
        client, mocks = admin_client
        mocks["prevention_engine"].block_ip.return_value = True
        client.post("/api/v1/block", json={"ip": "1.2.3.4", "duration": 300})
        mocks["prevention_engine"].block_ip.assert_called_once()
        _, kwargs = mocks["prevention_engine"].block_ip.call_args
        assert kwargs.get("duration") == 300
        mocks["prevention_engine"].set_block_duration.assert_not_called()
