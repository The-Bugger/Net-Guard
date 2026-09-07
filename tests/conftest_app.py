"""
conftest_app.py — Flask test client factory for API tests.

Provides a minimal app with mocked services for testing routes in isolation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

from flask.testing import FlaskClient


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_future(s: int = 120) -> str:
    from datetime import timedelta
    dt = datetime.now(timezone.utc) + timedelta(seconds=s)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_test_app(config: dict | None = None, auth_role: str | None = "admin") -> tuple:
    """
    Build a minimal Flask test app with all services mocked.
    Returns (app, mocks_dict).

    Args:
        config: Optional Flask config overrides.
        auth_role: Role injected into ``g.current_user`` for every request
            (RBAC decorators consult it). Defaults to "admin" so existing
            handler-level tests keep exercising route logic without wiring
            real JWTs. Pass None to leave the request anonymous — used by
            tests that assert 401/403 enforcement on protected routes.
    """
    # Must import after any eventlet patching is NOT in effect
    from backend.api import create_app
    from backend.api import dependencies

    # Build mocks
    mocks = {
        "monitor_service": MagicMock(),
        "monitoring_state": MagicMock(active=False, interface="", packets_processed=0, active_blocks=0),
        "detection_engine": MagicMock(is_running=False),
        "prevention_engine": MagicMock(),
        "whitelist_manager": MagicMock(),
        "event_repo": MagicMock(),
        "block_repo": MagicMock(),
        "log_repo": MagicMock(),
        "stats_service": MagicMock(),
        "config": MagicMock(),
        "log_engine": MagicMock(),
    }

    # Configure default return values
    mocks["monitor_service"].get_interfaces.return_value = ["eth0", "lo"]
    mocks["monitor_service"].start_monitoring.return_value = None
    mocks["monitor_service"].stop_monitoring.return_value = None
    mocks["whitelist_manager"].get_all.return_value = []
    mocks["whitelist_manager"].is_whitelisted.return_value = False
    mocks["event_repo"].get_all.return_value = []
    mocks["event_repo"].get_by_id.return_value = None
    mocks["event_repo"].count_filtered.return_value = 0
    mocks["block_repo"].get_all_active.return_value = []
    mocks["block_repo"].get_active.return_value = None
    mocks["block_repo"].is_blocked.return_value = False
    mocks["prevention_engine"].block_ip.return_value = True
    mocks["prevention_engine"].unblock_ip.return_value = True
    mocks["prevention_engine"]._block_duration = 120
    mocks["config"].validate_settings.return_value = []
    mocks["config"].update.return_value = None
    mocks["config"].get.return_value = None
    mocks["stats_service"].get_health_score.return_value = 100
    mocks["stats_service"].get_dashboard_data.return_value = {
        "total_events": 0, "alerts_today": 0, "active_blocks": 0,
        "packets_processed": 0, "packets_per_second": 0,
        "blocked_ips_total": 0, "detection_accuracy": 0, "health_score": 100,
    }
    mocks["stats_service"].invalidate_cache.return_value = None

    # Register all mocks
    for name, mock in mocks.items():
        dependencies.register(name, mock)

    # Override async_mode to threading for test compatibility (eventlet breaks on Python 3.14)
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "SOCKETIO_ASYNC_MODE": "threading"})
    app.config["TESTING"] = True

    # Test identity injection — production authn is covered by the JWT
    # before_request hook (test_auth_middleware.py); here we simulate a fully
    # authenticated principal so @require_role decorators see a user.
    if auth_role is not None:
        from flask import g as _flask_g

        @app.before_request
        def _inject_test_user():  # pragma: no cover — test scaffolding
            _flask_g.current_user = {"sub": "tester", "role": auth_role}

    return app, mocks
