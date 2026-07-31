"""
test_hackathon_upgrade.py — Unit/example tests for NetGuard Hackathon Upgrade components.

Covers: DemoService routes, AIExplainService, ExportService, timeline, health score,
        rate limiter, pagination, security headers, input hardening, dashboard cache.

Requirements: 1.1–1.8, 2.1–2.10, 4.5, 6.1–6.7, 7.1–7.2, 8.6–8.7,
              9.2–9.3, 10.2–10.4, 11.1–11.4, 12.2–12.3
"""

from __future__ import annotations

import sys
import os
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from unittest.mock import MagicMock, patch
from conftest_app import make_test_app, _utc_now


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(**overrides):
    """Minimal event dict for seeding mocks."""
    base = {
        "event_id": str(uuid.uuid4()),
        "timestamp": _utc_now(),
        "attack_type": "SQL Injection",
        "source_ip": "192.0.2.1",
        "destination_ip": "10.0.0.1",
        "protocol": "TCP",
        "rule_name": "SQL_INJECTION_001",
        "severity": "High",
        "confidence": 100,
        "packet_count": 1,
        "evidence": "{}",
        "explanation": "SQL injection detected",
        "recommendation": "Use parameterised queries",
        "blocked": False,
    }
    base.update(overrides)
    return base


def _demo_svc_mock(is_active=False):
    """Build a MagicMock that quacks like DemoService."""
    svc = MagicMock()
    svc.is_active = is_active
    svc.get_status.return_value = {
        "active": is_active,
        "events_generated": 0,
        "started_at": None,
    }
    svc.trigger.return_value = str(uuid.uuid4())
    return svc


@pytest.fixture
def client_mocks():
    """Flask test client + mocks dict from conftest_app."""
    app, mocks = make_test_app()
    with app.test_client() as client:
        yield client, mocks


# ---------------------------------------------------------------------------
# Demo lifecycle — Req 1.1, 1.4
# ---------------------------------------------------------------------------

class TestDemoStartStop:

    def test_demo_start_stop(self, client_mocks):
        """Start returns 200; stop (while active) also returns 200. Req 1.1, 1.4."""
        client, mocks = client_mocks
        svc = _demo_svc_mock(is_active=False)
        from backend.api import dependencies
        dependencies.register("demo_service", svc)

        resp = client.post("/api/v1/demo/start")
        assert resp.status_code == 200
        svc.start.assert_called_once()

        # Simulate active after start
        svc.is_active = True
        resp = client.post("/api/v1/demo/stop")
        assert resp.status_code == 200
        svc.stop.assert_called_once()

    def test_demo_double_start_409(self, client_mocks):
        """Starting while already active → 409 DEMO_ALREADY_RUNNING. Req 1.2."""
        client, mocks = client_mocks
        svc = _demo_svc_mock(is_active=True)
        from backend.api import dependencies
        dependencies.register("demo_service", svc)

        resp = client.post("/api/v1/demo/start")
        assert resp.status_code == 409
        data = resp.get_json()
        assert data["error_code"] == "DEMO_ALREADY_RUNNING"

    def test_demo_stop_when_inactive_409(self, client_mocks):
        """Stopping while not running → 409 DEMO_NOT_RUNNING. Req 1.5."""
        client, mocks = client_mocks
        svc = _demo_svc_mock(is_active=False)
        from backend.api import dependencies
        dependencies.register("demo_service", svc)

        resp = client.post("/api/v1/demo/stop")
        assert resp.status_code == 409
        data = resp.get_json()
        assert data["error_code"] == "DEMO_NOT_RUNNING"


# ---------------------------------------------------------------------------
# Attack trigger — Req 7.1, 7.2
# ---------------------------------------------------------------------------

_ALL_ATTACK_TYPES = [
    "SQL Injection",
    "Brute Force",
    "Port Scan",
    "DDoS/SYN Flood",
    "XSS",
    "SSH Login",
    "Suspicious DNS",
    "Malware Download",
    "Privilege Escalation",
]


class TestDemoTrigger:

    def test_demo_trigger_all_9_types(self, client_mocks):
        """Each of the 9 attack types triggers an event and returns event_id. Req 7.1."""
        client, mocks = client_mocks
        svc = _demo_svc_mock(is_active=False)
        from backend.api import dependencies
        dependencies.register("demo_service", svc)

        for attack_type in _ALL_ATTACK_TYPES:
            fixed_id = str(uuid.uuid4())
            svc.trigger.return_value = fixed_id
            resp = client.post(
                "/api/v1/demo/trigger",
                json={"attack_type": attack_type},
            )
            assert resp.status_code == 200, f"Failed for attack_type={attack_type!r}"
            data = resp.get_json()
            assert "event_id" in data["data"], (
                f"Missing event_id in response for attack_type={attack_type!r}"
            )
            assert data["data"]["event_id"] == fixed_id

    def test_demo_trigger_unknown_422(self, client_mocks):
        """Unknown attack_type → 422 INVALID_ATTACK_TYPE. Req 7.2."""
        client, mocks = client_mocks
        svc = _demo_svc_mock(is_active=False)
        svc.trigger.side_effect = ValueError("Unknown attack_type")
        from backend.api import dependencies
        dependencies.register("demo_service", svc)

        resp = client.post(
            "/api/v1/demo/trigger",
            json={"attack_type": "Laser Beam Attack"},
        )
        assert resp.status_code == 422
        assert resp.get_json()["error_code"] == "INVALID_ATTACK_TYPE"


# ---------------------------------------------------------------------------
# AIExplainService — Req 2.3, 2.5, 2.7
# ---------------------------------------------------------------------------

class TestAIExplainService:

    def test_ai_provider_stub_default(self):
        """When AI_PROVIDER is unset, stub provider is used (is_fallback=False). Req 2.3."""
        from detection.rules.base_rule import ThreatEvent, Explanation
        from backend.services.ai_explain_service import AIExplainService

        env_without_provider = {k: v for k, v in os.environ.items() if k != "AI_PROVIDER"}
        with patch.dict(os.environ, env_without_provider, clear=True):
            svc = AIExplainService()
            assert svc._provider == "stub"

            threat = ThreatEvent(
                event_id=str(uuid.uuid4()),
                timestamp=_utc_now(),
                attack_type="SQL Injection",
                source_ip="192.0.2.1",
                destination_ip="10.0.0.1",
                source_port=None,
                destination_port=80,
                protocol="TCP",
                rule_name="SQL_INJECTION_001",
                severity="High",
                confidence=100,
                packet_count=1,
                evidence={},
                blocked=False,
            )
            base_expl = Explanation(
                attack_name="SQL Injection",
                rule_triggered="SQL_INJECTION_001",
                plain_english_text="SQL injection detected.",
                evidence={},
                confidence_score=100,
                severity="High",
                recommendation="Use parameterised queries.",
            )
            result = svc.generate(threat, base_expl)
            assert result.is_fallback is False
            assert result.markdown_report

    def test_ai_fallback_on_provider_error(self):
        """When provider raises, generate() returns stub with is_fallback=True. Req 2.5."""
        import os
        from detection.rules.base_rule import ThreatEvent, Explanation
        from backend.services.ai_explain_service import AIExplainService

        threat = ThreatEvent(
            event_id=str(uuid.uuid4()),
            timestamp=_utc_now(),
            attack_type="Brute Force",
            source_ip="198.51.100.1",
            destination_ip="10.0.0.1",
            source_port=None,
            destination_port=22,
            protocol="TCP",
            rule_name="BRUTE_FORCE_001",
            severity="Medium",
            confidence=75,
            packet_count=15,
            evidence={},
            blocked=False,
        )
        base_expl = Explanation(
            attack_name="Brute Force",
            rule_triggered="BRUTE_FORCE_001",
            plain_english_text="Brute force detected.",
            evidence={},
            confidence_score=75,
            severity="Medium",
            recommendation="Enable lockout.",
        )

        with patch.dict(os.environ, {"AI_PROVIDER": "gemini"}):
            svc = AIExplainService()
            # Patch _call_gemini to raise to simulate provider failure
            with patch.object(svc, "_call_gemini", side_effect=RuntimeError("network error")):
                # _call_provider dispatches to _call_gemini; patch it to raise,
                # then the fallback inside _call_gemini catches and returns stub.
                # Instead, patch _call_provider to raise so _stub_response path is forced:
                pass

        # Simpler: set provider to gemini but make _call_gemini itself raise
        with patch.dict(os.environ, {"AI_PROVIDER": "gemini"}):
            svc = AIExplainService()

        # The real _call_gemini has a try/except → falls back to stub with is_fallback=True
        # We simulate a missing gemini package so it raises ImportError (the real fallback path)
        with patch.dict(os.environ, {"AI_PROVIDER": "gemini"}):
            svc = AIExplainService()
            # Patch google.generativeai import to fail → _call_gemini catches → fallback
            import builtins
            real_import = builtins.__import__

            def _no_genai(name, *args, **kwargs):
                if name == "google.generativeai":
                    raise ImportError("mocked: no genai")
                return real_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=_no_genai):
                result = svc.generate(threat, base_expl)

        assert result.is_fallback is True

    def test_ai_lru_eviction(self):
        """Inserting 101 entries evicts the oldest. Req 2.7."""
        from detection.rules.base_rule import ThreatEvent, Explanation
        from backend.services.ai_explain_service import AIExplainService

        svc = AIExplainService()
        assert svc._CACHE_SIZE == 100

        def _make_threat(eid):
            return ThreatEvent(
                event_id=eid,
                timestamp=_utc_now(),
                attack_type="Port Scan",
                source_ip="192.0.2.1",
                destination_ip="10.0.0.1",
                source_port=None,
                destination_port=None,
                protocol="TCP",
                rule_name="PORT_SCAN_001",
                severity="Medium",
                confidence=80,
                packet_count=1,
                evidence={},
                blocked=False,
            )

        base_expl = Explanation(
            attack_name="Port Scan",
            rule_triggered="PORT_SCAN_001",
            plain_english_text="Port scan.",
            evidence={},
            confidence_score=80,
            severity="Medium",
            recommendation="Block.",
        )

        # Insert 101 unique event_ids → oldest (first) must be evicted
        first_id = str(uuid.uuid4())
        ids = [first_id] + [str(uuid.uuid4()) for _ in range(100)]
        for eid in ids:
            threat = _make_threat(eid)
            svc.generate(threat, base_expl)

        # Cache should have exactly 100 entries
        assert len(svc._cache) == 100
        # The first one must have been evicted
        assert first_id not in svc._cache


# ---------------------------------------------------------------------------
# ExportService — Req 6.1–6.4, 6.7
# ---------------------------------------------------------------------------

class TestExportRoutes:

    def _make_client(self, event_list=None):
        app, mocks = make_test_app()
        if event_list is not None:
            mocks["event_repo"].get_all.return_value = event_list
        return app.test_client(), mocks

    def test_export_json_csv_markdown_headers(self):
        """Content-Disposition filename matches netguard-export-YYYY-MM-DD.{ext}. Req 6.1–6.3."""
        import re
        events = [_make_event()]

        with self._make_client(events)[0] as client:
            for fmt in ("json", "csv", "markdown"):
                resp = client.get(f"/api/v1/export?format={fmt}")
                assert resp.status_code == 200, f"format={fmt}: got {resp.status_code}"
                cd = resp.headers.get("Content-Disposition", "")
                # Must contain netguard-export-YYYY-MM-DD.<ext>
                expected_ext = "md" if fmt == "markdown" else fmt
                assert re.search(
                    rf"netguard-export-\d{{4}}-\d{{2}}-\d{{2}}\.{expected_ext}", cd
                ), f"format={fmt}: Content-Disposition={cd!r} does not match expected pattern"

    def test_export_pdf_501_without_library(self):
        """PDF export with no reportlab/weasyprint installed → 501 PDF_NOT_SUPPORTED. Req 6.4."""
        with self._make_client()[0] as client:
            with patch(
                "backend.services.export_service.ExportService.export_pdf",
                side_effect=ImportError("no pdf library"),
            ):
                resp = client.get("/api/v1/export?format=pdf")
        assert resp.status_code == 501
        assert resp.get_json()["error_code"] == "PDF_NOT_SUPPORTED"

    def test_export_invalid_format_400(self):
        """Unknown format → 400 INVALID_EXPORT_FORMAT. Req 6.7."""
        with self._make_client()[0] as client:
            resp = client.get("/api/v1/export?format=xml")
        assert resp.status_code == 400
        assert resp.get_json()["error_code"] == "INVALID_EXPORT_FORMAT"


# ---------------------------------------------------------------------------
# Timeline — Req 4.5, 4.2
# ---------------------------------------------------------------------------

class TestTimeline:

    def test_timeline_404_nonexistent(self, client_mocks):
        """Non-existent event_id → 404 NOT_FOUND. Req 4.5."""
        client, mocks = client_mocks
        mocks["event_repo"].get_by_id.return_value = None

        resp = client.get(f"/api/v1/timeline/{uuid.uuid4()}")
        assert resp.status_code == 404
        assert resp.get_json()["error_code"] == "NOT_FOUND"

    def test_timeline_detected_step_always_first(self, client_mocks):
        """Timeline for a known event always starts with Detected/completed. Req 4.2."""
        client, mocks = client_mocks
        eid = str(uuid.uuid4())
        mocks["event_repo"].get_by_id.return_value = _make_event(
            event_id=eid,
            rule_name="SQL_INJECTION_001",
        )
        mocks["block_repo"].get_active.return_value = None

        resp = client.get(f"/api/v1/timeline/{eid}")
        assert resp.status_code == 200
        entries = resp.get_json()["data"]["timeline"]
        assert entries[0]["step_name"] == "Detected"
        assert entries[0]["status"] == "completed"


# ---------------------------------------------------------------------------
# Health score — Req 9.2, 9.3
# ---------------------------------------------------------------------------

class TestHealthScore:

    def test_health_score_in_status_and_dashboard(self, client_mocks):
        """GET /status and GET /dashboard both include health_score. Req 9.2, 9.3."""
        client, mocks = client_mocks
        mocks["stats_service"].get_health_score.return_value = 75
        mocks["stats_service"].get_dashboard_data.return_value = {
            "health_score": 75,
            "monitoring": False,
            "interface": "",
            "packets": 0,
            "alerts": 0,
            "alerts_today": 0,
            "blocked_ips": 0,
            "traffic_rate": 0.0,
            "top_attack": "",
            "recent_events": [],
            "active_blocks": [],
            "attack_type_counts": [],
        }

        # /status
        resp = client.get("/api/v1/status")
        assert resp.status_code == 200
        status_data = resp.get_json()["data"]
        assert "health_score" in status_data, "/status missing health_score"
        assert status_data["health_score"] == 75

        # /dashboard
        resp = client.get("/api/v1/dashboard")
        assert resp.status_code == 200
        dash_data = resp.get_json()["data"]
        assert "health_score" in dash_data, "/dashboard missing health_score"
        assert dash_data["health_score"] == 75


# ---------------------------------------------------------------------------
# Rate limiter — Req 10.2, 10.3, 10.4
# ---------------------------------------------------------------------------

def _make_rate_limit_app():
    """Minimal Flask app with RateLimiter only."""
    from flask import Flask, jsonify
    from backend.middleware.rate_limiter import RateLimiter

    app = Flask(__name__)
    app.config["TESTING"] = True

    limiter = RateLimiter()
    app.before_request(limiter.check)

    @app.route("/api/v1/detections")
    def detections():
        return jsonify({"ok": True}), 200

    @app.route("/api/v1/status")
    def status():
        return jsonify({"ok": True}), 200

    @app.route("/api/v1/health")
    def health():
        return jsonify({"ok": True}), 200

    return app


class TestRateLimiter:

    def test_rate_limit_retry_after_header(self):
        """On 429, Retry-After header must be present. Req 10.2."""
        app = _make_rate_limit_app()
        ip = "10.1.2.3"
        headers = {"X-Forwarded-For": ip}

        with app.test_client() as client:
            # Exhaust allowance
            for _ in range(120):
                client.get("/api/v1/detections", headers=headers)

            resp = client.get("/api/v1/detections", headers=headers)
            assert resp.status_code == 429
            assert "Retry-After" in resp.headers
            assert int(resp.headers["Retry-After"]) > 0

    def test_rate_limiter_exempted_endpoints_not_blocked(self):
        """
        Exempt endpoints (/api/v1/health, /api/v1/status) are never blocked even
        when the window is exhausted. Req 10.3, 10.4.
        """
        app = _make_rate_limit_app()
        ip = "10.5.6.7"
        headers = {"X-Forwarded-For": ip}

        with app.test_client() as client:
            # Send 200 requests to a non-exempt endpoint to saturate the window
            for _ in range(200):
                client.get("/api/v1/detections", headers=headers)

            # Exempt endpoints must still return 200
            for exempt_path in ("/api/v1/health", "/api/v1/status"):
                resp = client.get(exempt_path, headers=headers)
                assert resp.status_code == 200, (
                    f"{exempt_path} returned {resp.status_code} but should be 200 (exempt)"
                )


# ---------------------------------------------------------------------------
# Pagination — Req 8.6, 8.7
# ---------------------------------------------------------------------------

class TestPagination:

    def test_pagination_clamp_to_500(self, client_mocks):
        """limit > 500 is silently clamped to 500, returns 200. Req 8.6."""
        client, mocks = client_mocks
        mocks["event_repo"].get_all.return_value = []
        mocks["event_repo"].count_filtered.return_value = 0

        resp = client.get("/api/v1/detections?limit=9999")
        assert resp.status_code == 200
        # Verify the actual call used limit=500 not 9999
        _, kwargs = mocks["event_repo"].get_all.call_args
        assert kwargs.get("limit", 9999) <= 500, (
            f"Expected limit clamped to 500, got {kwargs.get('limit')}"
        )

    def test_pagination_invalid_422(self, client_mocks):
        """limit < 1 or negative offset → 422 INVALID_PAGINATION_PARAMS. Req 8.7."""
        client, _ = client_mocks

        # limit=0 (below minimum)
        resp = client.get("/api/v1/detections?limit=0")
        assert resp.status_code == 422
        assert resp.get_json()["error_code"] == "INVALID_PAGINATION_PARAMS"

        # negative offset
        resp = client.get("/api/v1/detections?offset=-1")
        assert resp.status_code == 422
        assert resp.get_json()["error_code"] == "INVALID_PAGINATION_PARAMS"

        # non-integer limit
        resp = client.get("/api/v1/detections?limit=abc")
        assert resp.status_code == 422
        assert resp.get_json()["error_code"] == "INVALID_PAGINATION_PARAMS"


# ---------------------------------------------------------------------------
# Security headers — Req 11.1
# ---------------------------------------------------------------------------

_EXPECTED_SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


class TestSecurityHeaders:

    def test_security_headers_on_error_response(self, client_mocks):
        """Security headers present even on error (e.g. 404) responses. Req 11.1."""
        client, mocks = client_mocks
        mocks["event_repo"].get_by_id.return_value = None

        resp = client.get(f"/api/v1/detections/{uuid.uuid4()}")
        assert resp.status_code == 404
        for header, value in _EXPECTED_SEC_HEADERS.items():
            assert header in resp.headers, f"Missing security header: {header}"
            assert resp.headers[header] == value, (
                f"{header}: expected {value!r}, got {resp.headers[header]!r}"
            )


# ---------------------------------------------------------------------------
# Input hardening — Req 11.3, 11.4
# ---------------------------------------------------------------------------

class TestInputHardening:

    def test_input_too_long_422(self, client_mocks):
        """String field > 1024 chars after strip → 422 INPUT_TOO_LONG. Req 11.3."""
        client, _ = client_mocks
        long_value = "A" * 1025
        resp = client.post(
            "/api/v1/demo/trigger",
            json={"attack_type": long_value},
            content_type="application/json",
        )
        assert resp.status_code == 422
        data = resp.get_json()
        assert data.get("error") == "INPUT_TOO_LONG" or data.get("error_code") == "INPUT_TOO_LONG"

    def test_no_traceback_in_response(self, client_mocks):
        """Unhandled exception must not leak traceback text. Req 11.4."""
        client, mocks = client_mocks
        # Make the dashboard data call raise an unexpected exception
        mocks["stats_service"].get_dashboard_data.side_effect = RuntimeError(
            "Traceback (most recent call last):\n  File 'fake.py'"
        )

        resp = client.get("/api/v1/dashboard")
        body = resp.get_data(as_text=True)
        assert "Traceback" not in body, "Response body contains a raw traceback"
        assert "most recent call last" not in body
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# Dashboard cache — Req 12.2, 12.3
# ---------------------------------------------------------------------------

class TestDashboardCache:

    def test_dashboard_cache_hit(self):
        """StatsService returns cached data without re-querying DB within 2s. Req 12.2."""
        from backend.services.stats_service import StatsService

        event_repo = MagicMock()
        block_repo = MagicMock()
        state = MagicMock(active=False, interface="", packets_processed=0)

        block_repo.get_all_active.return_value = []
        event_repo.get_all.return_value = []
        event_repo.count.return_value = 0
        event_repo.count_today.return_value = 0
        event_repo.get_attack_type_counts.return_value = []

        svc = StatsService(event_repo, block_repo, state)

        # First call populates cache
        first = svc.get_dashboard_data()
        call_count_after_first = event_repo.get_all.call_count

        # Second call within 2 seconds must use cache — no extra DB call
        second = svc.get_dashboard_data()
        assert event_repo.get_all.call_count == call_count_after_first, (
            "get_all was called again within cache window — cache miss"
        )
        assert first == second

    def test_dashboard_cache_invalidated_on_new_event(self):
        """invalidate_cache() causes next get_dashboard_data() to re-query DB. Req 12.3."""
        from backend.services.stats_service import StatsService

        event_repo = MagicMock()
        block_repo = MagicMock()
        state = MagicMock(active=False, interface="", packets_processed=0)

        block_repo.get_all_active.return_value = []
        event_repo.get_all.return_value = []
        event_repo.count.return_value = 0
        event_repo.count_today.return_value = 0
        event_repo.get_attack_type_counts.return_value = []

        svc = StatsService(event_repo, block_repo, state)

        svc.get_dashboard_data()
        call_count_after_first = event_repo.get_all.call_count

        # Invalidate then call again — must re-query
        svc.invalidate_cache()
        svc.get_dashboard_data()
        assert event_repo.get_all.call_count > call_count_after_first, (
            "get_all was NOT called after cache invalidation"
        )
