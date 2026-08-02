"""
ai_routes.py — AI/anomaly engine calibration endpoints.

GET /api/v1/ai/calibration  — per-IP rolling stats + warm-up status
PUT /api/v1/ai/calibration  — operator manual override of baseline values

Requirements: 9.9
"""

from datetime import datetime, timezone

from flask import Blueprint, request

from backend.api import dependencies
from backend.middleware.auth_middleware import require_role
from backend.utils.response import success_response, error_response

ai_bp = Blueprint("ai_enterprise", __name__)


@ai_bp.get("/ai/calibration")
@require_role("admin", "analyst", "hunter", "viewer")
def get_calibration():
    engine = dependencies.get("anomaly_engine")
    if not engine:
        return error_response("Anomaly engine not available", 503)
    return success_response({
        "calibration": engine.calibration_data(),
        "baseline_window_start": datetime.fromtimestamp(
            engine._start_time, tz=timezone.utc
        ).isoformat(),
        "warming_up": engine.is_warming_up(),
    })


@ai_bp.put("/ai/calibration")
@require_role("admin", "analyst")
def put_calibration():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    values = data.get("values", {})
    if not ip:
        return error_response("ip required", 400)

    engine = dependencies.get("anomaly_engine")
    if not engine:
        return error_response("Anomaly engine not available", 503)

    engine.override_calibration(ip, values)
    return success_response({"ip": ip}, "Calibration updated")
