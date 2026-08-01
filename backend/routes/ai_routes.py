"""
ai_routes.py — AI/anomaly engine calibration endpoints.

GET /api/v1/ai/calibration
PUT /api/v1/ai/calibration

Requirements: 9.8
"""

from flask import Blueprint, request
from backend.api import dependencies
from backend.middleware.auth_middleware import require_role
from backend.utils.response import success_response, error_response

ai_bp = Blueprint("ai_enterprise", __name__)


@ai_bp.get("/ai/calibration")
@require_role("admin", "analyst", "hunter")
def get_calibration():
    engine = dependencies.get("anomaly_engine")
    if not engine:
        return error_response("Anomaly engine not available", 503)
    return success_response(engine.calibration_data())


@ai_bp.put("/ai/calibration")
@require_role("admin")
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
