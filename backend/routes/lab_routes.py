"""
lab_routes.py — Attack Lab REST API.

GET    /api/v1/lab/attacks
POST   /api/v1/lab/sessions
GET    /api/v1/lab/sessions
GET    /api/v1/lab/sessions/{id}
DELETE /api/v1/lab/sessions/{id}

Requirements: 3.1–3.9
"""

from flask import Blueprint, request, g
from backend.api import dependencies
from backend.middleware.auth_middleware import require_role
from backend.utils.response import success_response, error_response

lab_bp = Blueprint("lab", __name__)

# Estimated detection time in seconds by difficulty (Req 3.4)
_ESTIMATED_DETECTION_S = {"low": 30, "medium": 15, "high": 8, "critical": 3}


def _svc():
    return dependencies.get("attack_lab_service")


@lab_bp.get("/lab/attacks")
@require_role("admin", "analyst", "hunter", "viewer")
def list_attack_types():
    from backend.services.attack_lab_service import AttackLabService
    return success_response(AttackLabService.get_attack_types())


@lab_bp.post("/lab/sessions")
@require_role("admin", "analyst")
def launch_session():
    config = request.get_json(silent=True) or {}
    operator = getattr(g, "current_user", {}).get("sub", "api")
    difficulty = str(config.get("difficulty", "medium")).lower()
    estimated = _ESTIMATED_DETECTION_S.get(difficulty, 15)
    svc = _svc()
    if not svc:
        return error_response("Attack lab service not available", 503)
    try:
        session_id = svc.launch(config, operator=operator)
    except ValueError as exc:
        msg = str(exc)
        if "CONCURRENCY_LIMIT" in msg:
            return error_response(msg, 429, "CONCURRENCY_LIMIT")
        return error_response(msg, 400)
    return success_response({
        "session_id": session_id,
        "config": config,
        "operator": operator,
        "estimated_detection_time": estimated,
    }, "Session launched")


@lab_bp.get("/lab/sessions")
@require_role("admin", "analyst", "hunter", "viewer")
def list_sessions():
    svc = _svc()
    if not svc:
        return error_response("Attack lab service not available", 503)
    return success_response(svc.list_active())


@lab_bp.get("/lab/sessions/<session_id>")
@require_role("admin", "analyst", "hunter", "viewer")
def get_session(session_id: str):
    svc = _svc()
    if not svc:
        return error_response("Attack lab service not available", 503)
    s = svc.status(session_id)
    if not s:
        return error_response("Session not found", 404)
    return success_response(s)


@lab_bp.delete("/lab/sessions/<session_id>")
@require_role("admin", "analyst")
def cancel_session(session_id: str):
    svc = _svc()
    if not svc:
        return error_response("Attack lab service not available", 503)
    if not svc.cancel(session_id):
        return error_response("Session not found", 404)
    return success_response(None, "Session cancelled")
