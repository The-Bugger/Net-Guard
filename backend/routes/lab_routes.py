"""
lab_routes.py — Attack Lab REST API.

GET    /api/v1/lab/attacks
POST   /api/v1/lab/sessions
DELETE /api/v1/lab/sessions/{id}
GET    /api/v1/lab/sessions/{id}

Requirements: 3.1, 3.2, 3.5, 3.6, 3.8, 3.9
"""

from flask import Blueprint, request, g
from backend.api import dependencies
from backend.middleware.auth_middleware import require_role
from backend.utils.response import success_response, error_response, created_response

lab_bp = Blueprint("lab", __name__)


def _svc():
    return dependencies.get("attack_lab_service")


@lab_bp.get("/lab/attacks")
@require_role("admin", "analyst")
def list_attack_types():
    from backend.services.attack_lab_service import AttackLabService
    return success_response(AttackLabService.get_attack_types())


@lab_bp.post("/lab/sessions")
@require_role("admin", "analyst")
def launch_session():
    config = request.get_json(silent=True) or {}
    operator = getattr(g, "current_user", {}).get("sub", "api")
    try:
        session_id = _svc().launch(config, operator=operator)
        return created_response({"session_id": session_id}, "Session started")
    except ValueError as exc:
        msg = str(exc)
        if "CONCURRENCY_LIMIT" in msg:
            return error_response(msg, 429, "CONCURRENCY_LIMIT")
        return error_response(msg, 400)


@lab_bp.delete("/lab/sessions/<session_id>")
@require_role("admin", "analyst")
def cancel_session(session_id: str):
    ok = _svc().cancel(session_id)
    if not ok:
        return error_response("Session not found", 404)
    return success_response(None, "Session cancelled")


@lab_bp.get("/lab/sessions/<session_id>")
@require_role("admin", "analyst", "hunter", "viewer")
def get_session(session_id: str):
    s = _svc().status(session_id)
    if not s:
        return error_response("Session not found", 404)
    return success_response(s)
