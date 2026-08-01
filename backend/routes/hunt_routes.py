"""
hunt_routes.py — Threat hunting and false-positive feedback endpoints.

GET  /api/v1/hunt?ioc={value}
POST /api/v1/events/{id}/feedback

Requirements: 10.5, 10.6
"""

from flask import Blueprint, request, g
from backend.api import dependencies
from backend.middleware.auth_middleware import require_role
from backend.utils.response import success_response, error_response

hunt_bp = Blueprint("hunt", __name__)


@hunt_bp.get("/hunt")
@require_role("admin", "analyst", "hunter")
def hunt():
    ioc = request.args.get("ioc", "").strip()
    if not ioc:
        return error_response("ioc parameter required", 400)
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    svc = dependencies.get("threat_intel_service")
    if not svc:
        return error_response("Threat intel service not available", 503)

    return success_response(svc.hunt(ioc, page=page))


@hunt_bp.post("/events/<event_id>/feedback")
@require_role("admin", "analyst")
def event_feedback(event_id: str):
    data = request.get_json(silent=True) or {}
    is_fp = bool(data.get("is_false_positive", False))
    operator = getattr(g, "current_user", {}).get("sub", "api")

    svc = dependencies.get("threat_intel_service")
    if not svc:
        return error_response("Threat intel service not available", 503)

    svc.feedback(event_id, is_fp, operator)
    return success_response(None, "Feedback recorded")
