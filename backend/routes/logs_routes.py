"""
logs_routes.py — Log viewer endpoint.

GET /logs  (paginated, filterable)

Requirements: 13.2, 13.3, 13.9, 15.6
"""

from __future__ import annotations

from flask import Blueprint, request

from backend.api.dependencies import get_log_repo
from backend.utils.response import success_response, error_response

logs_bp = Blueprint("logs", __name__)

_VALID_LEVELS = {"INFO", "WARNING", "ERROR", "CRITICAL", "DEBUG"}


@logs_bp.get("/logs")
def get_logs():
    filters = {}

    severity = request.args.get("severity") or request.args.get("level")
    date = request.args.get("date")
    module = request.args.get("module")
    attack_type = request.args.get("attack_type")
    source_ip = request.args.get("source_ip")

    if severity:
        if severity.upper() not in _VALID_LEVELS:
            return error_response(
                f"Invalid severity: {severity}", 422, "VALIDATION_ERROR"
            )
        filters["level"] = severity.upper()

    if date:
        filters["date"] = date
    if module:
        filters["module"] = module
    if attack_type:
        filters["event"] = attack_type

    try:
        limit = min(int(request.args.get("limit", 50)), 500)
        offset = int(request.args.get("offset", 0))
    except (ValueError, TypeError):
        return error_response("limit and offset must be integers.", 422, "INVALID_PAGINATION_PARAMS")

    repo = get_log_repo()
    if repo is None:
        return success_response(data={"logs": [], "total": 0})

    logs = repo.get_all(filters=filters, limit=limit, offset=offset)
    total = repo.count(filters=filters)

    return success_response(data={
        "logs": logs,
        "total": total,
        "limit": limit,
        "offset": offset,
    })
