"""
audit_routes.py — Read-only audit log endpoint.

GET /api/v1/audit  (admin only, paginated)

Requirements: 14.5
"""

from flask import Blueprint, request
from backend.api import dependencies
from backend.middleware.auth_middleware import require_role
from backend.utils.response import success_response, error_response

audit_bp = Blueprint("audit", __name__)


@audit_bp.get("/audit")
@require_role("admin")
def get_audit():
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("per_page", 50))))
    except (ValueError, TypeError):
        return error_response("Invalid pagination params", 400)

    audit_svc = dependencies.get("audit_service")
    result = audit_svc.get_paginated(page, per_page)
    return success_response(result)
