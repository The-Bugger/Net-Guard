"""
stats_routes.py — Statistics endpoints.

GET /statistics
GET /statistics/rules

Requirements: 13.2, 13.3
"""

from __future__ import annotations

from flask import Blueprint

from backend.api.dependencies import get_stats_service
from backend.utils.response import success_response, error_response

stats_bp = Blueprint("stats", __name__)


@stats_bp.get("/statistics")
def get_statistics():
    svc = get_stats_service()
    if svc is None:
        return error_response("Stats service unavailable", 500, "SERVICE_UNAVAILABLE")
    return success_response(data=svc.get_statistics())


@stats_bp.get("/statistics/rules")
def get_rule_statistics():
    svc = get_stats_service()
    if svc is None:
        return success_response(data={"rules": []})
    return success_response(data={"rules": svc.get_rule_statistics()})
