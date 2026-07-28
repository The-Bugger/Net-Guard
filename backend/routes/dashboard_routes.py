"""
dashboard_routes.py — Dashboard data endpoints.

GET /dashboard       — full snapshot
GET /dashboard/live  — lightweight live stats

Requirements: 13.2, 13.3, 16.1, 16.2
"""

from __future__ import annotations

from flask import Blueprint

from backend.api.dependencies import get_stats_service
from backend.utils.response import success_response, error_response

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("/dashboard")
def get_dashboard():
    svc = get_stats_service()
    if svc is None:
        return error_response("Stats service unavailable", 500, "SERVICE_UNAVAILABLE")
    data = svc.get_dashboard_data()
    return success_response(data=data)


@dashboard_bp.get("/dashboard/live")
def get_dashboard_live():
    svc = get_stats_service()
    if svc is None:
        return success_response(data={
            "packets_per_second": 0,
            "active_threats": 0,
            "alerts_today": 0,
            "monitoring": False,
        })
    data = svc.get_live_stats()
    return success_response(data=data)
