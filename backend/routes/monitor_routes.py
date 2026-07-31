"""
monitor_routes.py — Monitoring control endpoints.

POST /monitor/start
POST /monitor/stop
GET  /monitor/interfaces
GET  /interfaces             — flat interface list with is_up (Req 2.2, 15.3)

Requirements: 2.1, 2.2, 2.5, 2.6, 2.7, 2.8, 2.9, 13.3, 13.4, 15.3
"""

from __future__ import annotations

from flask import Blueprint, request

from backend.api.dependencies import get_monitor_service
from backend.utils.response import success_response, error_response

monitor_bp = Blueprint("monitor", __name__)


@monitor_bp.post("/monitor/start")
def start_monitoring():
    body = request.get_json(silent=True) or {}
    interface = body.get("interface", "").strip()

    if not interface:
        return error_response("Missing required field: interface", 400, "VALIDATION_ERROR")

    svc = get_monitor_service()
    if svc is None:
        return error_response("Monitor service unavailable", 500, "SERVICE_UNAVAILABLE")

    try:
        svc.start_monitoring(interface)
        return success_response(message="Monitoring started.", data={"interface": interface})
    except RuntimeError as exc:
        err = str(exc)
        if "ALREADY_MONITORING" in err:
            return error_response("Monitoring is already active.", 409, "ALREADY_MONITORING")
        return error_response(str(exc), 500, "UNKNOWN_ERROR")
    except ValueError as exc:
        err = str(exc)
        if "INVALID_INTERFACE" in err:
            return error_response(
                f"Interface '{interface}' is not available.", 422, "INVALID_INTERFACE"
            )
        return error_response(str(exc), 422, "VALIDATION_ERROR")


@monitor_bp.post("/monitor/stop")
def stop_monitoring():
    svc = get_monitor_service()
    if svc is None:
        return error_response("Monitor service unavailable", 500, "SERVICE_UNAVAILABLE")

    try:
        svc.stop_monitoring()
        return success_response(message="Monitoring stopped.")
    except RuntimeError as exc:
        if "NOT_MONITORING" in str(exc):
            return error_response("Monitoring is not active.", 409, "NOT_MONITORING")
        return error_response(str(exc), 500, "UNKNOWN_ERROR")


@monitor_bp.get("/monitor/interfaces")
def list_interfaces():
    svc = get_monitor_service()
    interfaces = svc.get_interfaces() if svc else []
    return success_response(data={"interfaces": interfaces})


@monitor_bp.get("/interfaces")
def list_interfaces_v2():
    """
    GET /api/v1/interfaces

    Returns all OS network interfaces including down ones, with is_up status.
    Used by frontend interface-picker and auto-select logic.

    Requirements: 2.2, 15.3
    """
    try:
        import psutil
        stats = psutil.net_if_stats()
        data = [{"name": name, "is_up": info.isup} for name, info in stats.items()]
    except Exception:
        data = []
    return success_response(data={"interfaces": data})
