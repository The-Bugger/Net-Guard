"""
whitelist_routes.py — Whitelist management endpoints.

GET    /whitelist
POST   /whitelist
DELETE /whitelist/<ip>

Requirements: 12.2, 12.3, 12.4, 12.5, 12.6, 13.2, 13.3, 13.4
"""

from __future__ import annotations

from flask import Blueprint, request

from backend.api.dependencies import get_whitelist_manager
from backend.utils.response import success_response, error_response, created_response, no_content_response
from backend.utils.validators import validate_ip_address

whitelist_bp = Blueprint("whitelist", __name__)


@whitelist_bp.get("/whitelist")
def list_whitelist():
    mgr = get_whitelist_manager()
    if mgr is None:
        return success_response(data={"whitelist": []})
    entries = mgr.get_all()
    return success_response(data={"whitelist": entries})


@whitelist_bp.post("/whitelist")
def add_whitelist():
    body = request.get_json(silent=True) or {}
    ip = (body.get("ip") or "").strip()
    description = (body.get("description") or "").strip() or None

    if not ip:
        return error_response("Missing required field: ip", 400, "VALIDATION_ERROR")
    if not validate_ip_address(ip):
        return error_response(f"Invalid IP address: {ip}", 422, "INVALID_IP")

    mgr = get_whitelist_manager()
    if mgr is None:
        return error_response("Whitelist service unavailable", 500, "SERVICE_UNAVAILABLE")

    try:
        mgr.add(ip, description=description)
        return created_response(
            data={"ip": ip, "description": description},
            message=f"{ip} added to whitelist.",
        )
    except ValueError as exc:
        return error_response(str(exc), 422, "INVALID_IP")
    except RuntimeError as exc:
        return error_response(str(exc), 500, "DATABASE_ERROR")


@whitelist_bp.delete("/whitelist/<string:ip>")
def remove_whitelist(ip: str):
    if not validate_ip_address(ip):
        return error_response(f"Invalid IP address: {ip}", 422, "INVALID_IP")

    mgr = get_whitelist_manager()
    if mgr is None:
        return error_response("Whitelist service unavailable", 500, "SERVICE_UNAVAILABLE")

    removed = mgr.remove(ip)
    if not removed:
        return error_response(f"{ip} not found in whitelist.", 404, "NOT_FOUND")

    return no_content_response()
