"""
block_routes.py — IP blocking endpoints.

POST /block
POST /unblock
GET  /blocked

Requirements: 11.7, 13.2, 13.3, 13.4, 13.6
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from flask import Blueprint, request

from backend.api.dependencies import get_prevention_engine, get_block_repo
from backend.utils.response import success_response, error_response
from backend.utils.validators import validate_ip_address

block_bp = Blueprint("blocks", __name__)


@block_bp.post("/block")
def block_ip():
    body = request.get_json(silent=True) or {}
    ip = (body.get("ip") or "").strip()
    reason = (body.get("reason") or "Manual").strip()
    duration = body.get("duration", 120)

    if not ip:
        return error_response("Missing required field: ip", 400, "VALIDATION_ERROR")
    if not validate_ip_address(ip):
        return error_response(f"Invalid IP address: {ip}", 422, "INVALID_IP")

    engine = get_prevention_engine()
    if engine is None:
        return error_response("Prevention engine unavailable", 500, "SERVICE_UNAVAILABLE")

    event_id = f"MANUAL-{str(uuid.uuid4())[:8]}"
    original_duration = engine._block_duration
    engine.set_block_duration(int(duration))
    success = engine.block_ip(ip, reason, event_id)
    engine.set_block_duration(original_duration)

    if not success:
        return error_response(f"Failed to block {ip}.", 500, "BLOCK_FAILED")

    return success_response(data={"blocked": True, "ip": ip}, status_code=201)


@block_bp.post("/unblock")
def unblock_ip():
    body = request.get_json(silent=True) or {}
    ip = (body.get("ip") or "").strip()

    if not ip:
        return error_response("Missing required field: ip", 400, "VALIDATION_ERROR")
    if not validate_ip_address(ip):
        return error_response(f"Invalid IP address: {ip}", 422, "INVALID_IP")

    # Check active block exists
    block_repo = get_block_repo()
    if block_repo and not block_repo.is_blocked(ip):
        return error_response(f"No active block found for {ip}.", 404, "NOT_FOUND")

    engine = get_prevention_engine()
    if engine is None:
        return error_response("Prevention engine unavailable", 500, "SERVICE_UNAVAILABLE")

    success = engine.unblock_ip(ip)
    if not success:
        return error_response(f"Failed to unblock {ip}.", 500, "BLOCK_FAILED")

    return success_response(data={"success": True, "ip": ip})


@block_bp.get("/blocked")
def list_blocked():
    block_repo = get_block_repo()
    if block_repo is None:
        return success_response(data={"blocked": []})

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    active = block_repo.get_all_active()

    # Add expires_in countdown
    for record in active:
        try:
            exp = datetime.strptime(record["expires_at"], "%Y-%m-%dT%H:%M:%SZ")
            exp = exp.replace(tzinfo=timezone.utc)
            now_dt = datetime.now(timezone.utc)
            record["expires_in"] = max(0, int((exp - now_dt).total_seconds()))
        except Exception:
            record["expires_in"] = 0

    return success_response(data={"blocked": active})
