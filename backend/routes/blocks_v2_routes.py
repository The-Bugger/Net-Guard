"""
blocks_v2_routes.py — Enterprise block management REST API.

POST   /api/v1/blocks
DELETE /api/v1/blocks/{id}
GET    /api/v1/blocks
GET    /api/v1/blocks/{id}
GET    /api/v1/blocks/{ip}/history

Requirements: 1.10, 1.11, 1.12
"""

from flask import Blueprint, request
from backend.api import dependencies
from backend.middleware.auth_middleware import require_role
from backend.utils.response import success_response, error_response, created_response

blocks_v2_bp = Blueprint("blocks_v2", __name__)


def _mgr():
    return dependencies.get("block_manager")

def _repo():
    return dependencies.get("block_repo")


@blocks_v2_bp.post("/blocks")
@require_role("admin", "analyst")
def create_block():
    data = request.get_json(silent=True) or {}
    target = str(data.get("target", "")).strip()
    if not target:
        return error_response("target required", 400)

    result = _mgr().block(
        target=target,
        target_type=data.get("target_type", "ip"),
        reason=str(data.get("reason", ""))[:1000],
        duration=int(data.get("duration", 3600)),
        operator=data.get("operator", "api"),
        severity=int(data.get("severity", 5)),
        confidence=int(data.get("confidence", 50)),
    )

    if not result["success"]:
        code = result.get("error_code", "BLOCK_FAILED")
        if code == "WHITELISTED_IP":
            return error_response("IP is whitelisted", 409, code)
        if code == "FIREWALL_ERROR":
            return error_response("Firewall rule failed", 500, code)
        if code == "DB_ERROR":
            return error_response("Database error — block rolled back", 500, code)
        return error_response(code, 400, code)

    # Confirmation dialog data (Req 1.11) embedded in response
    confirmation = {
        "target": target,
        "target_type": data.get("target_type", "ip"),
        "reason": data.get("reason", ""),
        "duration": data.get("duration", 3600),
        "threat_score": result.get("threat_score", 0),
    }
    return created_response({**result, "confirmation": confirmation}, "Block applied")


@blocks_v2_bp.delete("/blocks/<int:block_id>")
@require_role("admin", "analyst")
def delete_block(block_id: int):
    from flask import g
    operator = getattr(g, "current_user", {}).get("sub", "api")
    ok = _mgr().unblock(block_id, operator)
    if not ok:
        return error_response("Block not found", 404)
    return success_response(None, "Unblocked")


@blocks_v2_bp.get("/blocks")
@require_role("admin", "analyst", "hunter", "viewer")
def list_blocks():
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("per_page", 20))))
    except (ValueError, TypeError):
        return error_response("Invalid pagination", 400)

    filters = {
        "ip": request.args.get("ip"),
        "block_type": request.args.get("block_type"),
        "active": {"true": True, "false": False}.get(request.args.get("active", "").lower()),
        "date_from": request.args.get("date_from"),
        "date_to": request.args.get("date_to"),
    }
    result = _repo().get_paginated(page, per_page, filters)
    return success_response(result)


@blocks_v2_bp.get("/blocks/<int:block_id>")
@require_role("admin", "analyst", "hunter", "viewer")
def get_block(block_id: int):
    record = _repo().get_by_id(block_id)
    if not record:
        return error_response("Not found", 404)
    return success_response(record)


@blocks_v2_bp.get("/blocks/<path:ip>/history")
@require_role("admin", "analyst", "hunter", "viewer")
def get_block_history(ip: str):
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("per_page", 20))))
    except (ValueError, TypeError):
        return error_response("Invalid pagination", 400)
    result = _mgr().get_history(ip, page, per_page)
    return success_response(result)
