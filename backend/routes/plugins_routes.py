"""
plugins_routes.py — Plugin management endpoints.

GET  /api/v1/plugins
POST /api/v1/plugins/{name}/enable
POST /api/v1/plugins/{name}/disable

Requirements: 6.8, 13.6
"""

from flask import Blueprint
from backend.api import dependencies
from backend.middleware.auth_middleware import require_role
from backend.utils.response import success_response, error_response

plugins_bp = Blueprint("plugins", __name__)


def _reg():
    return dependencies.get("plugin_registry")


@plugins_bp.get("/plugins")
@require_role("admin", "analyst", "hunter", "viewer")
def list_plugins():
    reg = _reg()
    if not reg:
        return success_response([])
    return success_response(reg.list_plugins())


@plugins_bp.post("/plugins/<name>/enable")
@require_role("admin")
def enable_plugin(name: str):
    ok = _reg().enable(name)
    if not ok:
        return error_response("Plugin not found", 404)
    return success_response(None, f"Plugin '{name}' enabled")


@plugins_bp.post("/plugins/<name>/disable")
@require_role("admin")
def disable_plugin(name: str):
    ok = _reg().disable(name)
    if not ok:
        return error_response("Plugin not found", 404)
    return success_response(None, f"Plugin '{name}' disabled")
