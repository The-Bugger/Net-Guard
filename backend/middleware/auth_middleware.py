"""
auth_middleware.py — JWT authentication and RBAC for Net-Guard Enterprise IDPS.

before_request hook + @require_role decorator.

Requirements: 14.1, 14.2, 14.3
"""

from __future__ import annotations

import functools
import logging

from flask import g, request, jsonify

logger = logging.getLogger("netguard.auth_middleware")

# Paths that never require a token
_PUBLIC_PREFIXES = (
    "/api/v1/auth/login",
    "/api/v1/auth/refresh",
    "/api/v1/health",
    "/socket.io",
)

# Pages served at root don't need auth
_PUBLIC_METHODS = ("OPTIONS",)


def _auth_service():
    from backend.api import dependencies
    return dependencies.get("auth_service")


def _audit_service():
    from backend.api import dependencies
    return dependencies.get("audit_service")


def jwt_required_hook() -> None:
    """
    Flask before_request hook.
    Validates Bearer token and sets g.current_user = decoded payload.
    Returns 401 on missing/invalid/expired token for all non-public API paths.
    """
    path = request.path
    method = request.method

    # OPTIONS pass-through for CORS pre-flight
    if method in _PUBLIC_METHODS:
        return None

    # Public paths pass through
    if not path.startswith("/api/"):
        return None
    if any(path.startswith(p) for p in _PUBLIC_PREFIXES):
        return None

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"success": False, "error": "UNAUTHORIZED", "message": "Missing token"}), 401

    token = auth_header[7:]
    svc = _auth_service()
    if svc is None:
        # auth service not wired yet (startup); fail open for health checks
        return None

    try:
        payload = svc.validate_token(token)
        g.current_user = payload
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc), "message": "Invalid or expired token"}), 401

    return None


def require_role(*roles: str):
    """
    Route decorator that enforces RBAC.
    Usage: @require_role("admin", "analyst")
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if user is None:
                return jsonify({"success": False, "error": "UNAUTHORIZED"}), 401
            if user.get("role") not in roles:
                audit = _audit_service()
                if audit:
                    audit.log(
                        user.get("sub", "unknown"),
                        "FORBIDDEN",
                        request.path,
                        {"method": request.method, "required_roles": list(roles)},
                    )
                return jsonify({"success": False, "error": "FORBIDDEN", "error_code": "FORBIDDEN"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator
