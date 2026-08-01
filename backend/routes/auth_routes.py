"""
auth_routes.py — Authentication endpoints for Net-Guard Enterprise IDPS.

POST /api/v1/auth/login
POST /api/v1/auth/refresh
POST /api/v1/auth/logout
POST /api/v1/auth/users   (admin only)

Requirements: 14.1, 14.2, 14.4, 14.6
"""

from flask import Blueprint, request, g
from backend.api import dependencies
from backend.middleware.auth_middleware import require_role
from backend.utils.response import success_response, error_response, created_response

auth_bp = Blueprint("auth", __name__)


def _auth():
    return dependencies.get("auth_service")


@auth_bp.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    totp_code = data.get("totp_code")

    if not username or not password:
        return error_response("username and password required", 400)

    try:
        tokens = _auth().login(username, password, totp_code)
        return success_response(tokens, "Login successful")
    except ValueError as exc:
        code = str(exc)
        if code == "MFA_REQUIRED":
            return error_response("MFA code required", 401, "MFA_REQUIRED")
        if code == "MFA_INVALID":
            return error_response("Invalid MFA code", 401, "MFA_INVALID")
        return error_response("Invalid credentials", 401, "LOGIN_FAILED")


@auth_bp.post("/auth/refresh")
def refresh():
    data = request.get_json(silent=True) or {}
    token = data.get("refresh_token", "")
    if not token:
        return error_response("refresh_token required", 400)
    try:
        result = _auth().refresh(token)
        return success_response(result)
    except ValueError as exc:
        return error_response(str(exc), 401, "INVALID_TOKEN")


@auth_bp.post("/auth/logout")
def logout():
    # Stateless JWT — client discards the token; log the event
    audit = dependencies.get("audit_service")
    user = getattr(g, "current_user", {})
    if audit and user:
        audit.log(user.get("sub", "unknown"), "LOGOUT", "/api/v1/auth/logout", {})
    return success_response(None, "Logged out")


@auth_bp.post("/auth/users")
@require_role("admin")
def create_user():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    role = str(data.get("role", "viewer")).strip()

    if not username or not password:
        return error_response("username and password required", 400)

    try:
        user = _auth().create_user(username, password, role)
        return created_response(user, "User created")
    except ValueError as exc:
        msg = str(exc)
        if "PASSWORD_POLICY" in msg.upper() or "password policy" in msg.lower():
            return error_response(msg, 400, "PASSWORD_POLICY_VIOLATION")
        if msg == "USERNAME_TAKEN":
            return error_response("Username already exists", 409, "USERNAME_TAKEN")
        return error_response(msg, 400)
