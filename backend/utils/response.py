"""
Standard JSON response helpers for NetGuard REST API.

All API responses use the envelope:
    Success: {"success": true, "message": "...", "data": {...}}
    Error:   {"success": false, "error": "...", "code": <HTTP status>}
"""

from flask import jsonify
from typing import Any, Optional


def success_response(data: Any = None, message: str = "OK", status_code: int = 200):
    """
    Build a standard success JSON response.

    Args:
        data: The response payload.
        message: Human-readable success message.
        status_code: HTTP status code (default 200).

    Returns:
        Flask Response object with JSON body and correct status code.
    """
    response = {
        "success": True,
        "message": message,
        "data": data
    }
    return jsonify(response), status_code


def error_response(error: str, code: int, error_code: Optional[str] = None):
    """
    Build a standard error JSON response.

    Args:
        error: Human-readable error description.
        code: HTTP status code.
        error_code: Machine-readable error code string (e.g. "INVALID_IP").

    Returns:
        Flask Response object with JSON error body and correct status code.
    """
    response = {
        "success": False,
        "error": error,
        "code": code
    }
    if error_code is not None:
        response["error_code"] = error_code
    return jsonify(response), code


def created_response(data: Any = None, message: str = "Created"):
    """Convenience wrapper for HTTP 201 Created responses."""
    return success_response(data=data, message=message, status_code=201)


def no_content_response(message: str = "Deleted successfully."):
    """
    Returns HTTP 200 with a minimal JSON envelope.

    HTTP 204 No Content breaks the frontend apiRequest wrapper which always
    calls res.json() — returning a JSON 200 keeps the API envelope consistent.
    """
    return success_response(data=None, message=message, status_code=200)
