"""
backend/middleware/security_headers.py

after_request hook  — add 4 security headers to every response (Req 11.1)
before_request hook — sanitise JSON body string fields + 1024-char limit (Req 11.2, 11.3)

Both functions are registered in create_app() via:
    app.after_request(add_security_headers)
    app.before_request(sanitise_and_validate)
"""

from __future__ import annotations

import logging

from flask import Response, request, jsonify

logger = logging.getLogger("netguard.middleware")

_MAX_FIELD_LEN = 1024


def add_security_headers(response: Response) -> Response:
    """Attach 4 security headers to every response. Req 11.1."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def sanitise_and_validate() -> "Response | None":
    """
    Strip whitespace from all string fields in JSON body; reject any field
    whose post-strip length exceeds 1024 chars with 422 INPUT_TOO_LONG. Req 11.2, 11.3.

    Mutates request.json in-place by rebuilding the parsed body, then replaces
    the cached parsed value via force=True on re-parse after we stash the cleaned
    data in the WSGI environ.

    Handles nested dicts and array-of-string elements recursively.
    Returns None on success (Flask continues to the view), or a 422 Response.
    """
    # Only process JSON requests with a body
    if not request.is_json:
        return None

    body = request.get_json(silent=True, force=True)
    if body is None:
        return None  # malformed JSON — let the view handle it

    # body is a mutable object from Flask's JSON cache — mutate in-place so
    # any subsequent request.get_json() call in the view sees the cleaned data.
    error = _sanitise(body)
    if error:
        field_name, _ = error
        resp = jsonify({
            "success": False,
            "error": "INPUT_TOO_LONG",
            "field": field_name,
        })
        resp.status_code = 422
        return resp

    return None


def _sanitise(obj, parent_key: str = "") -> tuple[str, str] | None:
    """
    Recursively strip whitespace from all strings in *obj*.
    Mutates dicts and lists in-place.
    Returns (field_name, value) tuple on first violation, else None.
    """
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            val = obj[key]
            if isinstance(val, str):
                stripped = val.strip()
                if len(stripped) > _MAX_FIELD_LEN:
                    return (key, stripped)
                obj[key] = stripped
            elif isinstance(val, (dict, list)):
                err = _sanitise(val, parent_key=key)
                if err:
                    return err
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, str):
                stripped = item.strip()
                if len(stripped) > _MAX_FIELD_LEN:
                    return (parent_key or str(i), stripped)
                obj[i] = stripped
            elif isinstance(item, (dict, list)):
                err = _sanitise(item, parent_key=parent_key)
                if err:
                    return err
    return None
