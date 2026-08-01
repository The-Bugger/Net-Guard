"""
backend/middleware/auth.py — API key authentication before_request hook.

Module purpose:
    Authenticate mutating HTTP requests (POST, PUT, DELETE, PATCH) using a
    shared secret in the X-API-Key header. Read-only GET requests pass by
    default; set REQUIRE_AUTH_FOR_READS=true to enforce auth on them too.

Architecture role:
    Registered in create_app() as a before_request hook after sanitise_and_validate
    and RateLimiter.check. Returns None to pass the request through, or a 401
    Response to abort it.

Dependencies:
    hmac (stdlib), os (stdlib), flask.request, backend.utils.response.error_response

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6
"""

from __future__ import annotations

import hmac
import os

from flask import request

from backend.utils.response import error_response

_MUTATING = {"POST", "PUT", "DELETE", "PATCH"}


def check_api_key() -> "Response | None":
    """
    Flask before_request hook — enforce API key auth on mutating endpoints.

    Skip logic (in order):
      1. SocketIO paths (/socket.io/) — dashboard uses SocketIO without keys.
      2. Methods not requiring auth — pass through unless REQUIRE_AUTH_FOR_READS
         forces auth on GET.

    If NETGUARD_API_KEY is unset the function returns None (dev pass-through).
    Otherwise the X-API-Key header is compared using hmac.compare_digest to
    prevent timing-oracle attacks.

    Returns:
        None on pass-through, or (Response, 401) on auth failure.
    """
    # SocketIO handshake and event traffic must never be blocked (Req 1.6)
    if request.path.startswith("/socket.io/"):
        return None

    require_reads = os.environ.get("REQUIRE_AUTH_FOR_READS", "false").lower() == "true"
    method_needs_auth = request.method in _MUTATING
    read_needs_auth = require_reads and request.method == "GET"

    if not (method_needs_auth or read_needs_auth):
        return None  # OPTIONS, HEAD, and unenforced GETs — skip

    key = os.environ.get("NETGUARD_API_KEY", "")
    if not key:
        return None  # no key configured → dev mode, pass through (Req 1.4)

    provided = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(provided, key):
        return error_response("Valid X-API-Key header required.", 401, "UNAUTHORIZED")

    return None
