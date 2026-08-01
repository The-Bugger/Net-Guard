"""
backend/middleware/rate_limiter.py — Per-IP sliding-window rate limiter.

Registered as a Flask before_request hook via app.before_request(limiter.check).

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5

ponytail: global in-process defaultdict — not shared across workers.
         Upgrade path: swap deque for Redis INCR + EXPIRE.
"""

from __future__ import annotations

import logging
import math
import time
import threading
from collections import defaultdict, deque

from flask import Response, request, jsonify

logger = logging.getLogger("netguard.rate_limiter")


class RateLimiter:
    """Sliding-window rate limiter: 120 API requests per 60-second window per client IP.

    Only applies to /api/v1/ routes. Static files, HTML pages, and Socket.IO
    traffic are never rate-limited so a single browser page load (which fetches
    8+ JS/CSS files) cannot trigger the limit.
    """

    _WINDOW = 60      # seconds
    _MAX_REQ = 120    # requests per window (API calls only)

    # Paths that are completely exempt even if counted would exceed the limit.
    # High-frequency polling endpoints that must always succeed.
    _EXEMPT = {"/api/v1/health", "/api/v1/dashboard/live", "/api/v1/status"}

    def __init__(self) -> None:
        self._windows: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self) -> "Response | None":
        """
        Flask before_request handler.

        Only counts and limits requests to /api/v1/ paths.
        Static files, HTML, and Socket.IO handshakes are passed through unconditionally.
        Returns None (allow) for all non-API and exempt paths.
        Returns 429 with Retry-After header when the API rate limit is exceeded.
        Fails open on any internal error.
        """
        try:
            path = request.path

            # Only rate-limit API routes — never static files or HTML pages
            if not path.startswith("/api/"):
                return None

            # High-frequency endpoints are always exempt
            if path in self._EXEMPT:
                return None

            ip = self._client_ip()
            now = time.monotonic()
            cutoff = now - self._WINDOW

            with self._lock:
                window = self._windows[ip]
                while window and window[0] <= cutoff:
                    window.popleft()
                window.append(now)
                count = len(window)

            if count > self._MAX_REQ:
                with self._lock:
                    window = self._windows[ip]
                    retry_after = math.ceil(window[0] + self._WINDOW - now) if window else self._WINDOW

                response = jsonify({
                    "success": False,
                    "error": "RATE_LIMIT_EXCEEDED",
                    "message": "Rate limit exceeded.",
                })
                response.status_code = 429
                response.headers["Retry-After"] = str(retry_after)
                logger.warning("Rate limit exceeded for %s (%d reqs in %ds)", ip, count, self._WINDOW)
                return response

            return None

        except Exception:
            logger.error("Rate limiter error", exc_info=True)
            return None  # fail open

    def _client_ip(self) -> str:
        """Extract leftmost IP from X-Forwarded-For or fall back to remote_addr."""
        forwarded_for = request.headers.get("X-Forwarded-For", "").strip()
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.remote_addr or "unknown"
