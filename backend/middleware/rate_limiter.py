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
    """Sliding-window rate limiter: 120 requests per 60-second window per client IP."""

    _WINDOW = 60      # seconds
    _MAX_REQ = 120    # requests per window
    _EXEMPT = {"/api/v1/health", "/api/v1/dashboard/live", "/api/v1/status"}

    def __init__(self) -> None:
        """Initialize the sliding-window rate limiter with an empty per-IP request store."""
        self._windows: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self) -> "Response | None":
        """
        Flask before_request handler.

        Counts every request in the sliding window regardless of exemption.
        Returns 429 Response with Retry-After header when over limit on non-exempt paths.
        Returns None (allow) on exempt paths even if over limit, and for all allowed requests.
        On any exception, logs ERROR and returns None (fail open).
        """
        try:
            ip = self._client_ip()
            now = time.monotonic()
            cutoff = now - self._WINDOW

            with self._lock:
                window = self._windows[ip]
                # Evict timestamps outside the window
                while window and window[0] <= cutoff:
                    window.popleft()
                # Count this request
                window.append(now)
                count = len(window)

            # Exempt endpoints are never blocked
            if request.path in self._EXEMPT:
                return None

            if count > self._MAX_REQ:
                with self._lock:
                    window = self._windows[ip]
                    # Retry-After = seconds until oldest timestamp falls outside window
                    retry_after = math.ceil(window[0] + self._WINDOW - now) if window else self._WINDOW

                response = jsonify({
                    "success": False,
                    "error": "RATE_LIMIT_EXCEEDED",
                    "message": "Rate limit exceeded.",
                })
                response.status_code = 429
                response.headers["Retry-After"] = str(retry_after)
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
