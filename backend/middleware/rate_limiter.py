"""
backend/middleware/rate_limiter.py — Sliding-window rate limiter.

Two tiers (both enforced, whichever fires first wins):
  1. Per-IP  : 120 req / 60 s  — unauthenticated safety net (original Req 10.x)
  2. Per-User: 300 req / 60 s  — authenticated user limit (Req 11.4)

Only /api/v1/ paths are counted. Static files and Socket.IO are never limited.
Returns HTTP 429 + Retry-After header on breach.

ponytail: in-process deque windows — not shared across workers.
          Ceiling: one worker process only. Upgrade path: Redis INCR + EXPIRE.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import defaultdict, deque

from flask import Response, g, jsonify, request

logger = logging.getLogger("netguard.rate_limiter")


class RateLimiter:
    """Dual sliding-window rate limiter: per-IP and per-authenticated-user."""

    # Per-IP limit (unauthenticated baseline)
    _IP_WINDOW  = 60
    _IP_MAX     = 120

    # Per-user limit (Req 11.4)
    _USER_WINDOW = 60
    _USER_MAX    = 300

    # Paths always exempt even if a window is full
    _EXEMPT = {"/api/v1/health", "/api/v1/dashboard/live", "/api/v1/status"}

    def __init__(self) -> None:
        self._ip_windows:   dict[str, deque] = defaultdict(deque)
        self._user_windows: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Flask before_request hook
    # ------------------------------------------------------------------

    def check(self) -> "Response | None":
        """
        Count this request against both the per-IP and per-user windows.
        Returns None (allow) or a 429 Response (deny).
        Fails open on any internal error.
        """
        try:
            path = request.path
            if not path.startswith("/api/"):
                return None
            if path in self._EXEMPT:
                return None

            now = time.monotonic()

            # ── per-IP check ──────────────────────────────────────────
            ip = self._client_ip()
            ip_result = self._check_window(
                self._ip_windows, ip, now,
                self._IP_WINDOW, self._IP_MAX,
            )
            if ip_result is not None:
                return ip_result

            # ── per-user check (only when a JWT user is present) ──────
            user = getattr(g, "current_user", None)
            if user:
                username = user.get("sub", "")
                if username:
                    user_result = self._check_window(
                        self._user_windows, username, now,
                        self._USER_WINDOW, self._USER_MAX,
                    )
                    if user_result is not None:
                        return user_result

            return None

        except Exception:
            logger.error("Rate limiter error", exc_info=True)
            return None  # fail open

    # ------------------------------------------------------------------
    # Sliding-window helper
    # ------------------------------------------------------------------

    def _check_window(
        self,
        store: dict[str, deque],
        key: str,
        now: float,
        window: int,
        max_req: int,
    ) -> "Response | None":
        cutoff = now - window
        with self._lock:
            dq = store[key]
            while dq and dq[0] <= cutoff:
                dq.popleft()
            dq.append(now)
            count = len(dq)
            oldest = dq[0] if dq else now

        if count > max_req:
            retry_after = math.ceil(oldest + window - now)
            resp = jsonify({
                "success": False,
                "error": "RATE_LIMIT_EXCEEDED",
                "message": f"Rate limit exceeded. Retry after {retry_after}s.",
            })
            resp.status_code = 429
            resp.headers["Retry-After"] = str(max(1, retry_after))
            logger.warning(
                "Rate limit hit for %s (%d/%d req in %ds)",
                key, count, max_req, window,
            )
            return resp
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _client_ip(self) -> str:
        forwarded = request.headers.get("X-Forwarded-For", "").strip()
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote_addr or "unknown"
