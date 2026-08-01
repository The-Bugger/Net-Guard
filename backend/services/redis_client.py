"""
redis_client.py — Shared lazy Redis connection with graceful fallback.

A single module-level function get_redis() returns a connected Redis client
or None when Redis is unavailable. All callers must treat None as "Redis
offline — fall back to direct computation".

ponytail: one lazy singleton; no connection pool abstraction.
          Ceiling: not thread-safe across fork. Upgrade path: redis.ConnectionPool.

Requirements: 11.3, 11.5
"""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger("netguard.redis_client")

_redis_client = None
_redis_checked = False


def get_redis():
    """
    Return a connected redis.Redis client, or None if Redis is unavailable.

    Tries to connect once; subsequent calls return the cached result.
    Falls back silently — never raises.
    """
    global _redis_client, _redis_checked
    if _redis_checked:
        return _redis_client

    _redis_checked = True
    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    try:
        import redis  # optional dependency
        client = redis.from_url(url, socket_connect_timeout=2, socket_timeout=2, decode_responses=True)
        client.ping()
        _redis_client = client
        logger.info("Redis connected: %s", url)
    except ImportError:
        logger.debug("redis-py not installed — Redis features disabled")
    except Exception as exc:
        logger.warning("redis_unavailable: %s — falling back to in-process cache", exc)

    return _redis_client


def reset():
    """Force re-check on next call (used in tests)."""
    global _redis_client, _redis_checked
    _redis_client = None
    _redis_checked = False
