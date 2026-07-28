"""
whitelist_service.py — Whitelist_Manager for NetGuard IDPS.

Manages the set of trusted IP addresses that must never be automatically blocked.
Maintains an in-memory set for O(1) lookups during high-frequency packet processing
and syncs with the database on startup and after every mutation.

Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from backend.repositories.whitelist_repository import WhitelistRepository
from backend.utils.validators import require_valid_ip

logger = logging.getLogger("netguard.whitelist_manager")


class WhitelistManager:
    """
    Thread-safe whitelist manager with in-memory O(1) lookup.

    All mutations write through to the database and sync the in-memory set.

    Usage::

        manager = WhitelistManager(whitelist_repo)
        manager.sync_from_db()
        if manager.is_whitelisted("192.168.1.1"):
            # skip blocking
    """

    def __init__(self, whitelist_repo: WhitelistRepository) -> None:
        self._repo = whitelist_repo
        self._lock = threading.RLock()
        self._ip_set: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_whitelisted(self, ip: str) -> bool:
        """
        Check if an IP is on the whitelist (O(1) in-memory lookup).

        Args:
            ip: IPv4 or IPv6 address string.

        Returns:
            True if whitelisted, False otherwise.
        """
        with self._lock:
            return ip in self._ip_set

    def add(self, ip: str, description: Optional[str] = None,
            created_by: str = "admin") -> None:
        """
        Add an IP to the whitelist.

        Args:
            ip: Valid IPv4 or IPv6 address string.
            description: Optional human-readable label.
            created_by: Creator identifier.

        Raises:
            ValueError: If ip is not a valid IPv4/IPv6 address.
            RuntimeError: If the database insert fails.
        """
        require_valid_ip(ip)
        now = _utc_now()
        success = self._repo.insert(ip, description, now, created_by)
        if not success:
            raise RuntimeError(f"Failed to add {ip} to whitelist.")
        with self._lock:
            self._ip_set.add(ip)
        logger.info("WhitelistManager: added %s (created_by=%s).", ip, created_by)

    def remove(self, ip: str) -> bool:
        """
        Remove an IP from the whitelist.

        Args:
            ip: IPv4 or IPv6 address string.

        Returns:
            True if removed, False if IP was not in whitelist.
        """
        deleted = self._repo.delete(ip)
        if deleted:
            with self._lock:
                self._ip_set.discard(ip)
            logger.info("WhitelistManager: removed %s.", ip)
        return deleted

    def get_all(self) -> list[dict]:
        """
        Return all whitelist entries from the database.

        Returns:
            List of dicts with ip_address, description, created_at, created_by.
        """
        return self._repo.get_all()

    def sync_from_db(self) -> None:
        """
        Rebuild the in-memory set from the database.

        Called on startup and after any bulk operation.
        """
        try:
            entries = self._repo.get_all()
            with self._lock:
                self._ip_set = {e["ip_address"] for e in entries}
            logger.info(
                "WhitelistManager: synced %d entries from DB.", len(self._ip_set)
            )
        except Exception as exc:
            logger.error("WhitelistManager.sync_from_db failed: %s", exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
