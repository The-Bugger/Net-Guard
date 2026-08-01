"""
block_repository.py — Repository for the blocked_ips table.

CRUD operations for active and historical firewall block records.

Requirements: 11.2, 11.3, 11.6
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from database.schema import BlockedIP

logger = logging.getLogger("netguard.block_repository")


class BlockRepository:
    """CRUD operations for the blocked_ips table."""

    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    def insert(self, record_data: dict) -> bool:
        """
        Insert a new block record.

        Args:
            record_data: Dict with ip_address, event_id, blocked_at, expires_at, reason.

        Returns:
            True on success.
        """
        try:
            with self._session_factory() as session:
                record = BlockedIP(
                    event_id=record_data["event_id"],
                    ip_address=record_data["ip_address"],
                    blocked_at=record_data["blocked_at"],
                    expires_at=record_data["expires_at"],
                    reason=record_data.get("reason", ""),
                    active=1,
                )
                session.add(record)
                session.commit()
                return True
        except Exception as exc:
            logger.error("BlockRepository.insert failed: %s", exc, exc_info=True)
            return False

    def get_active(self, ip_address: str) -> Optional[dict]:
        """
        Return the active block record for an IP, or None.

        Args:
            ip_address: The IP address to check.

        Returns:
            Dict representation of BlockedIP, or None.
        """
        try:
            with self._session_factory() as session:
                record = (
                    session.query(BlockedIP)
                    .filter_by(ip_address=ip_address, active=1)
                    .first()
                )
                return _block_to_dict(record) if record else None
        except Exception as exc:
            logger.error("BlockRepository.get_active(%s) failed: %s", ip_address, exc)
            return None

    def get_all_active(self) -> list[dict]:
        """Return all currently active block records."""
        try:
            with self._session_factory() as session:
                records = (
                    session.query(BlockedIP)
                    .filter_by(active=1)
                    .order_by(BlockedIP.blocked_at.desc())
                    .all()
                )
                return [_block_to_dict(r) for r in records]
        except Exception as exc:
            logger.error("BlockRepository.get_all_active failed: %s", exc)
            return []

    def set_inactive(self, ip_address: str) -> bool:
        """
        Mark all active blocks for an IP as inactive.

        Args:
            ip_address: The IP address to unblock.

        Returns:
            True on success.
        """
        try:
            with self._session_factory() as session:
                records = (
                    session.query(BlockedIP)
                    .filter_by(ip_address=ip_address, active=1)
                    .all()
                )
                now = _utc_now()
                for r in records:
                    r.active = 0
                    r.unblock_time = now
                session.commit()
                return True
        except Exception as exc:
            logger.error("BlockRepository.set_inactive(%s) failed: %s", ip_address, exc)
            return False

    def extend_expiry(self, ip_address: str, new_expires_at: str) -> bool:
        """
        Extend the expiry time of the active block for an IP.

        Args:
            ip_address: The IP address.
            new_expires_at: New expires_at ISO-8601 string.

        Returns:
            True on success.
        """
        try:
            with self._session_factory() as session:
                record = (
                    session.query(BlockedIP)
                    .filter_by(ip_address=ip_address, active=1)
                    .first()
                )
                if record:
                    record.expires_at = new_expires_at
                    session.commit()
                return True
        except Exception as exc:
            logger.error(
                "BlockRepository.extend_expiry(%s) failed: %s", ip_address, exc
            )
            return False

    def get_expired(self) -> list[dict]:
        """
        Return all active blocks whose expires_at has passed.

        Returns:
            List of expired BlockedIP dicts.
        """
        try:
            now = _utc_now()
            with self._session_factory() as session:
                records = (
                    session.query(BlockedIP)
                    .filter(BlockedIP.active == 1, BlockedIP.expires_at <= now)
                    .all()
                )
                return [_block_to_dict(r) for r in records]
        except Exception as exc:
            logger.error("BlockRepository.get_expired failed: %s", exc)
            return []

    def is_blocked(self, ip_address: str) -> bool:
        """Return True if the IP has an active block."""
        return self.get_active(ip_address) is not None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _block_to_dict(record: BlockedIP) -> dict:
    return {
        "id": record.id,
        "event_id": record.event_id,
        "ip_address": record.ip_address,
        "blocked_at": record.blocked_at,
        "expires_at": record.expires_at,
        "unblock_time": record.unblock_time,
        "reason": record.reason,
        "active": bool(record.active),
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
