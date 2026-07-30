"""
whitelist_repository.py — Repository for the whitelist table.

All operations use single database transactions as required.

Requirements: 12.2, 12.3
"""

from __future__ import annotations

import logging
from typing import Optional

from database.schema import WhitelistEntry

logger = logging.getLogger("netguard.whitelist_repository")


class WhitelistRepository:
    """CRUD operations for the whitelist table."""

    def __init__(self, session_factory) -> None:
        """
        Args:
            session_factory: Callable returning a new SQLAlchemy Session context manager.
        """
        self._session_factory = session_factory

    def insert(self, ip_address: str, description: Optional[str], created_at: str,
               created_by: str = "admin") -> bool:
        """
        Insert a new whitelist entry.

        Args:
            ip_address: Valid IPv4 or IPv6 address string.
            description: Optional human-readable label for the entry.
            created_at: UTC ISO-8601 timestamp string.
            created_by: Identifier of the creator (default "admin").

        Returns:
            True on success, False on failure.
        """
        try:
            with self._session_factory() as session:
                entry = WhitelistEntry(
                    ip_address=ip_address,
                    description=description,
                    created_at=created_at,
                    created_by=created_by,
                )
                session.add(entry)
                session.commit()
                return True
        except Exception as exc:
            logger.error("WhitelistRepository.insert(%s) failed: %s", ip_address, exc)
            return False

    def delete(self, ip_address: str) -> bool:
        """
        Remove a whitelist entry by IP address.

        Args:
            ip_address: The IP address to remove.

        Returns:
            True if deleted, False if not found.
        """
        try:
            with self._session_factory() as session:
                record = (
                    session.query(WhitelistEntry)
                    .filter_by(ip_address=ip_address)
                    .first()
                )
                if record is None:
                    return False
                session.delete(record)
                session.commit()
                return True
        except Exception as exc:
            logger.error("WhitelistRepository.delete(%s) failed: %s", ip_address, exc)
            return False

    def get_all(self) -> list[dict]:
        """
        Return all whitelist entries ordered by created_at descending.

        Returns:
            List of dicts with id, ip_address, description, created_at, created_by.
        """
        try:
            with self._session_factory() as session:
                records = (
                    session.query(WhitelistEntry)
                    .order_by(WhitelistEntry.created_at.desc())
                    .all()
                )
                return [_entry_to_dict(r) for r in records]
        except Exception as exc:
            logger.error("WhitelistRepository.get_all failed: %s", exc)
            return []

    def exists(self, ip_address: str) -> bool:
        """
        Check whether an IP address has a whitelist entry.

        Args:
            ip_address: The IP address to look up.

        Returns:
            True if the IP is whitelisted, False otherwise.
        """
        try:
            with self._session_factory() as session:
                return (
                    session.query(WhitelistEntry)
                    .filter_by(ip_address=ip_address)
                    .count()
                ) > 0
        except Exception:
            return False


def _entry_to_dict(record: WhitelistEntry) -> dict:
    """Convert a WhitelistEntry ORM object to a plain dict."""
    return {
        "id": record.id,
        "ip_address": record.ip_address,
        "description": record.description,
        "created_at": record.created_at,
        "created_by": record.created_by,
    }
