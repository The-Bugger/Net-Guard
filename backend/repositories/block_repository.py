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

    # ------------------------------------------------------------------
    # Enterprise extensions (Task 3.1)
    # ------------------------------------------------------------------

    def get_by_id(self, block_id: int) -> Optional[dict]:
        """Return a single block record by primary key."""
        try:
            with self._session_factory() as session:
                record = session.query(BlockedIP).filter_by(id=block_id).first()
                return _block_to_dict(record) if record else None
        except Exception as exc:
            logger.error("BlockRepository.get_by_id(%s) failed: %s", block_id, exc)
            return None

    def set_inactive_by_id(self, block_id: int) -> bool:
        """Mark a specific block record inactive (unblock by ID)."""
        try:
            with self._session_factory() as session:
                record = session.query(BlockedIP).filter_by(id=block_id).first()
                if record:
                    record.active = 0
                    record.unblock_time = _utc_now()
                    session.commit()
                return record is not None
        except Exception as exc:
            logger.error("BlockRepository.set_inactive_by_id(%s) failed: %s", block_id, exc)
            return False

    def get_history(self, ip: str, page: int = 1, per_page: int = 20) -> dict:
        """Return paginated block history for a specific IP (all records, not just active)."""
        try:
            offset = (page - 1) * per_page
            with self._session_factory() as session:
                total = session.query(BlockedIP).filter_by(ip_address=ip).count()
                records = (
                    session.query(BlockedIP)
                    .filter_by(ip_address=ip)
                    .order_by(BlockedIP.blocked_at.desc())
                    .offset(offset)
                    .limit(per_page)
                    .all()
                )
                return {
                    "items": [_block_to_dict(r) for r in records],
                    "total": total, "page": page, "per_page": per_page,
                }
        except Exception as exc:
            logger.error("BlockRepository.get_history(%s) failed: %s", ip, exc)
            return {"items": [], "total": 0, "page": page, "per_page": per_page}

    def get_by_type(self, block_type: str) -> list[dict]:
        """Return all active blocks of a given block_type."""
        try:
            with self._session_factory() as session:
                records = (
                    session.query(BlockedIP)
                    .filter_by(active=1)
                    .filter(BlockedIP.block_type == block_type)
                    .all()
                )
                return [_block_to_dict(r) for r in records]
        except Exception as exc:
            logger.error("BlockRepository.get_by_type(%s) failed: %s", block_type, exc)
            return []

    def get_paginated(
        self,
        page: int = 1,
        per_page: int = 20,
        filters: Optional[dict] = None,
    ) -> dict:
        """
        Return paginated block records with optional filtering.

        filters keys:
            ip         – partial match (LIKE %ip%)
            block_type – exact match
            status     – "active" → active=1, "inactive" → active=0
            date_from  – ISO string, created_at >=
            date_to    – ISO string, created_at <=
        """
        try:
            per_page = min(per_page, 100)  # cap at 100 (Req 1.10)
            offset = (page - 1) * per_page
            filters = filters or {}
            with self._session_factory() as session:
                q = session.query(BlockedIP)
                if filters.get("ip"):
                    q = q.filter(BlockedIP.ip_address.contains(filters["ip"]))
                if filters.get("block_type"):
                    q = q.filter(BlockedIP.block_type == filters["block_type"])
                status = filters.get("status")
                if status == "active":
                    q = q.filter(BlockedIP.active == 1)
                elif status == "inactive":
                    q = q.filter(BlockedIP.active == 0)
                if filters.get("date_from"):
                    q = q.filter(BlockedIP.blocked_at >= filters["date_from"])
                if filters.get("date_to"):
                    q = q.filter(BlockedIP.blocked_at <= filters["date_to"])
                total = q.count()
                records = q.order_by(BlockedIP.blocked_at.desc()).offset(offset).limit(per_page).all()
                return {
                    "items": [_block_to_dict(r) for r in records],
                    "total": total, "page": page, "per_page": per_page,
                }
        except Exception as exc:
            logger.error("BlockRepository.get_paginated failed: %s", exc)
            return {"items": [], "total": 0, "page": page, "per_page": per_page}

    def count_hits(self, ip_address: str) -> int:
        """Return total number of block records (all time) for an IP — used for threat score."""
        try:
            with self._session_factory() as session:
                return session.query(BlockedIP).filter_by(ip_address=ip_address).count()
        except Exception as exc:
            logger.error("BlockRepository.count_hits(%s) failed: %s", ip_address, exc)
            return 0

    def insert_enterprise(self, record_data: dict) -> Optional[int]:
        """
        Insert a new block record with enterprise fields.
        Returns the new record's id, or None on failure.
        """
        try:
            with self._session_factory() as session:
                record = BlockedIP(
                    event_id=record_data.get("event_id", ""),
                    ip_address=record_data["ip_address"],
                    blocked_at=record_data["blocked_at"],
                    expires_at=record_data["expires_at"],
                    reason=record_data.get("reason", ""),
                    active=1,
                    block_type=record_data.get("block_type", "ip"),
                    threat_score=record_data.get("threat_score", 0),
                    operator_id=record_data.get("operator_id", "system"),
                    audit_entry_id=record_data.get("audit_entry_id"),
                )
                session.add(record)
                session.commit()
                return record.id
        except Exception as exc:
            logger.error("BlockRepository.insert_enterprise failed: %s", exc, exc_info=True)
            return None


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
        "block_type": getattr(record, "block_type", "ip"),
        "threat_score": getattr(record, "threat_score", 0),
        "operator_id": getattr(record, "operator_id", "system"),
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
