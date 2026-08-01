"""
log_repository.py — Repository for the system_logs table.

Requirements: 14.5
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from database.schema import SystemLog

logger = logging.getLogger("netguard.log_repository")


class LogRepository:
    """CRUD operations for the system_logs table."""

    def __init__(self, session_factory) -> None:
        """
        Args:
            session_factory: Callable returning a new SQLAlchemy Session context manager.
        """
        self._session_factory = session_factory

    def insert(self, timestamp: str, level: str, module: str,
               event: str, message: str, metadata: Optional[dict] = None) -> bool:
        """
        Insert a system log entry.

        Args:
            timestamp: UTC ISO-8601 string.
            level: Log level string (INFO, WARNING, ERROR, CRITICAL).
            module: Originating module name.
            event: Short event label (e.g. "MONITOR_START").
            message: Human-readable description.
            metadata: Optional dict of extra context; serialised as JSON.

        Returns:
            True on success, False on failure.
        """
        try:
            with self._session_factory() as session:
                record = SystemLog(
                    timestamp=timestamp,
                    level=level,
                    module=module,
                    event=event,
                    message=message,
                    meta=json.dumps(metadata) if metadata else None,
                )
                session.add(record)
                session.commit()
                return True
        except Exception as exc:
            logger.error("LogRepository.insert failed: %s", exc)
            return False

    def get_all(self, filters: Optional[dict] = None,
                limit: int = 50, offset: int = 0) -> list[dict]:
        """
        Query system log entries with optional filters.

        Args:
            filters: Dict with optional keys: level, module, date (YYYY-MM-DD), event.
            limit: Maximum records to return.
            offset: Pagination offset.

        Returns:
            List of log entry dicts ordered by timestamp descending.
        """
        try:
            with self._session_factory() as session:
                q = session.query(SystemLog)
                if filters:
                    if filters.get("level"):
                        q = q.filter(SystemLog.level == filters["level"].upper())
                    if filters.get("module"):
                        q = q.filter(SystemLog.module == filters["module"])
                    if filters.get("date"):
                        q = q.filter(SystemLog.timestamp.like(f"{filters['date']}%"))
                    if filters.get("event"):
                        q = q.filter(SystemLog.event.like(f"%{filters['event']}%"))
                records = (
                    q.order_by(SystemLog.timestamp.desc())
                    .limit(limit)
                    .offset(offset)
                    .all()
                )
                return [_log_to_dict(r) for r in records]
        except Exception as exc:
            logger.error("LogRepository.get_all failed: %s", exc)
            return []

    def count(self, filters: Optional[dict] = None) -> int:
        """
        Return the total number of system log entries matching optional filters.

        Args:
            filters: Dict with optional key: level.

        Returns:
            Integer count, or 0 on error.
        """
        try:
            with self._session_factory() as session:
                q = session.query(SystemLog)
                if filters:
                    if filters.get("level"):
                        q = q.filter(SystemLog.level == filters["level"].upper())
                return q.count()
        except Exception:
            return 0


def _log_to_dict(record: SystemLog) -> dict:
    """Convert a SystemLog ORM object to a plain dict."""
    metadata = None
    if record.meta:
        try:
            metadata = json.loads(record.meta)
        except Exception:
            metadata = {"raw": record.meta}
    return {
        "id": record.id,
        "timestamp": record.timestamp,
        "level": record.level,
        "module": record.module,
        "event": record.event,
        "message": record.message,
        "metadata": metadata,
    }
