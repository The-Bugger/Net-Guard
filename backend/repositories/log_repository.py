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
        self._session_factory = session_factory

    def insert(self, timestamp: str, level: str, module: str,
               event: str, message: str, metadata: Optional[dict] = None) -> bool:
        try:
            with self._session_factory() as session:
                record = SystemLog(
                    timestamp=timestamp,
                    level=level,
                    module=module,
                    event=event,
                    message=message,
                    metadata=json.dumps(metadata) if metadata else None,
                )
                session.add(record)
                session.commit()
                return True
        except Exception as exc:
            logger.error("LogRepository.insert failed: %s", exc)
            return False

    def get_all(self, filters: Optional[dict] = None,
                limit: int = 50, offset: int = 0) -> list[dict]:
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
    metadata = None
    if record.metadata:
        try:
            metadata = json.loads(record.metadata)
        except Exception:
            metadata = {"raw": record.metadata}
    return {
        "id": record.id,
        "timestamp": record.timestamp,
        "level": record.level,
        "module": record.module,
        "event": record.event,
        "message": record.message,
        "metadata": metadata,
    }
