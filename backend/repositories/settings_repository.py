"""
settings_repository.py — Repository for the settings table.

Requirements: 1.4
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from database.schema import Setting

logger = logging.getLogger("netguard.settings_repository")


class SettingsRepository:
    """CRUD operations for the settings table."""

    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    def get(self, key: str) -> Optional[str]:
        try:
            with self._session_factory() as session:
                record = session.query(Setting).filter_by(key=key).first()
                return record.value if record else None
        except Exception as exc:
            logger.error("SettingsRepository.get(%s) failed: %s", key, exc)
            return None

    def set(self, key: str, value: str) -> bool:
        try:
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            with self._session_factory() as session:
                record = session.query(Setting).filter_by(key=key).first()
                if record:
                    record.value = value
                    record.updated_at = now
                else:
                    record = Setting(key=key, value=value, updated_at=now)
                    session.add(record)
                session.commit()
                return True
        except Exception as exc:
            logger.error("SettingsRepository.set(%s) failed: %s", key, exc)
            return False

    def get_all(self) -> dict:
        try:
            with self._session_factory() as session:
                records = session.query(Setting).all()
                return {r.key: r.value for r in records}
        except Exception as exc:
            logger.error("SettingsRepository.get_all failed: %s", exc)
            return {}
