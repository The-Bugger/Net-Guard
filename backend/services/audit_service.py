"""
audit_service.py — Append-only audit log for Net-Guard Enterprise IDPS.

Requirements: 14.5, 1.3, 14.3
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from database.schema import AuditLog

logger = logging.getLogger("netguard.audit_service")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AuditService:
    """Append-only audit log writer."""

    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    def log(self, username: str, action: str, resource_path: str, detail: dict | None = None) -> None:
        """Append an immutable audit entry. Never raises."""
        try:
            detail_json = json.dumps(detail) if detail else None
            with self._session_factory() as session:
                entry = AuditLog(
                    timestamp=_utc_now(),
                    username=username or "unknown",
                    action=action,
                    resource_path=resource_path,
                    detail_json=detail_json,
                )
                session.add(entry)
                session.commit()
        except Exception as exc:
            logger.error("AuditService.log failed: %s", exc)

    def get_paginated(self, page: int = 1, per_page: int = 50) -> dict:
        """Return a page of audit log entries (admin-only, enforced in route)."""
        try:
            offset = (page - 1) * per_page
            with self._session_factory() as session:
                total = session.query(AuditLog).count()
                rows = (
                    session.query(AuditLog)
                    .order_by(AuditLog.id.desc())
                    .offset(offset)
                    .limit(per_page)
                    .all()
                )
                items = [
                    {
                        "id": r.id,
                        "timestamp": r.timestamp,
                        "username": r.username,
                        "action": r.action,
                        "resource_path": r.resource_path,
                        "detail": json.loads(r.detail_json) if r.detail_json else None,
                    }
                    for r in rows
                ]
            return {"items": items, "total": total, "page": page, "per_page": per_page}
        except Exception as exc:
            logger.error("AuditService.get_paginated failed: %s", exc)
            return {"items": [], "total": 0, "page": page, "per_page": per_page}
