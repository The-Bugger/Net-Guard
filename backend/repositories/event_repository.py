"""Repository for the events table."""

from __future__ import annotations

import json
import logging
import queue
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from database.schema import Event

logger = logging.getLogger("netguard.event_repository")


class EventRepository:
    """CRUD operations for the events table with a thread-safe retry queue."""

    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory
        self._retry_queue: queue.Queue = queue.Queue(maxsize=1000)
        self._lock = threading.Lock()

    def insert(self, event_data: dict) -> bool:
        """Insert a detection event. Returns True on success; queues for retry on failure."""
        try:
            with self._session_factory() as session:
                session.add(self._to_record(event_data))
                session.commit()
                return True
        except Exception as exc:
            logger.error("EventRepository.insert failed: %s", exc, exc_info=True)
            try:
                self._retry_queue.put_nowait(event_data)
            except queue.Full:
                logger.error("EventRepository: retry queue full — event dropped.")
                try:
                    from backend.services.drop_metrics import DropMetrics
                    DropMetrics.get().increment("event_retry")
                except Exception:
                    pass
            return False

    @staticmethod
    def _to_record(event_data: dict) -> "Event":
        """Build an Event ORM object from a plain event_data dict."""
        return Event(
            event_id=event_data["event_id"],
            timestamp=event_data["timestamp"],
            attack_type=event_data["attack_type"],
            source_ip=event_data["source_ip"],
            destination_ip=event_data.get("destination_ip", ""),
            source_port=event_data.get("source_port"),
            destination_port=event_data.get("destination_port"),
            protocol=event_data.get("protocol", "UNKNOWN"),
            rule_name=event_data["rule_name"],
            severity=event_data["severity"],
            confidence=max(0, min(100, int(event_data.get("confidence", 0)))),
            packet_count=event_data.get("packet_count", 0),
            evidence=json.dumps(event_data.get("evidence", {})),
            explanation=event_data.get("explanation", ""),
            recommendation=event_data.get("recommendation"),
            blocked=1 if event_data.get("blocked") else 0,
        )

    def insert_many(self, events: list[dict]) -> int:
        """Insert multiple detection events in a single transaction.

        Returns the number of rows committed. On failure, falls back to
        per-row insert() so one bad row does not discard the whole batch.
        """
        if not events:
            return 0
        try:
            with self._session_factory() as session:
                session.add_all([self._to_record(e) for e in events])
                session.commit()
                return len(events)
        except Exception as exc:
            logger.error(
                "EventRepository.insert_many failed for batch of %d: %s — falling back to per-row insert",
                len(events), exc, exc_info=True,
            )
            inserted = 0
            for e in events:
                if self.insert(e):
                    inserted += 1
            return inserted

    def get_by_id(self, event_id: str) -> Optional[dict]:
        """Return a single event by event_id, or None if not found."""
        try:
            with self._session_factory() as session:
                record = session.query(Event).filter_by(event_id=event_id).first()
                return _event_to_dict(record) if record else None
        except Exception as exc:
            logger.error("EventRepository.get_by_id(%s) failed: %s", event_id, exc)
            return None

    def get_all(self, filters: Optional[dict] = None, limit: int = 100, offset: int = 0) -> list[dict]:
        """Query events with optional filters, ordered by timestamp descending."""
        try:
            with self._session_factory() as session:
                q = _apply_filters(session.query(Event), filters)
                records = q.order_by(Event.timestamp.desc()).limit(limit).offset(offset).all()
                return [_event_to_dict(r) for r in records]
        except Exception as exc:
            logger.error("EventRepository.get_all failed: %s", exc)
            return []

    def count_filtered(self, filters: Optional[dict] = None) -> int:
        """COUNT(*) with the same filter logic as get_all()."""
        try:
            with self._session_factory() as session:
                return _apply_filters(session.query(Event), filters).count()
        except Exception as exc:
            logger.error("EventRepository.count_filtered failed: %s", exc)
            return 0

    def update_blocked(self, event_id: str, blocked: bool) -> bool:
        """Update the blocked flag on an event."""
        try:
            with self._session_factory() as session:
                record = session.query(Event).filter_by(event_id=event_id).first()
                if record:
                    record.blocked = 1 if blocked else 0
                    session.commit()
                return True
        except Exception as exc:
            logger.error("EventRepository.update_blocked failed: %s", exc)
            return False

    def count(self) -> int:
        """Return total number of stored events."""
        try:
            with self._session_factory() as session:
                return session.query(Event).count()
        except Exception:
            return 0

    def count_today(self) -> int:
        """Return number of events detected today (UTC date)."""
        try:
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            with self._session_factory() as session:
                return session.query(Event).filter(Event.timestamp.like(f"{today}%")).count()
        except Exception:
            return 0

    def get_attack_type_counts(self) -> list[dict]:
        """Return aggregate counts per attack_type."""
        try:
            with self._session_factory() as session:
                rows = (
                    session.query(Event.attack_type, func.count(Event.id))
                    .group_by(Event.attack_type)
                    .all()
                )
                return [{"attack_type": r[0], "count": r[1]} for r in rows]
        except Exception as exc:
            logger.error("EventRepository.get_attack_type_counts failed: %s", exc)
            return []

    def get_distinct_attack_types_today(self) -> set[str]:
        """Return distinct attack_type values for the current UTC calendar day."""
        try:
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            with self._session_factory() as session:
                rows = (
                    session.query(Event.attack_type)
                    .filter(Event.timestamp.like(f"{today}%"))
                    .distinct()
                    .all()
                )
                return {r[0] for r in rows if r[0]}
        except Exception as exc:
            logger.error("EventRepository.get_distinct_attack_types_today failed: %s", exc)
            raise

    def flush_retry_queue(self) -> int:
        """Attempt to insert all queued retry events. Returns count flushed."""
        flushed = 0
        while not self._retry_queue.empty():
            try:
                data = self._retry_queue.get_nowait()
                if self.insert(data):
                    flushed += 1
            except queue.Empty:
                break
        return flushed


def _apply_filters(q, filters: Optional[dict]):
    """Apply filter logic to a SQLAlchemy query."""
    if not filters:
        return q
    if filters.get("severity"):
        q = q.filter(Event.severity == filters["severity"])
    if filters.get("attack_type"):
        q = q.filter(Event.attack_type == filters["attack_type"])
    if filters.get("source_ip"):
        q = q.filter(Event.source_ip == filters["source_ip"])
    if filters.get("date"):
        q = q.filter(Event.timestamp.like(f"{filters['date']}%"))
    if filters.get("search"):
        term = f"%{filters['search']}%"
        q = q.filter(or_(
            func.lower(Event.source_ip).like(func.lower(term)),
            func.lower(Event.destination_ip).like(func.lower(term)),
            func.lower(Event.attack_type).like(func.lower(term)),
        ))
    return q


def _event_to_dict(record: Event) -> dict:
    evidence = {}
    if record.evidence:
        try:
            evidence = json.loads(record.evidence)
        except Exception:
            evidence = {"raw": record.evidence}

    return {
        "id": record.id,
        "event_id": record.event_id,
        "timestamp": record.timestamp,
        "attack_type": record.attack_type,
        "source_ip": record.source_ip,
        "destination_ip": record.destination_ip,
        "source_port": record.source_port,
        "destination_port": record.destination_port,
        "protocol": record.protocol,
        "rule_name": record.rule_name,
        "severity": record.severity,
        "confidence": record.confidence,
        "packet_count": record.packet_count,
        "evidence": evidence,
        "explanation": record.explanation,
        "recommendation": record.recommendation,
        "blocked": bool(record.blocked),
    }
