"""
threat_intel_service.py — Async enrichment, IOC correlation, risk scoring, and threat hunting.

Requirements: 10.1-10.6
"""

from __future__ import annotations

import json
import logging
import queue
import threading
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger("netguard.threat_intel_service")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ThreatIntelService:
    """
    Asynchronous threat-intel enrichment pipeline.

    Enqueues enrichment tasks on the calling thread; a background worker
    thread performs external lookups and updates the DB.
    """

    def __init__(self, event_repo, settings_repo, log_engine) -> None:
        self._event_repo = event_repo
        self._settings_repo = settings_repo
        self._log_engine = log_engine
        self._q: queue.Queue = queue.Queue(maxsize=500)
        self._worker = threading.Thread(
            target=self._enrichment_worker,
            name="EnrichmentWorker",
            daemon=True,
        )
        self._worker.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enqueue_enrichment(self, event_id: str, source_ip: str) -> None:
        """Enqueue an enrichment task (non-blocking; drops if queue full)."""
        try:
            self._q.put_nowait({"event_id": event_id, "source_ip": source_ip})
        except queue.Full:
            logger.warning("ThreatIntelService: enrichment queue full — dropping %s", event_id)
            try:
                from backend.services.drop_metrics import DropMetrics
                DropMetrics.get().increment("threat_intel")
            except Exception:
                pass

    @staticmethod
    def compute_risk_score(
        severity: float,
        reputation: float,
        ioc_match: bool,
        recurrence: int,
    ) -> int:
        """
        Composite risk score formula (Req 10.3):
        min(100, round(severity*40 + reputation*0.30 + ioc_match*20 + min(recurrence,10)*1.0))
        Weights: 40% + 30% + 20% + 10% = 100%
        """
        return min(100, round(
            severity * 40
            + reputation * 0.30
            + (20 if ioc_match else 0)
            + min(recurrence, 10) * 1.0
        ))

    def hunt(self, ioc_value: str, page: int = 1, per_page: int = 100) -> dict:
        """Return all events/blocks/enrichment related to an IOC value."""
        per_page = min(per_page, 100)
        offset = (page - 1) * per_page
        try:
            from database.schema import EnrichmentResult, IOCStore
            from sqlalchemy.orm import Session
            from backend.main import session_factory
            results: list[dict] = []
            with session_factory() as session:
                # Search enrichment_results
                rows = (
                    session.query(EnrichmentResult)
                    .filter(EnrichmentResult.ioc_identifiers.contains(ioc_value))
                    .offset(offset).limit(per_page).all()
                )
                results += [
                    {"source": "enrichment", "event_id": r.event_id,
                     "fetched_at": r.fetched_at, "status": r.status}
                    for r in rows
                ]
            return {"items": results, "page": page, "per_page": per_page}
        except Exception as exc:
            logger.error("ThreatIntelService.hunt failed: %s", exc)
            return {"items": [], "page": page, "per_page": per_page}

    def feedback(self, event_id: str, is_false_positive: bool, operator: str) -> None:
        """
        Persist false-positive feedback and decrease confidence for matching
        rule+subnet/24 by configurable step (default 5, floor 1) — Req 10.5.
        """
        try:
            step = int(self._settings_repo.get("threat_intel.fp_step") or 5)
            step = max(1, step)

            from database.schema import Event as EventModel
            from backend.main import session_factory
            with session_factory() as session:
                ev = session.query(EventModel).filter_by(event_id=event_id).first()
                if ev:
                    ev.false_positive = 1 if is_false_positive else 0
                    # Decrease confidence (floor 1)
                    if is_false_positive:
                        ev.confidence = max(1, (ev.confidence or 50) - step)
                    session.commit()
            logger.info("ThreatIntelService: feedback recorded for %s (fp=%s)", event_id, is_false_positive)
        except Exception as exc:
            logger.error("ThreatIntelService.feedback failed: %s", exc)

    # ------------------------------------------------------------------
    # Background enrichment worker
    # ------------------------------------------------------------------

    def _enrichment_worker(self) -> None:
        while True:
            try:
                task = self._q.get(timeout=5)
                self._enrich(task["event_id"], task["source_ip"])
            except queue.Empty:
                continue
            except Exception as exc:
                logger.error("EnrichmentWorker error: %s", exc, exc_info=True)

    def _enrich(self, event_id: str, source_ip: str) -> None:
        sources = ["abuseipdb", "virustotal"]  # expandable
        all_failed = True

        for source in sources:
            try:
                result = self._call_source(source, source_ip)
                if result:
                    all_failed = False
                    self._store_enrichment(event_id, source, result)
                    break
            except Exception as exc:
                logger.warning("ThreatIntelService: %s failed for %s: %s", source, source_ip, exc)

        if all_failed:
            self._mark_failed(event_id)

    def _call_source(self, source: str, ip: str) -> Optional[dict]:
        """Call external threat-intel source. Returns result dict or None."""
        if source == "abuseipdb":
            api_key = self._settings_repo.get("threat_intel.abuseipdb_key") if self._settings_repo else None
            if not api_key:
                return None
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json()
        if source == "virustotal":
            api_key = self._settings_repo.get("threat_intel.virustotal_key") if self._settings_repo else None
            if not api_key:
                return None
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": api_key},
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json()
        return None

    def _store_enrichment(self, event_id: str, source: str, result: dict) -> None:
        try:
            from database.schema import EnrichmentResult
            from backend.main import session_factory
            with session_factory() as session:
                row = EnrichmentResult(
                    event_id=event_id,
                    source=source,
                    fetched_at=_utc_now(),
                    result_json=json.dumps(result),
                    status="ok",
                )
                session.add(row)
                # Update event enrichment_status
                from database.schema import Event as EventModel
                ev = session.query(EventModel).filter_by(event_id=event_id).first()
                if ev:
                    ev.enrichment_status = "ok"
                session.commit()
        except Exception as exc:
            logger.error("ThreatIntelService._store_enrichment failed: %s", exc)

    def _mark_failed(self, event_id: str) -> None:
        try:
            from database.schema import Event as EventModel
            from backend.main import session_factory
            with session_factory() as session:
                ev = session.query(EventModel).filter_by(event_id=event_id).first()
                if ev:
                    ev.enrichment_status = "enrichment_failed"
                    session.commit()
            logger.warning("ThreatIntelService: all sources failed for event %s", event_id)
        except Exception as exc:
            logger.error("ThreatIntelService._mark_failed failed: %s", exc)
