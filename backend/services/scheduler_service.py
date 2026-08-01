"""
scheduler_service.py — Attack scheduling with APScheduler + SQLite job store.

Requirements: 2.1-2.10
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timezone

logger = logging.getLogger("netguard.scheduler_service")

_MAX_CONCURRENCY = 10
_MAX_BATCH = 50
_MAX_OCCURRENCES = 365


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SchedulerService:
    """
    Attack scheduler wrapping APScheduler BackgroundScheduler.

    ponytail: APScheduler is the minimal correct choice for cron+interval+oneshot
    with SQLite persistence. No home-grown scheduler needed.
    """

    def __init__(self, attack_lab_service, log_engine, socketio_emit=None) -> None:
        self._lab = attack_lab_service
        self._log = log_engine
        self._emit = socketio_emit or (lambda *a, **kw: None)
        self._semaphore = threading.Semaphore(_MAX_CONCURRENCY)
        self._scheduler = None
        self._session_factory = None  # wired after DB init in main.py

    def wire_session(self, session_factory) -> None:
        self._session_factory = session_factory

    def start(self) -> None:
        """Start the APScheduler. Call once at application startup."""
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
            from apscheduler.executors.pool import ThreadPoolExecutor
            from backend.main import db_url
            jobstore = SQLAlchemyJobStore(url=db_url)
            self._scheduler = BackgroundScheduler(
                jobstores={"default": jobstore},
                executors={"default": ThreadPoolExecutor(10)},
                job_defaults={"coalesce": False, "max_instances": 1},
            )
            self._scheduler.start()
            self._reschedule_pending()
            logger.info("SchedulerService: started")
        except Exception as exc:
            logger.error("SchedulerService: could not start APScheduler: %s", exc)
            self._scheduler = None

    def stop(self) -> None:
        if self._scheduler:
            try:
                self._scheduler.shutdown(wait=False)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Job management
    # ------------------------------------------------------------------

    def create_job(self, config: dict) -> dict:
        """
        Schedule a single attack job.
        Raises ValueError with descriptive message on invalid config.
        """
        self._validate_config(config)
        job_id = str(uuid.uuid4())
        self._persist_job(job_id, config)
        self._schedule_apscheduler(job_id, config)
        return {"job_id": job_id, "status": "PENDING"}

    def create_batch(self, configs: list) -> dict:
        """
        Schedule up to 50 jobs as a campaign (Req 2.6).
        Raises ValueError on oversized batch.
        """
        if len(configs) > _MAX_BATCH:
            raise ValueError("BATCH_LIMIT_EXCEEDED")
        campaign_id = str(uuid.uuid4())
        job_ids = []
        for cfg in configs:
            cfg = dict(cfg)
            cfg["campaign_id"] = campaign_id
            job_ids.append(self.create_job(cfg)["job_id"])
        return {"campaign_id": campaign_id, "job_ids": job_ids}

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a job. Returns False if not found."""
        updated = self._update_job_status(job_id, "CANCELLED")
        if not updated:
            return False
        if self._scheduler:
            try:
                self._scheduler.remove_job(job_id)
            except Exception:
                pass
        return True

    def list_jobs(
        self,
        page: int = 1,
        per_page: int = 20,
        status: str | None = None,
        attack_type: str | None = None,
    ) -> dict:
        per_page = min(per_page, 100)
        offset = (page - 1) * per_page
        try:
            from database.schema import ScheduledJob
            with self._session_factory() as session:
                q = session.query(ScheduledJob)
                if status:
                    q = q.filter(ScheduledJob.status == status.upper())
                if attack_type:
                    q = q.filter(ScheduledJob.attack_type == attack_type)
                total = q.count()
                rows = q.order_by(ScheduledJob.scheduled_at.desc()).offset(offset).limit(per_page).all()
                items = [self._job_to_dict(r) for r in rows]
            return {"items": items, "total": total, "page": page, "per_page": per_page}
        except Exception as exc:
            logger.error("SchedulerService.list_jobs failed: %s", exc)
            return {"items": [], "total": 0, "page": page, "per_page": per_page}

    # ------------------------------------------------------------------
    # Internal execution
    # ------------------------------------------------------------------

    def _execute_job(self, job_id: str) -> None:
        if not self._semaphore.acquire(blocking=False):
            # Concurrency cap — requeue (Req 2.8)
            self._update_job_status(job_id, "QUEUED")
            logger.warning("SchedulerService: concurrency cap reached — job %s queued", job_id)
            if self._scheduler:
                import datetime as _dt
                retry_at = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=10)
                self._scheduler.add_job(
                    self._execute_job, "date", run_date=retry_at,
                    args=[job_id], id=f"{job_id}-retry",
                    replace_existing=True,
                )
            return

        self._update_job_status(job_id, "RUNNING")
        try:
            config = self._get_job_config(job_id)
            if config and self._lab:
                self._lab.launch(config, operator="scheduler")
            self._update_job_status(job_id, "DONE")
        except Exception as exc:
            logger.error("SchedulerService: job %s FAILED: %s", job_id, exc)
            self._update_job_status(job_id, "FAILED")
            self._emit("scheduler_job_failed", {"job_id": job_id, "error": str(exc)})
        finally:
            self._semaphore.release()
            self._schedule_next(job_id)

    def _schedule_next(self, job_id: str) -> None:
        """Create next recurrence if applicable, capped at 365 total (Req 2.5)."""
        try:
            from database.schema import ScheduledJob
            with self._session_factory() as session:
                row = session.query(ScheduledJob).filter_by(id=job_id).first()
                if not row or not row.recurrence_rule:
                    return
                if row.occurrence_count >= _MAX_OCCURRENCES:
                    logger.info("SchedulerService: job %s reached 365 occurrence cap", job_id)
                    return
                config = json.loads(row.config_json)
                config["recurrence_rule"] = row.recurrence_rule
                config["campaign_id"] = row.campaign_id
                config["occurrence_count"] = row.occurrence_count + 1
                self.create_job(config)
        except Exception as exc:
            logger.error("SchedulerService._schedule_next failed: %s", exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _validate_config(self, config: dict) -> None:
        from datetime import datetime, timezone
        scheduled_at = config.get("scheduled_at")
        if scheduled_at:
            try:
                dt = datetime.fromisoformat(scheduled_at.replace("Z", "+00:00"))
                if dt < datetime.now(timezone.utc):
                    raise ValueError("Target datetime is in the past")
            except ValueError as exc:
                raise ValueError(f"Invalid scheduled_at: {exc}") from exc

        attack_type = config.get("attack_type", "")
        if not attack_type:
            raise ValueError("attack_type is required")

    def _persist_job(self, job_id: str, config: dict) -> None:
        try:
            from database.schema import ScheduledJob
            with self._session_factory() as session:
                row = ScheduledJob(
                    id=job_id,
                    attack_type=config.get("attack_type", ""),
                    config_json=json.dumps(config),
                    recurrence_rule=config.get("recurrence_rule"),
                    status="PENDING",
                    scheduled_at=config.get("scheduled_at", _utc_now()),
                    created_by=config.get("created_by", "system"),
                    campaign_id=config.get("campaign_id"),
                    occurrence_count=config.get("occurrence_count", 0),
                )
                session.add(row)
                session.commit()
        except Exception as exc:
            logger.error("SchedulerService._persist_job failed: %s", exc)

    def _schedule_apscheduler(self, job_id: str, config: dict) -> None:
        if not self._scheduler:
            return
        try:
            from apscheduler.triggers.date import DateTrigger
            from apscheduler.triggers.cron import CronTrigger
            scheduled_at = config.get("scheduled_at")
            recurrence = config.get("recurrence_rule")

            if recurrence:
                # Try cron first
                try:
                    trigger = CronTrigger.from_crontab(recurrence, timezone="UTC")
                except Exception:
                    trigger = DateTrigger(run_date=scheduled_at)
            else:
                trigger = DateTrigger(run_date=scheduled_at)

            self._scheduler.add_job(
                self._execute_job, trigger, args=[job_id],
                id=job_id, replace_existing=True,
                misfire_grace_time=5,
            )
        except Exception as exc:
            logger.error("SchedulerService._schedule_apscheduler failed: %s", exc)

    def _reschedule_pending(self) -> None:
        """On restart, skip past jobs and schedule only future ones (Req 2.4)."""
        if not self._session_factory:
            return
        try:
            from database.schema import ScheduledJob
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            with self._session_factory() as session:
                rows = session.query(ScheduledJob).filter(ScheduledJob.status == "PENDING").all()
                for row in rows:
                    try:
                        dt = datetime.fromisoformat(row.scheduled_at.replace("Z", "+00:00"))
                        if dt < now:
                            logger.info("SchedulerService: skipping past job %s at %s", row.id, row.scheduled_at)
                        else:
                            self._schedule_apscheduler(row.id, json.loads(row.config_json))
                    except Exception as exc:
                        logger.warning("SchedulerService: could not reschedule %s: %s", row.id, exc)
        except Exception as exc:
            logger.error("SchedulerService._reschedule_pending failed: %s", exc)

    def _update_job_status(self, job_id: str, status: str) -> bool:
        try:
            from database.schema import ScheduledJob
            with self._session_factory() as session:
                row = session.query(ScheduledJob).filter_by(id=job_id).first()
                if not row:
                    return False
                row.status = status
                if status in ("DONE", "FAILED", "CANCELLED"):
                    row.executed_at = _utc_now()
                session.commit()
            return True
        except Exception as exc:
            logger.error("SchedulerService._update_job_status failed: %s", exc)
            return False

    def _get_job_config(self, job_id: str) -> dict | None:
        try:
            from database.schema import ScheduledJob
            with self._session_factory() as session:
                row = session.query(ScheduledJob).filter_by(id=job_id).first()
                if row:
                    return json.loads(row.config_json)
        except Exception as exc:
            logger.error("SchedulerService._get_job_config failed: %s", exc)
        return None

    @staticmethod
    def _job_to_dict(row) -> dict:
        return {
            "id": row.id,
            "attack_type": row.attack_type,
            "status": row.status,
            "scheduled_at": row.scheduled_at,
            "executed_at": row.executed_at,
            "created_by": row.created_by,
            "campaign_id": row.campaign_id,
            "occurrence_count": row.occurrence_count,
            "recurrence_rule": row.recurrence_rule,
        }
