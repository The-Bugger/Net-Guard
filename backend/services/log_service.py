"""
log_service.py — Logging_Engine for NetGuard IDPS.

Provides three distinct log outputs:
  - logs/system.log    — INFO-level lifecycle events (startup, shutdown, monitor start/stop)
  - logs/detections.log — Every ThreatEvent detection and block/unblock action
  - logs/errors.log    — WARNING, ERROR, and CRITICAL from all modules

The LoggingEngine runs a dedicated background Logging_Thread that consumes
events from a thread-safe queue and persists them to the database and log
files without blocking packet capture or detection processing.

Requirements: 15.1, 15.2, 15.3, 15.4, 15.5
"""

from __future__ import annotations

import json
import logging
import queue
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent
_LOGS_DIR: Path = _PROJECT_ROOT / "logs"

_SYSTEM_LOG: Path = _LOGS_DIR / "system.log"
_DETECTIONS_LOG: Path = _LOGS_DIR / "detections.log"
_ERRORS_LOG: Path = _LOGS_DIR / "errors.log"

# Max 10 MB per file, keep 5 backups
_MAX_BYTES: int = 10 * 1024 * 1024
_BACKUP_COUNT: int = 5

# ---------------------------------------------------------------------------
# Sentinel for stopping the logging thread
# ---------------------------------------------------------------------------

_STOP_SENTINEL = object()


# ---------------------------------------------------------------------------
# Public API — module-level loggers
# ---------------------------------------------------------------------------

def get_system_logger() -> logging.Logger:
    """Return the logger that writes to logs/system.log."""
    return logging.getLogger("netguard.system")


def get_detection_logger() -> logging.Logger:
    """Return the logger that writes to logs/detections.log."""
    return logging.getLogger("netguard.detections")


def get_error_logger() -> logging.Logger:
    """Return the logger that writes to logs/errors.log."""
    return logging.getLogger("netguard.errors")


# ---------------------------------------------------------------------------
# Log initialisation (called once at startup)
# ---------------------------------------------------------------------------

def setup_logging(log_level: str = "INFO") -> None:
    """
    Configure all three rotating file log handlers.

    Must be called once during application startup before any module tries
    to log.  Safe to call multiple times — duplicate handlers are not added.

    Args:
        log_level: Root log level string (INFO, DEBUG, WARNING, etc.)
    """
    _LOGS_DIR.mkdir(parents=True, exist_ok=True)

    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    _configure_logger(
        "netguard.system",
        _SYSTEM_LOG,
        level=logging.INFO,
    )
    _configure_logger(
        "netguard.detections",
        _DETECTIONS_LOG,
        level=logging.INFO,
    )
    _configure_logger(
        "netguard.errors",
        _ERRORS_LOG,
        level=logging.WARNING,
    )

    # Root netguard logger at DEBUG so child loggers control their own level
    root = logging.getLogger("netguard")
    root.setLevel(logging.DEBUG)
    root.propagate = False


def _configure_logger(name: str, path: Path, level: int) -> None:
    """Attach a RotatingFileHandler to a named logger if not already attached."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False  # do not bubble up to root

    # Only add handler if one doesn't already exist for this path
    for handler in logger.handlers:
        if isinstance(handler, RotatingFileHandler) and handler.baseFilename == str(path):
            return

    handler = RotatingFileHandler(
        path,
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setLevel(level)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    logger.addHandler(handler)


# ---------------------------------------------------------------------------
# DB-aware log entry (written to system_logs table)
# ---------------------------------------------------------------------------

class LogEntry:
    """Lightweight data object queued by LoggingEngine for async DB persistence."""

    __slots__ = ("timestamp", "level", "module", "event", "message", "metadata")

    def __init__(
        self,
        level: str,
        module: str,
        event: str,
        message: str,
        metadata: Optional[dict] = None,
    ) -> None:
        self.timestamp: str = _utc_now()
        self.level = level
        self.module = module
        self.event = event
        self.message = message
        self.metadata: Optional[str] = json.dumps(metadata) if metadata else None


# ---------------------------------------------------------------------------
# LoggingEngine
# ---------------------------------------------------------------------------

class LoggingEngine:
    """
    Async logging engine for NetGuard.

    Maintains a background Logging_Thread that consumes items from an internal
    queue and persists them to the database (system_logs table).  Log files are
    written synchronously on the calling thread via Python's logging module so
    that they are never delayed.

    Usage::

        engine = LoggingEngine(session_factory)
        engine.start()
        engine.log_system("INFO", "CaptureEngine", "START", "Monitoring started on eth0")
        engine.stop()
    """

    def __init__(self, session_factory=None) -> None:
        """
        Args:
            session_factory: A callable that returns a new SQLAlchemy Session.
                             If None, DB persistence is skipped (log files still work).
        """
        self._session_factory = session_factory
        self._queue: queue.Queue = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self._sys_log = get_system_logger()
        self._det_log = get_detection_logger()
        self._err_log = get_error_logger()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background Logging_Thread."""
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._logging_loop,
            name="Logging_Thread",
            daemon=True,
        )
        self._thread.start()
        self._sys_log.info("LoggingEngine started.")

    def stop(self) -> None:
        """
        Signal the Logging_Thread to stop and wait for it to drain the queue.

        Blocks for up to 5 seconds.
        """
        if self._thread and self._thread.is_alive():
            self._queue.put(_STOP_SENTINEL)
            self._thread.join(timeout=5.0)
        self._sys_log.info("LoggingEngine stopped.")

    # ------------------------------------------------------------------
    # Public logging methods (call from any thread)
    # ------------------------------------------------------------------

    def log_event(self, event_data: dict, explanation_data: dict) -> None:
        """
        Queue a detection event for async DB persistence.

        Also writes immediately to detections.log on the calling thread.

        Args:
            event_data: Dict representation of a ThreatEvent.
            explanation_data: Dict representation of an Explanation.
        """
        # Write to detections.log immediately (non-blocking)
        self._det_log.info(
            "DETECTION | timestamp=%s source_ip=%s attack_type=%s "
            "severity=%s confidence=%s rule=%s action=%s",
            event_data.get("timestamp", ""),
            event_data.get("source_ip", ""),
            event_data.get("attack_type", ""),
            event_data.get("severity", ""),
            event_data.get("confidence", ""),
            event_data.get("rule_name", ""),
            "BLOCKED" if event_data.get("blocked") else "DETECTED",
        )

        # Queue for DB persistence
        entry = LogEntry(
            level="INFO",
            module="DetectionEngine",
            event=event_data.get("attack_type", "UNKNOWN"),
            message=(
                f"Detected {event_data.get('attack_type')} from "
                f"{event_data.get('source_ip')} — "
                f"severity={event_data.get('severity')} "
                f"confidence={event_data.get('confidence')}"
            ),
            metadata={
                "event_id": event_data.get("event_id"),
                "source_ip": event_data.get("source_ip"),
                "rule_name": event_data.get("rule_name"),
                "blocked": event_data.get("blocked", False),
            },
        )
        self._queue.put(entry)

    def log_block(self, ip: str, reason: str, duration: int) -> None:
        """
        Log an IP block action to detections.log and queue for DB.

        Args:
            ip: The IP address that was blocked.
            reason: The attack type that triggered the block.
            duration: Block duration in seconds.
        """
        self._det_log.info(
            "BLOCK     | ip=%s reason=%s duration=%ds",
            ip, reason, duration,
        )
        entry = LogEntry(
            level="INFO",
            module="PreventionEngine",
            event="IP_BLOCKED",
            message=f"Blocked {ip} for {duration}s — reason: {reason}",
            metadata={"ip": ip, "reason": reason, "duration": duration},
        )
        self._queue.put(entry)

    def log_unblock(self, ip: str, reason: str = "expired") -> None:
        """
        Log an IP unblock action to detections.log and queue for DB.

        Args:
            ip: The IP address that was unblocked.
            reason: Why the block was removed ("expired" or "manual").
        """
        self._det_log.info("UNBLOCK   | ip=%s reason=%s", ip, reason)
        entry = LogEntry(
            level="INFO",
            module="PreventionEngine",
            event="IP_UNBLOCKED",
            message=f"Unblocked {ip} — reason: {reason}",
            metadata={"ip": ip, "reason": reason},
        )
        self._queue.put(entry)

    def log_system(
        self,
        level: str,
        module: str,
        event: str,
        message: str,
        metadata: Optional[dict] = None,
    ) -> None:
        """
        Log a system lifecycle event to system.log and queue for DB.

        Args:
            level: Log level string (INFO, WARNING, ERROR, CRITICAL).
            module: Name of the originating module.
            event: Short event label (e.g. "STARTUP", "MONITOR_START").
            message: Human-readable description.
            metadata: Optional dict of extra context (serialized as JSON).
        """
        numeric = getattr(logging, level.upper(), logging.INFO)
        self._sys_log.log(numeric, "%s | %s — %s", module, event, message)

        if level.upper() in ("WARNING", "ERROR", "CRITICAL"):
            self._err_log.log(numeric, "%s | %s — %s", module, event, message)

        entry = LogEntry(
            level=level.upper(),
            module=module,
            event=event,
            message=message,
            metadata=metadata,
        )
        self._queue.put(entry)

    # ------------------------------------------------------------------
    # Background thread
    # ------------------------------------------------------------------

    def _logging_loop(self) -> None:
        """Consume log entries from the queue and persist to the DB."""
        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            if item is _STOP_SENTINEL:
                # Drain remaining items before exiting
                while True:
                    try:
                        remaining = self._queue.get_nowait()
                        if remaining is not _STOP_SENTINEL:
                            self._persist_entry(remaining)
                    except queue.Empty:
                        break
                break

            self._persist_entry(item)

    def _persist_entry(self, entry: LogEntry) -> None:
        """Persist a single LogEntry to the system_logs table."""
        if self._session_factory is None:
            return

        try:
            from database.schema import SystemLog

            log_record = SystemLog(
                timestamp=entry.timestamp,
                level=entry.level,
                module=entry.module,
                event=entry.event,
                message=entry.message,
                metadata=entry.metadata,
            )
            with self._session_factory() as session:
                session.add(log_record)
                session.commit()

        except Exception as exc:  # noqa: BLE001
            # Write to stderr so we don't lose the error
            import sys
            print(
                f"[LoggingEngine] Failed to persist log entry to DB: {exc}",
                file=sys.stderr,
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
