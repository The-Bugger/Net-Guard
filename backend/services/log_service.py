"""
log_service.py — Logging_Engine for NetGuard IDPS.

Provides three distinct rotating log file outputs:
  - logs/system.log    — INFO-level lifecycle events (startup, shutdown, monitor start/stop)
  - logs/detections.log — Every ThreatEvent detection and every block/unblock action
  - logs/errors.log    — WARNING, ERROR, and CRITICAL from all modules

The LoggingEngine runs a dedicated background Logging_Thread that consumes
ThreatEvent + Explanation tuples from a shared thread-safe ``event_queue`` and
persists them to the database and detections.log without blocking packet capture
or detection processing.

Design:
- ``event_queue`` is shared between Detection_Thread (producer) and Logging_Thread (consumer)
- log_system() writes to system.log / errors.log synchronously on the calling thread
- log_event() enqueues the event for the Logging_Thread to persist
- RotatingFileHandler: max 10 MB per file, 5 backups
- Sensitive keys (password, secret, token, private_key, api_key) are redacted

Requirements: 15.1, 15.2, 15.3, 15.4, 15.5
"""

from __future__ import annotations

import json
import logging
import queue
import re
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from detection.rules.base_rule import Explanation, ThreatEvent

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent
_LOGS_DIR: Path = _PROJECT_ROOT / "logs"

_SYSTEM_LOG: Path = _LOGS_DIR / "system.log"
_DETECTIONS_LOG: Path = _LOGS_DIR / "detections.log"
_ERRORS_LOG: Path = _LOGS_DIR / "errors.log"

# Max 10 MB per file, keep 5 backups (Req 15.1, 15.2, 15.3)
_MAX_BYTES: int = 10 * 1024 * 1024
_BACKUP_COUNT: int = 5

# ---------------------------------------------------------------------------
# Sensitive key patterns — never logged (Req 15.4)
# ---------------------------------------------------------------------------

_SENSITIVE_KEYS: frozenset = frozenset({
    "password", "passwd", "secret", "token",
    "private_key", "api_key", "auth", "credential",
})

# Matches: "password=<value>", "password: <value>", or just the bare key word
_SENSITIVE_PATTERN = re.compile(
    r"\b(?:" + "|".join(re.escape(k) for k in _SENSITIVE_KEYS) + r")\b(?:[=:\s]+\S+)?",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Sentinel for stopping the logging thread
# ---------------------------------------------------------------------------

_STOP_SENTINEL = object()


# ---------------------------------------------------------------------------
# Module-level logger accessors
# ---------------------------------------------------------------------------

def get_system_logger() -> logging.Logger:
    """Return the logger that writes to logs/system.log (Req 15.1)."""
    return logging.getLogger("netguard.system")


def get_detection_logger() -> logging.Logger:
    """Return the logger that writes to logs/detections.log (Req 15.2)."""
    return logging.getLogger("netguard.detections")


def get_error_logger() -> logging.Logger:
    """Return the logger that writes to logs/errors.log (Req 15.3)."""
    return logging.getLogger("netguard.errors")


# ---------------------------------------------------------------------------
# One-time log configuration — call at application startup
# ---------------------------------------------------------------------------

def setup_logging() -> None:
    """
    Configure all three rotating file log handlers.

    Must be called once during application startup before any module attempts
    to log.  Safe to call multiple times — duplicate handlers are not added.

    Creates the ``logs/`` directory if it does not already exist.
    """
    _LOGS_DIR.mkdir(parents=True, exist_ok=True)

    _configure_logger("netguard.system", _SYSTEM_LOG, level=logging.INFO)
    _configure_logger("netguard.detections", _DETECTIONS_LOG, level=logging.INFO)
    _configure_logger("netguard.errors", _ERRORS_LOG, level=logging.WARNING)

    # Parent netguard logger — keep at DEBUG so children decide their own floor
    root = logging.getLogger("netguard")
    root.setLevel(logging.DEBUG)
    root.propagate = False


def _configure_logger(name: str, path: Path, level: int) -> None:
    """Attach a RotatingFileHandler to a named logger if one is not already present."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    # Idempotent — skip if this exact file handler is already attached
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
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _redact_sensitive(message: str) -> str:
    """
    Replace any mention of sensitive key names in a message with [REDACTED].

    Requirement 15.4: never log passwords, private keys, tokens, or secrets.
    """
    return _SENSITIVE_PATTERN.sub("[REDACTED]", message)


def _safe_metadata(metadata: Optional[dict]) -> Optional[str]:
    """
    Serialise metadata to JSON, stripping any key whose name matches a
    sensitive-key pattern before serialisation.

    Returns None if metadata is None or empty.
    """
    if not metadata:
        return None
    safe = {
        k: v
        for k, v in metadata.items()
        if k.lower() not in _SENSITIVE_KEYS
    }
    return json.dumps(safe)


# ---------------------------------------------------------------------------
# LoggingEngine
# ---------------------------------------------------------------------------

class LoggingEngine:
    """
    Async logging engine for NetGuard.

    Maintains a background ``Logging_Thread`` that consumes ``(ThreatEvent,
    Explanation)`` tuples from the shared ``event_queue`` and persists them to
    both the database (via EventRepository / LogRepository) and detections.log.

    Lifecycle events (startup, shutdown, monitor start/stop) are written to
    system.log synchronously on the calling thread via ``log_system()``.

    Usage::

        engine = LoggingEngine(
            event_queue=event_queue,
            event_repo=EventRepository(session_factory),
            log_repo=LogRepository(session_factory),
        )
        engine.start()
        engine.log_system("INFO", "MonitorService", "MONITOR_START", "Started on eth0")
        # Detection_Thread puts (ThreatEvent, Explanation) onto event_queue
        engine.stop()
    """

    def __init__(
        self,
        event_queue: Optional[queue.Queue] = None,
        event_repo=None,
        log_repo=None,
    ) -> None:
        """
        Args:
            event_queue: Shared ``queue.Queue`` that the Detection_Thread puts
                         ``(ThreatEvent, Explanation)`` tuples onto.  If None,
                         a private queue is created (useful for testing / direct
                         ``log_event()`` calls).
            event_repo:  ``EventRepository`` instance for persisting ThreatEvents.
                         If None, DB persistence of events is skipped.
            log_repo:    ``LogRepository`` instance for persisting system log
                         entries.  If None, DB persistence of logs is skipped.
        """
        self._event_queue: queue.Queue = event_queue if event_queue is not None else queue.Queue()
        self._event_repo = event_repo
        self._log_repo = log_repo

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self._sys_log = get_system_logger()
        self._det_log = get_detection_logger()
        self._err_log = get_error_logger()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Start the background Logging_Thread (Req 15.5).

        Idempotent — safe to call if already running.
        """
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._logging_loop,
            name="Logging_Thread",
            daemon=True,
        )
        self._thread.start()

        # Req 15.1 — log startup lifecycle event to system.log
        self._sys_log.info("LoggingEngine started.")
        self._persist_system_log("INFO", "LoggingEngine", "STARTUP", "LoggingEngine started.")

    def stop(self) -> None:
        """
        Signal the Logging_Thread to stop and wait up to 5 seconds for it to
        drain the remaining queue items before exiting.
        """
        if self._thread and self._thread.is_alive():
            self._event_queue.put(_STOP_SENTINEL)
            self._thread.join(timeout=5.0)
            self._thread = None

        # Req 15.1 — log shutdown lifecycle event to system.log
        self._sys_log.info("LoggingEngine stopped.")
        self._persist_system_log("INFO", "LoggingEngine", "SHUTDOWN", "LoggingEngine stopped.")

    # ------------------------------------------------------------------
    # Public logging methods (callable from any thread)
    # ------------------------------------------------------------------

    def log_event(self, event: "ThreatEvent", explanation: "Explanation") -> None:
        """
        Queue a detection event for async persistence and write to detections.log.

        The write to detections.log happens synchronously on the calling thread
        (fast — no I/O blocking concerns at log volume).  The DB insert is
        deferred to the Logging_Thread.

        Requirement 15.2: write every ThreatEvent + block/unblock to detections.log
        including UTC timestamp, source IP, attack_type, severity, confidence,
        rule_name, and action taken.

        Args:
            event:       ThreatEvent dataclass produced by a detection rule.
            explanation: Explanation dataclass produced by ExplainabilityEngine.
        """
        action = "BLOCKED" if event.blocked else "DETECTED"

        # Req 15.2 — write to detections.log immediately (synchronous, fast)
        self._det_log.info(
            "DETECTION | timestamp=%s source_ip=%s attack_type=%s "
            "severity=%s confidence=%s rule=%s action=%s",
            event.timestamp,
            event.source_ip,
            event.attack_type,
            event.severity,
            event.confidence,
            event.rule_name,
            action,
        )

        # Enqueue for async DB persistence (Req 15.5 — must not block packet capture)
        self._event_queue.put((event, explanation))

    def log_block(self, ip: str, reason: str, duration: int) -> None:
        """
        Log an IP block action to detections.log and persist to system_logs.

        Req 15.2: every block action must appear in detections.log.

        Args:
            ip:       The IP address that was blocked.
            reason:   The attack type that triggered the block.
            duration: Block duration in seconds (0 = manual / indefinite).
        """
        self._det_log.info(
            "BLOCK     | ip=%s reason=%s duration=%ds",
            ip, reason, duration,
        )
        self._persist_system_log(
            level="INFO",
            module="PreventionEngine",
            event="IP_BLOCKED",
            message=f"Blocked {ip} for {duration}s — reason: {reason}",
            metadata={"ip": ip, "reason": reason, "duration": duration},
        )

    def log_unblock(self, ip: str, reason: str = "expired") -> None:
        """
        Log an IP unblock action to detections.log and persist to system_logs.

        Req 15.2: every unblock action must appear in detections.log.

        Args:
            ip:     The IP address that was unblocked.
            reason: Cause of removal — "expired" or "manual".
        """
        self._det_log.info("UNBLOCK   | ip=%s reason=%s", ip, reason)
        self._persist_system_log(
            level="INFO",
            module="PreventionEngine",
            event="IP_UNBLOCKED",
            message=f"Unblocked {ip} — reason: {reason}",
            metadata={"ip": ip, "reason": reason},
        )

    def log_system(
        self,
        level: str,
        module: str,
        event: str,
        message: str,
        metadata: Optional[dict] = None,
    ) -> None:
        """
        Log a system lifecycle event.

        Writes to system.log (Req 15.1) and, for WARNING/ERROR/CRITICAL,
        also writes to errors.log (Req 15.3).  Persists to system_logs table.

        Sensitive values in ``metadata`` are automatically stripped (Req 15.4).

        Args:
            level:    Log level string (INFO, WARNING, ERROR, CRITICAL).
            module:   Name of the originating module (e.g. ``"MonitorService"``).
            event:    Short event label (e.g. ``"MONITOR_START"``).
            message:  Human-readable description.
            metadata: Optional dict of extra context; serialised as JSON in DB.
        """
        numeric = getattr(logging, level.upper(), logging.INFO)
        safe_message = _redact_sensitive(message)

        # Req 15.1 — write lifecycle events to system.log
        self._sys_log.log(numeric, "%s | %s — %s", module, event, safe_message)

        # Req 15.3 — mirror WARNING+ to errors.log
        if level.upper() in ("WARNING", "ERROR", "CRITICAL"):
            self._err_log.log(numeric, "%s | %s — %s", module, event, safe_message)

        self._persist_system_log(level, module, event, safe_message, metadata)

    # ------------------------------------------------------------------
    # Background Logging_Thread
    # ------------------------------------------------------------------

    def _logging_loop(self) -> None:
        """
        Consume items from event_queue and persist them to the database.

        Each item is either:
        - ``(ThreatEvent, Explanation)`` tuple → persist event + log entry
        - ``_STOP_SENTINEL`` → drain queue then exit

        Req 15.5: all log I/O that could block must run in this thread,
        not the packet capture or detection threads.
        """
        while not self._stop_event.is_set():
            try:
                item = self._event_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            if item is _STOP_SENTINEL:
                # Drain remaining items before exiting
                self._drain_queue()
                break

            self._process_queue_item(item)

    def _drain_queue(self) -> None:
        """Process all remaining items after stop signal is received."""
        while True:
            try:
                item = self._event_queue.get_nowait()
                if item is not _STOP_SENTINEL:
                    self._process_queue_item(item)
            except queue.Empty:
                break

    def _process_queue_item(self, item: Any) -> None:
        """Dispatch a single queue item to the appropriate handler."""
        try:
            if isinstance(item, tuple) and len(item) == 2:
                event, explanation = item
                self._persist_threat_event(event, explanation)
            else:
                # Legacy support: plain LogEntry-style dicts or objects
                self._err_log.warning(
                    "LoggingEngine: unexpected queue item type %s", type(item).__name__
                )
        except Exception as exc:  # noqa: BLE001
            import sys
            print(
                f"[LoggingEngine._process_queue_item] Unhandled exception: {exc}",
                file=sys.stderr,
            )

    # ------------------------------------------------------------------
    # DB persistence helpers
    # ------------------------------------------------------------------

    def _persist_threat_event(
        self, event: "ThreatEvent", explanation: "Explanation"
    ) -> None:
        """
        Persist a ThreatEvent to the events table via EventRepository.

        Also writes a summary to the system_logs table via LogRepository.

        Requirement 14.2: persist every ThreatEvent within 50 ms.
        Requirement 15.4: never log passwords, private keys, tokens, secrets.
        """
        if self._event_repo is None:
            return

        try:
            event_data = {
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "attack_type": event.attack_type,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip or "",
                "source_port": event.source_port,
                "destination_port": event.destination_port,
                "protocol": event.protocol,
                "rule_name": event.rule_name,
                "severity": event.severity,
                "confidence": event.confidence,
                "packet_count": event.packet_count,
                "evidence": event.evidence,
                "explanation": explanation.plain_english_text,
                "recommendation": explanation.recommendation,
                "blocked": event.blocked,
            }
            self._event_repo.insert(event_data)

            # Mirror to system_logs for the log viewer
            self._persist_system_log(
                level="INFO",
                module="DetectionEngine",
                event=event.attack_type.upper().replace(" ", "_"),
                message=(
                    f"Detected {event.attack_type} from {event.source_ip} — "
                    f"severity={event.severity} confidence={event.confidence}"
                ),
                metadata={
                    "event_id": event.event_id,
                    "source_ip": event.source_ip,
                    "rule_name": event.rule_name,
                    "blocked": event.blocked,
                },
            )
        except Exception as exc:  # noqa: BLE001
            self._err_log.error(
                "LoggingEngine: failed to persist ThreatEvent %s — %s",
                getattr(event, "event_id", "?"), exc, exc_info=True,
            )

    def _persist_system_log(
        self,
        level: str,
        module: str,
        event: str,
        message: str,
        metadata: Optional[dict] = None,
    ) -> None:
        """
        Write a record to the system_logs table via LogRepository.

        Silently skips if log_repo is not configured.
        Strips sensitive keys from metadata before writing (Req 15.4).
        """
        if self._log_repo is None:
            return
        try:
            safe_meta = {
                k: v
                for k, v in (metadata or {}).items()
                if k.lower() not in _SENSITIVE_KEYS
            } or None
            self._log_repo.insert(
                timestamp=_utc_now(),
                level=level.upper(),
                module=module,
                event=event,
                message=_redact_sensitive(message),
                metadata=safe_meta,
            )
        except Exception as exc:  # noqa: BLE001
            import sys
            print(
                f"[LoggingEngine._persist_system_log] DB insert failed: {exc}",
                file=sys.stderr,
            )
