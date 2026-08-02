"""
Logging engine for NetGuard IDPS.

Three rotating log outputs:
  - logs/system.log      — INFO lifecycle events
  - logs/detections.log  — every ThreatEvent, block, and unblock
  - logs/errors.log      — WARNING and above from all modules

A background Logging_Thread consumes (ThreatEvent, Explanation) tuples from
event_queue and persists them to the database without blocking packet capture.
Sensitive keys (password, secret, token, private_key, api_key) are redacted.
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

_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent
_LOGS_DIR: Path = _PROJECT_ROOT / "logs"

_SYSTEM_LOG: Path    = _LOGS_DIR / "system.log"
_DETECTIONS_LOG: Path = _LOGS_DIR / "detections.log"
_ERRORS_LOG: Path    = _LOGS_DIR / "errors.log"

_MAX_BYTES: int   = 10 * 1024 * 1024
_BACKUP_COUNT: int = 5

_SENSITIVE_KEYS: frozenset = frozenset({
    "password", "passwd", "secret", "token",
    "private_key", "api_key", "auth", "credential",
})

_SENSITIVE_PATTERN = re.compile(
    r"\b(?:" + "|".join(re.escape(k) for k in _SENSITIVE_KEYS) + r")\b(?:[=:\s]+\S+)?",
    re.IGNORECASE,
)

_STOP_SENTINEL = object()


def get_system_logger() -> logging.Logger:
    return logging.getLogger("netguard.system")


def get_detection_logger() -> logging.Logger:
    return logging.getLogger("netguard.detections")


def get_error_logger() -> logging.Logger:
    return logging.getLogger("netguard.errors")


def setup_logging() -> None:
    """Configure all three rotating file handlers. Safe to call multiple times."""
    _LOGS_DIR.mkdir(parents=True, exist_ok=True)
    _configure_logger("netguard.system",     _SYSTEM_LOG,     level=logging.INFO)
    _configure_logger("netguard.detections", _DETECTIONS_LOG, level=logging.INFO)
    _configure_logger("netguard.errors",     _ERRORS_LOG,     level=logging.WARNING)
    root = logging.getLogger("netguard")
    root.setLevel(logging.DEBUG)
    root.propagate = False


def _configure_logger(name: str, path: Path, level: int) -> None:
    """Attach a RotatingFileHandler to a named logger if not already present."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False
    for handler in logger.handlers:
        if isinstance(handler, RotatingFileHandler) and handler.baseFilename == str(path):
            return
    handler = RotatingFileHandler(path, maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT, encoding="utf-8")
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    logger.addHandler(handler)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _redact_sensitive(message: str) -> str:
    """Replace sensitive key mentions in a message with [REDACTED]."""
    return _SENSITIVE_PATTERN.sub("[REDACTED]", message)


def _safe_metadata(metadata: Optional[dict]) -> Optional[str]:
    """Serialise metadata to JSON, stripping sensitive keys. Returns None if empty."""
    if not metadata:
        return None
    safe = {k: v for k, v in metadata.items() if k.lower() not in _SENSITIVE_KEYS}
    return json.dumps(safe)


class LoggingEngine:
    """
    Async logging engine with a background Logging_Thread.

    The thread consumes (ThreatEvent, Explanation) tuples from event_queue
    and persists them to the database. Lifecycle events (startup, shutdown,
    monitor start/stop) are written synchronously via log_system().
    """

    def __init__(
        self,
        event_queue: Optional[queue.Queue] = None,
        event_repo=None,
        log_repo=None,
    ) -> None:
        self._event_queue: queue.Queue = event_queue if event_queue is not None else queue.Queue()
        self._event_repo = event_repo
        self._log_repo = log_repo
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._sys_log = get_system_logger()
        self._det_log = get_detection_logger()
        self._err_log = get_error_logger()

    def start(self) -> None:
        """Start the background Logging_Thread. Idempotent."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._logging_loop, name="Logging_Thread", daemon=True)
        self._thread.start()
        self._sys_log.info("LoggingEngine started.")
        self._persist_system_log("INFO", "LoggingEngine", "STARTUP", "LoggingEngine started.")

    def stop(self) -> None:
        """Signal the Logging_Thread to drain and stop (waits up to 5 s)."""
        if self._thread and self._thread.is_alive():
            self._event_queue.put(_STOP_SENTINEL)
            self._thread.join(timeout=5.0)
            self._thread = None
        self._sys_log.info("LoggingEngine stopped.")
        self._persist_system_log("INFO", "LoggingEngine", "SHUTDOWN", "LoggingEngine stopped.")

    def log_event(self, event: "ThreatEvent", explanation: "Explanation") -> None:
        """Write detection to detections.log synchronously, then enqueue for DB persistence."""
        action = "BLOCKED" if event.blocked else "DETECTED"
        self._det_log.info(
            "DETECTION | timestamp=%s source_ip=%s attack_type=%s "
            "severity=%s confidence=%s rule=%s action=%s",
            event.timestamp, event.source_ip, event.attack_type,
            event.severity, event.confidence, event.rule_name, action,
        )
        try:
            self._event_queue.put_nowait((event, explanation))
        except queue.Full:
            self._err_log.error(
                "LoggingEngine: event_queue full — dropping event %s",
                getattr(event, "event_id", "?"),
            )

    def log_block(self, ip: str, reason: str, duration: int) -> None:
        """Log an IP block to detections.log and system_logs."""
        self._det_log.info("BLOCK     | ip=%s reason=%s duration=%ds", ip, reason, duration)
        self._persist_system_log(
            level="INFO", module="PreventionEngine", event="IP_BLOCKED",
            message=f"Blocked {ip} for {duration}s — reason: {reason}",
            metadata={"ip": ip, "reason": reason, "duration": duration},
        )

    def log_unblock(self, ip: str, reason: str = "expired") -> None:
        """Log an IP unblock to detections.log and system_logs."""
        self._det_log.info("UNBLOCK   | ip=%s reason=%s", ip, reason)
        self._persist_system_log(
            level="INFO", module="PreventionEngine", event="IP_UNBLOCKED",
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
        """Write a lifecycle event to system.log (and errors.log for WARNING+)."""
        numeric = getattr(logging, level.upper(), logging.INFO)
        safe_message = _redact_sensitive(message)
        self._sys_log.log(numeric, "%s | %s — %s", module, event, safe_message)
        if level.upper() in ("WARNING", "ERROR", "CRITICAL"):
            self._err_log.log(numeric, "%s | %s — %s", module, event, safe_message)
        self._persist_system_log(level, module, event, safe_message, metadata)

    def _logging_loop(self) -> None:
        """Consume queue items and persist to the database."""
        while not self._stop_event.is_set():
            try:
                item = self._event_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            if item is _STOP_SENTINEL:
                self._drain_queue()
                break
            self._process_queue_item(item)

    def _drain_queue(self) -> None:
        """Process all remaining items after stop signal."""
        while True:
            try:
                item = self._event_queue.get_nowait()
                if item is not _STOP_SENTINEL:
                    self._process_queue_item(item)
            except queue.Empty:
                break

    def _process_queue_item(self, item: Any) -> None:
        try:
            if isinstance(item, tuple) and len(item) == 2:
                event, explanation = item
                self._persist_threat_event(event, explanation)
            else:
                self._err_log.warning("LoggingEngine: unexpected queue item type %s", type(item).__name__)
        except Exception as exc:  # noqa: BLE001
            import sys
            print(f"[LoggingEngine._process_queue_item] Unhandled exception: {exc}", file=sys.stderr)

    def _persist_threat_event(self, event: "ThreatEvent", explanation: "Explanation") -> None:
        if self._event_repo is None:
            return
        try:
            event_data = {
                "event_id":         event.event_id,
                "timestamp":        event.timestamp,
                "attack_type":      event.attack_type,
                "source_ip":        event.source_ip,
                "destination_ip":   event.destination_ip or "",
                "source_port":      event.source_port,
                "destination_port": event.destination_port,
                "protocol":         event.protocol,
                "rule_name":        event.rule_name,
                "severity":         event.severity,
                "confidence":       event.confidence,
                "packet_count":     event.packet_count,
                "evidence":         event.evidence,
                "explanation":      explanation.plain_english_text,
                "recommendation":   explanation.recommendation,
                "blocked":          event.blocked,
            }
            self._event_repo.insert(event_data)
            self._persist_system_log(
                level="INFO", module="DetectionEngine",
                event=event.attack_type.upper().replace(" ", "_"),
                message=(
                    f"Detected {event.attack_type} from {event.source_ip} — "
                    f"severity={event.severity} confidence={event.confidence}"
                ),
                metadata={
                    "event_id":  event.event_id,
                    "source_ip": event.source_ip,
                    "rule_name": event.rule_name,
                    "blocked":   event.blocked,
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
        """Write a record to system_logs via LogRepository. Skips if log_repo is None."""
        if self._log_repo is None:
            return
        try:
            safe_meta = {
                k: v for k, v in (metadata or {}).items()
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
            print(f"[LoggingEngine._persist_system_log] DB insert failed: {exc}", file=sys.stderr)
