"""Monitor service — coordinates packet capture start/stop and interface validation."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("netguard.monitor_service")


@dataclass
class MonitoringState:
    """Shared monitoring state visible to all components."""
    active: bool = False
    interface: str = ""
    started_at: Optional[str] = None
    packets_processed: int = 0
    active_blocks: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, compare=False, repr=False)

    def increment_packets(self) -> None:
        with self._lock:
            self.packets_processed += 1

    def to_dict(self) -> dict:
        return {
            "active": self.active,
            "interface": self.interface,
            "started_at": self.started_at,
            "packets_processed": self.packets_processed,
            "active_blocks": self.active_blocks,
        }


class MonitorService:
    """Coordinates packet capture start/stop and interface validation."""

    def __init__(
        self,
        capture_engine,
        detection_engine,
        state: MonitoringState,
        log_engine=None,
        socketio_emit=None,
    ) -> None:
        self._capture = capture_engine
        self._detection = detection_engine
        self._state = state
        self._log_engine = log_engine
        self._socketio_emit = socketio_emit

    def start_monitoring(self, interface: str | None) -> None:
        """
        Start packet capture on the given interface.

        Auto-selects the first active non-loopback interface when interface is
        None or empty.

        Raises:
            RuntimeError: If already monitoring (ALREADY_MONITORING).
            ValueError: If no suitable interface found (NO_INTERFACE) or the
                named interface is not available (INVALID_INTERFACE).
        """
        if self._state.active:
            raise RuntimeError("ALREADY_MONITORING")

        if not interface:
            interface = _pick_default_interface()
            if not interface:
                raise ValueError("NO_INTERFACE:no active non-loopback interface found")

        available = self.get_interfaces()
        if interface not in available:
            raise ValueError(f"INVALID_INTERFACE:{interface}")

        self._capture.start(interface)
        if not self._detection.is_running:
            self._detection.start()

        self._state.active = True
        self._state.interface = interface
        self._state.started_at = _utc_now()

        threading.Thread(
            target=self._capture_watchdog,
            name="Capture_Watchdog_Thread",
            daemon=True,
        ).start()

        if self._log_engine:
            self._log_engine.log_system("INFO", "MonitorService", "MONITOR_START", f"Monitoring started on {interface}")
        if self._socketio_emit:
            self._socketio_emit("monitoring_status", {"active": True, "interface": interface})

        logger.info("MonitorService: started monitoring on %s.", interface)

    def stop_monitoring(self) -> None:
        """
        Stop packet capture.

        Raises:
            RuntimeError: If monitoring is not active (NOT_MONITORING).
        """
        if not self._state.active:
            raise RuntimeError("NOT_MONITORING")

        self._capture.stop()
        self._state.active = False

        if self._log_engine:
            self._log_engine.log_system("INFO", "MonitorService", "MONITOR_STOP", f"Monitoring stopped on {self._state.interface}")
        if self._socketio_emit:
            self._socketio_emit("monitoring_status", {"active": False})

        logger.info("MonitorService: stopped monitoring.")

    def _capture_watchdog(self) -> None:
        """
        Poll the capture thread; on unexpected death mark state inactive and
        emit monitoring_error to connected clients.

        ponytail: 0.5 s poll — finer resolution adds thread churn for no benefit.
        """
        import time

        capture = self._capture
        time.sleep(0.5)

        while self._state.active and capture.is_running:
            time.sleep(0.5)

        if self._state.active and not capture.is_running:
            interface = self._state.interface
            logger.error("MonitorService: capture thread died unexpectedly on '%s'.", interface)
            self._state.active = False
            if self._socketio_emit:
                try:
                    self._socketio_emit("monitoring_error", {"interface": interface, "reason": "Capture thread stopped unexpectedly"})
                    self._socketio_emit("monitoring_status", {"active": False})
                except Exception:  # noqa: BLE001
                    pass

    def get_interfaces(self) -> list[str]:
        """Return all available network interfaces from the OS."""
        try:
            import psutil
            return list(psutil.net_if_stats().keys())
        except Exception as exc:
            logger.warning("MonitorService.get_interfaces failed: %s", exc)
            return []


def _pick_default_interface() -> str:
    """
    Return the first non-loopback is_up interface from psutil.

    Returns "" when no non-loopback interface is up (loopback is never
    selected as a capture source).
    ponytail: linear scan — typical host has < 10 interfaces.
    """
    def _is_loopback(name: str) -> bool:
        return name.lower().startswith("lo")

    try:
        import psutil
        stats = psutil.net_if_stats()
        for name, info in stats.items():
            if info.isup and not _is_loopback(name):
                return name
    except Exception as exc:
        logger.warning("_pick_default_interface failed: %s", exc)
    return ""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
