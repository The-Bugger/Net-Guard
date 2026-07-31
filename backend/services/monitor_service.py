"""
monitor_service.py — MonitorService for NetGuard IDPS.

Coordinates starting and stopping packet capture. Validates interface names.
Manages shared MonitoringState. Emits monitoring_status SocketIO events.
On unexpected capture failure, sets active=False and emits monitoring_error.

Requirements: 2.1, 2.2, 2.4, 2.6, 2.7, 2.8, 2.9, 15.1, 15.2, 15.4
"""

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
    """
    Coordinates packet capture start/stop and interface validation.

    Usage::

        svc = MonitorService(capture_engine, detection_engine, state)
        svc.start_monitoring("eth0")
        svc.stop_monitoring()
    """

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

        If *interface* is None or empty, auto-selects the first active
        non-loopback interface via ``_pick_default_interface()``.

        Args:
            interface: Network interface name, or None/empty for auto-select.

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

        # Watchdog: detect unexpected capture thread death and update state
        # Requirements: 15.2, 15.4
        watchdog = threading.Thread(
            target=self._capture_watchdog,
            name="Capture_Watchdog_Thread",
            daemon=True,
        )
        watchdog.start()

        if self._log_engine:
            self._log_engine.log_system(
                "INFO", "MonitorService", "MONITOR_START",
                f"Monitoring started on {interface}",
            )
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
            self._log_engine.log_system(
                "INFO", "MonitorService", "MONITOR_STOP",
                f"Monitoring stopped on {self._state.interface}",
            )
        if self._socketio_emit:
            self._socketio_emit("monitoring_status", {"active": False})

        logger.info("MonitorService: stopped monitoring.")

    def _capture_watchdog(self) -> None:
        """
        Polls the capture thread; on unexpected death marks state inactive and
        emits ``monitoring_error`` to connected clients.

        "Unexpected" means the capture stopped while ``_state.active`` is still
        True (i.e. nobody called ``stop_monitoring()``).

        ponytail: 0.5 s poll is coarse but sufficient — finer resolution adds
        thread churn for no measurable user benefit.

        Requirements: 15.2, 15.4
        """
        import time

        capture = self._capture
        # Wait for the capture thread to actually start before watching it
        time.sleep(0.5)

        while self._state.active and capture.is_running:
            time.sleep(0.5)

        # If we exit because active was set False externally (stop_monitoring),
        # nothing to do.  If we exit because the thread died unexpectedly, act.
        if self._state.active and not capture.is_running:
            interface = self._state.interface
            logger.error(
                "MonitorService: capture thread died unexpectedly on '%s'.", interface
            )
            self._state.active = False
            if self._socketio_emit:
                try:
                    self._socketio_emit(
                        "monitoring_error",
                        {
                            "interface": interface,
                            "reason": "Capture thread stopped unexpectedly",
                        },
                    )
                    self._socketio_emit("monitoring_status", {"active": False})
                except Exception:  # noqa: BLE001
                    pass

    def get_interfaces(self) -> list[str]:
        """
        Return all available network interfaces from the OS.

        Returns:
            List of interface name strings.
        """
        try:
            import psutil
            return list(psutil.net_if_stats().keys())
        except Exception as exc:
            logger.warning("MonitorService.get_interfaces failed: %s", exc)
            return []


def _pick_default_interface() -> str:
    """
    Return the first non-loopback is_up interface from psutil.

    Excludes any interface whose lowercased name starts with 'lo' (covers
    lo, loopback, localhost on Linux and Windows).  Returns empty string
    if none found so callers can handle the missing-interface case explicitly.

    ponytail: linear scan is fine — typical host has < 10 interfaces.

    Requirements: 2.3
    """
    try:
        import psutil
        for name, info in psutil.net_if_stats().items():
            if info.isup and not name.lower().startswith("lo"):
                return name
    except Exception as exc:
        logger.warning("_pick_default_interface failed: %s", exc)
    return ""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
