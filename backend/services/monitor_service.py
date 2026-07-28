"""
monitor_service.py — MonitorService for NetGuard IDPS.

Coordinates starting and stopping packet capture. Validates interface names.
Manages shared MonitoringState. Emits monitoring_status SocketIO events.

Requirements: 2.1, 2.2, 2.6, 2.7, 2.8, 2.9
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

    def start_monitoring(self, interface: str) -> None:
        """
        Start packet capture on the given interface.

        Args:
            interface: Network interface name.

        Raises:
            RuntimeError: If already monitoring (ALREADY_MONITORING).
            ValueError: If interface is not in the available list (INVALID_INTERFACE).
        """
        if self._state.active:
            raise RuntimeError("ALREADY_MONITORING")

        available = self.get_interfaces()
        if interface not in available:
            raise ValueError(f"INVALID_INTERFACE:{interface}")

        self._capture.start(interface)
        if not self._detection.is_running:
            self._detection.start()

        self._state.active = True
        self._state.interface = interface
        self._state.started_at = _utc_now()

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


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
