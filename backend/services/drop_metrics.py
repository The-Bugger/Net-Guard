"""
drop_metrics.py — Process-wide counters for dropped work at each pipeline stage.

Under flood load, queues fill and work is dropped. These counters make that
visible so operators can see *where* the pipeline is shedding load instead of
dropping silently. Thread-safe; each stage increments its own counter.

Stages:
  capture_packet   — packet_queue full in CaptureEngine (decode OK, no room)
  event_log        — event_queue full in LoggingEngine (detection dropped)
  event_retry      — EventRepository retry queue full (DB insert failed twice)
  threat_intel     — ThreatIntelService enrichment queue full
"""

from __future__ import annotations

import threading
from typing import Dict


class DropMetrics:
    """Thread-safe named counters for dropped items. Process-wide singleton."""

    _instance: "DropMetrics | None" = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        self._counts: Dict[str, int] = {}
        self._lock = threading.Lock()

    @classmethod
    def get(cls) -> "DropMetrics":
        """Return the process-wide singleton."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def increment(self, stage: str, n: int = 1) -> None:
        """Add *n* to the drop counter for *stage*."""
        with self._lock:
            self._counts[stage] = self._counts.get(stage, 0) + n

    def snapshot(self) -> Dict[str, int]:
        """Return a copy of all drop counters."""
        with self._lock:
            return dict(self._counts)

    def total(self) -> int:
        """Return the sum of all drop counters."""
        with self._lock:
            return sum(self._counts.values())

    def reset(self) -> None:
        """Clear all counters (used by tests)."""
        with self._lock:
            self._counts.clear()
