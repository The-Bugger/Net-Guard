"""
anomaly_engine.py — Per-IP statistical anomaly detection using Welford online algorithm.

Requirements: 9.1, 9.8
"""

from __future__ import annotations

import logging
import math
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("netguard.anomaly_engine")

_SIGMA_THRESHOLD = 3.0
_MIN_SAMPLES = 5  # minimum samples before flagging


@dataclass
class AnomalyEvent:
    ip: str
    metric: str
    value: float
    mean: float
    std: float
    deviation_sigmas: float
    timestamp: float


class _WelfordStat:
    """Welford online mean/variance — O(1) per sample."""
    __slots__ = ("n", "mean", "_M2")

    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self._M2 = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self._M2 += delta * delta2

    @property
    def std(self) -> float:
        if self.n < 2:
            return 0.0
        return math.sqrt(self._M2 / (self.n - 1))


class _IPStats:
    __slots__ = ("pps", "conn_freq", "entropy", "first_seen", "manual_override")

    def __init__(self) -> None:
        self.pps = _WelfordStat()
        self.conn_freq = _WelfordStat()
        self.entropy = _WelfordStat()
        self.first_seen: float = time.monotonic()
        self.manual_override: bool = False


class AnomalyEngine:
    """
    Baseline statistical anomaly detector.

    - Welford online algorithm for per-IP rolling mean/std.
    - Suppresses flagging during warm-up (first baseline_window_seconds of data).
    - Thread-safe: lock per IP via a simple dict mutation (GIL-safe for CPython).

    ponytail: No deque-based sliding window — Welford gives exact online stats
              with O(1) memory per IP. Ceiling: no forgetting old samples; if
              an IP goes quiet for days, its baseline persists. Upgrade path:
              time-weighted Welford or deque when per-session reset is needed.
    """

    def __init__(self, baseline_window_seconds: float = 300, sigma_threshold: float = _SIGMA_THRESHOLD) -> None:
        self._window = baseline_window_seconds
        self._sigma = sigma_threshold
        self._stats: dict[str, _IPStats] = {}
        self._start_time: float = time.monotonic()

    def ingest(self, ip: str, pps: float, conn_freq: float, entropy: float) -> Optional[AnomalyEvent]:
        """
        Update stats for *ip* and check for anomaly.

        Returns AnomalyEvent if any metric exceeds sigma threshold, else None.
        Suppresses flagging during warm-up.
        """
        self._ingest_raw(ip, pps, time.monotonic())
        st = self._stats[ip]
        st.conn_freq.update(conn_freq)
        st.entropy.update(entropy)

        if self.is_warming_up():
            logger.debug("AnomalyEngine: warm-up phase — suppressing flags")
            return None

        for metric, value, stat in [
            ("pps", pps, st.pps),
            ("conn_freq", conn_freq, st.conn_freq),
            ("entropy", entropy, st.entropy),
        ]:
            if stat.n < _MIN_SAMPLES or stat.std == 0:
                continue
            dev = abs(value - stat.mean) / stat.std
            if dev > self._sigma:
                return AnomalyEvent(
                    ip=ip, metric=metric, value=value,
                    mean=stat.mean, std=stat.std,
                    deviation_sigmas=dev,
                    timestamp=time.monotonic(),
                )
        return None

    def _ingest_raw(self, ip: str, pps: float, ts: float) -> None:
        """Update pps stat for ip (also used by property test)."""
        if ip not in self._stats:
            self._stats[ip] = _IPStats()
            self._stats[ip].first_seen = ts
        self._stats[ip].pps.update(pps)

    def is_warming_up(self) -> bool:
        """True if system has less than baseline_window_seconds of data."""
        return (time.monotonic() - self._start_time) < self._window

    def calibration_data(self) -> dict:
        result = {}
        for ip, st in self._stats.items():
            result[ip] = {
                "pps_mean": st.pps.mean, "pps_std": st.pps.std,
                "conn_freq_mean": st.conn_freq.mean, "conn_freq_std": st.conn_freq.std,
                "entropy_mean": st.entropy.mean, "entropy_std": st.entropy.std,
                "first_seen": st.first_seen,
                "warming_up": self.is_warming_up(),
                "manual_override": st.manual_override,
            }
        return result

    def override_calibration(self, ip: str, values: dict) -> None:
        """Replace stored baseline with operator-supplied values."""
        if ip not in self._stats:
            self._stats[ip] = _IPStats()
        st = self._stats[ip]
        for metric in ("pps", "conn_freq", "entropy"):
            stat_obj: _WelfordStat = getattr(st, metric)
            mean_key, std_key = f"{metric}_mean", f"{metric}_std"
            if mean_key in values:
                stat_obj.mean = float(values[mean_key])
            if std_key in values:
                # Back-compute M2 from std so the online update still works
                if stat_obj.n >= 2:
                    stat_obj._M2 = float(values[std_key]) ** 2 * (stat_obj.n - 1)
        st.manual_override = True
        logger.info("AnomalyEngine: manual calibration override applied for %s", ip)
