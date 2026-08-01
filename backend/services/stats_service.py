"""
stats_service.py — StatsService for NetGuard IDPS.

Aggregates detection statistics from the database and in-memory counters.
Serves the /statistics and /dashboard endpoints.

Requirements: 13.2, 16.1, 9.1, 9.2, 9.3, 9.5, 9.6, 12.2, 12.3
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Optional

logger = logging.getLogger("netguard.stats_service")


class StatsService:
    """
    Aggregates live and historical statistics for the dashboard.

    Maintains a rolling packets-per-second counter and delegates
    historical counts to the EventRepository.
    """

    def __init__(self, event_repo, block_repo, state, whitelist_manager=None) -> None:
        """
        Args:
            event_repo: EventRepository instance.
            block_repo: BlockRepository instance.
            state: Shared MonitoringState.
            whitelist_manager: Optional WhitelistManager for dashboard whitelist panel.
        """
        self._event_repo = event_repo
        self._block_repo = block_repo
        self._state = state
        self._whitelist_manager = whitelist_manager
        self._lock = threading.Lock()

        # Rolling packets-per-second: timestamps of recent packets (last 60s)
        self._pkt_timestamps: deque = deque()
        self._start_time: float = time.monotonic()

        # 2-second in-process dashboard cache (Req 12.2)
        self._cache_data: Optional[dict] = None
        self._cache_time: float = 0.0

    def record_packet(self) -> None:
        """Record a packet capture event for PPS calculation."""
        now = time.monotonic()
        with self._lock:
            self._pkt_timestamps.append(now)
            # Evict timestamps older than 60 seconds
            cutoff = now - 60
            while self._pkt_timestamps and self._pkt_timestamps[0] < cutoff:
                self._pkt_timestamps.popleft()

    def get_packets_per_second(self) -> float:
        """Return packets per second over the last 5 seconds."""
        now = time.monotonic()
        with self._lock:
            cutoff = now - 5
            recent = sum(1 for t in self._pkt_timestamps if t >= cutoff)
        return round(recent / 5, 1)

    def get_health_score(self) -> int:
        """
        Compute security health score — deterministic weighted deductions.

        All 8 detection rules contribute deductions (Task 7):
          SYN Flood:    -15   Port Scan:    -8   SQL Injection: -12
          Brute Force:  -10   ARP Spoofing: -20  ICMP Flood:    -8
          Slow HTTP:    -5    DNS Tunneling:-10
          Diversity penalty: -10 if ≥3 distinct attack types present

        Returns -1 on DB error.
        """
        DEDUCTIONS = {
            "SYN Flood":     15,
            "Port Scan":      8,
            "SQL Injection": 12,
            "Brute Force":   10,
            "ARP Spoofing":  20,
            "ICMP Flood":     8,
            "Slow HTTP":      5,
            "DNS Tunneling": 10,
        }
        try:
            types_today = self._event_repo.get_distinct_attack_types_today()
            score = 100
            for attack, penalty in DEDUCTIONS.items():
                if attack in types_today:
                    score -= penalty
            if len(types_today & set(DEDUCTIONS.keys())) >= 3:
                score -= 10
            return max(0, min(100, score))
        except Exception as exc:
            logger.error("get_health_score failed: %s", exc, exc_info=True)
            return -1

    def invalidate_cache(self) -> None:
        """Force next get_dashboard_data() to query the DB. Req 12.3."""
        with self._lock:
            self._cache_time = 0.0

    def get_live_stats(self) -> dict:
        """Return lightweight live statistics for the dashboard."""
        pps = self.get_packets_per_second()
        active_blocks = len(self._block_repo.get_all_active())
        alerts_today = self._event_repo.count_today()

        return {
            "packets_per_second": pps,
            "active_threats": active_blocks,
            "alerts_today": alerts_today,
            "monitoring": self._state.active,
        }

    def get_dashboard_data(self) -> dict:
        """Return full dashboard snapshot, cached for 2 seconds. Req 12.2."""
        now = time.monotonic()
        with self._lock:
            if self._cache_data is not None and now - self._cache_time < 2.0:
                return self._cache_data

        recent_events = self._event_repo.get_all(limit=20)
        active_blocks = self._block_repo.get_all_active()
        attack_counts = self._event_repo.get_attack_type_counts()

        top_attack = ""
        if attack_counts:
            top_attack = max(attack_counts, key=lambda x: x["count"])["attack_type"]

        data = {
            "monitoring": self._state.active,
            "interface": self._state.interface,
            "packets": self._state.packets_processed,
            "alerts": self._event_repo.count(),
            "alerts_today": self._event_repo.count_today(),
            "blocked_ips": len(active_blocks),
            "traffic_rate": self.get_packets_per_second(),
            "top_attack": top_attack,
            "recent_events": recent_events,
            "active_blocks": active_blocks,
            "attack_type_counts": attack_counts,
            "health_score": self.get_health_score(),
            "whitelist": self._get_whitelist_safe(),
        }

        with self._lock:
            self._cache_data = data
            self._cache_time = time.monotonic()

        return data

    def get_statistics(self) -> dict:
        """Return aggregate statistics."""
        return {
            "packets_processed": self._state.packets_processed,
            "detections": self._event_repo.count(),
            "blocks": len(self._block_repo.get_all_active()),
            "attack_type_breakdown": self._event_repo.get_attack_type_counts(),
        }

    def get_rule_statistics(self) -> list[dict]:
        """Return per-rule detection counts."""
        return self._event_repo.get_attack_type_counts()

    def _get_whitelist_safe(self) -> list:
        """Return whitelist entries; returns [] on any error."""
        try:
            if self._whitelist_manager is None:
                return []
            return self._whitelist_manager.get_all() or []
        except Exception as exc:
            logger.debug("_get_whitelist_safe failed: %s", exc)
            return []


# ---------------------------------------------------------------------------
# Self-check: verify the formula on a known input at import time.
# ponytail: inline assert, no framework needed — fails loudly on import if
#           the formula regresses.
# ---------------------------------------------------------------------------

def _get_health_score_from(types_today: set) -> int:
    """Compute the weighted health score from a set of attack type strings."""
    DEDUCTIONS = {
        "SYN Flood":     15,
        "Port Scan":      8,
        "SQL Injection": 12,
        "Brute Force":   10,
        "ARP Spoofing":  20,
        "ICMP Flood":     8,
        "Slow HTTP":      5,
        "DNS Tunneling": 10,
    }
    score = 100
    for attack, penalty in DEDUCTIONS.items():
        if attack in types_today:
            score -= penalty
    if len(types_today & set(DEDUCTIONS.keys())) >= 3:
        score -= 10
    return max(0, min(100, score))


assert _get_health_score_from(set()) == 100, "_get_health_score_from(set()) must equal 100"
# All 8 attack types: 100 - 15 - 8 - 12 - 10 - 20 - 8 - 5 - 10 - 10(diversity) = 2
assert _get_health_score_from({
    "SYN Flood", "Port Scan", "SQL Injection", "Brute Force",
    "ARP Spoofing", "ICMP Flood", "Slow HTTP", "DNS Tunneling"
}) == 2, "All 8 attack types must yield score 2"
