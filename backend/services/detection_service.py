"""
detection_service.py — Detection_Engine for NetGuard IDPS.

Consumes packets from the packet_queue, evaluates all enabled detection rules
on each packet, and emits ThreatEvents to downstream handlers when attacks
are confirmed.

Design:
- Runs as a dedicated Detection_Thread consuming a thread-safe packet_queue
- Enforces 10-second cooldown per (source_ip, rule_name) pair
  (allows escalation to higher severity within cooldown window)
- Assigns UUID4 event_id to every ThreatEvent
- On rule exception: disables that rule for the session, continues others
- Expires Flow_Tracker counters for inactive IPs
- Completes all rule evaluation within 100 ms per packet

Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Callable, Optional

from detection.parsers.packet_decoder import Packet
from detection.rules.base_rule import BaseRule, ThreatEvent
from detection.rules.arp_spoof import ArpSpoofRule
from detection.rules.brute_force import BruteForceRule
from detection.rules.port_scan import PortScanRule
from detection.rules.sql_injection import SqlInjectionRule
from detection.rules.syn_flood import SynFloodRule

logger = logging.getLogger("netguard.detection_engine")

# Severity ordering for cooldown escalation logic
_SEVERITY_ORDER: dict[str, int] = {
    "Low": 0,
    "Medium": 1,
    "High": 2,
    "Critical": 3,
}

# Sentinel for stopping the detection thread
_STOP_SENTINEL = object()


class DetectionEngine:
    """
    Core detection engine that evaluates all enabled rules on every packet.

    Runs in a dedicated daemon thread (Detection_Thread).  Communicates with:
    - upstream: receives Packet objects from packet_queue
    - downstream: calls on_event callback for each ThreatEvent (then logs + SocketIO)

    Usage::

        engine = DetectionEngine(packet_queue, event_callback=handle_event)
        engine.start()
        # ... monitoring ...
        engine.stop()
    """

    COOLDOWN_SECONDS: int = 10

    def __init__(
        self,
        packet_queue: queue.Queue,
        on_event: Optional[Callable[[ThreatEvent], None]] = None,
        config_manager=None,
    ) -> None:
        """
        Args:
            packet_queue: Thread-safe queue of decoded Packet objects.
            on_event: Callback invoked for each confirmed ThreatEvent.
                      Called on the Detection_Thread.
            config_manager: ConfigurationManager for rule thresholds.
        """
        self._packet_queue = packet_queue
        self._on_event = on_event
        self._config_manager = config_manager

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Detection rules (initialised in start())
        self._rules: list[BaseRule] = []

        # Cooldown tracker: (src_ip, rule_name) -> (severity_str, monotonic_time)
        self._cooldown: dict[tuple[str, str], tuple[str, float]] = {}

        # Disabled rules (rule_name set) — disabled on exception
        self._disabled_rules: set[str] = set()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Initialise detection rules and start the Detection_Thread.
        """
        if self._thread and self._thread.is_alive():
            logger.warning("DetectionEngine is already running.")
            return

        self._rules = self._build_rules()
        for rule in self._rules:
            try:
                rule.initialize()
            except Exception as exc:
                logger.error(
                    "DetectionEngine: rule %s failed initialize() — %s",
                    rule.rule_name, exc,
                )
                self._disabled_rules.add(rule.rule_name)

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._detection_loop,
            name="Detection_Thread",
            daemon=True,
        )
        self._thread.start()
        logger.info("DetectionEngine started with %d rules.", len(self._rules))

    def stop(self) -> None:
        """Signal the Detection_Thread to stop and wait for it to exit."""
        if self._thread and self._thread.is_alive():
            self._packet_queue.put(_STOP_SENTINEL)
            self._stop_event.set()
            self._thread.join(timeout=5.0)
            self._thread = None

        for rule in self._rules:
            try:
                rule.cleanup()
            except Exception as exc:
                logger.debug("Rule %s cleanup error: %s", rule.rule_name, exc)

        logger.info("DetectionEngine stopped.")

    def reload_rules(self) -> None:
        """
        Reload rules from configuration (applies updated thresholds).

        Rebuilds rule instances using current configuration values.
        """
        for rule in self._rules:
            try:
                rule.cleanup()
            except Exception:
                pass

        self._rules = self._build_rules()
        self._disabled_rules.clear()
        for rule in self._rules:
            try:
                rule.initialize()
            except Exception as exc:
                logger.error(
                    "DetectionEngine.reload_rules: %s failed initialize — %s",
                    rule.rule_name, exc,
                )
                self._disabled_rules.add(rule.rule_name)

        logger.info("DetectionEngine rules reloaded.")

    # ------------------------------------------------------------------
    # Detection loop (Detection_Thread)
    # ------------------------------------------------------------------

    def _detection_loop(self) -> None:
        """Consume packets from packet_queue and evaluate all enabled rules."""
        logger.debug("Detection_Thread: started.")
        while not self._stop_event.is_set():
            try:
                item = self._packet_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            if item is _STOP_SENTINEL:
                break

            if not isinstance(item, Packet):
                continue

            self._dispatch(item)

        logger.debug("Detection_Thread: stopped.")

    def _dispatch(self, packet: Packet) -> None:
        """
        Run all enabled rules on a single packet.

        Must complete within 100 ms (Requirement 9.3).
        Never raises — all exceptions are caught per rule.

        Args:
            packet: Normalised packet from PacketDecoder.
        """
        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.rule_name in self._disabled_rules:
                continue

            try:
                rule.process_packet(packet)
                event = rule.evaluate()
            except Exception as exc:  # noqa: BLE001
                # Requirement 9.5: disable faulty rule for the session
                logger.error(
                    "DetectionEngine: rule %s raised %s — disabling for this session. %s",
                    rule.rule_name,
                    type(exc).__name__,
                    exc,
                    exc_info=True,
                )
                self._disabled_rules.add(rule.rule_name)
                continue

            if event is None:
                continue

            # Cooldown check (Requirement 9.2)
            if not self._should_emit(event):
                continue

            # Update cooldown
            key = (event.source_ip, event.rule_name)
            self._cooldown[key] = (event.severity, time.monotonic())

            # Dispatch to callback
            if self._on_event:
                try:
                    self._on_event(event)
                except Exception as exc:
                    logger.error(
                        "DetectionEngine: on_event callback raised %s: %s",
                        type(exc).__name__, exc,
                    )

    def _should_emit(self, event: ThreatEvent) -> bool:
        """
        Check the cooldown for this (source_ip, rule_name) pair.

        Allows emission if:
        - No previous event in cooldown window, OR
        - New severity is strictly higher than the last emitted severity

        Args:
            event: Candidate ThreatEvent.

        Returns:
            True if the event should be emitted.
        """
        key = (event.source_ip, event.rule_name)
        if key not in self._cooldown:
            return True

        prev_severity, prev_time = self._cooldown[key]
        elapsed = time.monotonic() - prev_time

        if elapsed >= self.COOLDOWN_SECONDS:
            return True

        # Allow escalation to higher severity within cooldown
        prev_order = _SEVERITY_ORDER.get(prev_severity, 0)
        new_order = _SEVERITY_ORDER.get(event.severity, 0)
        return new_order > prev_order

    # ------------------------------------------------------------------
    # Rule factory
    # ------------------------------------------------------------------

    def _build_rules(self) -> list[BaseRule]:
        """
        Build rule instances using current configuration values.

        Returns:
            List of configured, ready-to-initialise rule objects.
        """
        cfg = self._config_manager

        def _get(key: str, default):
            if cfg:
                val = cfg.get(key)
                return val if val is not None else default
            return default

        rules_enabled = _get("rules_enabled", {})

        rules: list[BaseRule] = []

        # SYN Flood
        syn_rule = SynFloodRule(
            threshold=_get("syn_flood_threshold", 100),
            window_seconds=_get("syn_flood_window", 3),
        )
        syn_rule.enabled = rules_enabled.get("syn_flood", True)
        rules.append(syn_rule)

        # Port Scan
        scan_rule = PortScanRule(
            threshold=_get("port_scan_threshold", 20),
            window_seconds=_get("port_scan_window", 10),
        )
        scan_rule.enabled = rules_enabled.get("port_scan", True)
        rules.append(scan_rule)

        # SQL Injection
        sqli_rule = SqlInjectionRule()
        sqli_rule.enabled = rules_enabled.get("sql_injection", True)
        rules.append(sqli_rule)

        # Brute Force
        bf_rule = BruteForceRule(
            threshold=_get("brute_force_threshold", 10),
            window_seconds=_get("brute_force_window", 60),
        )
        bf_rule.enabled = rules_enabled.get("brute_force", True)
        rules.append(bf_rule)

        # ARP Spoofing
        arp_rule = ArpSpoofRule()
        arp_rule.enabled = rules_enabled.get("arp_spoof", True)
        rules.append(arp_rule)

        return rules

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """True if the Detection_Thread is active."""
        return self._thread is not None and self._thread.is_alive()

    @property
    def active_rule_names(self) -> list[str]:
        """Names of rules that are currently enabled and not disabled."""
        return [
            r.rule_name
            for r in self._rules
            if r.enabled and r.rule_name not in self._disabled_rules
        ]

    @property
    def disabled_rule_names(self) -> list[str]:
        """Names of rules disabled due to exceptions this session."""
        return list(self._disabled_rules)
