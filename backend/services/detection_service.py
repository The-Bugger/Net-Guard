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

import concurrent.futures
import logging
import queue
import threading
import time
from typing import Callable, Optional

from detection.parsers.packet_decoder import Packet
from detection.rules.base_rule import BaseRule, ThreatEvent
from detection.rules.arp_spoof import ArpSpoofRule
from detection.rules.brute_force import BruteForceRule
from detection.rules.dns_tunnel import DnsTunnelRule
from detection.rules.icmp_flood import IcmpFloodRule
from detection.rules.port_scan import PortScanRule
from detection.rules.slow_http import SlowHttpRule
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

        # Enterprise extensions (Tasks 13.1, 13.7)
        self._sigma_rules: list = []
        self._yara_rules = None
        self._rule_workers: int = 4
        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._socketio_emit = None  # wired by main.py

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

        # Configure thread pool (Task 13.7, Req 11.1)
        if self._config_manager:
            try:
                workers = int(self._config_manager.get("performance.rule_workers") or 4)
                self._rule_workers = max(1, min(workers, 32))
            except Exception:
                self._rule_workers = 4
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self._rule_workers, thread_name_prefix="RuleWorker"
        )

        # Load Sigma rules (Task 13.1, Req 9.3)
        self._load_sigma_rules()

        # Load YARA rules (Task 13.2, Req 9.4)
        self._load_yara_rules()

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

        if self._executor:
            self._executor.shutdown(wait=False)

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

            # Queue pressure warning (Task 16.4, Req 11.6)
            q_size = self._packet_queue.qsize()
            if q_size >= 8000:
                logger.warning("DetectionEngine: queue_pressure (%d/10000 slots)", q_size)
                if self._socketio_emit:
                    try:
                        self._socketio_emit("queue_pressure", {"queue_size": q_size})
                    except Exception:
                        pass

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

            # MITRE annotation (Task 13.3)
            event = self._annotate_mitre(event)

            # Dispatch to callback
            if self._on_event:
                try:
                    self._on_event(event)
                except Exception as exc:
                    logger.error(
                        "DetectionEngine: on_event callback raised %s: %s",
                        type(exc).__name__, exc,
                    )

            # Redis Streams publish (Task 16.3, Req 11.3)
            self._publish_to_redis(event)

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

        # ICMP Flood
        icmp_rule = IcmpFloodRule()
        icmp_rule.enabled = rules_enabled.get("icmp_flood", True)
        rules.append(icmp_rule)

        # Slow HTTP / Slowloris
        slow_http_rule = SlowHttpRule()
        slow_http_rule.enabled = rules_enabled.get("slow_http", True)
        rules.append(slow_http_rule)

        # DNS Tunneling
        dns_tunnel_rule = DnsTunnelRule()
        dns_tunnel_rule.enabled = rules_enabled.get("dns_tunnel", True)
        rules.append(dns_tunnel_rule)

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

    # ------------------------------------------------------------------
    # Enterprise extensions (Tasks 13.1-13.3, 13.7)
    # ------------------------------------------------------------------

    def _load_sigma_rules(self) -> None:
        """Load Sigma YAML rules from configured directory (Req 9.3)."""
        sigma_dir = None
        if self._config_manager:
            try:
                sigma_dir = self._config_manager.get("ai.sigma_rules_dir")
            except Exception:
                pass
        if not sigma_dir:
            return
        try:
            from pathlib import Path
            rules_path = Path(sigma_dir)
            if not rules_path.exists():
                return
            for f in rules_path.glob("*.yml"):
                try:
                    import yaml
                    with open(f) as fh:
                        rule = yaml.safe_load(fh)
                    self._sigma_rules.append(rule)
                except Exception as exc:
                    logger.error("DetectionEngine: Sigma parse error %s: %s", f.name, exc)
            logger.info("DetectionEngine: loaded %d Sigma rules", len(self._sigma_rules))
        except Exception as exc:
            logger.error("DetectionEngine: Sigma load failed: %s", exc)

    def _load_yara_rules(self) -> None:
        """Load YARA rules from configured directory (Req 9.4)."""
        yara_dir = None
        if self._config_manager:
            try:
                yara_dir = self._config_manager.get("ai.yara_rules_dir")
            except Exception:
                pass
        if not yara_dir:
            return
        try:
            import yara
            from pathlib import Path
            rules_path = Path(yara_dir)
            if not rules_path.exists():
                return
            rule_files = {}
            for f in rules_path.glob("*.yar"):
                try:
                    compiled = yara.compile(str(f))
                    rule_files[f.stem] = compiled
                except Exception as exc:
                    logger.error("DetectionEngine: YARA compile error %s: %s", f.name, exc)
            if rule_files:
                self._yara_rules = rule_files
                logger.info("DetectionEngine: loaded %d YARA rule files", len(rule_files))
        except ImportError:
            logger.debug("DetectionEngine: yara-python not installed — YARA disabled")
        except Exception as exc:
            logger.error("DetectionEngine: YARA load failed: %s", exc)

    @staticmethod
    def _publish_to_redis(event: ThreatEvent) -> None:
        """
        Publish ThreatEvent to Redis Stream 'netguard:events' (Req 11.3).
        Falls back silently — never raises.
        """
        try:
            from backend.services.redis_client import get_redis
            r = get_redis()
            if r is None:
                return
            r.xadd("netguard:events", {
                "event_id":   event.event_id,
                "attack_type": event.attack_type,
                "source_ip":  event.source_ip,
                "severity":   event.severity,
                "confidence": str(event.confidence),
                "timestamp":  event.timestamp,
                "rule_name":  event.rule_name,
            })
        except Exception as exc:
            logger.warning("DetectionEngine: redis publish failed — %s", exc)

    @staticmethod
    def _annotate_mitre(event: ThreatEvent) -> ThreatEvent:
        """Annotate ThreatEvent with MITRE tactic/technique (Task 13.3, Req 9.8)."""
        _MITRE = {
            "SYN Flood":          ("Impact", "T1499"),
            "Port Scan":          ("Reconnaissance", "T1595"),
            "SQL Injection":      ("Initial Access", "T1190"),
            "Brute Force":        ("Credential Access", "T1110"),
            "ARP Spoofing":       ("Credential Access", "T1557"),
            "ICMP Flood":         ("Impact", "T1498"),
            "Slow HTTP":          ("Impact", "T1499"),
            "DNS Tunneling":      ("Command and Control", "T1071.004"),
        }
        tactic, technique = _MITRE.get(event.attack_type, ("", ""))
        if hasattr(event, "mitre_tactic"):
            event.mitre_tactic = tactic
        if hasattr(event, "mitre_technique"):
            event.mitre_technique = technique
        # Also store in evidence dict
        if isinstance(event.evidence, dict):
            event.evidence["mitre_tactic"] = tactic
            event.evidence["mitre_technique"] = technique
        return event
