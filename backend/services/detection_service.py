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
import uuid
from datetime import datetime, timezone
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

# Optional YARA dependency (Req 9.4)
try:
    import yara as _yara_mod
    _YARA_AVAILABLE = True
except ImportError:
    _yara_mod = None  # type: ignore[assignment]
    _YARA_AVAILABLE = False
    logger.warning("yara-python not installed; YARA evaluation disabled")

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
        futures: list[concurrent.futures.Future] = []

        # Submit enabled rules to thread pool
        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.rule_name in self._disabled_rules:
                continue

            try:
                rule.process_packet(packet)
                future = self._executor.submit(rule.evaluate)
                futures.append((future, rule))
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

        # Collect results from thread pool
        for future, rule in futures:
            try:
                event = future.result()
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
            event = self.annotate_mitre(event)

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

        # YARA evaluation against HTTP payload (Req 9.4)
        if packet.payload:
            self._dispatch_yara(packet)

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
        """Load Sigma YAML rules at startup using configured directory (Req 9.3)."""
        sigma_dir = None
        if self._config_manager:
            try:
                sigma_dir = self._config_manager.get("ai.sigma_rules_dir")
            except Exception:
                pass
        directory = sigma_dir or "rules/sigma"
        loaded = self.load_sigma_rules(directory)
        if loaded:
            logger.info("DetectionEngine: loaded %d Sigma rules from '%s'", loaded, directory)
        self._start_sigma_watcher(directory)

    def load_sigma_rules(self, directory: str) -> int:
        """
        Load Sigma YAML files from *directory*, converting each to the internal
        rule format.  Returns the count of successfully loaded rules.

        Internal rule format::

            {"id": str, "name": str, "tags": list, "conditions": list[dict], "logsource": dict}

        Parse errors skip the offending file and log with filename + line number
        (Req 9.3).
        """
        import yaml
        from pathlib import Path

        rules_path = Path(directory)
        rules_path.mkdir(parents=True, exist_ok=True)

        loaded: list[dict] = []
        for f in sorted(rules_path.glob("*.yml")) + sorted(rules_path.glob("*.yaml")):
            try:
                with open(f, encoding="utf-8") as fh:
                    raw = yaml.safe_load(fh)
                if not isinstance(raw, dict):
                    raise ValueError("expected a YAML mapping")
                rule = {
                    "id":         str(raw.get("id", f.stem)),
                    "name":       str(raw.get("title", f.stem)),
                    "tags":       list(raw.get("tags") or []),
                    "conditions": _sigma_conditions(raw.get("detection", {})),
                    "logsource":  dict(raw.get("logsource") or {}),
                }
                loaded.append(rule)
            except yaml.YAMLError as exc:
                # Extract line number when available
                lineno = getattr(getattr(exc, "problem_mark", None), "line", 0) + 1
                logger.warning(
                    "Sigma parse error in %s line %d: %s", f.name, lineno, exc
                )
            except Exception as exc:
                logger.warning("Sigma parse error in %s line %d: %s", f.name, 0, exc)

        # Atomically replace the rule list
        self._sigma_rules = loaded
        # Track mtimes for hot-reload watcher
        self._sigma_mtimes = {
            str(f): f.stat().st_mtime
            for f in list(rules_path.glob("*.yml")) + list(rules_path.glob("*.yaml"))
        }
        return len(loaded)

    def reload_sigma_rules(self) -> None:
        """Hot-reload Sigma rules from the configured directory."""
        sigma_dir = None
        if self._config_manager:
            try:
                sigma_dir = self._config_manager.get("ai.sigma_rules_dir")
            except Exception:
                pass
        directory = sigma_dir or "rules/sigma"
        loaded = self.load_sigma_rules(directory)
        logger.info("DetectionEngine: reloaded %d Sigma rules from '%s'", loaded, directory)

    def _match_sigma(self, event: dict) -> list[str]:
        """
        Return names of Sigma rules that match *event*.

        Matching is keyword/field based (Req 9.3): a rule matches when every
        condition in the rule matches (AND across conditions), where a condition
        matches when any of its keywords appears in any string value of the event
        OR every field/value pair in its ``fields`` dict matches an event key.

        ponytail: O(rules * conditions * fields) linear scan — fine for typical
        Sigma rule counts (<1000); upgrade to compiled regexes if profiling shows
        this hot path is costly.
        """
        matched: list[str] = []
        event_str = " ".join(str(v) for v in event.values()).lower()
        for rule in self._sigma_rules:
            conditions = rule.get("conditions", [])
            if not conditions:
                continue
            # All conditions must match (AND semantics across conditions)
            if all(_sigma_cond_matches(cond, event, event_str) for cond in conditions):
                matched.append(rule["name"])
        return matched

    def _start_sigma_watcher(self, directory: str) -> None:
        """Start a daemon thread that hot-reloads Sigma rules on file changes (every 5 s)."""
        # ponytail: polling instead of inotify/watchdog — O(files) scan every 5 s;
        # upgrade to watchdog if the rules directory grows beyond ~1000 files.
        if not hasattr(self, "_sigma_mtimes"):
            self._sigma_mtimes: dict[str, float] = {}

        def _watch() -> None:
            from pathlib import Path
            rules_path = Path(directory)
            while True:
                time.sleep(5)
                try:
                    if not rules_path.is_dir():
                        continue
                    current = {
                        str(f): f.stat().st_mtime
                        for f in list(rules_path.glob("*.yml")) + list(rules_path.glob("*.yaml"))
                    }
                    if current != self._sigma_mtimes:
                        self.reload_sigma_rules()
                except Exception as exc:
                    logger.debug("Sigma watcher error: %s", exc)

        t = threading.Thread(target=_watch, name="SigmaWatcher", daemon=True)
        t.start()

    def _load_yara_rules(self) -> None:
        """Load YARA rules from configured directory (Req 9.4)."""
        yara_dir = None
        if self._config_manager:
            try:
                yara_dir = self._config_manager.get("ai.yara_rules_dir")
            except Exception:
                pass
        directory = yara_dir or "rules/yara"
        count = self.load_yara_rules(directory)
        if count:
            logger.info("DetectionEngine: loaded %d YARA rule files", count)

    def load_yara_rules(self, directory: str) -> int:
        """
        Load and compile YARA rules from *directory*.

        Skips files that fail to compile (logs a warning per file) and
        continues loading the rest.  Stores compiled rules internally for
        use by :meth:`evaluate_yara`.

        Args:
            directory: Path to the directory containing ``*.yar`` files.

        Returns:
            Number of successfully compiled rule files.
        """
        if not _YARA_AVAILABLE:
            return 0

        from pathlib import Path  # stdlib

        rules_path = Path(directory)
        if not rules_path.exists():
            return 0

        compiled: dict = {}
        rule_files = sorted(rules_path.glob("*.yar")) + sorted(rules_path.glob("*.yara"))
        for f in rule_files:
            try:
                compiled[f.stem] = _yara_mod.compile(str(f))
            except Exception as exc:  # noqa: BLE001
                logger.warning("YARA compile error in %s: %s", f.name, exc)

        if compiled:
            self._yara_rules = compiled
        return len(compiled)

    def evaluate_yara(self, payload: bytes) -> list[str]:
        """
        Match all loaded YARA rules against *payload*.

        Args:
            payload: Raw HTTP payload bytes to scan.

        Returns:
            List of matched rule names (strings).  Empty list when YARA is
            unavailable, no rules are loaded, or there are no matches.
            Never raises.
        """
        if not self._yara_rules or not payload:
            return []
        matched: list[str] = []
        for _filename, compiled in self._yara_rules.items():
            try:
                matches = compiled.match(data=payload)
                matched.extend(m.rule for m in matches)
            except Exception as exc:  # noqa: BLE001
                logger.warning("DetectionEngine: YARA eval error: %s", exc)
        return matched

    def _dispatch_yara(self, packet: Packet) -> None:
        """
        Run YARA evaluation on packet payload and emit ThreatEvents for matches.

        Called from _dispatch when a packet carries payload bytes.
        Never raises.
        """
        try:
            matched = self.evaluate_yara(packet.payload)
        except Exception as exc:  # noqa: BLE001
            logger.warning("DetectionEngine: YARA dispatch error: %s", exc)
            return

        for rule_name in matched:
            event = ThreatEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                attack_type="YARA Match",
                source_ip=packet.src_ip,
                destination_ip=packet.dst_ip,
                source_port=packet.src_port,
                destination_port=packet.dst_port,
                protocol=packet.protocol,
                rule_name=rule_name,
                severity="High",
                confidence=80,
                packet_count=1,
                evidence={"yara_rule": rule_name, "payload_length": len(packet.payload or b"")},
            )
            if not self._should_emit(event):
                continue
            self._cooldown[(event.source_ip, event.rule_name)] = (event.severity, time.monotonic())
            event = self.annotate_mitre(event)
            if self._on_event:
                try:
                    self._on_event(event)
                except Exception as exc:
                    logger.error("DetectionEngine: on_event (YARA) raised %s: %s", type(exc).__name__, exc)
            self._publish_to_redis(event)

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

    # MITRE ATT&CK mapping keyed by rule_name or attack_type (Task 13.3, Req 9.8)
    _MITRE_MAP: dict[str, dict] = {
        # rule_name keys (primary lookup)
        "port_scan":          {"tactic": "Reconnaissance",       "technique": "T1595"},
        "syn_flood":          {"tactic": "Impact",               "technique": "T1499"},
        "brute_force":        {"tactic": "Credential Access",    "technique": "T1110"},
        "sql_injection":      {"tactic": "Initial Access",       "technique": "T1190"},
        "xss":                {"tactic": "Initial Access",       "technique": "T1189"},
        "dns_amplification":  {"tactic": "Impact",               "technique": "T1498"},
        "http_flood":         {"tactic": "Impact",               "technique": "T1499"},
        "ssh_attack":         {"tactic": "Lateral Movement",     "technique": "T1021"},
        "data_exfiltration":  {"tactic": "Exfiltration",         "technique": "T1041"},
        "malware_beacon":     {"tactic": "Command and Control",  "technique": "T1071"},
        # attack_type fallback keys (display names used by built-in rules)
        "SYN Flood":          {"tactic": "Impact",               "technique": "T1499"},
        "Port Scan":          {"tactic": "Reconnaissance",       "technique": "T1595"},
        "SQL Injection":      {"tactic": "Initial Access",       "technique": "T1190"},
        "Brute Force":        {"tactic": "Credential Access",    "technique": "T1110"},
        "ARP Spoofing":       {"tactic": "Credential Access",    "technique": "T1557"},
        "ICMP Flood":         {"tactic": "Impact",               "technique": "T1498"},
        "Slow HTTP":          {"tactic": "Impact",               "technique": "T1499"},
        "DNS Tunneling":      {"tactic": "Command and Control",  "technique": "T1071.004"},
    }

    def annotate_mitre(self, event: ThreatEvent) -> ThreatEvent:
        """
        Annotate *event* with MITRE ATT&CK tactic and technique (Task 13.3, Req 9.8).

        Looks up ``event.rule_name`` then ``event.attack_type`` in ``_MITRE_MAP``.
        Falls back to ``"Unknown"`` for both fields if no entry is found.
        Stores the result on ``event.mitre_tactic``, ``event.mitre_technique``,
        and inside ``event.evidence`` so it surfaces in serialised event data.

        Args:
            event: ThreatEvent to annotate (mutated in place).

        Returns:
            The same event with MITRE fields populated.
        """
        entry = (
            self._MITRE_MAP.get(event.rule_name)
            or self._MITRE_MAP.get(event.attack_type)
        )
        tactic    = entry["tactic"]    if entry else "Unknown"
        technique = entry["technique"] if entry else "Unknown"

        event.mitre_tactic    = tactic
        event.mitre_technique = technique
        if isinstance(event.evidence, dict):
            event.evidence["mitre_tactic"]    = tactic
            event.evidence["mitre_technique"] = technique
        return event


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _sigma_conditions(detection: dict) -> list[dict]:
    """
    Convert a Sigma ``detection`` block into a flat list of condition dicts.

    Each condition dict has the form::

        {"keywords": [...], "fields": {field: value, ...}}

    Named selections (``condition: selection``) are inlined; the special
    ``condition`` key itself is ignored.  Unknown/complex condition combinators
    (``and``, ``or``, ``not``, ``1 of``, etc.) are silently treated as
    individual keyword matches — good enough for simple keyword/field matching
    against event dicts (Req 9.3).

    ponytail: linear scan, no parser — upgrade to pySigma if full condition
    algebra is needed.
    """
    if not detection or not isinstance(detection, dict):
        return []

    conditions: list[dict] = []
    for key, value in detection.items():
        if key == "condition":
            continue  # combinator expression, not a selection block
        cond: dict = {"keywords": [], "fields": {}}
        if isinstance(value, list):
            # e.g. keywords: [cmd.exe, powershell]
            cond["keywords"] = [str(v) for v in value]
        elif isinstance(value, dict):
            # e.g. EventID: 1 / CommandLine|contains: 'malware'
            for field, val in value.items():
                cond["fields"][field] = val
        elif isinstance(value, str):
            cond["keywords"] = [value]
        if cond["keywords"] or cond["fields"]:
            conditions.append(cond)
    return conditions


def _sigma_cond_matches(cond: dict, event: dict, event_str: str) -> bool:
    """
    Return True if *cond* matches *event*.

    - keywords: any keyword present (case-insensitive) in the flattened event string
    - fields: every field key present in event with a value that contains the rule value
              (Sigma modifiers like ``|contains`` stripped to the bare field name)
    """
    keywords = cond.get("keywords", [])
    fields = cond.get("fields", {})

    if keywords and not any(kw.lower() in event_str for kw in keywords):
        return False
    if fields:
        for field, val in fields.items():
            bare_field = field.split("|")[0]  # strip |contains, |startswith, etc.
            ev_val = str(event.get(bare_field, "")).lower()
            if str(val).lower() not in ev_val:
                return False
    return True
