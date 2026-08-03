"""Detection engine — evaluates all enabled rules on every captured packet."""

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

try:
    import yara as _yara_mod
    _YARA_AVAILABLE = True
except ImportError:
    _yara_mod = None  # type: ignore[assignment]
    _YARA_AVAILABLE = False
    logger.warning("yara-python not installed; YARA evaluation disabled")

_SEVERITY_ORDER: dict[str, int] = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
_STOP_SENTINEL = object()


class DetectionEngine:
    """
    Evaluates all enabled rules on every packet in a dedicated Detection_Thread.

    Enforces a 10-second cooldown per (source_ip, rule_name) pair, allowing
    escalation to higher severity within the window. On rule exception, that
    rule is disabled for the session and the rest continue.
    """

    COOLDOWN_SECONDS: int = 10

    def __init__(
        self,
        packet_queue: queue.Queue,
        on_event: Optional[Callable[[ThreatEvent], None]] = None,
        config_manager=None,
    ) -> None:
        self._packet_queue = packet_queue
        self._on_event = on_event
        self._config_manager = config_manager

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._rules: list[BaseRule] = []
        self._cooldown: dict[tuple[str, str], tuple[str, float]] = {}
        self._disabled_rules: set[str] = set()
        self._sigma_rules: list = []
        self._yara_rules = None
        self._rule_workers: int = 4
        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._socketio_emit = None

    def start(self) -> None:
        """Initialise detection rules and start the Detection_Thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("DetectionEngine is already running.")
            return

        self._rules = self._build_rules()
        for rule in self._rules:
            try:
                rule.initialize()
            except Exception as exc:
                logger.error("DetectionEngine: rule %s failed initialize() — %s", rule.rule_name, exc)
                self._disabled_rules.add(rule.rule_name)

        if self._config_manager:
            try:
                workers = int(self._config_manager.get("performance.rule_workers") or 4)
                self._rule_workers = max(1, min(workers, 32))
            except Exception:
                self._rule_workers = 4
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self._rule_workers, thread_name_prefix="RuleWorker"
        )

        self._load_sigma_rules()
        self._load_yara_rules()

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._detection_loop, name="Detection_Thread", daemon=True)
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
        """Rebuild rule instances using current configuration values."""
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
                logger.error("DetectionEngine.reload_rules: %s failed initialize — %s", rule.rule_name, exc)
                self._disabled_rules.add(rule.rule_name)

        logger.info("DetectionEngine rules reloaded.")

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
        """Run all enabled rules on a single packet. Never raises."""
        # Lazily create the executor so _dispatch works before start() is called
        # (e.g. in unit tests that drive the engine directly).
        if self._executor is None:
            self._executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=self._rule_workers, thread_name_prefix="RuleWorker"
            )

        futures: list[concurrent.futures.Future] = []

        for rule in self._rules:
            if not rule.enabled or rule.rule_name in self._disabled_rules:
                continue
            try:
                rule.process_packet(packet)
                future = self._executor.submit(rule.evaluate)
                futures.append((future, rule))
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "DetectionEngine: rule %s raised %s — disabling for this session. %s",
                    rule.rule_name, type(exc).__name__, exc, exc_info=True,
                )
                self._disabled_rules.add(rule.rule_name)

        for future, rule in futures:
            try:
                event = future.result()
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "DetectionEngine: rule %s raised %s — disabling for this session. %s",
                    rule.rule_name, type(exc).__name__, exc, exc_info=True,
                )
                self._disabled_rules.add(rule.rule_name)
                continue

            if event is None or not self._should_emit(event):
                continue

            key = (event.source_ip, event.rule_name)
            self._cooldown[key] = (event.severity, time.monotonic())
            event = self.annotate_mitre(event)

            if self._on_event:
                try:
                    self._on_event(event)
                except Exception as exc:
                    logger.error("DetectionEngine: on_event callback raised %s: %s", type(exc).__name__, exc)

            self._publish_to_redis(event)

        if packet.payload:
            self._dispatch_yara(packet)

    def _should_emit(self, event: ThreatEvent) -> bool:
        """
        Return True if the event passes the cooldown gate.

        Allows emission when there is no prior event in the window, or when
        the new severity is strictly higher than the last emitted severity.
        """
        key = (event.source_ip, event.rule_name)
        if key not in self._cooldown:
            return True
        prev_severity, prev_time = self._cooldown[key]
        if time.monotonic() - prev_time >= self.COOLDOWN_SECONDS:
            return True
        return _SEVERITY_ORDER.get(event.severity, 0) > _SEVERITY_ORDER.get(prev_severity, 0)

    def _build_rules(self) -> list[BaseRule]:
        """Build rule instances from current configuration."""
        cfg = self._config_manager

        def _get(key: str, default):
            if cfg:
                val = cfg.get(key)
                return val if val is not None else default
            return default

        rules_enabled = _get("rules_enabled", {})
        rules: list[BaseRule] = []

        syn_rule = SynFloodRule(threshold=_get("syn_flood_threshold", 100), window_seconds=_get("syn_flood_window", 3))
        syn_rule.enabled = rules_enabled.get("syn_flood", True)
        rules.append(syn_rule)

        scan_rule = PortScanRule(threshold=_get("port_scan_threshold", 20), window_seconds=_get("port_scan_window", 10))
        scan_rule.enabled = rules_enabled.get("port_scan", True)
        rules.append(scan_rule)

        sqli_rule = SqlInjectionRule()
        sqli_rule.enabled = rules_enabled.get("sql_injection", True)
        rules.append(sqli_rule)

        bf_rule = BruteForceRule(threshold=_get("brute_force_threshold", 10), window_seconds=_get("brute_force_window", 60))
        bf_rule.enabled = rules_enabled.get("brute_force", True)
        rules.append(bf_rule)

        arp_rule = ArpSpoofRule()
        arp_rule.enabled = rules_enabled.get("arp_spoof", True)
        rules.append(arp_rule)

        icmp_rule = IcmpFloodRule()
        icmp_rule.enabled = rules_enabled.get("icmp_flood", True)
        rules.append(icmp_rule)

        slow_http_rule = SlowHttpRule()
        slow_http_rule.enabled = rules_enabled.get("slow_http", True)
        rules.append(slow_http_rule)

        dns_tunnel_rule = DnsTunnelRule()
        dns_tunnel_rule.enabled = rules_enabled.get("dns_tunnel", True)
        rules.append(dns_tunnel_rule)

        return rules

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def active_rule_names(self) -> list[str]:
        return [r.rule_name for r in self._rules if r.enabled and r.rule_name not in self._disabled_rules]

    @property
    def disabled_rule_names(self) -> list[str]:
        return list(self._disabled_rules)

    def _load_sigma_rules(self) -> None:
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
        Load Sigma YAML files from directory. Returns count of loaded rules.

        Internal rule format: {"id", "name", "tags", "conditions", "logsource"}.
        Parse errors are logged with filename + line number; the file is skipped.
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
                lineno = getattr(getattr(exc, "problem_mark", None), "line", 0) + 1
                logger.warning("Sigma parse error in %s line %d: %s", f.name, lineno, exc)
            except Exception as exc:
                logger.warning("Sigma parse error in %s line %d: %s", f.name, 0, exc)

        self._sigma_rules = loaded
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
        Return names of Sigma rules matching event.

        A rule matches when all its conditions match (AND semantics).
        ponytail: O(rules × conditions × fields) scan — fine for <1000 rules;
        upgrade to compiled regexes if this becomes a hot path.
        """
        matched: list[str] = []
        event_str = " ".join(str(v) for v in event.values()).lower()
        for rule in self._sigma_rules:
            conditions = rule.get("conditions", [])
            if not conditions:
                continue
            if all(_sigma_cond_matches(cond, event, event_str) for cond in conditions):
                matched.append(rule["name"])
        return matched

    def _start_sigma_watcher(self, directory: str) -> None:
        """
        Start a daemon thread that hot-reloads Sigma rules on file changes.

        ponytail: polls every 5 s — upgrade to watchdog if the rules directory
        grows beyond ~1000 files.
        """
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

        threading.Thread(target=_watch, name="SigmaWatcher", daemon=True).start()

    def _load_yara_rules(self) -> None:
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
        """Load and compile YARA rules from directory. Returns count of compiled files."""
        if not _YARA_AVAILABLE:
            return 0

        from pathlib import Path
        rules_path = Path(directory)
        if not rules_path.exists():
            return 0

        compiled: dict = {}
        for f in sorted(rules_path.glob("*.yar")) + sorted(rules_path.glob("*.yara")):
            try:
                compiled[f.stem] = _yara_mod.compile(str(f))
            except Exception as exc:  # noqa: BLE001
                logger.warning("YARA compile error in %s: %s", f.name, exc)

        if compiled:
            self._yara_rules = compiled
        return len(compiled)

    def evaluate_yara(self, payload: bytes) -> list[str]:
        """Match all loaded YARA rules against payload. Returns matched rule names. Never raises."""
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
        """Run YARA evaluation on packet payload and emit ThreatEvents for matches. Never raises."""
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
        """Publish ThreatEvent to Redis Stream 'netguard:events'. Falls back silently."""
        try:
            from backend.services.redis_client import get_redis
            r = get_redis()
            if r is None:
                return
            r.xadd("netguard:events", {
                "event_id":    event.event_id,
                "attack_type": event.attack_type,
                "source_ip":   event.source_ip,
                "severity":    event.severity,
                "confidence":  str(event.confidence),
                "timestamp":   event.timestamp,
                "rule_name":   event.rule_name,
            })
        except Exception as exc:
            logger.warning("DetectionEngine: redis publish failed — %s", exc)

    # MITRE ATT&CK lookup — rule_name (primary) then attack_type (fallback)
    _MITRE_MAP: dict[str, dict] = {
        "port_scan":         {"tactic": "Reconnaissance",      "technique": "T1595"},
        "syn_flood":         {"tactic": "Impact",              "technique": "T1499"},
        "brute_force":       {"tactic": "Credential Access",   "technique": "T1110"},
        "sql_injection":     {"tactic": "Initial Access",      "technique": "T1190"},
        "xss":               {"tactic": "Initial Access",      "technique": "T1189"},
        "dns_amplification": {"tactic": "Impact",              "technique": "T1498"},
        "http_flood":        {"tactic": "Impact",              "technique": "T1499"},
        "ssh_attack":        {"tactic": "Lateral Movement",    "technique": "T1021"},
        "data_exfiltration": {"tactic": "Exfiltration",        "technique": "T1041"},
        "malware_beacon":    {"tactic": "Command and Control", "technique": "T1071"},
        "SYN Flood":         {"tactic": "Impact",              "technique": "T1499"},
        "Port Scan":         {"tactic": "Reconnaissance",      "technique": "T1595"},
        "SQL Injection":     {"tactic": "Initial Access",      "technique": "T1190"},
        "Brute Force":       {"tactic": "Credential Access",   "technique": "T1110"},
        "ARP Spoofing":      {"tactic": "Credential Access",   "technique": "T1557"},
        "ICMP Flood":        {"tactic": "Impact",              "technique": "T1498"},
        "Slow HTTP":         {"tactic": "Impact",              "technique": "T1499"},
        "DNS Tunneling":     {"tactic": "Command and Control", "technique": "T1071.004"},
    }

    def annotate_mitre(self, event: ThreatEvent) -> ThreatEvent:
        """Annotate event with MITRE ATT&CK tactic/technique. Mutates and returns event."""
        entry = self._MITRE_MAP.get(event.rule_name) or self._MITRE_MAP.get(event.attack_type)
        tactic    = entry["tactic"]    if entry else "Unknown"
        technique = entry["technique"] if entry else "Unknown"
        event.mitre_tactic    = tactic
        event.mitre_technique = technique
        if isinstance(event.evidence, dict):
            event.evidence["mitre_tactic"]    = tactic
            event.evidence["mitre_technique"] = technique
        return event


def _sigma_conditions(detection: dict) -> list[dict]:
    """
    Convert a Sigma detection block into a flat list of condition dicts.

    Each condition: {"keywords": [...], "fields": {field: value, ...}}.
    The "condition" key (combinator) is ignored.
    ponytail: no parser — upgrade to pySigma if full condition algebra is needed.
    """
    if not detection or not isinstance(detection, dict):
        return []
    conditions: list[dict] = []
    for key, value in detection.items():
        if key == "condition":
            continue
        cond: dict = {"keywords": [], "fields": {}}
        if isinstance(value, list):
            cond["keywords"] = [str(v) for v in value]
        elif isinstance(value, dict):
            for field, val in value.items():
                cond["fields"][field] = val
        elif isinstance(value, str):
            cond["keywords"] = [value]
        if cond["keywords"] or cond["fields"]:
            conditions.append(cond)
    return conditions


def _sigma_cond_matches(cond: dict, event: dict, event_str: str) -> bool:
    """Return True if cond matches event (keywords: any present; fields: all must match)."""
    keywords = cond.get("keywords", [])
    fields = cond.get("fields", {})
    if keywords and not any(kw.lower() in event_str for kw in keywords):
        return False
    if fields:
        for field, val in fields.items():
            bare_field = field.split("|")[0]
            ev_val = str(event.get(bare_field, "")).lower()
            if str(val).lower() not in ev_val:
                return False
    return True
