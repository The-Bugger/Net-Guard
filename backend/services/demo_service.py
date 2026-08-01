"""
demo_service.py — DemoService for NetGuard IDPS.

Generates synthetic ThreatEvents and injects them through the existing
_on_threat_event callback pipeline.  No new DB tables; no bypass of
existing detection/prevention logic.

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8
"""

from __future__ import annotations

import ipaddress
import logging
import random
import threading
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional

from detection.rules.base_rule import ThreatEvent

logger = logging.getLogger("netguard.demo_service")

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_TEST_NET_RANGES = [
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
]

_ATTACK_TEMPLATES: list[dict] = [
    {"attack_type": "SQL Injection",        "rule_name": "SQL_INJECTION_001",    "severity": "High",     "confidence": 100, "destination_ip": "10.0.0.1", "destination_port": 80,   "protocol": "TCP",     "packet_count": 1},
    {"attack_type": "Brute Force",          "rule_name": "BRUTE_FORCE_001",      "severity": "Medium",   "confidence": 75,  "destination_ip": "10.0.0.1", "destination_port": 22,   "protocol": "TCP",     "packet_count": 15},
    {"attack_type": "Port Scan",            "rule_name": "PORT_SCAN_001",        "severity": "Medium",   "confidence": 80,  "destination_ip": "10.0.0.1", "destination_port": None, "protocol": "TCP",     "packet_count": 30},
    {"attack_type": "DDoS/SYN Flood",       "rule_name": "SYN_FLOOD_001",        "severity": "Critical", "confidence": 95,  "destination_ip": "10.0.0.1", "destination_port": 80,   "protocol": "TCP",     "packet_count": 500},
    {"attack_type": "XSS",                  "rule_name": "XSS_001",              "severity": "High",     "confidence": 90,  "destination_ip": "10.0.0.1", "destination_port": 443,  "protocol": "TCP",     "packet_count": 1},
    {"attack_type": "SSH Login",            "rule_name": "SSH_LOGIN_001",        "severity": "Medium",   "confidence": 70,  "destination_ip": "10.0.0.1", "destination_port": 22,   "protocol": "TCP",     "packet_count": 8},
    {"attack_type": "Suspicious DNS",       "rule_name": "SUSPICIOUS_DNS_001",   "severity": "Low",      "confidence": 60,  "destination_ip": "8.8.8.8",  "destination_port": 53,   "protocol": "UDP",     "packet_count": 20},
    {"attack_type": "Malware Download",     "rule_name": "MALWARE_DOWNLOAD_001", "severity": "Critical", "confidence": 85,  "destination_ip": "10.0.0.1", "destination_port": 80,   "protocol": "TCP",     "packet_count": 3},
    {"attack_type": "Privilege Escalation", "rule_name": "PRIV_ESC_001",         "severity": "Critical", "confidence": 88,  "destination_ip": "10.0.0.1", "destination_port": None, "protocol": "UNKNOWN", "packet_count": 1},
]

# Keyed set of all attack_type values — used by trigger() for fast validation
_KNOWN_ATTACK_TYPES: frozenset[str] = frozenset(t["attack_type"] for t in _ATTACK_TEMPLATES)

# All host IPs in the three TEST-NET ranges (used for whitelist injection)
# ponytail: 762 strings pre-computed once at import; O(n) whitelist injection on start/stop.
# Acceptable for a demo service; upgrade path: add CIDR support to WhitelistManager.
_TEST_NET_IPS: frozenset[str] = frozenset(
    str(net.network_address + i)
    for net in _TEST_NET_RANGES
    for i in range(1, 255)
)

# Explanation/recommendation templates keyed by attack_type
_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "SQL Injection": (
        "An attacker sent crafted SQL payload in an HTTP request attempting to manipulate the database.",
        "Sanitise all user inputs with parameterised queries and deploy a WAF rule for SQL metacharacters.",
    ),
    "Brute Force": (
        "Multiple rapid authentication attempts were detected from a single source, indicating a brute-force attack.",
        "Enforce account lockout after 5 failed attempts and require MFA for all privileged accounts.",
    ),
    "Port Scan": (
        "A systematic probe of multiple ports was detected, typically used for network reconnaissance.",
        "Block the source IP at the perimeter firewall and review exposure of unnecessary open ports.",
    ),
    "DDoS/SYN Flood": (
        "A high volume of TCP SYN packets without corresponding ACKs is overwhelming the server's connection table.",
        "Enable SYN cookies, rate-limit incoming SYN packets, and engage upstream DDoS mitigation.",
    ),
    "XSS": (
        "A cross-site scripting payload was detected in an HTTP request targeting web application users.",
        "Apply strict Content-Security-Policy headers and encode all user-supplied output in HTML context.",
    ),
    "SSH Login": (
        "Repeated SSH authentication failures from a single source indicate a credential stuffing attempt.",
        "Restrict SSH access by IP allowlist, disable password auth, and rotate SSH keys immediately.",
    ),
    "Suspicious DNS": (
        "Unusual DNS query patterns suggest potential DNS tunnelling or C2 beaconing activity.",
        "Inspect DNS traffic for data exfiltration signs and block resolution of known malicious domains.",
    ),
    "Malware Download": (
        "An HTTP GET request matched a known malware download signature.",
        "Quarantine the requesting host, revoke its network access, and initiate endpoint forensic analysis.",
    ),
    "Privilege Escalation": (
        "Anomalous privilege escalation activity was detected on the target system.",
        "Review sudoers and SUID binaries, rotate credentials for all privileged accounts, and patch known CVEs.",
    ),
}


class DemoService:
    """
    Generates synthetic ThreatEvents and injects them through the existing
    _on_threat_event callback.  Manages a single background emit loop.
    """

    def __init__(self, on_threat_event: Callable, block_repo) -> None:
        """
        Args:
            on_threat_event: The existing _on_threat_event callback from main.py.
            block_repo: BlockRepository — held for potential future use (Req 1.6
                        protection is handled via whitelist injection).
        """
        self._on_threat_event = on_threat_event
        self._block_repo = block_repo

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._events_generated: int = 0
        self._started_at: Optional[str] = None

        # Optional whitelist_manager injected by the caller (main.py) after construction.
        # Set via .whitelist_manager property before start().
        self._whitelist_manager = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def whitelist_manager(self) -> Optional[object]:
        """Return the injected WhitelistManager instance, or None if unset."""
        return self._whitelist_manager

    @whitelist_manager.setter
    def whitelist_manager(self, wm) -> None:
        self._whitelist_manager = wm

    def start(self) -> None:
        """
        Start the background emit loop.

        No-op if already active (route layer returns 409).
        Adds TEST-NET IPs to the in-memory whitelist so PreventionEngine
        skips blocking demo source IPs (Req 1.6).
        """
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return  # already running — route layer handles 409

            self._stop_event.clear()
            self._events_generated = 0
            self._started_at = _utc_now()

            # Inject TEST-NET IPs into whitelist (in-memory only, no DB writes)
            self._add_to_whitelist()

            self._thread = threading.Thread(
                target=self._emit_loop, name="demo-emit", daemon=True
            )
            self._thread.start()
        logger.info("DemoService: started.")

    def stop(self) -> None:
        """
        Signal the background thread to stop; wait up to 2 seconds.
        Removes TEST-NET IPs from the in-memory whitelist (Req 1.6).
        """
        with self._lock:
            self._stop_event.set()
            thread = self._thread

        if thread is not None:
            thread.join(timeout=2.0)

        with self._lock:
            self._thread = None
            self._remove_from_whitelist()

        logger.info("DemoService: stopped.")

    def trigger(self, attack_type: str) -> str:
        """
        Emit one synthetic event for the given attack_type immediately.

        Works whether or not a Demo_Session is active (Req 7.5).

        Args:
            attack_type: Must match one of the nine template attack_type values.

        Returns:
            event_id (UUID4 string).

        Raises:
            ValueError: If attack_type is unknown.
        """
        attack_type = attack_type.strip()
        template = next(
            (t for t in _ATTACK_TEMPLATES if t["attack_type"] == attack_type), None
        )
        if template is None:
            raise ValueError(f"Unknown attack_type: {attack_type!r}")

        event = self._build_event(template)
        self._on_threat_event(event)
        with self._lock:
            self._events_generated += 1
        logger.debug("DemoService.trigger: emitted %s (event_id=%s)", attack_type, event.event_id)
        return event.event_id

    def get_status(self) -> dict:
        """Return current Demo_Session state (Req 1.7)."""
        with self._lock:
            return {
                "active": self._thread is not None and self._thread.is_alive(),
                "events_generated": self._events_generated,
                "started_at": self._started_at,
            }

    @property
    def is_active(self) -> bool:
        """True if the background emit loop is running."""
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------

    def _emit_loop(self) -> None:
        """
        Background thread.  Shuffles the 9 templates, emits each one, then
        reshuffles and repeats until stop_event is set (Req 1.1).
        Sleep 2–5 s between emissions.
        """
        templates = list(_ATTACK_TEMPLATES)
        while not self._stop_event.is_set():
            random.shuffle(templates)
            for template in templates:
                if self._stop_event.is_set():
                    return
                try:
                    event = self._build_event(template)
                    self._on_threat_event(event)
                    with self._lock:
                        self._events_generated += 1
                    logger.debug(
                        "DemoService: emitted %s (event_id=%s)",
                        template["attack_type"], event.event_id,
                    )
                except Exception as exc:
                    logger.error("DemoService._emit_loop error: %s", exc, exc_info=True)
                    # Continue loop — don't crash the demo (error handling design spec)

                # Sleep 2–5 s, interruptible by stop_event
                self._stop_event.wait(timeout=random.uniform(2.0, 5.0))
                if self._stop_event.is_set():
                    return

    # ------------------------------------------------------------------
    # Event builder
    # ------------------------------------------------------------------

    def _build_event(self, template: dict) -> ThreatEvent:
        """
        Build a ThreatEvent from a template dict.

        Source IP is a random host from one of the three TEST-NET /24 ranges (Req 1.6).
        Evidence includes demo: True (Req 1.8).
        """
        network = random.choice(_TEST_NET_RANGES)
        host_octet = random.randint(1, 254)
        source_ip = str(network.network_address + host_octet)

        attack_type = template["attack_type"]
        explanation_text, recommendation = _EXPLANATIONS.get(
            attack_type,
            (
                f"Simulated {attack_type} attack detected by demo engine.",
                f"Review and mitigate {attack_type} exposure in your environment.",
            ),
        )

        return ThreatEvent(
            event_id=str(uuid.uuid4()),
            timestamp=_utc_now(),
            attack_type=attack_type,
            source_ip=source_ip,
            destination_ip=template["destination_ip"],
            source_port=None,
            destination_port=template["destination_port"],
            protocol=template["protocol"],
            rule_name=template["rule_name"],
            severity=template["severity"],
            confidence=template["confidence"],
            packet_count=template["packet_count"],
            evidence={
                "demo": True,
                "rule": template["rule_name"],
                "simulated": True,
            },
        )

    # ------------------------------------------------------------------
    # Whitelist helpers (in-memory only, no DB writes)
    # ------------------------------------------------------------------

    def _add_to_whitelist(self) -> None:
        """Add all TEST-NET host IPs to whitelist_manager._ip_set (no DB write)."""
        if self._whitelist_manager is None:
            return
        try:
            with self._whitelist_manager._lock:
                self._whitelist_manager._ip_set.update(_TEST_NET_IPS)
            logger.debug("DemoService: added %d TEST-NET IPs to whitelist.", len(_TEST_NET_IPS))
        except Exception as exc:
            logger.warning("DemoService: could not update whitelist: %s", exc)

    def _remove_from_whitelist(self) -> None:
        """Remove TEST-NET host IPs from whitelist_manager._ip_set on stop."""
        if self._whitelist_manager is None:
            return
        try:
            with self._whitelist_manager._lock:
                self._whitelist_manager._ip_set.difference_update(_TEST_NET_IPS)
            logger.debug("DemoService: removed TEST-NET IPs from whitelist.")
        except Exception as exc:
            logger.warning("DemoService: could not clean whitelist: %s", exc)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
