"""
attack_lab_service.py — Interactive attack simulation manager.

Each session runs in a daemon thread pushing synthetic packets into packet_queue.
Uses ThreatSimulator for attacker profiles.

Requirements: 3.1-3.9
"""

from __future__ import annotations

import logging
import queue
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("netguard.attack_lab_service")

_MAX_CONCURRENCY = 10

ATTACK_TYPES: list[str] = [
    "Port Scan",
    "SYN Flood",
    "UDP Flood",
    "ICMP Flood",
    "SQL Injection",
    "Brute Force",
    "XSS",
    "Directory Traversal",
    "DNS Amplification",
    "HTTP Flood",
    "SSH Attack",
    "FTP Attack",
    "Ransomware Behaviour",
    "Malware Beacon",
    "Lateral Movement",
    "Privilege Escalation",
    "Data Exfiltration",
]

_MITRE_MAP: dict[str, dict] = {
    "Port Scan":         {"tactic": "Reconnaissance", "technique": "T1595"},
    "SYN Flood":         {"tactic": "Impact", "technique": "T1499"},
    "UDP Flood":         {"tactic": "Impact", "technique": "T1499"},
    "ICMP Flood":        {"tactic": "Impact", "technique": "T1499"},
    "SQL Injection":     {"tactic": "Initial Access", "technique": "T1190"},
    "Brute Force":       {"tactic": "Credential Access", "technique": "T1110"},
    "XSS":               {"tactic": "Initial Access", "technique": "T1190"},
    "Directory Traversal": {"tactic": "Discovery", "technique": "T1083"},
    "DNS Amplification": {"tactic": "Impact", "technique": "T1498"},
    "HTTP Flood":        {"tactic": "Impact", "technique": "T1499"},
    "SSH Attack":        {"tactic": "Lateral Movement", "technique": "T1021.004"},
    "FTP Attack":        {"tactic": "Lateral Movement", "technique": "T1021"},
    "Ransomware Behaviour": {"tactic": "Impact", "technique": "T1486"},
    "Malware Beacon":    {"tactic": "Command and Control", "technique": "T1071"},
    "Lateral Movement":  {"tactic": "Lateral Movement", "technique": "T1021"},
    "Privilege Escalation": {"tactic": "Privilege Escalation", "technique": "T1068"},
    "Data Exfiltration": {"tactic": "Exfiltration", "technique": "T1041"},
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AttackLabService:
    """Manages simulated attack sessions for the Attack Lab."""

    def __init__(self, packet_queue, threat_simulator=None) -> None:
        self._packet_queue = packet_queue
        self._simulator = threat_simulator
        self._sessions: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._semaphore = threading.Semaphore(_MAX_CONCURRENCY)

    # ------------------------------------------------------------------
    # Class-level attack type list (Req 3.2)
    # ------------------------------------------------------------------

    @classmethod
    def get_attack_types(cls) -> list[dict]:
        return [
            {
                "name": at,
                "mitre_tactic": _MITRE_MAP.get(at, {}).get("tactic", ""),
                "mitre_technique": _MITRE_MAP.get(at, {}).get("technique", ""),
            }
            for at in ATTACK_TYPES
        ]

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def launch(self, config: dict, operator: str = "manual") -> str:
        """
        Launch a simulation session (Req 3.4, 3.9).
        Raises ValueError on concurrency limit exceeded.
        Returns session_id.
        """
        attack_type = config.get("attack_type", "Port Scan")
        if attack_type not in ATTACK_TYPES:
            raise ValueError(f"Unknown attack type: {attack_type}")

        if not self._semaphore.acquire(blocking=False):
            raise ValueError(f"CONCURRENCY_LIMIT: max {_MAX_CONCURRENCY} concurrent sessions")

        session_id = str(uuid.uuid4())
        mitre = _MITRE_MAP.get(attack_type, {})
        session = {
            "session_id": session_id,
            "attack_type": attack_type,
            "config": config,
            "operator": operator,
            "status": "PENDING",
            "started_at": _utc_now(),
            "elapsed_s": 0,
            "packets_sent": 0,
            "detection_status": "PENDING",
            "detection_latency_ms": None,
            "mitre_tactic": mitre.get("tactic", ""),
            "mitre_technique": mitre.get("technique", ""),
            "_stop": threading.Event(),
        }
        with self._lock:
            self._sessions[session_id] = session

        t = threading.Thread(
            target=self._run_session,
            args=(session_id,),
            name=f"AttackSim-{session_id[:8]}",
            daemon=True,
        )
        t.start()
        return session_id

    def cancel(self, session_id: str) -> bool:
        """Stop a running session within ~1 second (Req 3.8)."""
        with self._lock:
            session = self._sessions.get(session_id)
        if not session:
            return False
        session["_stop"].set()
        session["detection_status"] = "CANCELLED"
        session["status"] = "CANCELLED"
        return True

    def status(self, session_id: str) -> Optional[dict]:
        with self._lock:
            s = self._sessions.get(session_id)
        if not s:
            return None
        return {k: v for k, v in s.items() if not k.startswith("_")}

    def list_active(self) -> list[dict]:
        with self._lock:
            return [
                {k: v for k, v in s.items() if not k.startswith("_")}
                for s in self._sessions.values()
                if s["status"] in ("PENDING", "RUNNING")
            ]

    # ------------------------------------------------------------------
    # Session runner
    # ------------------------------------------------------------------

    def _run_session(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions[session_id]
        try:
            session["status"] = "RUNNING"
            config = session["config"]
            pps = max(1, min(int(config.get("pps", 100)), 100_000))
            duration = max(1, min(int(config.get("duration", 30)), 3600))
            concurrency = max(1, min(int(config.get("concurrent_attackers", 1)), 100))

            profiles = []
            if self._simulator:
                profiles = self._simulator.generate_session(count=concurrency)
            if not profiles:
                profiles = [{"ip": f"10.{i}.0.1", "source_category": None} for i in range(concurrency)]

            start = time.monotonic()
            detect_start = start
            attack_type = session["attack_type"]
            stop_event = session["_stop"]

            delay = 1.0 / max(pps, 1)
            packets_sent = 0

            while not stop_event.is_set():
                elapsed = time.monotonic() - start
                if elapsed >= duration:
                    break
                session["elapsed_s"] = round(elapsed, 1)

                # Synthesise a minimal packet dict and push to queue
                profile = profiles[packets_sent % len(profiles)]
                self._push_synthetic_packet(profile, attack_type)
                packets_sent += 1
                session["packets_sent"] = packets_sent
                time.sleep(max(0, delay))

            session["status"] = "DONE"
            session["elapsed_s"] = round(time.monotonic() - start, 1)
            if session["detection_status"] == "PENDING":
                session["detection_status"] = "MISSED"
            if session["detection_latency_ms"] is None:
                session["detection_latency_ms"] = round((time.monotonic() - detect_start) * 1000)

        except Exception as exc:
            logger.error("AttackLabService session %s failed: %s", session_id, exc, exc_info=True)
            session["status"] = "FAILED"
        finally:
            self._semaphore.release()

    def _push_synthetic_packet(self, profile: dict, attack_type: str) -> None:
        """Push a lightweight synthetic 'packet' dict into the packet_queue."""
        pkt = {
            "src_ip": profile.get("ip", "1.2.3.4"),
            "attack_type": attack_type,
            "synthetic": True,
        }
        try:
            self._packet_queue.put_nowait(pkt)
        except queue.Full:
            pass  # drop if queue full

    def mark_detected(self, session_id: str, latency_ms: float) -> None:
        """Called by detection engine when a simulated attack is detected."""
        with self._lock:
            session = self._sessions.get(session_id)
        if session and session["detection_status"] == "PENDING":
            session["detection_status"] = "DETECTED"
            session["detection_latency_ms"] = round(latency_ms)
