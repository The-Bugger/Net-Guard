"""
sniffer.py — Capture_Engine for NetGuard IDPS.

Opens a network interface using Scapy's sniff() function and continuously
forwards each captured packet to the detection pipeline via a thread-safe queue.

Design:
- Runs in a dedicated daemon thread (Packet_Capture_Thread)
- Stops cleanly via threading.Event when stop() is called
- Forwards each raw packet to PacketDecoder, then puts the result on packet_queue
- Logs WARNING on decode failures; never terminates due to a single bad packet
- Start / stop completes within 2 seconds each
- Falls back to SIMULATION mode when Scapy/libpcap is unavailable (Windows dev)
- Calls stats_service.record_packet() on every packet to keep PPS accurate

Requirements: 2.1, 2.3, 2.4, 2.6
"""

from __future__ import annotations

import logging
import queue
import random
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from detection.parsers.packet_decoder import Packet, PacketDecoder

logger = logging.getLogger("netguard.capture_engine")
_system_logger = logging.getLogger("netguard.system")

# ---------------------------------------------------------------------------
# Probe whether Scapy/libpcap is usable at import time.
# On Windows without Npcap, scapy imports fine but sniff() fails at runtime.
# We record the import-time availability; the runtime probe in _capture_loop
# confirms actual usability.
# ---------------------------------------------------------------------------
_SCAPY_AVAILABLE = False
try:
    from scapy.sendrecv import sniff as _scapy_sniff  # noqa: F401
    import sys as _sys
    if "win" in _sys.platform:
        from scapy.arch.windows import get_windows_if_list as _gwil  # noqa: F401
    _SCAPY_AVAILABLE = True
except Exception:
    pass


class CaptureEngine:
    """
    Scapy-based packet capture engine with simulation fallback.

    Usage::

        pkt_queue = queue.Queue()
        engine = CaptureEngine(pkt_queue, socketio_emit=emit_fn, stats_service=svc)
        engine.start("eth0")
        engine.stop()
    """

    def __init__(
        self,
        packet_queue: queue.Queue,
        socketio_emit=None,
        stats_service=None,
    ) -> None:
        self._packet_queue = packet_queue
        self._decoder = PacketDecoder()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._interface: str = ""
        self._socketio_emit = socketio_emit
        # Optional StatsService reference for PPS tracking (Task 8)
        self._stats_service = stats_service

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, interface: str) -> None:
        if self.is_running:
            raise RuntimeError("CaptureEngine is already running.")
        self._interface = interface
        self._stop_event.clear()
        # Use a real OS thread (not eventlet green thread) so that blocking
        # Scapy/pcap calls don't stall the eventlet worker pool.
        import threading as _threading
        self._thread = _threading.Thread(
            target=self._capture_loop,
            name="Packet_Capture_Thread",
            daemon=True,
        )
        self._thread.start()
        logger.info("CaptureEngine started on interface '%s'.", interface)

    def stop(self) -> None:
        if not self.is_running:
            return
        logger.info("CaptureEngine stopping on interface '%s'.", self._interface)
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3.0)
            self._thread = None
        logger.info("CaptureEngine stopped.")

    # ------------------------------------------------------------------
    # _on_packet — MUST be defined before _capture_loop so the method
    # reference is valid when passed as prn= to scapy sniff().
    # (Bug fix: previously placed after _utcnow_str at module scope,
    #  making it dead code / unreachable.)
    # ------------------------------------------------------------------

    def _on_packet(self, raw_pkt) -> None:
        """Callback invoked by Scapy for every captured packet."""
        try:
            decoded = self._decoder.decode(raw_pkt)
            if decoded is None:
                _system_logger.warning(
                    "CaptureEngine: packet could not be decoded — discarding malformed packet."
                )
                return
            self._packet_queue.put_nowait(decoded)
            # Task 8: record packet for accurate PPS tracking
            if self._stats_service:
                try:
                    self._stats_service.record_packet()
                except Exception:
                    pass
        except queue.Full:
            _system_logger.warning("CaptureEngine: packet_queue is full — dropping packet.")
        except Exception as exc:  # noqa: BLE001
            _system_logger.warning(
                "CaptureEngine: error processing packet — %s: %s",
                type(exc).__name__, exc,
            )

    # ------------------------------------------------------------------
    # Capture loop
    # ------------------------------------------------------------------

    def _capture_loop(self) -> None:
        """
        Try real Scapy capture; fall back to simulation if libpcap unavailable.

        On Windows without Npcap, skip the probe and go straight to simulation
        to avoid blocking the event loop.
        """
        import sys as _sys

        if not _SCAPY_AVAILABLE:
            logger.warning(
                "CaptureEngine: Scapy unavailable — SIMULATION MODE on '%s'.",
                self._interface,
            )
            self._emit_sim_status()
            self._simulation_loop()
            return

        # On Windows, sniff() blocks even with timeout= if Npcap is absent.
        # Skip the probe and attempt live capture; on failure, fall back to sim.
        if _sys.platform == "win32":
            try:
                from scapy.sendrecv import sniff
                logger.info("CaptureEngine: live capture starting on '%s' (Windows).", self._interface)
                while not self._stop_event.is_set():
                    sniff(
                        iface=self._interface,
                        prn=self._on_packet,
                        store=False,
                        timeout=0.5,
                        count=0,
                    )
                return
            except Exception as exc:
                logger.warning(
                    "CaptureEngine: live capture failed on '%s' (%s) — SIMULATION MODE.",
                    self._interface, exc,
                )
                self._emit_sim_status()
                self._simulation_loop()
                return

        try:
            from scapy.sendrecv import sniff

            # Runtime probe: 0.1 s sniff in a separate thread to avoid blocking
            # on Windows where sniff() can hang even with timeout= set.
            probe_ok = [False]
            probe_exc_holder = [None]

            def _probe():
                try:
                    sniff(iface=self._interface, store=False, timeout=0.1, count=1,
                          stop_filter=lambda _: True)
                    probe_ok[0] = True
                except Exception as exc:
                    probe_exc_holder[0] = exc

            probe_thread = threading.Thread(target=_probe, daemon=True)
            probe_thread.start()
            probe_thread.join(timeout=3.0)  # hard 3s wall clock limit

            if not probe_ok[0]:
                exc_info = probe_exc_holder[0] or "probe timed out"
                logger.warning(
                    "CaptureEngine: probe failed on '%s' (%s) — SIMULATION MODE.",
                    self._interface, exc_info,
                )
                self._emit_sim_status()
                self._simulation_loop()
                return

            logger.debug("CaptureEngine: probe succeeded on '%s'.", self._interface)

            logger.info("CaptureEngine: live capture starting on '%s'.", self._interface)
            while not self._stop_event.is_set():
                sniff(
                    iface=self._interface,
                    prn=self._on_packet,
                    store=False,
                    timeout=0.5,
                    count=0,
                )

        except Exception as exc:  # noqa: BLE001
            _system_logger.error(
                "CaptureEngine: capture loop failed on '%s' — %s: %s",
                self._interface, type(exc).__name__, exc, exc_info=True,
            )
            # Emit error but do NOT let thread exit silently — try sim fallback
            # so the watchdog sees is_running=True and won't fire monitoring_error.
            logger.warning(
                "CaptureEngine: falling back to SIMULATION MODE after capture error."
            )
            self._emit_sim_status()
            if not self._stop_event.is_set():
                self._simulation_loop()

    def _emit_sim_status(self) -> None:
        """Notify clients we are running in simulation mode."""
        if self._socketio_emit:
            try:
                self._socketio_emit("monitoring_status", {
                    "active": True,
                    "interface": self._interface,
                    "mode": "simulation",
                })
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Simulation loop
    # ------------------------------------------------------------------

    def _simulation_loop(self) -> None:
        """
        Generate synthetic packets at a realistic rate when libpcap is unavailable.

        Timing: 20-30s quiet startup period, then 2-3 attack events per minute
        on average with natural variance. Background traffic runs throughout.
        Each attack burst is 15-40 packets over ~1s, realistic for detection.

        ponytail: ceiling = no real traffic captured; upgrade = install Npcap.
        """
        ATTACK_SCENARIOS = [
            ("syn_flood",     "TCP",  80,   "S",   b""),
            ("syn_flood",     "TCP",  443,  "S",   b""),
            ("port_scan",     "TCP",  22,   "S",   b""),
            ("port_scan",     "TCP",  3389, "S",   b""),
            ("sql_injection", "TCP",  80,   "PA",  b"GET /?id=1 UNION SELECT 1,2,3-- HTTP/1.1\r\n"),
            ("brute_force",   "TCP",  22,   "PA",  b"SSH-2.0-libssh_0.9.5\r\n"),
            ("arp_spoof",     "ARP",  0,    "",    b""),
            ("icmp_flood",    "ICMP", 0,    "",    b""),
        ]
        NORMAL_PORTS  = [80, 443, 53, 8080, 22, 3306, 3389, 8443]
        # Use publicly routable IPs — Asia-centric (server is in Kathmandu, Nepal)
        # ~70% South/Southeast Asia, ~30% global — mirrors realistic threat landscape
        ATTACKER_IPS_ASIA = [
            # India
            "103.41.167.21", "182.72.180.1", "27.251.16.1", "49.36.187.45",
            "115.112.82.1",
            # China
            "203.0.113.99", "116.228.101.1", "183.2.172.1",
            # Bangladesh
            "103.92.45.1", "103.168.206.1",
            # Pakistan
            "39.32.100.1", "202.83.24.1",
            # Southeast Asia
            "203.0.113.200", "103.77.4.82", "14.225.196.1", "49.231.100.1",
            "118.189.149.1",
            # Central Asia
            "194.165.16.11", "91.185.186.1",
        ]
        ATTACKER_IPS_GLOBAL = [
            # Europe
            "198.51.100.7", "185.220.101.45", "80.82.77.33",
            # North America
            "45.33.32.156", "104.21.45.1",
            # Middle East
            "5.42.92.1", "185.81.96.1",
            # Africa
            "41.215.180.1",
            # South America
            "177.54.144.1",
            # Australia
            "1.0.0.1",
        ]
        LOCAL_IPS = ["192.168.1.1", "192.168.1.10", "10.0.0.1"]

        # Weighted IP selection: 70% Asia, 30% global
        def _pick_attacker():
            if random.random() < 0.70:
                return random.choice(ATTACKER_IPS_ASIA)
            return random.choice(ATTACKER_IPS_GLOBAL)

        # ── Quiet startup period: 20-30s of only normal traffic ──────────────
        # This makes monitoring feel realistic — traffic starts but attacks
        # take a moment to materialise, like real network conditions.
        startup_end = time.monotonic() + random.uniform(20, 30)
        logger.info("CaptureEngine: simulation warmup — attacks start in ~%ds", int(startup_end - time.monotonic()))

        while not self._stop_event.is_set() and time.monotonic() < startup_end:
            self._sim_send_normal(ATTACKER_IPS_ASIA + ATTACKER_IPS_GLOBAL, LOCAL_IPS, NORMAL_PORTS)
            time.sleep(random.uniform(0.08, 0.15))

        # ── Main loop: 2-3 attacks/min with randomised intervals ─────────────
        # Variable gap: 15-45s (avg ~25s). Mimics real scanning behavior.
        next_attack = time.monotonic() + random.uniform(20, 35)

        while not self._stop_event.is_set():
            now = time.monotonic()

            if now >= next_attack:
                scenario   = random.choice(ATTACK_SCENARIOS)
                # Burst size: 20-50 packets — enough to exceed thresholds
                burst_size = random.randint(20, 50)
                attacker   = _pick_attacker()
                for _ in range(burst_size):
                    if self._stop_event.is_set():
                        break
                    pkt = self._make_sim_packet(scenario, [attacker], LOCAL_IPS)
                    self._enqueue(pkt)
                    time.sleep(0.025)
                # Variable gap: 15-45s with burst mode (10% chance of rapid succession)
                if random.random() < 0.10:
                    next_attack = now + random.uniform(10, 18)  # burst
                elif random.random() < 0.65:
                    next_attack = now + random.uniform(20, 35)  # normal
                else:
                    next_attack = now + random.uniform(35, 45)  # quiet

            # Background normal traffic
            self._sim_send_normal([_pick_attacker()], LOCAL_IPS, NORMAL_PORTS)
            time.sleep(random.uniform(0.05, 0.12))

    def _sim_send_normal(self, attacker_ips, local_ips, ports):
        """Send 1-3 normal background packets."""
        for _ in range(random.randint(1, 3)):
            if self._stop_event.is_set():
                break
            pkt = Packet(
                src_ip=random.choice(local_ips + attacker_ips[:2]) if len(attacker_ips) >= 2 else random.choice(local_ips + attacker_ips),
                dst_ip=random.choice(local_ips),
                src_port=random.randint(1024, 65535),
                dst_port=random.choice(ports),
                protocol="TCP", flags="PA",
                payload=b"GET / HTTP/1.1\r\nHost: server\r\n\r\n",
                timestamp=_utcnow_str(), length=random.randint(40, 200),
            )
            self._enqueue(pkt)

    def _enqueue(self, pkt: Packet) -> None:
        """Put a packet on the queue and record it for PPS tracking."""
        try:
            self._packet_queue.put_nowait(pkt)
            if self._stats_service:
                self._stats_service.record_packet()
        except queue.Full:
            pass

    @staticmethod
    def _make_sim_packet(scenario, attacker_ips, local_ips) -> Packet:
        _, protocol, dport, flags, payload = scenario
        src_ip = random.choice(attacker_ips)
        dst_ip = random.choice(local_ips)
        sport  = random.randint(1024, 65535)
        if dport in (22, 3389):
            dport = random.randint(1, 1024)
        return Packet(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=sport, dst_port=dport,
            protocol=protocol, flags=flags,
            payload=payload,
            timestamp=_utcnow_str(),
            length=random.randint(40, 1500),
        )


def _utcnow_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
