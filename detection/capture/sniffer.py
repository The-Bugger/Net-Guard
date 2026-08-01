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

Requirements: 2.1, 2.3, 2.4, 2.6
"""

from __future__ import annotations

import logging
import queue
import threading
from typing import Optional

from detection.parsers.packet_decoder import Packet, PacketDecoder

logger = logging.getLogger("netguard.capture_engine")


class CaptureEngine:
    """
    Scapy-based packet capture engine.

    Captures packets on a selected network interface and forwards
    normalised Packet objects into a thread-safe queue consumed by
    the Detection_Thread.

    Usage::

        pkt_queue = queue.Queue()
        engine = CaptureEngine(pkt_queue)
        engine.start("eth0")
        # ... monitoring ...
        engine.stop()
    """

    def __init__(self, packet_queue: queue.Queue) -> None:
        """
        Args:
            packet_queue: Thread-safe queue where decoded Packet objects are placed.
        """
        self._packet_queue = packet_queue
        self._decoder = PacketDecoder()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._interface: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """True if the capture thread is currently active."""
        return self._thread is not None and self._thread.is_alive()

    def start(self, interface: str) -> None:
        """
        Begin capturing packets on *interface*.

        Must complete within 2 seconds (Requirement 2.1).

        Args:
            interface: Name of the OS network interface (e.g. "eth0", "wlan0").

        Raises:
            RuntimeError: If capture is already active.
        """
        if self.is_running:
            raise RuntimeError("CaptureEngine is already running.")

        self._interface = interface
        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._capture_loop,
            name="Packet_Capture_Thread",
            daemon=True,
        )
        self._thread.start()
        logger.info("CaptureEngine started on interface '%s'.", interface)

    def stop(self) -> None:
        """
        Signal the capture thread to stop and wait up to 3 seconds for it to exit.

        Must complete within 2 seconds under normal conditions (Requirement 2.6).
        """
        if not self.is_running:
            return

        logger.info("CaptureEngine stopping on interface '%s'.", self._interface)
        self._stop_event.set()

        if self._thread:
            self._thread.join(timeout=3.0)
            self._thread = None

        logger.info("CaptureEngine stopped.")

    # ------------------------------------------------------------------
    # Capture loop (runs in Packet_Capture_Thread)
    # ------------------------------------------------------------------

    def _capture_loop(self) -> None:
        """
        Main capture loop — runs Scapy sniff() with a periodic stop check.

        Uses store=False to avoid memory accumulation and prn callback to
        process each packet immediately.
        """
        try:
            from scapy.sendrecv import sniff

            logger.debug(
                "Packet_Capture_Thread: sniff starting on '%s'.", self._interface
            )

            # sniff in short bursts so the stop_event is checked frequently
            while not self._stop_event.is_set():
                sniff(
                    iface=self._interface,
                    prn=self._on_packet,
                    store=False,
                    timeout=0.5,  # yield control every 0.5 s to check stop_event
                    count=0,      # 0 = no limit per burst
                )

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Packet_Capture_Thread: unexpected error — %s: %s",
                type(exc).__name__,
                exc,
                exc_info=True,
            )

    def _on_packet(self, raw_pkt) -> None:
        """
        Callback invoked by Scapy for every captured packet.

        Decodes the raw packet and puts it on the queue.  Malformed packets
        are discarded after a WARNING log — capture never terminates.

        Args:
            raw_pkt: Raw Scapy packet.
        """
        try:
            decoded = self._decoder.decode(raw_pkt)
            if decoded is not None:
                self._packet_queue.put_nowait(decoded)
        except queue.Full:
            logger.warning(
                "CaptureEngine: packet_queue is full — dropping packet."
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "CaptureEngine: error processing packet — %s: %s",
                type(exc).__name__,
                exc,
            )
