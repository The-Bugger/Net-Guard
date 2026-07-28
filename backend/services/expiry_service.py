"""
expiry_service.py — Block Expiry Thread for NetGuard IDPS.

Polls the blocked_ips table every 5 seconds and removes expired iptables rules,
setting the active flag to False in the database.

Requirements: 11.3
"""

from __future__ import annotations

import logging
import shlex
import subprocess
import threading
import time
from typing import Optional

logger = logging.getLogger("netguard.expiry_service")


class ExpiryThread:
    """
    Background daemon thread that expires IP blocks automatically.

    Polls the blocked_ips table on a 5-second interval and removes
    iptables DROP rules when expires_at has passed.

    Usage::

        expiry = ExpiryThread(block_repo, log_engine=log_engine)
        expiry.start()
        # ... monitoring ...
        expiry.stop()
    """

    POLL_INTERVAL: int = 5  # seconds

    def __init__(
        self,
        block_repo,
        log_engine=None,
        socketio_emit=None,
    ) -> None:
        """
        Args:
            block_repo: BlockRepository instance.
            log_engine: LoggingEngine instance (optional).
            socketio_emit: Callable(event_name, data) for SocketIO notifications.
        """
        self._block_repo = block_repo
        self._log_engine = log_engine
        self._socketio_emit = socketio_emit

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the expiry daemon thread."""
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._expiry_loop,
            name="Expiry_Thread",
            daemon=True,
        )
        self._thread.start()
        logger.info("ExpiryThread started (poll interval=%ds).", self.POLL_INTERVAL)

    def stop(self) -> None:
        """Signal the expiry thread to stop and wait for it."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10.0)
        logger.info("ExpiryThread stopped.")

    # ------------------------------------------------------------------
    # Expiry loop
    # ------------------------------------------------------------------

    def _expiry_loop(self) -> None:
        """Poll for expired blocks and remove them."""
        logger.debug("Expiry_Thread: started.")
        while not self._stop_event.is_set():
            try:
                self._process_expired_blocks()
            except Exception as exc:
                logger.error("ExpiryThread: unexpected error — %s", exc, exc_info=True)

            self._stop_event.wait(timeout=self.POLL_INTERVAL)

        logger.debug("Expiry_Thread: stopped.")

    def _process_expired_blocks(self) -> None:
        """Find and expire all blocks whose expires_at has passed."""
        try:
            expired = self._block_repo.get_expired()
        except Exception as exc:
            logger.error("ExpiryThread: failed to query expired blocks: %s", exc)
            return

        for block in expired:
            ip = block["ip_address"]
            logger.info("ExpiryThread: expiring block for %s.", ip)

            # Remove iptables rule
            cmd = f"iptables -D INPUT -s {shlex.quote(ip)} -j DROP"
            self._run_iptables(cmd, ip)

            # Mark inactive in database
            try:
                self._block_repo.set_inactive(ip)
            except Exception as exc:
                logger.error(
                    "ExpiryThread: failed to mark %s inactive in DB: %s", ip, exc
                )

            # Log the unblock
            if self._log_engine:
                try:
                    self._log_engine.log_unblock(ip, reason="expired")
                except Exception:
                    pass

            # SocketIO notification
            if self._socketio_emit:
                try:
                    self._socketio_emit("ip_unblocked", {"ip": ip, "reason": "expired"})
                except Exception:
                    pass

    def _run_iptables(self, cmd: str, ip: str) -> bool:
        """Execute an iptables command. Failures are logged but not fatal."""
        try:
            result = subprocess.run(
                shlex.split(cmd),
                capture_output=True,
                timeout=5,
            )
            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace").strip()
                logger.warning(
                    "ExpiryThread: iptables -D for %s returned rc=%d: %s",
                    ip, result.returncode, stderr,
                )
                return False
            return True
        except Exception as exc:
            logger.error("ExpiryThread: iptables error for %s: %s", ip, exc)
            return False
