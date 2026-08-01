"""
prevention_service.py — Prevention_Engine for NetGuard IDPS.

Automatically blocks confirmed attackers via iptables. Checks the whitelist
before issuing any block. Handles duplicate blocks by extending expiry.
Verifies iptables privileges at startup.

Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 11.1, 11.2, 11.4, 11.5, 11.6, 11.7, 11.8
"""

from __future__ import annotations

import ipaddress
import logging
import shlex
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Optional

import psutil

from detection.rules.base_rule import Explanation, ThreatEvent

logger = logging.getLogger("netguard.prevention_engine")

# iptables command templates
_IPTABLES_BLOCK = "iptables -I INPUT -s {ip} -j DROP"
_IPTABLES_UNBLOCK = "iptables -D INPUT -s {ip} -j DROP"
_IPTABLES_CHECK = "iptables -L INPUT -n"

# Private, loopback, link-local, and multicast ranges that must never be blocked.
# ponytail: stdlib ipaddress only — no new dependency needed.
_PRIVATE_NETS: list = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]


def _is_private(ip: str) -> tuple:
    """Return (True, range_name) if ip falls in a protected range, else (False, '')."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, ""
    for net in _PRIVATE_NETS:
        if addr in net:
            return True, str(net)
    return False, ""


def _is_own_address(ip: str) -> bool:
    """Return True if ip matches any address assigned to this host's network interfaces."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    try:
        for iface_addrs in psutil.net_if_addrs().values():
            for snic in iface_addrs:
                try:
                    if ipaddress.ip_address(snic.address) == addr:
                        return True
                except ValueError:
                    continue
    except Exception:
        pass
    return False


class PreventionEngine:
    """
    Blocks and unblocks IP addresses via iptables.

    Must be started with root/sudo privileges for iptables operations.

    Usage::

        engine = PreventionEngine(block_repo, whitelist_manager, log_engine)
        engine.verify_privileges()   # call at startup
        engine.handle_event(threat_event, explanation)
    """

    def __init__(
        self,
        block_repo,
        whitelist_manager,
        log_engine=None,
        block_duration: int = 120,
        socketio_emit=None,
    ) -> None:
        """
        Args:
            block_repo: BlockRepository instance.
            whitelist_manager: WhitelistManager instance.
            log_engine: LoggingEngine instance (optional).
            block_duration: Default block duration in seconds.
            socketio_emit: Callable(event_name, data) for SocketIO notifications.
        """
        self._block_repo = block_repo
        self._whitelist_manager = whitelist_manager
        self._log_engine = log_engine
        self._block_duration = block_duration
        self._socketio_emit = socketio_emit

    # ------------------------------------------------------------------
    # Startup check
    # ------------------------------------------------------------------

    def verify_privileges(self) -> None:
        """
        Verify that iptables commands can be executed.

        Raises:
            RuntimeError: If the process lacks iptables privileges.
        """
        ok = self._run_iptables(_IPTABLES_CHECK)
        if not ok:
            msg = (
                "PreventionEngine: insufficient privileges to execute iptables. "
                "Run NetGuard with sudo or grant CAP_NET_ADMIN."
            )
            logger.critical(msg)
            raise RuntimeError(msg)
        logger.info("PreventionEngine: iptables privilege check passed.")

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------

    def handle_event(self, event: ThreatEvent, explanation: Explanation) -> None:
        """
        Process a confirmed ThreatEvent and block the attacker if not whitelisted.

        Args:
            event: The ThreatEvent from the Detection_Engine.
            explanation: The Explanation from the Explainability_Engine.
        """
        ip = event.source_ip

        # Check whitelist first (Requirement 11.1, 12.7)
        if self._whitelist_manager and self._whitelist_manager.is_whitelisted(ip):
            logger.info(
                "PreventionEngine: %s is whitelisted — no block applied.", ip
            )
            return

        self.block_ip(ip, event.attack_type, event.event_id)

    def block_ip(self, ip: str, reason: str, event_id: str, *, allow_private_block: bool = False) -> bool:
        """
        Block an IP address via iptables and record the block in the database.

        Handles duplicate blocks by extending expiry (Requirement 11.6).

        Args:
            ip: IPv4 or IPv6 address to block.
            reason: Attack type that triggered the block.
            event_id: Originating ThreatEvent ID.

        Returns:
            True if block was applied (new or extended), False on failure.
        """
        # Private-IP safety guard — Requirement 3.1–3.5
        if not allow_private_block:
            private, range_name = _is_private(ip)
            if private:
                logger.warning(
                    "PreventionEngine: refusing to block private/special IP %s — reason: %s",
                    ip, range_name,
                )
                return False
            if _is_own_address(ip):
                logger.warning(
                    "PreventionEngine: refusing to block own interface address %s", ip
                )
                return False

        now = _utc_now()
        expires_at = _utc_future(self._block_duration)

        # Check for existing active block (Requirement 11.6)
        existing = self._block_repo.get_active(ip)
        if existing:
            logger.info(
                "PreventionEngine: extending existing block for %s (was %s).",
                ip, existing["expires_at"],
            )
            self._block_repo.extend_expiry(ip, expires_at)
            self._log_block(ip, reason, self._block_duration)
            return True

        # Issue new iptables rule
        cmd = _IPTABLES_BLOCK.format(ip=shlex.quote(ip))
        success = self._run_iptables(cmd)

        if not success:
            logger.error(
                "PreventionEngine: iptables block FAILED for %s — continuing.", ip
            )
            return False

        # Record in database
        record_data = {
            "event_id": event_id,
            "ip_address": ip,
            "blocked_at": now,
            "expires_at": expires_at,
            "reason": reason,
        }
        self._block_repo.insert(record_data)
        self._log_block(ip, reason, self._block_duration)

        # SocketIO notification
        if self._socketio_emit:
            try:
                self._socketio_emit("ip_blocked", {
                    "ip": ip,
                    "reason": reason,
                    "blocked_at": now,
                    "expires_at": expires_at,
                })
            except Exception as exc:
                logger.warning("PreventionEngine: SocketIO emit failed: %s", exc)

        logger.info(
            "PreventionEngine: blocked %s for %ds — reason: %s",
            ip, self._block_duration, reason,
        )
        return True

    def unblock_ip(self, ip: str) -> bool:
        """
        Remove the iptables DROP rule for an IP and mark the block inactive.

        Args:
            ip: IPv4 or IPv6 address to unblock.

        Returns:
            True if unblocked successfully.
        """
        cmd = _IPTABLES_UNBLOCK.format(ip=shlex.quote(ip))
        success = self._run_iptables(cmd)

        if not success:
            logger.error(
                "PreventionEngine: iptables unblock FAILED for %s.", ip
            )
            # Still mark DB inactive so UI reflects change
            self._block_repo.set_inactive(ip)
            return False

        self._block_repo.set_inactive(ip)

        if self._log_engine:
            try:
                self._log_engine.log_unblock(ip, reason="manual")
            except Exception:
                pass

        if self._socketio_emit:
            try:
                self._socketio_emit("ip_unblocked", {"ip": ip})
            except Exception:
                pass

        logger.info("PreventionEngine: unblocked %s (manual).", ip)
        return True

    def set_block_duration(self, duration: int) -> None:
        """Update the block duration from configuration."""
        self._block_duration = max(1, min(3600, duration))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _run_iptables(self, cmd: str) -> bool:
        """
        Execute an iptables command via subprocess.

        Args:
            cmd: The complete iptables command string.

        Returns:
            True if the command exited with code 0, False otherwise.
        """
        try:
            result = subprocess.run(
                shlex.split(cmd),
                capture_output=True,
                timeout=5,
            )
            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace").strip()
                logger.error(
                    "PreventionEngine: iptables command failed (rc=%d): %s — stderr: %s",
                    result.returncode, cmd, stderr,
                )
                return False
            return True
        except FileNotFoundError:
            logger.error(
                "PreventionEngine: iptables not found. Is it installed and in PATH?"
            )
            return False
        except subprocess.TimeoutExpired:
            logger.error(
                "PreventionEngine: iptables command timed out: %s", cmd
            )
            return False
        except Exception as exc:
            logger.error(
                "PreventionEngine: unexpected error running iptables: %s — %s",
                cmd, exc,
            )
            return False

    def _log_block(self, ip: str, reason: str, duration: int) -> None:
        if self._log_engine:
            try:
                self._log_engine.log_block(ip, reason, duration)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_future(seconds: int) -> str:
    dt = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
