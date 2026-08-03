"""Prevention engine — blocks confirmed attackers via the platform firewall."""

from __future__ import annotations

import ipaddress
import logging
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Optional

import psutil

from detection.rules.base_rule import Explanation, ThreatEvent

logger = logging.getLogger("netguard.prevention_engine")

# Private, loopback, link-local, and multicast ranges — never blocked.
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
    """Return (True, range_name) if ip is in a protected range, else (False, '')."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, ""
    for net in _PRIVATE_NETS:
        if addr in net:
            return True, str(net)
    return False, ""


def _is_own_address(ip: str) -> bool:
    """Return True if ip matches any address on this host's interfaces."""
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
    Blocks and unblocks IPs via the platform firewall
    (iptables on Linux, netsh advfirewall on Windows).

    Requires elevated privileges. Duplicate blocks extend expiry rather than
    creating a second rule.
    """

    def __init__(
        self,
        block_repo,
        whitelist_manager,
        log_engine=None,
        block_duration: int = 120,
        socketio_emit=None,
    ) -> None:
        self._block_repo = block_repo
        self._whitelist_manager = whitelist_manager
        self._log_engine = log_engine
        self._block_duration = block_duration
        self._socketio_emit = socketio_emit

    def verify_privileges(self) -> None:
        """Raise RuntimeError if the process cannot execute firewall commands."""
        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n"],
                capture_output=True,
                timeout=5,
            )
            ok = result.returncode == 0
        except Exception:
            ok = False
        if not ok:
            msg = (
                "PreventionEngine: insufficient privileges to execute firewall commands. "
                "On Linux run with sudo or grant CAP_NET_ADMIN; "
                "on Windows run as Administrator."
            )
            logger.critical(msg)
            raise RuntimeError(msg)
        logger.info("PreventionEngine: firewall privilege check passed.")

    def _run_iptables(self, cmd: list[str]) -> bool:
        """Run an iptables command, return True on rc=0. Never raises."""
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            if result.returncode != 0:
                logger.error("PreventionEngine: cmd failed (rc=%d) %s", result.returncode, cmd)
                return False
            return True
        except Exception as exc:
            logger.error("PreventionEngine: error running %s — %s", cmd, exc)
            return False

    def handle_event(self, event: ThreatEvent, explanation: Explanation) -> None:
        """Block the attacker IP unless it is whitelisted."""
        ip = event.source_ip
        if self._whitelist_manager and self._whitelist_manager.is_whitelisted(ip):
            logger.info("PreventionEngine: %s is whitelisted — no block applied.", ip)
            return
        self.block_ip(ip, event.attack_type, event.event_id)

    def block_ip(self, ip: str, reason: str, event_id: str, *, allow_private_block: bool = False) -> bool:
        """
        Block an IP and record it in the database.

        Extends expiry if an active block already exists.
        Returns True if block was applied (new or extended), False on failure.
        """
        if not allow_private_block:
            private, range_name = _is_private(ip)
            if private:
                logger.warning("PreventionEngine: refusing to block private/special IP %s — reason: %s", ip, range_name)
                return False
            if _is_own_address(ip):
                logger.warning("PreventionEngine: refusing to block own interface address %s", ip)
                return False

        now = _utc_now()
        expires_at = _utc_future(self._block_duration)

        existing = self._block_repo.get_active(ip)
        if existing:
            logger.info("PreventionEngine: extending existing block for %s (was %s).", ip, existing["expires_at"])
            self._block_repo.extend_expiry(ip, expires_at)
            self._log_block(ip, reason, self._block_duration)
            return True

        if not self._run_iptables(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]):
            logger.error("PreventionEngine: firewall block FAILED for %s — continuing.", ip)
            return False

        self._block_repo.insert({
            "event_id":   event_id,
            "ip_address": ip,
            "blocked_at": now,
            "expires_at": expires_at,
            "reason":     reason,
        })
        self._log_block(ip, reason, self._block_duration)

        if self._socketio_emit:
            try:
                self._socketio_emit("ip_blocked", {"ip": ip, "reason": reason, "blocked_at": now, "expires_at": expires_at})
            except Exception as exc:
                logger.warning("PreventionEngine: SocketIO emit failed: %s", exc)

        logger.info("PreventionEngine: blocked %s for %ds — reason: %s", ip, self._block_duration, reason)
        return True

    def unblock_ip(self, ip: str) -> bool:
        """Remove the firewall rule for an IP and mark the block inactive."""
        success = self._run_iptables(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])

        if not success:
            logger.error("PreventionEngine: firewall unblock FAILED for %s.", ip)
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

    def _log_block(self, ip: str, reason: str, duration: int) -> None:
        if self._log_engine:
            try:
                self._log_engine.log_block(ip, reason, duration)
            except Exception:
                pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_future(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
