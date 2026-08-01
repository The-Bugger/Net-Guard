"""
block_manager.py — Enterprise IP blocking with threat scores, atomicity, and audit.

Complements (does not replace) PreventionEngine. Existing auto-block flow unchanged.

Requirements: 1.1-1.15
"""

from __future__ import annotations

import ipaddress
import logging
import shlex
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger("netguard.block_manager")

_VALID_TYPES = {"ip", "cidr", "country", "asn"}

_IPTABLES_BLOCK   = "iptables -I INPUT -s {target} -j DROP"
_IPTABLES_UNBLOCK = "iptables -D INPUT -s {target} -j DROP"
_IP6TABLES_BLOCK  = "ip6tables -I INPUT -s {target} -j DROP"
_IP6TABLES_UNBLOCK= "ip6tables -D INPUT -s {target} -j DROP"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_future(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_ipv6(target: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(target), ipaddress.IPv6Address)
    except ValueError:
        try:
            return isinstance(ipaddress.ip_network(target, strict=False), ipaddress.IPv6Network)
        except ValueError:
            return False


class BlockManager:
    """Enterprise block manager with threat scores, atomicity, and ip6tables support."""

    def __init__(self, block_repo, whitelist_manager, log_engine, socketio_emit=None) -> None:
        self._block_repo = block_repo
        self._whitelist_manager = whitelist_manager
        self._log_engine = log_engine
        self._emit = socketio_emit or (lambda *a, **kw: None)

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def block(
        self,
        target: str,
        target_type: str = "ip",
        reason: str = "",
        duration: int = 3600,
        operator: str = "system",
        severity: int = 5,
        confidence: int = 50,
    ) -> dict:
        """
        Atomically apply firewall rule then persist DB record.

        On DB failure → rollback firewall rule → return error.
        On firewall failure → never write DB → return error.

        Returns dict with keys: success, block_id, threat_score, error_code.
        """
        if target_type not in _VALID_TYPES:
            return {"success": False, "error_code": "INVALID_BLOCK_TYPE"}

        # Whitelist check (Req 1.7)
        if target_type == "ip" and self._whitelist_manager and self._whitelist_manager.is_whitelisted(target):
            return {"success": False, "error_code": "WHITELISTED_IP"}

        # Duplicate block — extend expiry (Req 1.5)
        if target_type == "ip":
            existing = self._block_repo.get_active(target)
            if existing:
                new_expires = _utc_future(duration)
                self._block_repo.extend_expiry(target, new_expires)
                logger.info("BlockManager: extended expiry for %s → %s", target, new_expires)
                return {"success": True, "block_id": existing["id"], "extended": True,
                        "threat_score": existing.get("threat_score", 0)}

        hit_count = self._block_repo.count_hits(target) if target_type == "ip" else 0
        threat_score = self.compute_threat_score(severity, confidence, hit_count)

        now = _utc_now()
        expires_at = _utc_future(duration)

        # Step 1: apply firewall rule
        fw_ok = self._apply_firewall(target, block=True, target_type=target_type)
        if not fw_ok:
            return {"success": False, "error_code": "FIREWALL_ERROR"}

        # Step 2: persist DB record
        record_data = {
            "event_id": f"manual-{now}",
            "ip_address": target,
            "blocked_at": now,
            "expires_at": expires_at,
            "reason": reason[:1000],
            "block_type": target_type,
            "threat_score": threat_score,
            "operator_id": operator,
        }
        block_id = self._block_repo.insert_enterprise(record_data)
        if block_id is None:
            # Rollback firewall — Req 1.14
            self._apply_firewall(target, block=False, target_type=target_type)
            return {"success": False, "error_code": "DB_ERROR"}

        self._emit("ip_blocked", {
            "ip": target, "block_type": target_type, "reason": reason,
            "blocked_at": now, "expires_at": expires_at,
            "threat_score": threat_score, "operator": operator,
        })
        logger.info("BlockManager: blocked %s (%s) score=%d by %s", target, target_type, threat_score, operator)
        return {"success": True, "block_id": block_id, "threat_score": threat_score}

    def unblock(self, block_id: int, operator: str = "system") -> bool:
        """Remove firewall rule and mark record inactive."""
        record = self._block_repo.get_by_id(block_id)
        if not record:
            return False
        target = record["ip_address"]
        block_type = record.get("block_type", "ip")
        self._apply_firewall(target, block=False, target_type=block_type)
        ok = self._block_repo.set_inactive_by_id(block_id)
        if ok:
            self._emit("ip_unblocked", {"ip": target, "block_id": block_id, "operator": operator})
        return ok

    def restore_on_startup(self) -> None:
        """Re-apply all active DB blocks to firewall on startup (Req 1.2, 1.15)."""
        try:
            active = self._block_repo.get_all_active()
        except Exception as exc:
            logger.critical("BlockManager: DB unavailable during restore — %s", exc)
            self._emit("blocklist_restore_failed", {"error": str(exc)})
            return

        restored = 0
        for record in active:
            target = record["ip_address"]
            block_type = record.get("block_type", "ip")
            if self._apply_firewall(target, block=True, target_type=block_type):
                restored += 1
            else:
                logger.warning("BlockManager: could not restore firewall rule for %s", target)

        logger.info("BlockManager: restored %d/%d block(s) on startup.", restored, len(active))

    def get_history(self, ip: str, page: int = 1, per_page: int = 20) -> dict:
        return self._block_repo.get_history(ip, page, per_page)

    # ------------------------------------------------------------------
    # Static helpers (exposed for property tests)
    # ------------------------------------------------------------------

    @staticmethod
    def compute_threat_score(severity: int, confidence: int, hit_count: int) -> int:
        """
        Threat score formula (Req 1.8):
        min(100, round(severity/10*40 + confidence*0.30 + min(hit_count,100)*0.30))
        """
        return min(100, round(severity / 10 * 40 + confidence * 0.30 + min(hit_count, 100) * 0.30))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _apply_firewall(self, target: str, block: bool, target_type: str = "ip") -> bool:
        """
        Apply or remove iptables/ip6tables rule based on target type.

        - ip/cidr  → iptables -s {target} -j DROP
        - country  → iptables -m geoip --src-cc {code} -j DROP (logs warning if geoip unavailable)
        - asn      → ipset (falls back to warning if ipset unavailable)

        Returns True on success or non-fatal skip (dev environment, unsupported module).
        """
        try:
            if target_type == "country":
                return self._apply_country_rule(target, block)
            if target_type == "asn":
                return self._apply_asn_rule(target, block)
            # ip or cidr — pick ip6tables if IPv6
            if _is_ipv6(target):
                cmd_tmpl = _IP6TABLES_BLOCK if block else _IP6TABLES_UNBLOCK
            else:
                cmd_tmpl = _IPTABLES_BLOCK if block else _IPTABLES_UNBLOCK
            return self._run_cmd(cmd_tmpl.format(target=shlex.quote(target)))
        except Exception as exc:
            logger.error("BlockManager: firewall error: %s", exc)
            return False

    def _apply_country_rule(self, country_code: str, block: bool) -> bool:
        """
        Apply/remove country-level block via iptables geoip match extension.
        Logs a warning and returns True (non-fatal skip) if geoip module unavailable.
        """
        action = "-I" if block else "-D"
        cmd = f"iptables {action} INPUT -m geoip --src-cc {shlex.quote(country_code)} -j DROP"
        try:
            result = subprocess.run(shlex.split(cmd), capture_output=True, timeout=5)
            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace").strip()
                if "geoip" in stderr.lower() or "no match" in stderr.lower():
                    # ponytail: geoip iptables extension not installed — log and skip
                    logger.warning(
                        "BlockManager: iptables geoip module unavailable; "
                        "country block for %s recorded in DB only. "
                        "Install xtables-addons to enforce at firewall level.", country_code
                    )
                    return True  # DB record still created; firewall skip is non-fatal
                logger.error("BlockManager: country rule failed (rc=%d): %s", result.returncode, stderr)
                return False
            return True
        except FileNotFoundError:
            logger.warning("BlockManager: iptables not found — skipping country rule.")
            return True

    def _apply_asn_rule(self, asn: str, block: bool) -> bool:
        """
        Apply/remove ASN block via ipset.
        Falls back to a warning log if ipset is unavailable.
        """
        set_name = f"ng_asn_{asn.lstrip('ASas')}"
        try:
            if block:
                # Create the ipset if it doesn't exist, then reference it in iptables
                subprocess.run(
                    shlex.split(f"ipset create {set_name} hash:net"),
                    capture_output=True, timeout=5
                )  # ignore error — may already exist
                self._run_cmd(f"iptables -I INPUT -m set --match-set {shlex.quote(set_name)} src -j DROP")
            else:
                self._run_cmd(f"iptables -D INPUT -m set --match-set {shlex.quote(set_name)} src -j DROP")
                subprocess.run(
                    shlex.split(f"ipset destroy {set_name}"),
                    capture_output=True, timeout=5
                )  # best-effort cleanup
            return True
        except FileNotFoundError:
            logger.warning(
                "BlockManager: ipset not found; ASN block for %s recorded in DB only. "
                "Install ipset to enforce at firewall level.", asn
            )
            return True  # non-fatal skip

    def _run_cmd(self, cmd: str) -> bool:
        """Run a firewall command; return True on success, False on error."""
        try:
            result = subprocess.run(shlex.split(cmd), capture_output=True, timeout=5)
            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace").strip()
                logger.error("BlockManager: firewall cmd failed (rc=%d): %s", result.returncode, stderr)
                return False
            return True
        except FileNotFoundError:
            logger.warning("BlockManager: iptables not found — skipping firewall rule.")
            return True  # dev/test environment — don't hard-fail
        except Exception as exc:
            logger.error("BlockManager: firewall error: %s", exc)
            return False
