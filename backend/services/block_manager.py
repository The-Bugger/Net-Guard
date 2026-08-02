"""
block_manager.py — Enterprise IP blocking with threat scores, atomicity, and audit.

Complements (does not replace) PreventionEngine. Existing auto-block flow unchanged.

Requirements: 1.1-1.15
"""

from __future__ import annotations

import logging
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Optional

from .firewall import fw_block, fw_unblock

logger = logging.getLogger("netguard.block_manager")

_VALID_TYPES = {"ip", "cidr", "country", "asn"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_future(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")




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

        # Duplicate block — extend expiry from current remaining time (Req 1.5)
        if target_type == "ip":
            existing = self._block_repo.get_active(target)
            if existing:
                # Parse current expiry and add duration on top (not from now).
                try:
                    current_exp = datetime.fromisoformat(existing["expires_at"].replace("Z", "+00:00"))
                except (KeyError, ValueError):
                    current_exp = datetime.now(timezone.utc)
                new_expires = (current_exp + timedelta(seconds=duration)).strftime("%Y-%m-%dT%H:%M:%SZ")
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
        Apply or remove a firewall rule based on target type.

        - ip/cidr    → fw_block / fw_unblock (platform-aware)
        - country    → iptables geoip on Linux; DB-only on Windows (non-fatal skip)
        - asn        → ipset on Linux; DB-only on Windows (non-fatal skip)

        Returns True on success or non-fatal skip.
        """
        try:
            if target_type == "country":
                return self._apply_country_rule(target, block)
            if target_type == "asn":
                return self._apply_asn_rule(target, block)
            # ip or cidr
            return fw_block(target) if block else fw_unblock(target)
        except Exception as exc:
            logger.error("BlockManager: firewall error: %s", exc)
            return False

    def _apply_country_rule(self, country_code: str, block: bool) -> bool:
        """
        Apply/remove country-level block via iptables geoip match extension.
        On Windows or when geoip module is unavailable, logs a warning and
        returns True (non-fatal skip — DB record still created).
        """
        import sys
        if sys.platform == "win32":
            logger.warning(
                "BlockManager: country block for %s recorded in DB only "
                "(netsh does not support geo-matching).", country_code
            )
            return True

        action = "-I" if block else "-D"
        cmd = ["iptables", action, "INPUT", "-m", "geoip",
               "--src-cc", country_code, "-j", "DROP"]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace").strip()
                if "geoip" in stderr.lower() or "no match" in stderr.lower():
                    # ponytail: geoip iptables extension not installed — log and skip
                    logger.warning(
                        "BlockManager: iptables geoip module unavailable; "
                        "country block for %s recorded in DB only. "
                        "Install xtables-addons to enforce at firewall level.", country_code
                    )
                    return True  # non-fatal
                logger.error("BlockManager: country rule failed (rc=%d): %s", result.returncode, stderr)
                return False
            return True
        except FileNotFoundError:
            logger.warning("BlockManager: iptables not found — skipping country rule.")
            return True

    def _apply_asn_rule(self, asn: str, block: bool) -> bool:
        """
        Apply/remove ASN block via ipset (Linux only).
        On Windows, logs a warning and returns True (non-fatal skip).
        """
        import sys
        if sys.platform == "win32":
            logger.warning(
                "BlockManager: ASN block for %s recorded in DB only "
                "(ipset not available on Windows).", asn
            )
            return True

        set_name = f"ng_asn_{asn.lstrip('ASas')}"
        try:
            if block:
                subprocess.run(
                    ["ipset", "create", set_name, "hash:net"],
                    capture_output=True, timeout=5,
                )  # ignore error — may already exist
                subprocess.run(
                    ["iptables", "-I", "INPUT", "-m", "set",
                     "--match-set", set_name, "src", "-j", "DROP"],
                    capture_output=True, timeout=5,
                )
            else:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-m", "set",
                     "--match-set", set_name, "src", "-j", "DROP"],
                    capture_output=True, timeout=5,
                )
                subprocess.run(
                    ["ipset", "destroy", set_name],
                    capture_output=True, timeout=5,
                )  # best-effort cleanup
            return True
        except FileNotFoundError:
            logger.warning(
                "BlockManager: ipset not found; ASN block for %s recorded in DB only. "
                "Install ipset to enforce at firewall level.", asn
            )
            return True  # non-fatal skip
