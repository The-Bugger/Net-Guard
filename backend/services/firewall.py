"""
firewall.py — Cross-platform firewall abstraction for NetGuard.

Picks the right backend at import time based on sys.platform:
  - Linux  → iptables / ip6tables
  - Windows → netsh advfirewall

Public API (three functions, all return bool):
    fw_block(ip)   → add DROP/block rule
    fw_unblock(ip) → remove rule
    fw_check()     → verify privileges / tool availability

ponytail: Windows netsh rules are named "NetGuard-block-<ip>" so they can be
removed reliably.  IPv6 on Windows uses the same netsh command family.
Ceiling: netsh doesn't support CIDR ranges natively; country/ASN blocks on
Windows remain DB-only (same behaviour as the existing Linux geoip/ipset fallback).
"""

from __future__ import annotations

import ipaddress
import logging
import shlex
import subprocess
import sys

logger = logging.getLogger("netguard.firewall")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 5) -> bool:
    """Run *cmd* list, return True on rc=0, False otherwise. Never raises."""
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            logger.error("firewall: cmd failed (rc=%d) %s — %s", result.returncode, cmd, stderr)
            return False
        return True
    except FileNotFoundError:
        logger.error("firewall: tool not found: %s", cmd[0])
        return False
    except subprocess.TimeoutExpired:
        logger.error("firewall: cmd timed out: %s", cmd)
        return False
    except Exception as exc:
        logger.error("firewall: unexpected error running %s — %s", cmd, exc)
        return False


def _is_ipv6(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
    except ValueError:
        return False


def _rule_name(ip: str) -> str:
    """Stable Windows firewall rule name for an IP."""
    # Replace colons (IPv6) with hyphens — netsh rule names can't contain colons.
    return f"NetGuard-block-{ip.replace(':', '-')}"


# ---------------------------------------------------------------------------
# Linux backend (iptables / ip6tables)
# ---------------------------------------------------------------------------

def _linux_block(ip: str) -> bool:
    tool = "ip6tables" if _is_ipv6(ip) else "iptables"
    return _run([tool, "-I", "INPUT", "-s", ip, "-j", "DROP"])


def _linux_unblock(ip: str) -> bool:
    tool = "ip6tables" if _is_ipv6(ip) else "iptables"
    return _run([tool, "-D", "INPUT", "-s", ip, "-j", "DROP"])


def _linux_check() -> bool:
    return _run(["iptables", "-L", "INPUT", "-n"])


# ---------------------------------------------------------------------------
# Windows backend (netsh advfirewall)
# ---------------------------------------------------------------------------

def _win_block(ip: str) -> bool:
    name = _rule_name(ip)
    # Delete any stale rule first (idempotent); ignore failure.
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
        capture_output=True,
    )
    return _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={name}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
        "enable=yes",
    ])


def _win_unblock(ip: str) -> bool:
    name = _rule_name(ip)
    return _run([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={name}",
    ])


def _win_check() -> bool:
    """Check that netsh is available and we have permission to list rules."""
    return _run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"])


# ---------------------------------------------------------------------------
# Public API — selected at import time
# ---------------------------------------------------------------------------

if sys.platform == "win32":
    fw_block   = _win_block
    fw_unblock = _win_unblock
    fw_check   = _win_check
    logger.debug("firewall: Windows backend selected (netsh advfirewall).")
else:
    fw_block   = _linux_block
    fw_unblock = _linux_unblock
    fw_check   = _linux_check
    logger.debug("firewall: Linux backend selected (iptables).")
