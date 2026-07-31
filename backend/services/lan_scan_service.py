"""
lan_scan_service.py — LAN device discovery for NetGuard IDPS.

Discovers active devices on the local network using ARP scanning via Scapy.
Results are cached for 30 seconds to avoid flooding the network.

Only runs on Linux (requires raw socket privileges for ARP).
On Windows returns an empty list gracefully.
"""

from __future__ import annotations

import logging
import socket
import subprocess
import threading
import time
from typing import Optional

logger = logging.getLogger("netguard.lan_scan")

# Cache TTL in seconds — avoid hammering the network
_CACHE_TTL = 30


class LanScanService:
    """
    Discovers LAN devices via ARP scanning.

    Uses Scapy's ARP ping when available (Linux + root).
    Falls back to parsing the OS ARP cache on Windows/no-root.
    Results cached for 30 seconds.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: list[dict] = []
        self._cache_time: float = 0.0

    def get_devices(self, interface: Optional[str] = None) -> list[dict]:
        """
        Return discovered LAN devices, using cache if fresh.

        Each device dict contains:
            ip, mac, hostname, vendor, status, last_seen (ISO-8601 UTC)

        Args:
            interface: Optional network interface to scan on. If None,
                       uses the default route interface.
        Returns:
            List of device dicts. Empty list on any error.
        """
        now = time.monotonic()
        with self._lock:
            if self._cache and now - self._cache_time < _CACHE_TTL:
                return list(self._cache)

        devices = self._scan(interface)

        with self._lock:
            self._cache = devices
            self._cache_time = time.monotonic()

        return devices

    def invalidate(self) -> None:
        """Force next call to get_devices() to re-scan."""
        with self._lock:
            self._cache_time = 0.0

    # ------------------------------------------------------------------
    # Private scan methods
    # ------------------------------------------------------------------

    def _scan(self, interface: Optional[str]) -> list[dict]:
        """Try Scapy ARP scan; fall back to ARP cache parse."""
        try:
            return self._scapy_arp_scan(interface)
        except Exception as exc:
            logger.debug("Scapy ARP scan unavailable (%s), falling back to ARP cache", exc)
        try:
            return self._arp_cache_scan()
        except Exception as exc2:
            logger.warning("LanScanService: both scan methods failed: %s", exc2)
            return []

    def _scapy_arp_scan(self, interface: Optional[str]) -> list[dict]:
        """
        Use Scapy to broadcast an ARP request across the local /24.

        Requires root + libpcap. Raises on any import or permission error.
        """
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
        import scapy.config

        # Determine target subnet from the active interface
        target = _get_scan_target(interface)
        if not target:
            return []

        logger.debug("LanScanService: ARP scanning %s on %s", target, interface or "default")

        # Broadcast ARP request
        arp = ARP(pdst=target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        answered, _ = srp(
            packet,
            iface=interface,
            timeout=2,
            verbose=False,
            retry=1,
        )

        now_str = _utc_now()
        devices = []
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            hostname = _resolve_hostname(ip)
            vendor = _mac_vendor(mac)
            devices.append({
                "ip": ip,
                "mac": mac.upper(),
                "hostname": hostname,
                "vendor": vendor,
                "status": "up",
                "last_seen": now_str,
            })

        logger.info("LanScanService: found %d devices via ARP scan", len(devices))
        return _sort_devices(devices)

    def _arp_cache_scan(self) -> list[dict]:
        """
        Parse the OS ARP cache as a fallback (no root needed, no active scan).

        Works on Linux (`ip neigh`) and Windows (`arp -a`).
        Returns only hosts already in the ARP table — not a full network scan.
        """
        import sys
        now_str = _utc_now()
        devices = []

        if sys.platform == "win32":
            output = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
            for line in output.splitlines():
                parts = line.split()
                # Windows arp -a: "  192.168.1.1  aa-bb-cc-dd-ee-ff  dynamic"
                if len(parts) >= 2 and _is_ip(parts[0]) and "-" in parts[1]:
                    ip = parts[0]
                    mac = parts[1].replace("-", ":").upper()
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "hostname": _resolve_hostname(ip),
                        "vendor": _mac_vendor(mac),
                        "status": "up",
                        "last_seen": now_str,
                    })
        else:
            # Linux: ip neigh show
            output = subprocess.check_output(
                ["ip", "neigh", "show"], text=True, timeout=5
            )
            for line in output.splitlines():
                # Format: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
                parts = line.split()
                if len(parts) >= 5 and _is_ip(parts[0]) and "lladdr" in parts:
                    idx = parts.index("lladdr")
                    ip = parts[0]
                    mac = parts[idx + 1].upper()
                    state = parts[-1].lower()
                    status = "up" if state in ("reachable", "stale", "delay") else "unknown"
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "hostname": _resolve_hostname(ip),
                        "vendor": _mac_vendor(mac),
                        "status": status,
                        "last_seen": now_str,
                    })

        logger.info("LanScanService: found %d devices via ARP cache", len(devices))
        return _sort_devices(devices)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_scan_target(interface: Optional[str]) -> Optional[str]:
    """Return a CIDR target like '192.168.1.0/24' for the given interface."""
    try:
        import psutil
        addrs = psutil.net_if_addrs()
        iface_list = [interface] if interface else list(addrs.keys())
        for iface in iface_list:
            for snic in addrs.get(iface, []):
                import psutil
                if snic.family == socket.AF_INET and snic.address and not snic.address.startswith("127."):
                    # Build /24 CIDR from IP
                    parts = snic.address.split(".")
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception as exc:
        logger.debug("_get_scan_target failed: %s", exc)
    return None


def _resolve_hostname(ip: str) -> str:
    """Reverse-DNS lookup; returns empty string on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _mac_vendor(mac: str) -> str:
    """
    Return a vendor name from the first 3 octets of the MAC address.

    Uses a small built-in table of common prefixes. For a full OUI database,
    integrate with an offline ieee-oui lookup.
    """
    if not mac or len(mac) < 8:
        return ""
    prefix = mac[:8].upper().replace(":", "").replace("-", "")[:6]
    # Common OUI prefixes — extend as needed
    _OUI: dict[str, str] = {
        "FCAA14": "Apple",
        "A4C138": "Apple",
        "3C9AFE": "Apple",
        "DC2B2A": "Apple",
        "001A2B": "Cisco",
        "00507F": "Cisco",
        "001BB1": "Cisco",
        "B827EB": "Raspberry Pi",
        "DCA632": "Raspberry Pi",
        "E45F01": "Raspberry Pi",
        "080027": "VirtualBox",
        "00163E": "Xen",
        "000C29": "VMware",
        "005056": "VMware",
        "001C42": "Parallels",
        "00155D": "Microsoft Hyper-V",
        "606BBD": "Dell",
        "F8DB88": "Dell",
        "74E6E2": "Dell",
        "001E4F": "Dell",
        "3417EB": "HP",
        "3C4A92": "HP",
        "001A4B": "HP",
        "9CEBE8": "Intel",
        "A4C496": "Intel",
        "10027B": "Intel",
        "74D435": "Intel",
    }
    return _OUI.get(prefix, "")


def _is_ip(s: str) -> bool:
    """Return True if s looks like an IPv4 address."""
    try:
        parts = s.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def _sort_devices(devices: list[dict]) -> list[dict]:
    """Sort by last octet of IP for stable display order."""
    try:
        return sorted(devices, key=lambda d: int(d["ip"].split(".")[-1]))
    except Exception:
        return devices


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
