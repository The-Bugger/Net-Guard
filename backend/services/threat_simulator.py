"""
threat_simulator.py — Realistic synthetic attacker profile generator.

Pure Python, no network calls. All data generated from embedded CIDR datasets
and seeded random values.

Requirements: 4.1-4.7
"""

from __future__ import annotations

import ipaddress
import logging
import random
from typing import Callable, Optional

logger = logging.getLogger("netguard.threat_simulator")

# ---------------------------------------------------------------------------
# Embedded source-category CIDR blocks (representative samples)
# ---------------------------------------------------------------------------

_CIDR_SETS: dict[str, list[str]] = {
    "aws":          ["52.0.0.0/8",       "54.0.0.0/8",       "3.0.0.0/8",       "18.0.0.0/8"],
    "azure":        ["20.0.0.0/8",       "40.0.0.0/8"],
    "gcp":          ["34.0.0.0/8",       "35.0.0.0/8"],
    "digitalocean": ["104.131.0.0/18",   "159.89.0.0/16"],
    "ovh":          ["51.38.0.0/16",     "51.77.0.0/16"],
    "hetzner":      ["5.9.0.0/16",       "78.46.0.0/16"],
    "oracle":       ["129.146.0.0/16",   "132.145.0.0/16"],
    "tencent":      ["101.32.0.0/12",    "211.159.128.0/18"],
    "alibaba":      ["47.88.0.0/14",     "101.200.0.0/13"],
    "tor":          ["176.10.99.0/24",   "185.220.101.0/24", "195.176.3.0/24"],
    "botnet":       ["5.188.0.0/16",     "45.146.0.0/16",    "91.243.0.0/16"],
    "vpn":          ["104.16.0.0/12",    "198.41.128.0/17"],
    "residential":  ["72.0.0.0/8",       "98.0.0.0/8"],
    "compromised":  ["89.248.0.0/16",    "185.244.0.0/16"],
    "cdn":          ["151.101.0.0/16",   "199.27.128.0/21"],
}
# "do" is an accepted short alias for "digitalocean" (Req 4.4)
_CIDR_SETS["do"] = _CIDR_SETS["digitalocean"]

_THREAT_ACTORS = [
    "APT28", "APT29", "APT41", "Lazarus Group", "Fancy Bear",
    "Cozy Bear", "Sandworm", "Charming Kitten", "Equation Group",
    "DarkHydrus", "OilRig", "FIN7", "Carbanak", "TA505",
    "SilverTerrier", "Scattered Spider", "Storm-0558", "Volt Typhoon",
    "Salt Typhoon", "Earth Preta",
]
_MALWARE_FAMILIES = [
    "Emotet", "TrickBot", "Ryuk", "Cobalt Strike", "Mimikatz",
    "AsyncRAT", "NjRAT", "RedLine", "Raccoon", "Qakbot",
    "IcedID", "DarkComet", "Remcos", "AgentTesla", "FormBook",
    "GuLoader", "SnakeKeylogger", "XWorm", "Vidar", "Lumma",
]
_CAMPAIGNS = [
    "Operation BlackSea", "Campaign Nightshade", "Operation Irongate",
    "Campaign Spectral", "Operation GhostShell", "Campaign Lazarus",
    "Operation TigerHunt", "Campaign RedNet", "Operation DarkPulse",
    "Campaign SilverFox", "Operation NightOwl", "Campaign Phantom",
    "Operation CrimsonRain", "Campaign StormWatch", "Operation VoidStar",
    "Campaign FrostByte", "Operation ShadowNet", "Campaign ViperStrike",
    "Operation BlueTide", "Campaign IronCurtain",
]
_COUNTRIES = [
    "RU", "CN", "KP", "IR", "US", "DE", "NL", "UA", "BR", "IN",
    "GB", "FR", "TR", "PL", "RO", "LV", "EE", "JP", "KR", "HK",
]
_CITIES = [
    "Moscow", "Beijing", "Pyongyang", "Tehran", "New York", "Berlin",
    "Amsterdam", "Kyiv", "São Paulo", "Mumbai", "London", "Paris",
    "Istanbul", "Warsaw", "Bucharest", "Riga", "Tallinn", "Tokyo",
    "Seoul", "Hong Kong", "Frankfurt", "Chicago", "Los Angeles",
    "Singapore", "Sydney", "Toronto", "Dubai", "Johannesburg",
]
_ASNS = [
    "AS13335", "AS16509", "AS15169", "AS8075", "AS4134",
    "AS9299",  "AS1299",  "AS3356",  "AS2914",  "AS701",
    "AS3257",  "AS6939",  "AS20473", "AS7922",  "AS4837",
    "AS9808",  "AS4766",  "AS3462",  "AS1221",  "AS7018",
]
_ISPS = [
    "Cloudflare Inc.", "Amazon Web Services", "Google LLC", "Microsoft Azure",
    "China Telecom", "PLDT Inc.", "Telia Carrier", "Lumen Technologies",
    "NTT Communications", "Verizon Business", "GTT Communications",
    "Hurricane Electric", "Choopa LLC", "Comcast Cable", "China Unicom",
    "China Mobile", "KT Corp", "Chunghwa Telecom", "Telstra", "AT&T",
]

# RFC-1918 and other reserved networks
_RESERVED: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]


def _is_reserved(addr: ipaddress.IPv4Address) -> bool:
    return any(addr in net for net in _RESERVED)


def _random_ip_in_cidr(cidr: str) -> Optional[str]:
    """Return a random host IP within the given CIDR, or None if the network is too small."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        num_hosts = net.num_addresses
        if num_hosts < 2:
            return None
        offset = random.randint(1, max(1, num_hosts - 2))
        addr = net.network_address + offset
        if isinstance(addr, ipaddress.IPv4Address) and _is_reserved(addr):
            return None
        return str(addr)
    except ValueError:
        return None


def _random_public_ipv4() -> str:
    """Generate a uniformly random public IPv4 address."""
    for _ in range(100):
        a = random.randint(1, 223)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        addr = ipaddress.ip_address(f"{a}.{b}.{c}.{d}")
        if not _is_reserved(addr):
            return str(addr)
    return "8.8.8.8"  # fallback — known public


class ThreatSimulator:
    """Generates realistic synthetic attacker profiles for simulations."""

    def __init__(self, whitelist_set: set | None = None) -> None:
        self._whitelist: set = whitelist_set or set()

    def generate_profile(self, source_category: Optional[str] = None) -> dict:
        """
        Generate a single attacker profile.

        Returns dict: ip, country, asn, isp, lat, lon, city,
                      actor_name, risk_score, reputation_score,
                      malware_family, campaign_name
        """
        ip = self._pick_ip(source_category)
        return {
            "ip": ip,
            "country": random.choice(_COUNTRIES),
            "asn": random.choice(_ASNS),
            "isp": random.choice(_ISPS),
            "lat": round(random.uniform(-60.0, 70.0), 4),
            "lon": round(random.uniform(-180.0, 180.0), 4),
            "city": random.choice(_CITIES),
            "actor_name": random.choice(_THREAT_ACTORS),
            "risk_score": random.randint(0, 100),
            "reputation_score": random.randint(0, 100),
            "malware_family": random.choice(_MALWARE_FAMILIES),
            "campaign_name": random.choice(_CAMPAIGNS),
            "source_category": source_category,
        }

    def generate_session(
        self,
        count: int,
        source_category: Optional[str] = None,
        _event_sink: Optional[Callable] = None,
    ) -> list[dict]:
        """
        Generate *count* unique-IP profiles for a simulation session.

        Whitelisted IPs are retried up to 10 times per slot;
        on exhaustion a whitelist_exhaustion event is emitted.
        """
        profiles: list[dict] = []
        used_ips: set[str] = set()

        for slot in range(count):
            profile = None
            for attempt in range(10):
                candidate = self.generate_profile(source_category)
                ip = candidate["ip"]
                if ip not in used_ips and ip not in self._whitelist:
                    profile = candidate
                    used_ips.add(ip)
                    break
            if profile is None:
                # whitelist exhaustion (Req 4.7)
                if _event_sink:
                    _event_sink({"type": "whitelist_exhaustion", "slot": slot})
                logger.warning("ThreatSimulator: whitelist_exhaustion for slot %d", slot)
            else:
                profiles.append(profile)

        return profiles

    def update_whitelist(self, whitelist_set: set) -> None:
        self._whitelist = whitelist_set

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _pick_ip(self, category: Optional[str]) -> str:
        """Pick an IP from the given category's CIDR pool, or random public."""
        cidrs = _CIDR_SETS.get(category, []) if category else []
        if cidrs:
            for _ in range(20):
                cidr = random.choice(cidrs)
                ip = _random_ip_in_cidr(cidr)
                if ip:
                    return ip
        return _random_public_ipv4()
