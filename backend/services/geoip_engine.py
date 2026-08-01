"""
geoip_engine.py — GeoIP resolution with provider chain and LRU cache.

Provider chain: MaxMind GeoLite2 → ip-api.com → IPinfo
Configurable via settings_repo key 'geoip.provider_chain'.

ponytail: stdlib functools.lru_cache + parallel _cache_times dict for TTL.
         Stale entries are evicted lazily on access. Ceiling: up to one
         cache period of staleness per entry. Upgrade path: swap to Redis
         cache (Task 16.3) when Redis is wired.

Requirements: 5.1, 5.2, 5.8, 5.9
"""

from __future__ import annotations

import functools
import logging
import time
from dataclasses import dataclass
from typing import Optional

import requests

logger = logging.getLogger("netguard.geoip_engine")

_TTL_HOURS = 24
_TTL_SECONDS = _TTL_HOURS * 3600
_CACHE_SIZE = 10_000

_DEFAULT_CHAIN = ["ipapi", "ipinfo"]  # maxmind requires DB file


@dataclass
class GeoIPError:
    ip: str
    error_code: str
    timestamp: str

    def __bool__(self) -> bool:
        return False


class GeoIPEngine:
    """Resolves IPs to geographic + ASN metadata with LRU cache and provider fallback."""

    def __init__(self, settings_repo=None, cache_size: int = _CACHE_SIZE, ttl_hours: float = _TTL_HOURS) -> None:
        self._settings_repo = settings_repo
        self._ttl = ttl_hours * 3600
        # ponytail: lru_cache on bound method needs a module-level wrapper trick;
        # use a plain dict with maxsize eviction instead — same O(1) amortised.
        self._cache: dict[str, dict] = {}
        self._cache_times: dict[str, float] = {}
        self._cache_size = cache_size
        self._provider_chain = self._load_chain()

    def resolve(self, ip: str) -> dict | GeoIPError:
        """
        Resolve an IP to {ip, country, lat, lon, city, asn, isp}.
        Returns GeoIPError on full-chain failure.
        Checks Redis cache (TTL 24 h) before the in-process dict (Req 11.5).
        """
        # Redis cache check (TTL 24 h, Req 11.5)
        redis_result = self._redis_get(ip)
        if redis_result is not None:
            return redis_result

        # In-process cache with lazy TTL eviction
        cached = self._cache.get(ip)
        if cached is not None:
            age = time.monotonic() - self._cache_times.get(ip, 0)
            if age < self._ttl:
                return cached
            del self._cache[ip]
            del self._cache_times[ip]

        result = self._resolve_uncached(ip)
        if not isinstance(result, GeoIPError):
            self._store(ip, result)
            self._redis_set(ip, result, ttl=int(self._ttl))
        return result

    # ------------------------------------------------------------------
    # Redis helpers (Req 11.5) — fall back silently when Redis is down
    # ------------------------------------------------------------------

    def _redis_get(self, ip: str) -> dict | None:
        try:
            from backend.services.redis_client import get_redis
            import json as _json
            r = get_redis()
            if r is None:
                return None
            raw = r.get(f"geoip:{ip}")
            if raw:
                return _json.loads(raw)
        except Exception:
            pass
        return None

    def _redis_set(self, ip: str, data: dict, ttl: int) -> None:
        try:
            from backend.services.redis_client import get_redis
            import json as _json
            r = get_redis()
            if r is None:
                return
            r.setex(f"geoip:{ip}", ttl, _json.dumps(data))
        except Exception:
            pass

    def set_provider(self, provider: str) -> None:
        """Reconfigure the provider chain at runtime."""
        self._provider_chain = [provider]
        logger.info("GeoIPEngine: provider chain set to [%s]", provider)

    def _load_chain(self) -> list[str]:
        if self._settings_repo:
            raw = self._settings_repo.get("geoip.provider_chain")
            if raw:
                return [p.strip() for p in raw.split(",") if p.strip()]
        return list(_DEFAULT_CHAIN)

    def _resolve_uncached(self, ip: str) -> dict | GeoIPError:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        for provider in self._provider_chain:
            try:
                if provider == "maxmind":
                    result = self._maxmind(ip)
                elif provider == "ipapi":
                    result = self._ipapi(ip)
                elif provider == "ipinfo":
                    result = self._ipinfo(ip)
                else:
                    logger.warning("GeoIPEngine: unknown provider %s", provider)
                    continue
                if result:
                    return result
            except Exception as exc:
                logger.warning("GeoIPEngine: provider %s failed for %s: %s", provider, ip, exc)

        return GeoIPError(ip=ip, error_code="ALL_PROVIDERS_FAILED", timestamp=now)

    def _store(self, ip: str, data: dict) -> None:
        # Evict oldest if at capacity (simple FIFO approximation)
        if len(self._cache) >= self._cache_size:
            oldest = min(self._cache_times, key=self._cache_times.get)
            del self._cache[oldest]
            del self._cache_times[oldest]
        self._cache[ip] = data
        self._cache_times[ip] = time.monotonic()

    def _ipapi(self, ip: str) -> Optional[dict]:
        """ip-api.com free tier, no key needed."""
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,as", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            return None
        return {
            "ip": ip,
            "country": data.get("countryCode", ""),
            "country_name": data.get("country", ""),
            "city": data.get("city", ""),
            "lat": data.get("lat", 0.0),
            "lon": data.get("lon", 0.0),
            "asn": data.get("as", ""),
            "isp": data.get("isp", ""),
        }

    def _ipinfo(self, ip: str) -> Optional[dict]:
        """IPinfo — free tier, no key for basic fields."""
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        loc = data.get("loc", "0,0").split(",")
        lat = float(loc[0]) if len(loc) == 2 else 0.0
        lon = float(loc[1]) if len(loc) == 2 else 0.0
        return {
            "ip": ip,
            "country": data.get("country", ""),
            "city": data.get("city", ""),
            "lat": lat,
            "lon": lon,
            "asn": data.get("org", ""),
            "isp": data.get("org", ""),
        }

    def _maxmind(self, ip: str) -> Optional[dict]:
        """MaxMind GeoLite2 — requires geoip2 and a local DB file."""
        import geoip2.database  # lazy import
        db_path = None
        if self._settings_repo:
            db_path = self._settings_repo.get("geoip.maxmind_db_path")
        if not db_path:
            return None
        with geoip2.database.Reader(db_path) as reader:
            response = reader.city(ip)
            return {
                "ip": ip,
                "country": response.country.iso_code or "",
                "city": response.city.name or "",
                "lat": response.location.latitude or 0.0,
                "lon": response.location.longitude or 0.0,
                "asn": "",
                "isp": "",
            }

    @property
    def cache_stats(self) -> dict:
        return {"size": len(self._cache), "capacity": self._cache_size}
