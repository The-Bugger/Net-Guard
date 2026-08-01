"""
map_routes.py — GeoIP resolution and map events API.

GET /api/v1/map/resolve?ip=...
GET /api/v1/map/events

Requirements: 5.1, 5.8
"""

from flask import Blueprint, request
from backend.api import dependencies
from backend.middleware.auth_middleware import require_role
from backend.utils.response import success_response, error_response
from backend.services.geoip_engine import GeoIPError

map_bp = Blueprint("map", __name__)


@map_bp.get("/map/resolve")
@require_role("admin", "analyst", "hunter", "viewer")
def resolve_ip():
    ip = request.args.get("ip", "").strip()
    if not ip:
        return error_response("ip parameter required", 400)

    engine = dependencies.get("geoip_engine")
    if not engine:
        return error_response("GeoIP engine not available", 503)

    result = engine.resolve(ip)
    if isinstance(result, GeoIPError):
        return success_response({
            "ip": ip, "country": "", "city": "", "lat": 0.0, "lon": 0.0,
            "asn": "", "isp": "", "error": result.error_code,
        })
    return success_response(result)


@map_bp.get("/map/events")
@require_role("admin", "analyst", "hunter", "viewer")
def map_events():
    """Return recent threat events with GeoIP coords for map initialisation."""
    event_repo = dependencies.get("event_repo")
    geoip = dependencies.get("geoip_engine")

    limit = min(int(request.args.get("limit", 100)), 500)
    events = event_repo.get_recent(limit) if hasattr(event_repo, "get_recent") else []

    items = []
    for ev in events:
        geo = {"lat": 0.0, "lon": 0.0, "country": "", "city": ""}
        if geoip:
            resolved = geoip.resolve(ev.get("source_ip", ""))
            if not isinstance(resolved, GeoIPError):
                geo = {k: resolved.get(k, geo[k]) for k in geo}
        items.append({**ev, **geo})

    return success_response({"events": items})
