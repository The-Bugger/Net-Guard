"""
map_routes.py — GeoIP resolution and map events API.

GET /api/v1/map/resolve?ip=...
GET /api/v1/map/events

Requirements: 5.1, 5.8
"""

from flask import Blueprint, jsonify, request
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
        # Req 5.8: structured error body {ip, error_code, timestamp} with HTTP 503
        return jsonify({"ip": result.ip, "error_code": result.error_code, "timestamp": result.timestamp}), 503
    return success_response(result)


@map_bp.get("/map/events")
@require_role("admin", "analyst", "hunter", "viewer")
def map_events():
    """Return recent threat events with GeoIP coords for map initialisation."""
    event_repo = dependencies.get("event_repo")
    geoip = dependencies.get("geoip_engine")

    try:
        limit = min(int(request.args.get("limit", 100)), 500)
    except (ValueError, TypeError):
        limit = 100

    # event_repo.get_all returns most-recent-first; limit is honoured
    events = event_repo.get_all(limit=limit) if event_repo else []

    items = []
    for ev in events:
        lat, lon, country, city = 0.0, 0.0, "", ""
        if geoip:
            resolved = geoip.resolve(ev.get("source_ip", ""))
            if not isinstance(resolved, GeoIPError):
                lat = resolved.get("lat", 0.0)
                lon = resolved.get("lon", 0.0)
                country = resolved.get("country", "")
                city = resolved.get("city", "")
        items.append({**ev, "lat": lat, "lon": lon, "country": country, "city": city})

    return success_response({"events": items})
