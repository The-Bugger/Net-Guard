"""
lan_devices_routes.py — LAN device discovery endpoint.

GET  /lan-devices          — list all discovered devices on the LAN
POST /lan-devices/refresh  — force a new ARP scan (invalidates cache)
"""

from __future__ import annotations

from flask import Blueprint

from backend.api.dependencies import get
from backend.utils.response import success_response, error_response

lan_devices_bp = Blueprint("lan_devices", __name__)


def _svc():
    return get("lan_scan_service")


@lan_devices_bp.get("/devices")
@lan_devices_bp.get("/lan-devices")
def list_lan_devices():
    """Return currently known LAN devices (from cache if fresh)."""
    svc = _svc()
    if svc is None:
        return error_response("LAN scan service unavailable.", 503, "SERVICE_UNAVAILABLE")

    monitoring_state = get("monitoring_state")
    interface = monitoring_state.interface if monitoring_state else None

    devices = svc.get_devices(interface or None)
    return success_response(data={"devices": devices, "count": len(devices)})


@lan_devices_bp.post("/lan-devices/refresh")
def refresh_lan_devices():
    """Invalidate the device cache and trigger a fresh ARP scan."""
    svc = _svc()
    if svc is None:
        return error_response("LAN scan service unavailable.", 503, "SERVICE_UNAVAILABLE")

    svc.invalidate()

    monitoring_state = get("monitoring_state")
    interface = monitoring_state.interface if monitoring_state else None

    devices = svc.get_devices(interface or None)
    return success_response(data={"devices": devices, "count": len(devices)})
