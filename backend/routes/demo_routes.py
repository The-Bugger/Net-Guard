"""
demo_routes.py — Demo attack simulation endpoints.

POST /demo/start    — start background event loop
POST /demo/stop     — stop background event loop
POST /demo/trigger  — emit one specific attack type immediately
GET  /demo/status   — current demo session state

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.7, 7.1, 7.2, 7.5
"""

from __future__ import annotations

from flask import Blueprint, request

from backend.api.dependencies import get
from backend.utils.response import success_response, error_response

demo_bp = Blueprint("demo", __name__)


def _svc():
    """Return the registered DemoService, or None."""
    return get("demo_service")


@demo_bp.post("/demo/start")
def demo_start():
    svc = _svc()
    if svc is None:
        return error_response("Demo service unavailable.", 500, "SERVICE_UNAVAILABLE")
    if svc.is_active:
        return error_response("Demo is already running.", 409, "DEMO_ALREADY_RUNNING")
    svc.start()
    return success_response(data={"message": "Demo started"})


@demo_bp.post("/demo/stop")
def demo_stop():
    svc = _svc()
    if svc is None:
        return error_response("Demo service unavailable.", 500, "SERVICE_UNAVAILABLE")
    if not svc.is_active:
        return error_response("Demo is not running.", 409, "DEMO_NOT_RUNNING")
    svc.stop()
    return success_response(data={"message": "Demo stopped"})


@demo_bp.post("/demo/trigger")
def demo_trigger():
    svc = _svc()
    if svc is None:
        return error_response("Demo service unavailable.", 500, "SERVICE_UNAVAILABLE")

    body = request.get_json(silent=True) or {}
    attack_type = body.get("attack_type", "")
    if isinstance(attack_type, str):
        attack_type = attack_type.strip()

    try:
        event_id = svc.trigger(attack_type)
    except ValueError:
        return error_response("Unknown or missing attack_type.", 422, "INVALID_ATTACK_TYPE")

    return success_response(data={"event_id": event_id})


@demo_bp.get("/demo/status")
def demo_status():
    svc = _svc()
    if svc is None:
        return error_response("Demo service unavailable.", 500, "SERVICE_UNAVAILABLE")
    return success_response(data=svc.get_status())


@demo_bp.get("/events/<event_id>/replay")
def replay_event(event_id):
    """Replay an event — look up by id, re-emit via demo_service.trigger()."""
    svc = _svc()
    if svc is None:
        return error_response("Demo service unavailable.", 500, "SERVICE_UNAVAILABLE")

    # Look up event by id
    event_repo = get("event_repository")
    if event_repo is None:
        return error_response("Event repository unavailable.", 500, "SERVICE_UNAVAILABLE")

    event = event_repo.get_by_id(event_id)
    if event is None:
        return error_response("Event not found.", 404, "NOT_FOUND")

    # Trigger same attack type
    try:
        new_event_id = svc.trigger(event["attack_type"])
    except ValueError:
        return error_response("Cannot replay — invalid attack type.", 422, "INVALID_ATTACK_TYPE")

    return success_response(data={"event_id": new_event_id})
