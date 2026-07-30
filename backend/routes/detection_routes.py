"""
detection_routes.py — Detection event endpoints.

GET  /detections         (with filters: severity, attack_type, source_ip, date)
GET  /detections/<id>
POST /detect             (internal — submit packet for manual analysis)

Requirements: 13.2, 13.3, 13.4, 13.8
"""

from __future__ import annotations

from flask import Blueprint, request

from backend.api.dependencies import get_event_repo
from backend.utils.response import success_response, error_response
from backend.utils.validators import validate_ip_address, validate_severity

detection_bp = Blueprint("detections", __name__)

_VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}


@detection_bp.get("/detections")
def list_detections():
    # --- Strict pagination validation (Req 8.7) ---
    raw_limit = request.args.get("limit", "50")
    raw_offset = request.args.get("offset", "0")
    try:
        limit = int(raw_limit)
        offset = int(raw_offset)
    except (ValueError, TypeError):
        return error_response(
            "limit and offset must be integers.", 422, "INVALID_PAGINATION_PARAMS"
        )
    if limit < 1 or offset < 0:
        return error_response(
            "limit must be >= 1 and offset must be >= 0.", 422, "INVALID_PAGINATION_PARAMS"
        )
    limit = min(limit, 500)  # clamp silently (Req 8.6)

    filters = {}
    severity = request.args.get("severity")
    attack_type = request.args.get("attack_type")
    source_ip = request.args.get("source_ip")
    date = request.args.get("date")
    search = request.args.get("search", "").strip()

    if severity:
        if not validate_severity(severity):
            return error_response(
                f"Invalid severity: {severity}. Must be one of Low, Medium, High, Critical.",
                422, "VALIDATION_ERROR",
            )
        filters["severity"] = severity

    if attack_type:
        filters["attack_type"] = attack_type

    if source_ip:
        if not validate_ip_address(source_ip):
            return error_response(
                f"Invalid IP address: {source_ip}", 422, "INVALID_IP"
            )
        filters["source_ip"] = source_ip

    if date:
        filters["date"] = date

    if search:
        filters["search"] = search

    repo = get_event_repo()
    if repo is None:
        return error_response("Event repository unavailable", 500, "SERVICE_UNAVAILABLE")

    events = repo.get_all(filters=filters, limit=limit, offset=offset)
    total = repo.count_filtered(filters=filters)
    return success_response(data={"events": events, "count": len(events), "total": total, "limit": limit, "offset": offset})


@detection_bp.get("/detections/<string:event_id>")
def get_detection(event_id: str):
    repo = get_event_repo()
    if repo is None:
        return error_response("Event repository unavailable", 500, "SERVICE_UNAVAILABLE")

    event = repo.get_by_id(event_id)
    if event is None:
        return error_response(f"Event {event_id} not found.", 404, "NOT_FOUND")

    return success_response(data=event)


@detection_bp.post("/detect")
def detect():
    """Internal endpoint — submit detection event from detection engine."""
    body = request.get_json(silent=True)
    if not body:
        return error_response("Request body required.", 400, "VALIDATION_ERROR")

    required = ["attack_type", "source_ip", "severity", "rule"]
    missing = [f for f in required if not body.get(f)]
    if missing:
        return error_response(
            f"Missing required fields: {', '.join(missing)}", 400, "VALIDATION_ERROR"
        )

    if not validate_ip_address(body["source_ip"]):
        return error_response(
            f"Invalid source IP: {body['source_ip']}", 422, "INVALID_IP"
        )

    return success_response(
        data={"received": True},
        message="Detection received.",
        status_code=201,
    )
