"""
evidence_routes.py — Evidence retrieval endpoint.

GET /evidence/<event_id>

Requirements: 13.2, 13.3, 13.4
"""

from __future__ import annotations

from flask import Blueprint

from backend.api.dependencies import get_event_repo
from backend.utils.response import success_response, error_response

evidence_bp = Blueprint("evidence", __name__)


@evidence_bp.get("/evidence/<string:event_id>")
def get_evidence(event_id: str):
    repo = get_event_repo()
    if repo is None:
        return error_response("Event repository unavailable", 500, "SERVICE_UNAVAILABLE")

    event_dict = repo.get_by_id(event_id)
    if event_dict is None:
        return error_response(f"Event {event_id} not found.", 404, "NOT_FOUND")

    return success_response(data={
        "event_id": event_id,
        "attack_name": event_dict.get("attack_type"),
        "rule_triggered": event_dict.get("rule_name"),
        "plain_english_text": event_dict.get("explanation", ""),
        "evidence": event_dict.get("evidence", {}),
        "confidence_score": event_dict.get("confidence", 0),
        "severity": event_dict.get("severity", ""),
        "recommendation": event_dict.get("recommendation", ""),
        "source_ip": event_dict.get("source_ip"),
        "timestamp": event_dict.get("timestamp"),
    })
