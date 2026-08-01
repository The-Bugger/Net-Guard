"""
ai_routes.py — AI explanation endpoint.

GET /ai-explanation/<event_id>

Requirements: 2.6
"""

from __future__ import annotations

from types import SimpleNamespace

from flask import Blueprint

from backend.api.dependencies import get, get_event_repo
from backend.utils.response import success_response, error_response

ai_bp = Blueprint("ai_explanation", __name__)


@ai_bp.get("/ai-explanation/<string:event_id>")
def get_ai_explanation(event_id: str):
    repo = get_event_repo()
    if repo is None:
        return error_response("Event repository unavailable.", 500, "SERVICE_UNAVAILABLE")

    event_dict = repo.get_by_id(event_id)
    if event_dict is None:
        return error_response(f"Event {event_id} not found.", 404, "NOT_FOUND")

    ai_service = get("ai_explain_service")
    if ai_service is None:
        return error_response("AI explain service unavailable.", 500, "SERVICE_UNAVAILABLE")

    # AIExplainService.generate() expects objects with attributes, not dicts.
    # SimpleNamespace is the zero-dep adapter here.
    threat_event = SimpleNamespace(**event_dict)
    base_explanation = SimpleNamespace(plain_english_text=event_dict.get("explanation", ""))

    try:
        result = ai_service.generate(threat_event, base_explanation)
    except ValueError as exc:
        return error_response(str(exc), 400, "VALIDATION_ERROR")

    return success_response(data={
        "event_id": event_id,
        "attack_name": result.attack_name,
        "severity": result.severity,
        "confidence_pct": result.confidence_pct,
        "description": result.description,
        "business_impact": result.business_impact,
        "attacker_methodology": result.attacker_methodology,
        "immediate_actions": result.immediate_actions,
        "long_term_recommendations": result.long_term_recommendations,
        "mitre_attack_mapping": result.mitre_attack_mapping,
        "cve_references": result.cve_references,
        "markdown_report": result.markdown_report,
        "is_fallback": result.is_fallback,
    })
