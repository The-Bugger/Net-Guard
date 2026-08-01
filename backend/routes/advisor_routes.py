"""
advisor_routes.py — GET /api/v1/advisor

Returns contextual security advice from SecurityAdvisor.

Requirements: 10.6
"""

from __future__ import annotations

from flask import Blueprint, jsonify

from backend.api.dependencies import get_event_repo, get_security_advisor, get_stats_service

advisor_bp = Blueprint("advisor", __name__)


@advisor_bp.route("/advisor", methods=["GET"])
def get_advisor():
    """
    Return current security advice.

    Calls SecurityAdvisor.advise() with:
    - current health score from StatsService
    - distinct attack types detected today from EventRepository
    """
    stats_service = get_stats_service()
    event_repo = get_event_repo()
    security_advisor = get_security_advisor()

    health_score = stats_service.get_health_score() if stats_service else 100
    today_attack_types = list(event_repo.get_distinct_attack_types_today()) if event_repo else []

    result = security_advisor.advise(health_score, today_attack_types)
    return jsonify(result), 200
