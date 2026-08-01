"""
timeline_routes.py — Timeline endpoint for a single threat event.

GET /timeline/<event_id>

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.7
"""

from __future__ import annotations

from datetime import datetime, timedelta

from flask import Blueprint

from backend.api.dependencies import get, get_event_repo
from backend.utils.response import success_response, error_response

timeline_bp = Blueprint("timeline", __name__)


def _build_timeline(event: dict, block: dict | None) -> list[dict]:
    """
    Build ordered timeline entries for a threat event.

    Steps: Detected → Analyzed → Blocked → Notified → Reported
    """
    detected_ts = event["timestamp"]

    # Analyzed: use analyzed_at if present, else detected + 500ms
    analyzed_ts = event.get("analyzed_at")
    if not analyzed_ts:
        analyzed_ts = (
            datetime.fromisoformat(detected_ts.replace("Z", "+00:00"))
            + timedelta(milliseconds=500)
        ).isoformat()

    return [
        {
            "step_name": "Detected",
            "timestamp": detected_ts,
            "description": f"Attack detected by {event['rule_name']}",
            "status": "completed",
        },
        {
            "step_name": "Analyzed",
            "timestamp": analyzed_ts,
            "description": "Explanation generated",
            "status": "completed",
        },
        {
            "step_name": "Blocked",
            "timestamp": block["blocked_at"] if block else None,
            "description": "Source IP blocked" if block else "IP not blocked",
            "status": "completed" if block else "skipped",
        },
        {
            "step_name": "Notified",
            "timestamp": None,
            "description": "No notification sent",
            "status": "skipped",
        },
        {
            "step_name": "Reported",
            "timestamp": None,
            "description": "No report generated",
            "status": "skipped",
        },
    ]


@timeline_bp.get("/timeline/<string:event_id>")
def get_timeline(event_id: str):
    event_repo = get_event_repo()
    if event_repo is None:
        return error_response("Event repository unavailable.", 500, "SERVICE_UNAVAILABLE")

    event = event_repo.get_by_id(event_id)
    if event is None:
        return error_response(f"Event {event_id} not found.", 404, "NOT_FOUND")

    block_repo = get("block_repo")
    block = block_repo.get_active(event["source_ip"]) if block_repo else None

    entries = _build_timeline(event, block)
    return success_response(data={"timeline": entries})
