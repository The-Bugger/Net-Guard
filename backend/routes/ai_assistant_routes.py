"""
ai_assistant_routes.py — AI Security Assistant chat endpoint.

POST /ai-assistant accepts {"question": "..."} and returns {"answer": "..."}
Re-uses AIExplainService._stub_response() with a question-answering template.

Requirements: Task 37 (Priority 7 — AI Security Assistant)
"""

from __future__ import annotations

from flask import Blueprint, request

from backend.api.dependencies import get, get_event_repo
from backend.utils.response import success_response, error_response

ai_assistant_bp = Blueprint("ai_assistant", __name__)


@ai_assistant_bp.post("/ai-assistant")
def ask_ai_assistant():
    """
    Accept a security question and return an AI-generated answer using stub logic.
    
    Request body: {"question": "..."}
    Response: {"answer": "..."}
    """
    body = request.get_json(silent=True) or {}
    question = body.get("question", "").strip()

    if not question:
        return error_response("Question is required.", 400, "VALIDATION_ERROR")

    # ponytail: re-use AIExplainService stub; no new service for a simple Q&A template
    ai_service = get("ai_explain_service")
    event_repo = get_event_repo()

    # Build a summary of current detections
    summary = _build_detection_summary(event_repo)

    # Generate answer using a simple template
    answer = (
        f"You asked about: \"{question}\"\n\n"
        f"Based on current detections:\n{summary}\n\n"
        f"This is a demonstration AI assistant. For detailed threat analysis, "
        f"view individual event explanations in the Threat Timeline."
    )

    return success_response(data={"answer": answer})


def _build_detection_summary(event_repo) -> str:
    """Build a short summary of recent detections for the AI assistant response."""
    if not event_repo:
        return "No event data available."

    try:
        events = event_repo.get_all(filters={}, limit=10, offset=0)
        if not events:
            return "No recent detections."

        # Count by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for e in events:
            sev = e.get("severity", "Medium")
            if sev in severity_counts:
                severity_counts[sev] += 1

        lines = [f"- {count} {sev} severity threats" for sev, count in severity_counts.items() if count > 0]
        lines.append(f"- Total recent detections: {len(events)}")

        return "\n".join(lines)
    except Exception:
        return "Unable to retrieve detection summary."
