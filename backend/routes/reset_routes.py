"""
reset_routes.py — Data reset endpoint.

POST /reset-data  — clears all detection events and active blocks from the DB.
Used for demo/testing to start with a clean slate.

Requirements: dev/demo utility
"""

from __future__ import annotations

from flask import Blueprint

from backend.api.dependencies import get_event_repo, get_block_repo, get_stats_service
from backend.middleware.auth_middleware import require_role
from backend.utils.response import success_response, error_response

reset_bp = Blueprint("reset", __name__)


@reset_bp.post("/reset-data")
@require_role("admin")
def reset_data():
    """
    DELETE all detection events and active blocks, then invalidate stats cache.
    Returns counts of deleted records.
    """
    event_repo = get_event_repo()
    block_repo = get_block_repo()
    stats_svc  = get_stats_service()

    if event_repo is None or block_repo is None:
        return error_response("Repositories unavailable", 500, "SERVICE_UNAVAILABLE")

    events_deleted = 0
    blocks_deleted = 0
    errors = []

    # Delete all events
    try:
        events_deleted = event_repo.delete_all()
    except Exception as exc:
        errors.append(f"events: {exc}")

    # Deactivate all blocks
    try:
        blocks_deleted = block_repo.deactivate_all()
    except Exception as exc:
        errors.append(f"blocks: {exc}")

    # Invalidate stats cache so next /dashboard reflects the reset
    if stats_svc:
        try:
            stats_svc.invalidate_cache()
        except Exception:
            pass

    if errors:
        return error_response(
            f"Partial reset — errors: {'; '.join(errors)}",
            500, "PARTIAL_RESET"
        )

    return success_response(
        data={"events_deleted": events_deleted, "blocks_deleted": blocks_deleted},
        message=f"Reset complete: {events_deleted} event(s) and {blocks_deleted} block(s) cleared.",
    )
