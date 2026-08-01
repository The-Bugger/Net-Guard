"""
reset_routes.py — Data reset endpoint.

POST /reset-data  — clears all detection events and active blocks from the DB.
Used for demo/testing to start with a clean slate.

Requirements: dev/demo utility
"""

from __future__ import annotations

from flask import Blueprint

from backend.api.dependencies import get_event_repo, get_block_repo, get_stats_service
from backend.utils.response import success_response, error_response

reset_bp = Blueprint("reset", __name__)


@reset_bp.post("/reset-data")
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
        events_deleted = _delete_all_events(event_repo)
    except Exception as exc:
        errors.append(f"events: {exc}")

    # Deactivate all blocks
    try:
        blocks_deleted = _deactivate_all_blocks(block_repo)
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


def _delete_all_events(event_repo) -> int:
    """Truncate the events table. Returns row count."""
    try:
        with event_repo._session_factory() as session:
            from database.schema import Event
            count = session.query(Event).count()
            session.query(Event).delete()
            session.commit()
            return count
    except Exception as exc:
        raise RuntimeError(f"Failed to delete events: {exc}") from exc


def _deactivate_all_blocks(block_repo) -> int:
    """Mark all active blocks inactive. Returns count."""
    try:
        with block_repo._session_factory() as session:
            from database.schema import BlockedIP
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            rows = session.query(BlockedIP).filter_by(active=1).all()
            count = len(rows)
            for r in rows:
                r.active = 0
                r.unblock_time = now
            session.commit()
            return count
    except Exception as exc:
        raise RuntimeError(f"Failed to deactivate blocks: {exc}") from exc
