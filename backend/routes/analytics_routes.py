"""
analytics_routes.py — Analytics endpoint.

GET /analytics?period=<hourly|daily|weekly>

Requirements: 5.1, 5.2, 5.3, 5.4
"""

from __future__ import annotations

from flask import Blueprint, request

from backend.api.dependencies import get_event_repo
from backend.utils.response import success_response, error_response

analytics_bp = Blueprint("analytics", __name__)


def _compute_analytics(event_repo, period: str) -> dict:
    from datetime import datetime, timezone, timedelta
    from collections import defaultdict

    now = datetime.now(timezone.utc)

    # Normalise period — any unrecognised value falls back to daily
    if period == "hourly":
        num_buckets, delta = 24, timedelta(hours=1)
        fmt = "%Y-%m-%dT%H:00"
    elif period == "weekly":
        num_buckets, delta = 4, timedelta(weeks=1)
        fmt = "%Y-W%W"
    else:
        num_buckets, delta = 7, timedelta(days=1)
        fmt = "%Y-%m-%d"

    window_start = now - delta * num_buckets

    # ponytail: O(events) grouping in Python; fine for hackathon (<10K events).
    # Upgrade path: push GROUP BY + strftime into SQLAlchemy query if dataset grows.
    all_events = event_repo.get_all(filters={}, limit=10000, offset=0)

    # Filter to the period window
    period_events: list[tuple] = []
    for e in all_events:
        try:
            ts = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
            if ts >= window_start:
                period_events.append((ts, e))
        except (ValueError, TypeError, AttributeError):
            pass

    # Build bucket labels: bucket i covers [now - delta*(i+1), now - delta*i)
    # Label each bucket by its START time so that an event at time T belongs to
    # the bucket whose start is floor(T to bucket boundary).
    # We generate labels for starts: now-delta*num_buckets, ..., now-delta*1
    # i.e. b_start = now - delta * (i+1) for i in range(num_buckets-1, -1, -1)
    # An event with ts in [b_start, b_start+delta) has label = b_start.strftime(fmt).
    # We assign each event's label as the bucket start, NOT ts.strftime(fmt), to
    # guarantee sum(bucket counts) == total_events (Property 6).

    bucket_labels: list[str] = []
    bucket_starts: list[datetime] = []
    for i in range(num_buckets - 1, -1, -1):
        b_start = now - delta * (i + 1)
        bucket_labels.append(b_start.strftime(fmt))
        bucket_starts.append(b_start)

    # Build a lookup: label -> (b_start, b_end) for fast bucket assignment
    bucket_bounds: list[tuple] = []
    for idx, b_start in enumerate(bucket_starts):
        b_end = b_start + delta
        bucket_bounds.append((bucket_labels[idx], b_start, b_end))

    bucket_counts: dict[str, int] = defaultdict(int)
    bucket_breakdown: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    # Assign each event to the correct bucket by comparing against boundaries
    # (avoids strftime collisions between e.g. hourly buckets spanning midnight)
    for ts, e in period_events:
        assigned = False
        for label, b_start, b_end in bucket_bounds:
            if b_start <= ts < b_end:
                bucket_counts[label] += 1
                bucket_breakdown[label][e.get("attack_type") or "Unknown"] += 1
                assigned = True
                break
        # ponytail: if ts == now exactly (floating boundary) it falls outside all
        # buckets; extremely rare, count it in the last bucket to keep sum invariant.
        if not assigned and period_events:
            last_label = bucket_labels[-1]
            bucket_counts[last_label] += 1
            bucket_breakdown[last_label][e.get("attack_type") or "Unknown"] += 1

    buckets = [
        {
            "bucket": label,
            "count": bucket_counts[label],
            "breakdown": dict(bucket_breakdown[label]),
        }
        for label in bucket_labels
    ]

    # Aggregations
    top_ip_counts: dict[str, int] = defaultdict(int)
    severity_counts: dict[str, int] = defaultdict(int)
    protocol_counts: dict[str, int] = defaultdict(int)
    blocked_count = 0
    detected_count = 0

    for _, e in period_events:
        top_ip_counts[e.get("source_ip") or "unknown"] += 1
        severity_counts[e.get("severity") or "Unknown"] += 1
        protocol_counts[e.get("protocol") or "Unknown"] += 1
        if e.get("blocked"):
            blocked_count += 1
        else:
            detected_count += 1

    top_ips = sorted(
        [{"source_ip": ip, "count": cnt} for ip, cnt in top_ip_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:5]

    return {
        "buckets": buckets,
        "top_ips": top_ips,
        "severity_counts": dict(severity_counts),
        "protocol_counts": dict(protocol_counts),
        "total_events": len(period_events),
        "blocked_count": blocked_count,
        "detected_count": detected_count,
    }


@analytics_bp.get("/analytics")
def get_analytics():
    repo = get_event_repo()
    if repo is None:
        return error_response("Event repository unavailable.", 500, "SERVICE_UNAVAILABLE")

    period = request.args.get("period", "daily")
    data = _compute_analytics(repo, period)
    return success_response(data=data)
