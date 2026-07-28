"""
health_routes.py — GET /health and GET /status endpoints.

Requirements: 13.1, 13.2, 13.3, 13.4, 13.5
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from flask import Blueprint

from backend.api.dependencies import get_monitoring_state, get_detection_engine
from backend.utils.response import success_response

health_bp = Blueprint("health", __name__)

_START_TIME: float = time.monotonic()


@health_bp.get("/health")
def health():
    """Liveness check."""
    elapsed = time.monotonic() - _START_TIME
    hours, rem = divmod(int(elapsed), 3600)
    minutes, secs = divmod(rem, 60)
    return success_response(data={
        "status": "healthy",
        "version": "1.0.0",
        "uptime": f"{hours:02d}:{minutes:02d}:{secs:02d}",
    })


@health_bp.get("/status")
def status():
    """Monitoring status overview."""
    state = get_monitoring_state()
    engine = get_detection_engine()

    monitoring = state.active if state else False
    interface = state.interface if state else ""
    packets = state.packets_processed if state else 0
    active_blocks = state.active_blocks if state else 0

    return success_response(data={
        "monitoring": monitoring,
        "interface": interface,
        "packets_processed": packets,
        "active_blocks": active_blocks,
        "detection_engine_running": engine.is_running if engine else False,
    })
