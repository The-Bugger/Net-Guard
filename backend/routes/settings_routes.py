"""
settings_routes.py — Configuration endpoints.

GET /settings
PUT /settings

Requirements: 1.4, 1.5, 13.2, 13.3, 13.4
"""

from __future__ import annotations

from dataclasses import asdict

from flask import Blueprint, request

from backend.api.dependencies import get_config
from backend.services.config_service import Settings
from backend.utils.response import success_response, error_response

settings_bp = Blueprint("settings", __name__)


@settings_bp.get("/settings")
def get_settings():
    cfg = get_config()
    if cfg is None:
        return error_response("Config service unavailable", 500, "SERVICE_UNAVAILABLE")
    # Return current settings as a plain dict
    settings = Settings(
        network_interface=cfg.get("network_interface") or "",
        syn_flood_threshold=cfg.get("syn_flood_threshold") or 100,
        syn_flood_window=cfg.get("syn_flood_window") or 3,
        port_scan_threshold=cfg.get("port_scan_threshold") or 20,
        port_scan_window=cfg.get("port_scan_window") or 10,
        brute_force_threshold=cfg.get("brute_force_threshold") or 10,
        brute_force_window=cfg.get("brute_force_window") or 60,
        block_duration=cfg.get("block_duration") or 120,
        dashboard_refresh_interval=cfg.get("dashboard_refresh_interval") or 1,
        rules_enabled=cfg.get("rules_enabled") or {},
    )
    return success_response(data=asdict(settings))


@settings_bp.put("/settings")
def update_settings():
    body = request.get_json(silent=True)
    if not body or not isinstance(body, dict):
        return error_response("JSON request body required.", 400, "VALIDATION_ERROR")

    cfg = get_config()
    if cfg is None:
        return error_response("Config service unavailable", 500, "SERVICE_UNAVAILABLE")

    # Validate first
    invalid = cfg.validate_settings(body)
    if invalid:
        return error_response(
            f"Invalid value(s) for field(s): {', '.join(invalid)}",
            422,
            "VALIDATION_ERROR",
        )

    try:
        cfg.update(body)
    except ValueError as exc:
        return error_response(str(exc), 422, "VALIDATION_ERROR")
    except Exception as exc:
        return error_response(f"Failed to update settings: {exc}", 500, "DATABASE_ERROR")

    return success_response(message="Settings updated successfully.")
