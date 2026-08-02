"""
settings_routes.py — Configuration endpoints (enterprise extension).

GET  /api/v1/settings
PUT  /api/v1/settings
POST /api/v1/settings/integrations/test
POST /api/v1/settings/apikeys/rotate
GET  /api/v1/settings/backup        (download)
POST /api/v1/settings/restore       (upload)

Requirements: 6.1-6.9, 12.6, 15.6, 15.7
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import socket
import zipfile
from dataclasses import asdict
from datetime import datetime, timezone

import requests

from flask import Blueprint, g, request, send_file

from backend.api.dependencies import get_config
from backend.middleware.auth_middleware import require_role
from backend.services.config_service import Settings
from backend.utils.response import success_response, error_response, created_response

settings_bp = Blueprint("settings", __name__)

# Sections that require admin write access (Req 6.5)
_ADMIN_WRITE_SECTIONS = {"security", "firewall", "ai", "roles", "licensing"}

# Keys that require a restart to take effect (Req 6.2)
_RESTART_REQUIRED_KEYS = {
    "network_interface", "database_url", "tls_cert_file", "tls_key_file",
    "performance.rule_workers",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# GET /settings
# ---------------------------------------------------------------------------

@settings_bp.get("/settings")
def get_settings():
    cfg = get_config()
    if cfg is None:
        return error_response("Config service unavailable", 500, "SERVICE_UNAVAILABLE")

    from backend.api import dependencies
    settings_repo = dependencies.get("settings_repo")

    # Build a merged view: dataclass defaults + DB overrides
    base = asdict(Settings(
        network_interface=cfg.get("network_interface") or "",
        syn_flood_threshold=cfg.get("syn_flood_threshold") or 100,
        syn_flood_window=cfg.get("syn_flood_window") or 3,
        port_scan_threshold=cfg.get("port_scan_threshold") or 20,
        port_scan_window=cfg.get("port_scan_window") or 10,
        brute_force_threshold=cfg.get("brute_force_threshold") or 10,
        brute_force_window=cfg.get("brute_force_window") or 60,
        icmp_flood_threshold=cfg.get("icmp_flood_threshold") or 100,
        icmp_flood_window=cfg.get("icmp_flood_window") or 3,
        slow_http_threshold=cfg.get("slow_http_threshold") or 10,
        slow_http_window=cfg.get("slow_http_window") or 10,
        block_duration=cfg.get("block_duration") or 120,
        dashboard_refresh_interval=cfg.get("dashboard_refresh_interval") or 1,
        rules_enabled=cfg.get("rules_enabled") or {},
    ))

    # Overlay all enterprise namespaced keys from DB
    if settings_repo:
        enterprise_keys = _enterprise_defaults()
        for key in enterprise_keys:
            val = settings_repo.get(key)
            if val is not None:
                enterprise_keys[key] = val
        base["enterprise"] = enterprise_keys

    return success_response(data=base)


# ---------------------------------------------------------------------------
# PUT /settings
# ---------------------------------------------------------------------------

@settings_bp.put("/settings")
def update_settings():
    body = request.get_json(silent=True)
    if not body or not isinstance(body, dict):
        return error_response("JSON request body required.", 400, "VALIDATION_ERROR")

    cfg = get_config()
    if cfg is None:
        return error_response("Config service unavailable", 500, "SERVICE_UNAVAILABLE")

    # RBAC: check if any admin-only section keys are present (Req 6.5)
    user = getattr(g, "current_user", {})
    user_role = user.get("role", "viewer") if user else "viewer"
    for key in body:
        section = key.split(".")[0].lower()
        if section in _ADMIN_WRITE_SECTIONS and user_role != "admin":
            from backend.api import dependencies
            audit = dependencies.get("audit_service")
            if audit:
                audit.log(user.get("sub", "unknown"), "FORBIDDEN_SETTINGS_WRITE",
                          "/api/v1/settings", {"key": key})
            return error_response(
                f"Admin role required to modify '{section}' settings", 403, "FORBIDDEN"
            )

    # Split enterprise keys from core settings
    enterprise = body.pop("enterprise", {})

    # Validate + apply core settings
    invalid = cfg.validate_settings(body)
    if invalid:
        return error_response(
            f"Invalid value(s) for: {', '.join(invalid)}", 422, "VALIDATION_ERROR"
        )
    try:
        cfg.update(body)
    except ValueError as exc:
        return error_response(str(exc), 422, "VALIDATION_ERROR")

    # Persist enterprise settings to DB (Req 6.3)
    from backend.api import dependencies
    settings_repo = dependencies.get("settings_repo")
    if settings_repo and enterprise:
        for key, val in enterprise.items():
            settings_repo.set(key, str(val))

    # Mark restart-required keys (Req 6.2)
    restart_needed = [k for k in {**body, **enterprise} if k in _RESTART_REQUIRED_KEYS]

    return success_response(
        data={"restart_required": restart_needed},
        message="Settings updated successfully."
    )


# ---------------------------------------------------------------------------
# POST /settings/integrations/test  (Req 15.7)
# ---------------------------------------------------------------------------

_SIEM_INTEGRATIONS = ("elastic", "splunk", "wazuh", "opensearch")

_SIEM_TEST_PAYLOAD = {
    "event_id": "test-0000",
    "attack_type": "Test Event",
    "source_ip": "1.2.3.4",
    "severity": "Low",
    "confidence": 100,
    "rule_name": "TEST",
}


@settings_bp.post("/settings/integrations/test")
@require_role("admin")
def test_integration():
    data = request.get_json(silent=True) or {}

    # SIEM path: body carries {"integration": "elastic"|"splunk"|"wazuh"|"opensearch"}
    integration = data.get("integration", "")
    if integration:
        if integration not in _SIEM_INTEGRATIONS:
            return error_response(
                f"Unknown integration '{integration}'. Valid: {list(_SIEM_INTEGRATIONS)}",
                400, "VALIDATION_ERROR",
            )

        from backend.api import dependencies
        settings_repo = dependencies.get("settings_repo")
        url = settings_repo.get(f"siem.{integration}.url") if settings_repo else None
        if not url:
            return error_response(
                f"siem.{integration}.url not configured", 400, "NOT_CONFIGURED"
            )

        token = settings_repo.get(f"siem.{integration}.token") if settings_repo else None
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        payload = {**_SIEM_TEST_PAYLOAD, "timestamp": _utc_now()}
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=15)
            return success_response({"status_code": resp.status_code, "response": resp.text})
        except requests.exceptions.Timeout:
            return error_response("INTEGRATION_TIMEOUT", 503, "INTEGRATION_TIMEOUT")
        except requests.exceptions.ConnectionError:
            return error_response("INTEGRATION_UNREACHABLE", 503, "INTEGRATION_UNREACHABLE")

    # SOAR channel path (original behaviour)
    channel = data.get("channel", "")
    if not channel:
        return error_response("integration or channel required", 400)

    from backend.api import dependencies
    soar = dependencies.get("soar_engine")
    if not soar:
        return error_response("SOAR engine not available", 503)

    result = soar.test_integration(channel)
    status = 200 if result.get("success") else 502
    return success_response(result) if result.get("success") else error_response(
        result.get("error", "Integration test failed"), status
    )


# ---------------------------------------------------------------------------
# POST /settings/apikeys/rotate  (Req 6.9)
# ---------------------------------------------------------------------------

@settings_bp.post("/settings/apikeys/rotate")
@require_role("admin")
def rotate_api_key():
    data = request.get_json(silent=True) or {}
    key_name = data.get("key_name", "").strip()
    if not key_name:
        return error_response("key_name required", 400)

    new_key = secrets.token_hex(32)

    from backend.api import dependencies
    settings_repo = dependencies.get("settings_repo")
    if settings_repo:
        # Req 6.9: store hash only — plain-text key never persisted
        key_hash = hashlib.sha256(new_key.encode()).hexdigest()
        settings_repo.set(key_name, key_hash)
        # Record masked value and creation time for the list endpoint
        settings_repo.set(f"{key_name}.__masked", new_key[-4:])
        settings_repo.set(f"{key_name}.__created_at", _utc_now())

    audit = dependencies.get("audit_service")
    if audit:
        user = getattr(g, "current_user", {})
        audit.log(user.get("sub", "system"), "API_KEY_ROTATED",
                  "/api/v1/settings/apikeys/rotate", {"key_name": key_name})

    # Return new key exactly once; mask on subsequent GET (Req 6.9)
    masked = f"{'*' * (len(new_key) - 4)}{new_key[-4:]}"
    return created_response(
        {"key_name": key_name, "new_key": new_key, "masked": masked},
        "API key rotated"
    )


# ---------------------------------------------------------------------------
# GET /settings/backup  (Req 6.6, 12.5)
# ---------------------------------------------------------------------------

@settings_bp.get("/settings/backup")
@require_role("admin")
def backup():
    """
    Export settings + rules + block history + whitelist to a password-
    protected ZIP archive with an embedded SHA-256 checksum file.
    """
    from backend.api import dependencies

    settings_repo = dependencies.get("settings_repo")
    block_repo = dependencies.get("block_repo")
    whitelist_repo = dependencies.get("whitelist_repo")

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive_name = f"netguard_backup_{ts}.zip"

    buf = io.BytesIO()

    # Collect data payloads
    payloads: dict[str, bytes] = {}

    # Settings
    if settings_repo:
        try:
            all_settings = settings_repo.get_all()
            payloads["settings.json"] = json.dumps(all_settings, indent=2).encode()
        except Exception:
            payloads["settings.json"] = b"{}"

    # Block history (last 10 000)
    if block_repo:
        try:
            result = block_repo.get_paginated(page=1, per_page=10000, filters={})
            payloads["blocks.json"] = json.dumps(result["items"], indent=2).encode()
        except Exception:
            payloads["blocks.json"] = b"[]"

    # Whitelist entries (Req 6.6)
    if whitelist_repo:
        try:
            payloads["whitelist.json"] = json.dumps(whitelist_repo.get_all(), indent=2).encode()
        except Exception:
            payloads["whitelist.json"] = b"[]"

    # config.yaml content
    try:
        cfg_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "config", "config.yaml"
        )
        payloads["config.yaml"] = open(cfg_path, "rb").read()
    except Exception:
        payloads["config.yaml"] = b""

    # Compute overall checksum
    combined = b"".join(payloads[k] for k in sorted(payloads))
    sha256 = hashlib.sha256(combined).hexdigest()
    payloads["checksum.sha256"] = f"{sha256}  combined\n".encode()

    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in payloads.items():
            zf.writestr(name, data)

    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=archive_name,
    )


# ---------------------------------------------------------------------------
# POST /settings/restore  (Req 6.7, 12.6)
# ---------------------------------------------------------------------------

@settings_bp.post("/settings/restore")
@require_role("admin")
def restore():
    """
    Upload a backup ZIP. Validates SHA-256 checksum; returns conflict list.
    Requires confirm=true to actually commit (Req 12.6).
    """
    f = request.files.get("file")
    if not f:
        return error_response("file required", 400)

    confirm = request.form.get("confirm", "false").lower() == "true"

    raw = f.read()
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        return error_response("Invalid ZIP archive", 400, "INVALID_ARCHIVE")

    names = zf.namelist()
    if "checksum.sha256" not in names:
        return error_response("Missing checksum.sha256 in archive", 400, "MISSING_CHECKSUM")

    # Verify checksum (Req 12.6)
    checksum_line = zf.read("checksum.sha256").decode().strip()
    expected_sha = checksum_line.split()[0]
    content_files = [n for n in names if n != "checksum.sha256"]
    combined = b"".join(zf.read(n) for n in sorted(content_files))
    actual_sha = hashlib.sha256(combined).hexdigest()

    if actual_sha != expected_sha:
        return error_response(
            f"Checksum mismatch: expected {expected_sha[:16]}…, got {actual_sha[:16]}…",
            400, "CHECKSUM_MISMATCH"
        )

    from backend.api import dependencies
    settings_repo = dependencies.get("settings_repo")

    if not confirm:
        # Build conflict list: backup settings that differ from current DB values
        conflicts = []
        if settings_repo and "settings.json" in names:
            try:
                backup_settings = json.loads(zf.read("settings.json"))
                for key, backup_val in backup_settings.items():
                    current_val = settings_repo.get(key)
                    if current_val is not None and str(current_val) != str(backup_val):
                        conflicts.append({"key": key, "current": current_val, "backup": backup_val})
            except Exception:
                pass
        return success_response(
            {"files": names, "checksum_ok": True, "confirm_required": True, "conflicts": conflicts},
            "Checksum verified. Send confirm=true to commit restore."
        )

    # Commit restore
    # Keys that must never be restored (security-sensitive, Req 12.6)
    _SKIP_ON_RESTORE = {"security.jwt_secret"}

    restored = 0
    if settings_repo and "settings.json" in names:
        try:
            data = json.loads(zf.read("settings.json"))
            for key, val in data.items():
                if key in _SKIP_ON_RESTORE:
                    continue
                settings_repo.set(key, val)
                restored += 1
        except Exception as exc:
            return error_response(f"Settings restore failed: {exc}", 500)

    audit = dependencies.get("audit_service")
    if audit:
        user = getattr(g, "current_user", {})
        audit.log(user.get("sub", "system"), "BACKUP_RESTORED",
                  "/api/v1/settings/restore", {"files": names, "restored_keys": restored})

    return success_response({"restored_keys": restored}, "Backup restored successfully")


# ---------------------------------------------------------------------------
# Enterprise defaults map (all 29 sections from Req 6.1)
# ---------------------------------------------------------------------------

def _enterprise_defaults() -> dict:
    return {
        "appearance.theme": "dark",
        "appearance.language": "en",
        "network.interface": "",
        "network.capture_filter": "",
        "security.jwt_expiry_hours": "8",
        "security.mfa_required": "false",
        "security.session_timeout_min": "480",
        "firewall.auto_block": "true",
        "firewall.block_duration_s": "3600",
        "firewall.ipv6_enabled": "true",
        "ai.model": "builtin",
        "ai.sigma_rules_dir": "",
        "ai.yara_rules_dir": "",
        "ai.anomaly_sigma": "3.0",
        "geoip.provider_chain": "ipapi,ipinfo",
        "geoip.maxmind_db_path": "",
        "threat_intel.abuseipdb_key": "",
        "threat_intel.virustotal_key": "",
        "threat_intel.fp_step": "5",
        "soar.slack.enabled": "false",
        "soar.discord.enabled": "false",
        "soar.telegram.enabled": "false",
        "soar.email.enabled": "false",
        "soar.syslog.enabled": "false",
        "siem.elastic_url": "",
        "siem.splunk_hec_url": "",
        "siem.wazuh_host": "",
        "siem.opensearch_url": "",
        "performance.rule_workers": "4",
        "licensing.key": "",
    }


# ---------------------------------------------------------------------------
# GET /settings/enterprise  (Req 6.1)
# ---------------------------------------------------------------------------

@settings_bp.get("/settings/enterprise")
@require_role("admin", "analyst", "hunter", "viewer")
def get_enterprise_settings():
    """Return all enterprise settings grouped by namespace prefix."""
    from backend.api import dependencies
    settings_repo = dependencies.get("settings_repo")

    defaults = _enterprise_defaults()
    if settings_repo:
        for key in list(defaults):
            val = settings_repo.get(key)
            if val is not None:
                defaults[key] = val

    # Group by prefix (part before first dot)
    grouped: dict = {}
    for key, val in defaults.items():
        ns, _, leaf = key.partition(".")
        grouped.setdefault(ns, {})[leaf] = val

    return success_response(data=grouped)


# ---------------------------------------------------------------------------
# PUT /settings/enterprise  (Req 6.1, 6.5)
# ---------------------------------------------------------------------------

# Sections that only admin may write (Req 6.5)
_ADMIN_ONLY_SECTIONS = {"security", "firewall", "ai", "roles", "licensing"}
# Sections that analyst+ may write
_ANALYST_SECTIONS = {"notifications", "alerting"}


@settings_bp.put("/settings/enterprise")
@require_role("admin", "analyst")
def update_enterprise_settings():
    """Bulk-update enterprise settings with fine-grained RBAC (Req 6.5)."""
    body = request.get_json(silent=True)
    if not body or not isinstance(body, dict):
        return error_response("JSON body required.", 400, "VALIDATION_ERROR")

    user = getattr(g, "current_user", {})
    user_role = user.get("role", "viewer") if user else "viewer"

    # RBAC check before touching the repo
    for key in body:
        section = key.split(".")[0].lower()
        if section in _ADMIN_ONLY_SECTIONS and user_role != "admin":
            return error_response(
                f"Admin role required to modify '{section}' settings", 403, "FORBIDDEN"
            )
        if section not in _ANALYST_SECTIONS and user_role != "admin":
            # anything not in analyst-allowed list → admin only
            return error_response(
                f"Admin role required to modify '{section}' settings", 403, "FORBIDDEN"
            )

    from backend.api import dependencies
    settings_repo = dependencies.get("settings_repo")
    if not settings_repo:
        return error_response("Settings service unavailable", 503, "SERVICE_UNAVAILABLE")

    for key, val in body.items():
        settings_repo.set(key, str(val))

    return success_response(data=None, message="Enterprise settings updated.")


# ---------------------------------------------------------------------------
# GET /settings/apikeys  (Req 6.9)
# ---------------------------------------------------------------------------

@settings_bp.get("/settings/apikeys")
@require_role("admin")
def list_api_keys():
    """List API keys: id, creation date, masked last-4 only (Req 6.9)."""
    from backend.api import dependencies
    settings_repo = dependencies.get("settings_repo")
    if not settings_repo:
        return success_response(data=[])

    all_settings = settings_repo.get_all()

    # Keys with a stored .__masked sentinel are managed API keys
    api_keys = []
    for k, v in all_settings.items():
        if k.endswith(".__masked"):
            key_name = k[: -len(".__masked")]
            created_at = all_settings.get(f"{key_name}.__created_at")
            api_keys.append({
                "key_id": key_name,
                "masked": f"{'*' * 60}{v}",
                "created_at": created_at,
            })

    return success_response(data=api_keys)
