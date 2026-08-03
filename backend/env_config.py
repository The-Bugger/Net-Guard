"""
env_config.py — Single source of truth for NetGuard environment variables.

All process-level configuration read from the environment lives here so that:
  * every supported variable is documented in one place,
  * defaults are defined once (no divergent fallbacks across files),
  * tests can monkeypatch a single module.

Detection-threshold settings are separate — see
backend/services/config_service.py (ConfigurationManager / Settings), which
persists user-tunable values to the database. This module is for deployment /
process config that must be known before the DB or services exist.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class EnvConfig:
    """Immutable snapshot of process-level environment configuration."""

    # Logging
    log_level: str = "INFO"

    # Database
    database_url: str = ""

    # API server
    flask_host: str = "0.0.0.0"
    flask_port: int = 5000
    allowed_origins: str = "*"
    socketio_async_mode: str = ""  # empty → auto (eventlet on Linux, threading on Windows)

    # TLS (both must be set to enable HTTPS)
    tls_cert_file: str = ""
    tls_key_file: str = ""

    # Auth / security middleware
    netguard_api_key: str = ""
    require_auth_for_reads: bool = False

    # Detection / analysis
    anomaly_baseline_window: float = 300.0

    # AI explanation providers
    ai_provider: str = "stub"
    gemini_api_key: str = ""
    openai_api_key: str = ""

    # Optional Redis (SOAR / caching); empty → disabled
    redis_url: str = "redis://localhost:6379/0"


def load_env(project_root: Path | None = None) -> EnvConfig:
    """Read all supported environment variables into an EnvConfig snapshot."""
    default_db = ""
    if project_root is not None:
        default_db = f"sqlite:///{project_root}/database/netguard.db"

    return EnvConfig(
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
        database_url=os.environ.get("DATABASE_URL", default_db),
        flask_host=os.environ.get("FLASK_HOST", "0.0.0.0"),
        flask_port=int(os.environ.get("FLASK_PORT", "5000")),
        allowed_origins=os.environ.get("ALLOWED_ORIGINS", "*"),
        socketio_async_mode=os.environ.get("SOCKETIO_ASYNC_MODE", ""),
        tls_cert_file=os.environ.get("TLS_CERT_FILE", ""),
        tls_key_file=os.environ.get("TLS_KEY_FILE", ""),
        netguard_api_key=os.environ.get("NETGUARD_API_KEY", ""),
        require_auth_for_reads=_bool("REQUIRE_AUTH_FOR_READS", False),
        anomaly_baseline_window=float(os.environ.get("ANOMALY_BASELINE_WINDOW", "300")),
        ai_provider=os.environ.get("AI_PROVIDER", "stub").lower(),
        gemini_api_key=os.environ.get("GEMINI_API_KEY", ""),
        openai_api_key=os.environ.get("OPENAI_API_KEY", ""),
        redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
    )
