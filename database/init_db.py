"""
init_db.py — Database initialization for NetGuard IDPS.

Creates the SQLite database and all required tables on first startup.
Seeds default detection rules and settings if the database is new.

Requirements: 14.1
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from database.schema import (
    Base,
    DetectionRule,
    Setting,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
_DB_PATH: Path = _PROJECT_ROOT / "database" / "netguard.db"
_DB_URL: str = f"sqlite:///{_DB_PATH}"

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

logger = logging.getLogger("netguard.init_db")


# ---------------------------------------------------------------------------
# Default seed data
# ---------------------------------------------------------------------------

_DEFAULT_RULES: list[dict] = [
    {
        "rule_name": "SYN_FLOOD_001",
        "attack_type": "SYN Flood",
        "threshold": 100,
        "severity": "High",
        "block_duration": 120,
        "enabled": 1,
        "priority": 1,
        "description": (
            "Detects volumetric TCP SYN floods. "
            "Triggers when a single source IP sends ≥100 SYN packets within 3 seconds."
        ),
    },
    {
        "rule_name": "PORT_SCAN_001",
        "attack_type": "Port Scan",
        "threshold": 20,
        "severity": "Medium",
        "block_duration": 120,
        "enabled": 1,
        "priority": 2,
        "description": (
            "Detects port scanning activity. "
            "Triggers when a single source IP connects to ≥20 unique ports within 10 seconds."
        ),
    },
    {
        "rule_name": "SQL_INJECTION_001",
        "attack_type": "SQL Injection",
        "threshold": 1,
        "severity": "High",
        "block_duration": 120,
        "enabled": 1,
        "priority": 3,
        "description": (
            "Detects SQL injection payloads in HTTP traffic. "
            "Triggers on a single matching pattern in the URL path, query string, or body."
        ),
    },
    {
        "rule_name": "BRUTE_FORCE_001",
        "attack_type": "Brute Force",
        "threshold": 10,
        "severity": "Medium",
        "block_duration": 120,
        "enabled": 1,
        "priority": 4,
        "description": (
            "Detects brute-force login attempts. "
            "Triggers when a source IP accumulates ≥10 auth failures within 60 seconds."
        ),
    },
    {
        "rule_name": "ARP_SPOOF_001",
        "attack_type": "ARP Spoofing",
        "threshold": 2,
        "severity": "High",
        "block_duration": 120,
        "enabled": 1,
        "priority": 5,
        "description": (
            "Detects ARP spoofing attacks. "
            "Triggers when two or more different MAC addresses claim the same IP."
        ),
    },
]

_DEFAULT_SETTINGS: list[dict] = [
    {"key": "network_interface", "value": ""},
    {"key": "syn_flood_threshold", "value": "100"},
    {"key": "syn_flood_window", "value": "3"},
    {"key": "port_scan_threshold", "value": "20"},
    {"key": "port_scan_window", "value": "10"},
    {"key": "brute_force_threshold", "value": "10"},
    {"key": "brute_force_window", "value": "60"},
    {"key": "block_duration", "value": "120"},
    {"key": "dashboard_refresh_interval", "value": "1"},
    {"key": "rules_enabled", "value": json.dumps({
        "syn_flood": True,
        "port_scan": True,
        "sql_injection": True,
        "brute_force": True,
        "arp_spoof": True,
    })},
    {"key": "debug", "value": "false"},
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def initialize_db(db_url: str | None = None) -> None:
    """
    Create the NetGuard SQLite database and seed default data.

    If the database file already exists, this function is idempotent — it
    will create any missing tables and insert only missing seed rows.

    Args:
        db_url: SQLAlchemy database URL.  Defaults to the project-relative
                sqlite:///database/netguard.db path.

    Raises:
        RuntimeError: If database creation or seeding fails in a way that
                      cannot be recovered from.
    """
    url = db_url or _DB_URL
    logger.info("Initializing database at: %s", url)

    try:
        engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            echo=False,
        )

        # Enable WAL mode for better concurrent read/write performance
        with engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL"))
            conn.execute(text("PRAGMA foreign_keys=ON"))
            conn.commit()

        # Create all tables (no-op if they already exist)
        Base.metadata.create_all(engine)
        logger.info("All database tables created or verified.")

        # Seed default data
        with Session(engine) as session:
            _seed_detection_rules(session)
            _seed_settings(session)
            session.commit()

        logger.info("Database initialization complete.")

    except Exception as exc:
        logger.critical("Database initialization failed: %s", exc, exc_info=True)
        raise RuntimeError(f"Database initialization failed: {exc}") from exc


def get_engine(db_url: str | None = None):
    """
    Return a configured SQLAlchemy engine for the NetGuard database.

    Args:
        db_url: Database URL. Defaults to the project-relative SQLite path.

    Returns:
        sqlalchemy.Engine instance.
    """
    url = db_url or _DB_URL
    return create_engine(
        url,
        connect_args={"check_same_thread": False},
        echo=False,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _tables_were_populated(engine) -> bool:
    """Return True if the detection_rules table already has rows."""
    inspector = inspect(engine)
    if "detection_rules" not in inspector.get_table_names():
        return False
    with Session(engine) as session:
        count = session.query(DetectionRule).count()
        return count > 0


def _seed_detection_rules(session: Session) -> None:
    """Insert default detection rules if they don't already exist."""
    for rule_data in _DEFAULT_RULES:
        existing = (
            session.query(DetectionRule)
            .filter_by(rule_name=rule_data["rule_name"])
            .first()
        )
        if existing is None:
            rule = DetectionRule(
                rule_name=rule_data["rule_name"],
                attack_type=rule_data["attack_type"],
                threshold=rule_data["threshold"],
                severity=rule_data["severity"],
                block_duration=rule_data["block_duration"],
                enabled=rule_data["enabled"],
                priority=rule_data["priority"],
                description=rule_data["description"],
            )
            session.add(rule)
            logger.debug("Seeded detection rule: %s", rule_data["rule_name"])


def _seed_settings(session: Session) -> None:
    """Insert default settings if they don't already exist."""
    now = _utc_now()
    for setting_data in _DEFAULT_SETTINGS:
        existing = (
            session.query(Setting)
            .filter_by(key=setting_data["key"])
            .first()
        )
        if existing is None:
            setting = Setting(
                key=setting_data["key"],
                value=setting_data["value"],
                updated_at=now,
            )
            session.add(setting)
            logger.debug("Seeded setting: %s", setting_data["key"])


def _utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    initialize_db()
    print("NetGuard database initialized successfully.")
