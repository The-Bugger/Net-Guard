"""
migrate.py — Idempotent database migrations for Net-Guard Enterprise IDPS.

Adds new columns to existing tables and creates new tables.
Called from init_db.initialize_db() on every startup — all statements are
safe to re-run (CREATE TABLE IF NOT EXISTS, ADD COLUMN guarded by inspection).

Requirements: 1.1, 1.3, 2.1, 10.1, 13.1, 14.1, 14.5
"""

from __future__ import annotations

import logging

from sqlalchemy import inspect, text

logger = logging.getLogger("netguard.migrate")


def migrate(engine) -> None:
    """Run all pending schema migrations against *engine* (idempotent)."""
    with engine.connect() as conn:
        _add_columns_blocked_ips(conn, engine)
        _add_columns_events(conn, engine)
        _create_new_tables(conn)
        conn.commit()
    logger.info("Database migration complete.")


# ---------------------------------------------------------------------------
# Column additions (idempotent via column-list inspection)
# ---------------------------------------------------------------------------

def _existing_columns(engine, table: str) -> set[str]:
    inspector = inspect(engine)
    return {c["name"] for c in inspector.get_columns(table)} if table in inspector.get_table_names() else set()


def _add_columns_blocked_ips(conn, engine) -> None:
    existing = _existing_columns(engine, "blocked_ips")
    additions = [
        ("block_type",      "VARCHAR(10) DEFAULT 'ip'"),
        ("threat_score",    "INTEGER DEFAULT 0"),
        ("operator_id",     "VARCHAR(100) DEFAULT 'system'"),
        ("audit_entry_id",  "INTEGER DEFAULT NULL"),
    ]
    for col, definition in additions:
        if col not in existing:
            conn.execute(text(f"ALTER TABLE blocked_ips ADD COLUMN {col} {definition}"))
            logger.info("blocked_ips: added column %s", col)


def _add_columns_events(conn, engine) -> None:
    existing = _existing_columns(engine, "events")
    additions = [
        ("ioc_match",           "INTEGER DEFAULT 0"),
        ("risk_score",          "INTEGER DEFAULT 0"),
        ("mitre_tactic",        "VARCHAR(100) DEFAULT ''"),
        ("mitre_technique",     "VARCHAR(20) DEFAULT ''"),
        ("enrichment_status",   "VARCHAR(30) DEFAULT 'pending'"),
        ("false_positive",      "INTEGER DEFAULT 0"),
    ]
    for col, definition in additions:
        if col not in existing:
            conn.execute(text(f"ALTER TABLE events ADD COLUMN {col} {definition}"))
            logger.info("events: added column %s", col)


# ---------------------------------------------------------------------------
# New table creation
# ---------------------------------------------------------------------------

def _create_new_tables(conn) -> None:
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS scheduled_jobs (
            id              VARCHAR(36) PRIMARY KEY,
            attack_type     VARCHAR(50) NOT NULL,
            config_json     TEXT NOT NULL,
            recurrence_rule VARCHAR(200),
            status          VARCHAR(20) NOT NULL DEFAULT 'PENDING',
            scheduled_at    VARCHAR(30) NOT NULL,
            executed_at     VARCHAR(30),
            created_by      VARCHAR(100) NOT NULL,
            campaign_id     VARCHAR(36),
            occurrence_count INTEGER NOT NULL DEFAULT 0
        )
    """))

    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS user_accounts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        VARCHAR(100) UNIQUE NOT NULL,
            password_hash   VARCHAR(256) NOT NULL,
            role            VARCHAR(20) NOT NULL DEFAULT 'viewer',
            mfa_secret      VARCHAR(64),
            mfa_enabled     INTEGER NOT NULL DEFAULT 0,
            created_at      VARCHAR(30) NOT NULL,
            last_login      VARCHAR(30),
            active          INTEGER NOT NULL DEFAULT 1
        )
    """))

    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       VARCHAR(30) NOT NULL,
            username        VARCHAR(100) NOT NULL,
            action          VARCHAR(100) NOT NULL,
            resource_path   VARCHAR(500) NOT NULL,
            detail_json     TEXT
        )
    """))

    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS enrichment_results (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id        VARCHAR(36) NOT NULL,
            source          VARCHAR(30) NOT NULL,
            fetched_at      VARCHAR(30) NOT NULL,
            result_json     TEXT NOT NULL,
            risk_score      INTEGER NOT NULL DEFAULT 0,
            ioc_match       INTEGER NOT NULL DEFAULT 0,
            ioc_identifiers TEXT,
            status          VARCHAR(30) NOT NULL DEFAULT 'ok'
        )
    """))

    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS compliance_reports (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            framework       VARCHAR(30) NOT NULL,
            generated_at    VARCHAR(30) NOT NULL,
            report_json     TEXT NOT NULL
        )
    """))

    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS ioc_store (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type        VARCHAR(20) NOT NULL,
            ioc_value       VARCHAR(500) NOT NULL,
            added_at        VARCHAR(30) NOT NULL,
            source          VARCHAR(30) NOT NULL DEFAULT 'manual',
            last_seen       VARCHAR(30) NOT NULL,
            UNIQUE(ioc_type, ioc_value)
        )
    """))

    logger.info("New tables verified/created.")
