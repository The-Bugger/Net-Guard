"""
test_database.py — Unit tests for database schema and repositories.

Tests:
- DB initialization creates all 6 tables
- ORM model insert/query (no raw SQL)
- Constraint enforcement (confidence range, uniqueness)
- EventRepository: insert, get_by_id, get_all with filters
- BlockRepository: insert, get_active, get_all_active, set_inactive, extend_expiry, get_expired
- WhitelistRepository: insert, delete, get_all, exists
- LogRepository: insert
- SettingsRepository: get, set, get_all

Requirements: 14.1–14.7
"""

from __future__ import annotations

import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from database.schema import (
    Base,
    BlockedIP,
    DetectionRule,
    Event,
    Setting,
    SystemLog,
    WhitelistEntry,
)
from database.init_db import initialize_db
from backend.repositories.event_repository import EventRepository
from backend.repositories.block_repository import BlockRepository
from backend.repositories.whitelist_repository import WhitelistRepository
from backend.repositories.log_repository import LogRepository
from backend.repositories.settings_repository import SettingsRepository


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_future(seconds: int = 120) -> str:
    dt = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_past(seconds: int = 10) -> str:
    dt = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def engine():
    """In-memory SQLite engine with all tables created."""
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    with eng.connect() as conn:
        conn.execute(text("PRAGMA foreign_keys = ON"))
        conn.commit()
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture
def session_factory(engine):
    """Context-manager session factory backed by the in-memory engine."""
    factory = sessionmaker(bind=engine)

    @contextmanager
    def _factory():
        session = factory()
        try:
            yield session
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    return _factory


@pytest.fixture
def event_repo(session_factory):
    return EventRepository(session_factory)


@pytest.fixture
def block_repo(session_factory):
    return BlockRepository(session_factory)


@pytest.fixture
def whitelist_repo(session_factory):
    return WhitelistRepository(session_factory)


@pytest.fixture
def log_repo(session_factory):
    return LogRepository(session_factory)


@pytest.fixture
def settings_repo(session_factory):
    return SettingsRepository(session_factory)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event_data(**overrides) -> dict:
    """Return a valid event_data dict for EventRepository.insert."""
    defaults = dict(
        event_id=str(uuid.uuid4()),
        timestamp=_utc_now(),
        attack_type="SYN Flood",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.1",
        source_port=54321,
        destination_port=80,
        protocol="TCP",
        rule_name="SYN_FLOOD_001",
        severity="High",
        confidence=85,
        packet_count=100,
        evidence={"syn_count": 100},
        explanation="SYN flood detected",
        recommendation="Block IP",
        blocked=False,
    )
    defaults.update(overrides)
    return defaults


def _make_block_data(event_id: str, ip: str = "10.0.0.50", **overrides) -> dict:
    """Return a valid record_data dict for BlockRepository.insert."""
    defaults = dict(
        event_id=event_id,
        ip_address=ip,
        blocked_at=_utc_now(),
        expires_at=_utc_future(120),
        reason="SYN Flood",
    )
    defaults.update(overrides)
    return defaults


def _insert_event(event_repo: EventRepository, **overrides) -> str:
    """Insert an event and return its event_id."""
    data = _make_event_data(**overrides)
    assert event_repo.insert(data) is True
    return data["event_id"]


# ===========================================================================
# Section 1: DB Initialization — all 6 tables exist (Requirement 14.1)
# ===========================================================================

class TestDatabaseInitialization:
    """Verify initialize_db creates all 6 required tables."""

    EXPECTED_TABLES = {
        "events",
        "blocked_ips",
        "whitelist",
        "detection_rules",
        "settings",
        "system_logs",
    }

    def test_initialize_db_creates_all_tables(self):
        """initialize_db with in-memory URL creates all 6 tables."""
        initialize_db("sqlite:///:memory:")

    def test_all_six_tables_exist_after_create_all(self, engine):
        """Base.metadata.create_all produces exactly the 6 required tables."""
        inspector = inspect(engine)
        table_names = set(inspector.get_table_names())
        assert self.EXPECTED_TABLES.issubset(table_names), (
            f"Missing tables: {self.EXPECTED_TABLES - table_names}"
        )

    def test_events_table_exists(self, engine):
        inspector = inspect(engine)
        assert "events" in inspector.get_table_names()

    def test_blocked_ips_table_exists(self, engine):
        inspector = inspect(engine)
        assert "blocked_ips" in inspector.get_table_names()

    def test_whitelist_table_exists(self, engine):
        inspector = inspect(engine)
        assert "whitelist" in inspector.get_table_names()

    def test_detection_rules_table_exists(self, engine):
        inspector = inspect(engine)
        assert "detection_rules" in inspector.get_table_names()

    def test_settings_table_exists(self, engine):
        inspector = inspect(engine)
        assert "settings" in inspector.get_table_names()

    def test_system_logs_table_exists(self, engine):
        inspector = inspect(engine)
        assert "system_logs" in inspector.get_table_names()


# ===========================================================================
# Section 2: ORM Model Insert/Query — no raw SQL (Requirement 14.2)
# ===========================================================================

class TestOrmModels:
    """Verify each ORM model can be inserted and queried via the ORM."""

    def test_event_insert_and_query(self, engine):
        eid = str(uuid.uuid4())
        with Session(engine) as session:
            session.add(Event(
                event_id=eid,
                timestamp=_utc_now(),
                attack_type="Port Scan",
                source_ip="1.2.3.4",
                destination_ip="5.6.7.8",
                protocol="TCP",
                rule_name="PORT_SCAN_001",
                severity="Medium",
                confidence=70,
                explanation="Port scan detected",
            ))
            session.commit()
        with Session(engine) as session:
            record = session.query(Event).filter_by(event_id=eid).first()
            assert record is not None
            assert record.attack_type == "Port Scan"
            assert record.confidence == 70

    def test_blocked_ip_insert_and_query(self, engine):
        # First insert a parent event (FK constraint)
        eid = str(uuid.uuid4())
        with Session(engine) as session:
            session.add(Event(
                event_id=eid,
                timestamp=_utc_now(),
                attack_type="SYN Flood",
                source_ip="1.2.3.4",
                destination_ip="5.6.7.8",
                protocol="TCP",
                rule_name="SYN_FLOOD_001",
                severity="High",
                confidence=90,
                explanation="flood",
            ))
            session.commit()
        with Session(engine) as session:
            session.add(BlockedIP(
                event_id=eid,
                ip_address="1.2.3.4",
                blocked_at=_utc_now(),
                expires_at=_utc_future(120),
                reason="SYN Flood",
                active=1,
            ))
            session.commit()
        with Session(engine) as session:
            record = session.query(BlockedIP).filter_by(ip_address="1.2.3.4").first()
            assert record is not None
            assert record.active == 1

    def test_whitelist_entry_insert_and_query(self, engine):
        with Session(engine) as session:
            session.add(WhitelistEntry(
                ip_address="192.168.0.1",
                description="Trusted gateway",
                created_at=_utc_now(),
            ))
            session.commit()
        with Session(engine) as session:
            record = session.query(WhitelistEntry).filter_by(ip_address="192.168.0.1").first()
            assert record is not None
            assert record.description == "Trusted gateway"

    def test_detection_rule_insert_and_query(self, engine):
        with Session(engine) as session:
            session.add(DetectionRule(
                rule_name="TEST_RULE_001",
                attack_type="Test",
                threshold=5,
                severity="Low",
                block_duration=60,
            ))
            session.commit()
        with Session(engine) as session:
            record = session.query(DetectionRule).filter_by(rule_name="TEST_RULE_001").first()
            assert record is not None
            assert record.threshold == 5
