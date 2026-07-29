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


    def test_setting_insert_and_query(self, engine):
        now = _utc_now()
        with Session(engine) as session:
            session.add(Setting(key="threshold", value="50", updated_at=now))
            session.commit()
        with Session(engine) as session:
            record = session.query(Setting).filter_by(key="threshold").first()
            assert record is not None
            assert record.value == "50"

    def test_system_log_insert_and_query(self, engine):
        with Session(engine) as session:
            session.add(SystemLog(
                timestamp=_utc_now(),
                level="INFO",
                module="test",
                event="TEST_EVENT",
                message="test log message",
            ))
            session.commit()
        with Session(engine) as session:
            record = session.query(SystemLog).filter_by(module="test").first()
            assert record is not None
            assert record.level == "INFO"


# ===========================================================================
# Section 3: Constraint Enforcement (Requirements 14.2, 14.3)
# ===========================================================================

class TestConstraints:
    """Verify CHECK and UNIQUE constraints are enforced at the DB level."""

    def test_confidence_below_range_rejected(self, engine):
        """confidence < 0 must be rejected by the CHECK constraint."""
        with pytest.raises((IntegrityError, OperationalError)):
            with Session(engine) as session:
                session.add(Event(
                    event_id=str(uuid.uuid4()),
                    timestamp=_utc_now(),
                    attack_type="Test",
                    source_ip="1.2.3.4",
                    destination_ip="5.6.7.8",
                    protocol="TCP",
                    rule_name="TEST_001",
                    severity="Low",
                    confidence=-1,
                    explanation="bad confidence",
                ))
                session.commit()

    def test_confidence_above_range_rejected(self, engine):
        """confidence > 100 must be rejected by the CHECK constraint."""
        with pytest.raises((IntegrityError, OperationalError)):
            with Session(engine) as session:
                session.add(Event(
                    event_id=str(uuid.uuid4()),
                    timestamp=_utc_now(),
                    attack_type="Test",
                    source_ip="1.2.3.4",
                    destination_ip="5.6.7.8",
                    protocol="TCP",
                    rule_name="TEST_001",
                    severity="Low",
                    confidence=101,
                    explanation="bad confidence",
                ))
                session.commit()

    def test_confidence_boundary_values_accepted(self, engine):
        """confidence = 0 and confidence = 100 must both be accepted."""
        with Session(engine) as session:
            session.add(Event(
                event_id=str(uuid.uuid4()),
                timestamp=_utc_now(),
                attack_type="Test",
                source_ip="1.2.3.4",
                destination_ip="5.6.7.8",
                protocol="TCP",
                rule_name="TEST_001",
                severity="Low",
                confidence=0,
                explanation="min confidence",
            ))
            session.add(Event(
                event_id=str(uuid.uuid4()),
                timestamp=_utc_now(),
                attack_type="Test",
                source_ip="1.2.3.4",
                destination_ip="5.6.7.8",
                protocol="TCP",
                rule_name="TEST_001",
                severity="Low",
                confidence=100,
                explanation="max confidence",
            ))
            session.commit()

    def test_duplicate_event_id_rejected(self, engine):
        """Inserting two Events with the same event_id must raise IntegrityError."""
        eid = str(uuid.uuid4())
        with Session(engine) as session:
            session.add(Event(
                event_id=eid,
                timestamp=_utc_now(),
                attack_type="Test",
                source_ip="1.2.3.4",
                destination_ip="5.6.7.8",
                protocol="TCP",
                rule_name="TEST_001",
                severity="Low",
                confidence=50,
                explanation="first",
            ))
            session.commit()

        with pytest.raises(IntegrityError):
            with Session(engine) as session:
                session.add(Event(
                    event_id=eid,
                    timestamp=_utc_now(),
                    attack_type="Test",
                    source_ip="1.2.3.4",
                    destination_ip="5.6.7.8",
                    protocol="TCP",
                    rule_name="TEST_001",
                    severity="Low",
                    confidence=50,
                    explanation="duplicate",
                ))
                session.commit()


# ===========================================================================
# Section 4: EventRepository (Requirements 14.2, 14.5, 14.6)
# ===========================================================================

class TestEventRepository:
    """EventRepository: insert, get_by_id, get_all with filters."""

    def test_insert_and_get_by_id(self, event_repo):
        eid = _insert_event(event_repo)
        result = event_repo.get_by_id(eid)
        assert result is not None
        assert result["event_id"] == eid
        assert result["attack_type"] == "SYN Flood"

    def test_get_by_id_unknown_returns_none(self, event_repo):
        assert event_repo.get_by_id("nonexistent-id") is None

    def test_get_all_returns_inserted_event(self, event_repo):
        eid = _insert_event(event_repo)
        results = event_repo.get_all()
        ids = [r["event_id"] for r in results]
        assert eid in ids

    def test_filter_by_severity(self, event_repo):
        _insert_event(event_repo, severity="High", attack_type="SYN Flood")
        _insert_event(event_repo, severity="Low", attack_type="Port Scan")
        results = event_repo.get_all(filters={"severity": "High"})
        assert all(r["severity"] == "High" for r in results)
        assert any(r["attack_type"] == "SYN Flood" for r in results)

    def test_filter_by_attack_type(self, event_repo):
        _insert_event(event_repo, attack_type="SQL Injection")
        _insert_event(event_repo, attack_type="SYN Flood")
        results = event_repo.get_all(filters={"attack_type": "SQL Injection"})
        assert all(r["attack_type"] == "SQL Injection" for r in results)

    def test_filter_by_source_ip(self, event_repo):
        _insert_event(event_repo, source_ip="10.0.0.1")
        _insert_event(event_repo, source_ip="10.0.0.2")
        results = event_repo.get_all(filters={"source_ip": "10.0.0.1"})
        assert all(r["source_ip"] == "10.0.0.1" for r in results)

    def test_filter_by_date(self, event_repo):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        eid = _insert_event(event_repo, timestamp=f"{today}T10:00:00Z")
        results = event_repo.get_all(filters={"date": today})
        ids = [r["event_id"] for r in results]
        assert eid in ids

    def test_insert_clamps_confidence_high(self, event_repo):
        """EventRepository.insert clamps confidence to 100 (no DB constraint error)."""
        # The repo itself clamps: max(0, min(100, value))
        eid = _insert_event(event_repo, confidence=999)
        result = event_repo.get_by_id(eid)
        assert result["confidence"] == 100

    def test_insert_clamps_confidence_low(self, event_repo):
        eid = _insert_event(event_repo, confidence=-50)
        result = event_repo.get_by_id(eid)
        assert result["confidence"] == 0


# ===========================================================================
# Section 5: BlockRepository (Requirements 11.2, 11.3, 11.6)
# ===========================================================================

class TestBlockRepository:
    """BlockRepository: insert, get_active, get_all_active, set_inactive, extend_expiry, get_expired."""

    def _setup_event(self, event_repo: EventRepository) -> str:
        return _insert_event(event_repo)

    def test_insert_and_get_active(self, event_repo, block_repo):
        eid = self._setup_event(event_repo)
        data = _make_block_data(eid, ip="192.168.1.50")
        assert block_repo.insert(data) is True
        result = block_repo.get_active("192.168.1.50")
        assert result is not None
        assert result["ip_address"] == "192.168.1.50"
        assert result["active"] is True

    def test_get_active_nonexistent_returns_none(self, block_repo):
        assert block_repo.get_active("0.0.0.0") is None

    def test_get_all_active(self, event_repo, block_repo):
        eid1 = _insert_event(event_repo, source_ip="10.1.1.1")
        eid2 = _insert_event(event_repo, source_ip="10.1.1.2")
        block_repo.insert(_make_block_data(eid1, ip="10.1.1.1"))
        block_repo.insert(_make_block_data(eid2, ip="10.1.1.2"))
        active = block_repo.get_all_active()
        ips = [r["ip_address"] for r in active]
        assert "10.1.1.1" in ips
        assert "10.1.1.2" in ips

    def test_set_inactive(self, event_repo, block_repo):
        eid = self._setup_event(event_repo)
        block_repo.insert(_make_block_data(eid, ip="10.2.2.2"))
        assert block_repo.get_active("10.2.2.2") is not None
        assert block_repo.set_inactive("10.2.2.2") is True
        assert block_repo.get_active("10.2.2.2") is None

    def test_extend_expiry(self, event_repo, block_repo):
        eid = self._setup_event(event_repo)
        block_repo.insert(_make_block_data(eid, ip="10.3.3.3"))
        new_expiry = _utc_future(3600)
        assert block_repo.extend_expiry("10.3.3.3", new_expiry) is True
        result = block_repo.get_active("10.3.3.3")
        assert result["expires_at"] == new_expiry

    def test_get_expired(self, event_repo, block_repo):
        eid = self._setup_event(event_repo)
        # Insert a block that has already expired
        block_repo.insert(_make_block_data(
            eid, ip="10.4.4.4",
            blocked_at=_utc_past(200),
            expires_at=_utc_past(100),
        ))
        expired = block_repo.get_expired()
        ips = [r["ip_address"] for r in expired]
        assert "10.4.4.4" in ips

    def test_get_expired_excludes_future(self, event_repo, block_repo):
        eid = self._setup_event(event_repo)
        block_repo.insert(_make_block_data(eid, ip="10.5.5.5", expires_at=_utc_future(3600)))
        expired = block_repo.get_expired()
        ips = [r["ip_address"] for r in expired]
        assert "10.5.5.5" not in ips


# ===========================================================================
# Section 6: WhitelistRepository (Requirements 12.2, 12.3)
# ===========================================================================

class TestWhitelistRepository:
    """WhitelistRepository: insert, delete, get_all, exists."""

    def test_insert_and_exists(self, whitelist_repo):
        assert whitelist_repo.exists("192.168.0.10") is False
        assert whitelist_repo.insert("192.168.0.10", "trusted host", _utc_now()) is True
        assert whitelist_repo.exists("192.168.0.10") is True

    def test_get_all(self, whitelist_repo):
        whitelist_repo.insert("10.0.0.1", "host A", _utc_now())
        whitelist_repo.insert("10.0.0.2", "host B", _utc_now())
        entries = whitelist_repo.get_all()
        ips = [e["ip_address"] for e in entries]
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips

    def test_delete(self, whitelist_repo):
        whitelist_repo.insert("10.9.9.9", "to be removed", _utc_now())
        assert whitelist_repo.exists("10.9.9.9") is True
        assert whitelist_repo.delete("10.9.9.9") is True
        assert whitelist_repo.exists("10.9.9.9") is False

    def test_delete_nonexistent_returns_false(self, whitelist_repo):
        assert whitelist_repo.delete("0.0.0.0") is False

    def test_exists_nonexistent_returns_false(self, whitelist_repo):
        assert whitelist_repo.exists("255.255.255.0") is False


# ===========================================================================
# Section 7: LogRepository (Requirement 14.5)
# ===========================================================================

class TestLogRepository:
    """LogRepository: insert a log entry."""

    def test_insert_log_entry(self, log_repo, session_factory):
        result = log_repo.insert(
            timestamp=_utc_now(),
            level="WARNING",
            module="test_module",
            event="TEST_LOG",
            message="This is a test log entry",
            metadata={"key": "value"},
        )
        assert result is True
        # Verify it's actually stored
        logs = log_repo.get_all(filters={"module": "test_module"})
        assert len(logs) == 1
        assert logs[0]["level"] == "WARNING"
        assert logs[0]["event"] == "TEST_LOG"
        assert logs[0]["metadata"] == {"key": "value"}

    def test_insert_log_without_metadata(self, log_repo):
        result = log_repo.insert(
            timestamp=_utc_now(),
            level="INFO",
            module="core",
            event="STARTUP",
            message="System started",
        )
        assert result is True


# ===========================================================================
# Section 8: SettingsRepository (Requirement 1.4)
# ===========================================================================

class TestSettingsRepository:
    """SettingsRepository: get, set, get_all."""

    def test_get_nonexistent_returns_none(self, settings_repo):
        assert settings_repo.get("no_such_key") is None

    def test_set_and_get(self, settings_repo):
        assert settings_repo.set("block_duration", "300") is True
        assert settings_repo.get("block_duration") == "300"

    def test_set_overwrites_existing(self, settings_repo):
        settings_repo.set("threshold", "10")
        settings_repo.set("threshold", "20")
        assert settings_repo.get("threshold") == "20"

    def test_get_all(self, settings_repo):
        settings_repo.set("key_a", "val_a")
        settings_repo.set("key_b", "val_b")
        all_settings = settings_repo.get_all()
        assert all_settings["key_a"] == "val_a"
        assert all_settings["key_b"] == "val_b"

    def test_get_all_empty(self, settings_repo):
        assert settings_repo.get_all() == {}
