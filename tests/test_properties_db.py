# Feature: netguard-idps, Property 39
# Feature: netguard-idps, Property 40
"""
test_properties_db.py — Property-based tests for database constraints.

Property 39: Database Confidence Constraint
  - Any INSERT into the `events` table with confidence outside [0, 100]
    must be rejected by the database (IntegrityError or OperationalError).

Property 40: Database Event ID Uniqueness Constraint
  - Any attempt to INSERT a second row with the same event_id as an
    existing row must be rejected by the database.

Validates: Requirements 14.3, 14.4
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

# Ensure the project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from hypothesis import given, settings as hyp_settings, assume, HealthCheck
from hypothesis import strategies as st
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from database.schema import Base, Event


# ---------------------------------------------------------------------------
# Shared engine fixture — one engine for all property examples
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def db_engine():
    """
    A single in-memory SQLite engine shared across all tests in this module.

    Each test clears the events table between examples to maintain isolation
    without the overhead of creating a new engine per example.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    with engine.connect() as conn:
        conn.execute(text("PRAGMA foreign_keys = ON"))
        conn.commit()
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_valid_event_kwargs(**overrides) -> dict:
    """Return keyword arguments for a fully valid Event row."""
    defaults = dict(
        event_id=str(uuid.uuid4()),
        timestamp="2024-01-01T00:00:00Z",
        attack_type="SYN Flood",
        source_ip="192.168.1.1",
        destination_ip="10.0.0.1",
        source_port=12345,
        destination_port=80,
        protocol="TCP",
        rule_name="SYN_FLOOD_001",
        severity="High",
        confidence=85,
        packet_count=100,
        evidence="{}",
        explanation="Detected flood",
        recommendation="Block IP",
        blocked=0,
    )
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# Property 39: Database Confidence Constraint
# Feature: netguard-idps, Property 39
# Validates: Requirement 14.3
# ---------------------------------------------------------------------------

@given(confidence=st.one_of(
    st.integers(min_value=-9_223_372_036_854_775_808, max_value=-1),   # strictly below 0, within SQLite range
    st.integers(min_value=101, max_value=9_223_372_036_854_775_807),   # strictly above 100, within SQLite range
))
@hyp_settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_confidence_outside_range_rejected(confidence, db_engine):
    """
    **Validates: Requirements 14.3**

    Property 39: INSERT with confidence outside [0, 100] must be rejected.

    For any confidence value strictly less than 0 or strictly greater than 100,
    the database CHECK constraint `confidence BETWEEN 0 AND 100` must cause
    the flush/INSERT to raise IntegrityError or OperationalError.
    The session is rolled back so the engine remains clean for the next example.
    """
    assume(confidence < 0 or confidence > 100)

    kwargs = _make_valid_event_kwargs(confidence=confidence)
    with Session(db_engine) as session:
        with pytest.raises((IntegrityError, OperationalError)):
            event = Event(**kwargs)
            session.add(event)
            session.flush()
        session.rollback()


# ---------------------------------------------------------------------------
# Property 40: Database Event ID Uniqueness Constraint
# Feature: netguard-idps, Property 40
# Validates: Requirement 14.4
# ---------------------------------------------------------------------------

@given(
    event_id=st.text(
        alphabet=st.characters(
            whitelist_categories=("Lu", "Ll", "Nd"),
            whitelist_characters="-",
        ),
        min_size=1,
        max_size=36,
    ),
    confidence_first=st.integers(min_value=0, max_value=100),
    confidence_second=st.integers(min_value=0, max_value=100),
)
@hyp_settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_duplicate_event_id_rejected(event_id, confidence_first, confidence_second, db_engine):
    """
    **Validates: Requirements 14.4**

    Property 40: Inserting a second row with an already-existing event_id must
    be rejected by the UNIQUE constraint on the `event_id` column.

    For any non-empty string used as event_id, the first INSERT succeeds and
    the second INSERT with the same event_id raises IntegrityError or
    OperationalError. The table is cleaned up between examples.
    """
    # Insert first row — must succeed
    with Session(db_engine) as session:
        first = Event(**_make_valid_event_kwargs(
            event_id=event_id,
            confidence=confidence_first,
        ))
        session.add(first)
        session.commit()

    # Insert second row with same event_id — must be rejected
    with Session(db_engine) as session:
        with pytest.raises((IntegrityError, OperationalError)):
            second = Event(**_make_valid_event_kwargs(
                event_id=event_id,
                confidence=confidence_second,
            ))
            session.add(second)
            session.flush()
        session.rollback()

    # Clean up so the next example starts from a clean state
    with Session(db_engine) as session:
        session.query(Event).filter_by(event_id=event_id).delete()
        session.commit()


# ---------------------------------------------------------------------------
# Boundary sanity: confidence at 0 and 100 must be accepted (not PBT)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("confidence", [0, 100])
def test_confidence_boundary_values_accepted(confidence, db_engine):
    """
    **Validates: Requirements 14.3**

    Boundary values 0 and 100 are the inclusive ends of the CHECK constraint
    and must be accepted without raising any exception.
    """
    eid = str(uuid.uuid4())
    with Session(db_engine) as session:
        event = Event(**_make_valid_event_kwargs(
            event_id=eid,
            confidence=confidence,
        ))
        session.add(event)
        session.commit()

    # Clean up
    with Session(db_engine) as session:
        session.query(Event).filter_by(event_id=eid).delete()
        session.commit()
