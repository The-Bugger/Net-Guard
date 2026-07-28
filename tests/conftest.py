"""
conftest.py — Shared pytest fixtures for NetGuard IDPS tests.

Provides reusable fixtures for database sessions, mock objects, and
common test data used across all test modules.
"""

from __future__ import annotations

import sys
import os
from pathlib import Path

# Ensure project root is on sys.path for all tests
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from database.schema import Base
from detection.parsers.packet_decoder import Packet
from detection.rules.base_rule import ThreatEvent, Explanation


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def in_memory_engine():
    """Create an in-memory SQLite engine with all tables."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)


@pytest.fixture
def session_factory(in_memory_engine):
    """Return a session factory for the in-memory engine."""
    factory = sessionmaker(bind=in_memory_engine)

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


# ---------------------------------------------------------------------------
# Packet factory helpers
# ---------------------------------------------------------------------------

def make_packet(
    src_ip="192.168.1.100",
    dst_ip="10.0.0.1",
    src_port=None,
    dst_port=None,
    protocol="TCP",
    flags=None,
    payload=None,
    length=64,
) -> Packet:
    """Build a test Packet with sensible defaults."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return Packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        flags=flags,
        timestamp=ts,
        length=length,
        payload=payload,
    )


def make_syn_packet(src_ip="192.168.1.100", dst_ip="10.0.0.1", dst_port=80) -> Packet:
    """Build a TCP SYN packet."""
    return make_packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=54321,
        dst_port=dst_port,
        protocol="TCP",
        flags="S",
    )


def make_http_packet(
    src_ip="192.168.1.100",
    dst_ip="10.0.0.1",
    payload: bytes = b"",
    dst_port: int = 80,
) -> Packet:
    """Build a TCP HTTP packet with payload."""
    return make_packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=12345,
        dst_port=dst_port,
        protocol="TCP",
        flags="PA",
        payload=payload,
    )


def make_arp_packet(src_ip="192.168.1.1", mac_payload: bytes = b"") -> Packet:
    """Build an ARP packet."""
    return make_packet(
        src_ip=src_ip,
        dst_ip="192.168.1.255",
        protocol="ARP",
        payload=mac_payload,
    )


# ---------------------------------------------------------------------------
# ThreatEvent factory
# ---------------------------------------------------------------------------

def make_threat_event(
    attack_type="SYN Flood",
    source_ip="192.168.1.100",
    severity="High",
    confidence=85,
    rule_name="SYN_FLOOD_001",
    blocked=False,
    evidence=None,
) -> ThreatEvent:
    """Build a minimal ThreatEvent for testing."""
    import uuid
    return ThreatEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        attack_type=attack_type,
        source_ip=source_ip,
        destination_ip="10.0.0.1",
        source_port=None,
        destination_port=None,
        protocol="TCP",
        rule_name=rule_name,
        severity=severity,
        confidence=confidence,
        packet_count=100,
        evidence=evidence or {},
        blocked=blocked,
    )


# ---------------------------------------------------------------------------
# Mock whitelist
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_whitelist():
    """A mock whitelist manager that returns False for all IPs by default."""
    wl = MagicMock()
    wl.is_whitelisted.return_value = False
    return wl


@pytest.fixture
def mock_block_repo():
    """A mock block repository."""
    repo = MagicMock()
    repo.get_active.return_value = None
    repo.insert.return_value = True
    repo.set_inactive.return_value = True
    repo.extend_expiry.return_value = True
    return repo
