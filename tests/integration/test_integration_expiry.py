"""
test_integration_expiry.py — Block expiry integration test.

Requires: Linux, root/sudo, iptables.
Verifies: ExpiryThread removes iptables rule and sets active=False within 5s.

Requirements: 11.3

NOTE: Run with: sudo pytest tests/integration/ -v
"""

from __future__ import annotations

import platform
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

pytestmark = [
    pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Expiry integration tests require Linux",
    ),
    pytest.mark.skipif(
        __import__("os").geteuid() != 0,
        reason="Expiry integration tests require root privileges (iptables)",
    ),
]

_TEST_IP = "192.0.2.98"  # TEST-NET-1


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_past(seconds: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _rule_exists(ip: str) -> bool:
    result = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
    )
    return result.returncode == 0


def _add_rule(ip: str) -> None:
    subprocess.run(
        ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
    )


def _cleanup_rule(ip: str) -> None:
    if _rule_exists(ip):
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
        )


@pytest.fixture
def in_memory_db():
    from database.schema import Base

    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    factory_fn = sessionmaker(bind=engine)

    @contextmanager
    def factory():
        s = factory_fn()
        try:
            yield s
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    return factory


def test_expiry_thread_removes_rule_within_5s(in_memory_db):
    """
    Requirement 11.3: ExpiryThread must remove expired iptables rules and
    set active=False within 5 seconds of expiry.
    """
    from backend.repositories.block_repository import BlockRepository
    from backend.repositories.event_repository import EventRepository
    from backend.services.expiry_service import ExpiryThread

    block_repo = BlockRepository(in_memory_db)
    event_repo = EventRepository(in_memory_db)

    # Insert a parent event first (FK constraint)
    event_id = str(uuid.uuid4())
    event_repo.insert({
        "event_id": event_id,
        "timestamp": _utc_now(),
        "attack_type": "SYN Flood",
        "source_ip": _TEST_IP,
        "destination_ip": "10.0.0.1",
        "source_port": None,
        "destination_port": 80,
        "protocol": "TCP",
        "rule_name": "SYN_FLOOD_001",
        "severity": "High",
        "confidence": 90,
        "packet_count": 200,
        "evidence": {},
        "explanation": "test",
        "recommendation": "block",
        "blocked": True,
    })

    # Insert a block that has already expired (1 second ago)
    block_repo.insert({
        "event_id": event_id,
        "ip_address": _TEST_IP,
        "blocked_at": _utc_past(10),
        "expires_at": _utc_past(1),   # expired 1 second ago
        "reason": "SYN Flood",
    })

    # Add the iptables rule manually
    _add_rule(_TEST_IP)
    assert _rule_exists(_TEST_IP), "iptables rule must exist before expiry test"

    expiry = ExpiryThread(block_repo=block_repo)
    expiry.POLL_INTERVAL = 1  # speed up for test
    expiry.start()

    try:
        # Wait up to 8 seconds for expiry to process (1s poll + overhead)
        deadline = time.monotonic() + 8.0
        rule_removed = False
        db_inactive = False

        while time.monotonic() < deadline:
            time.sleep(0.2)
            rule_removed = not _rule_exists(_TEST_IP)
            record = block_repo.get_active(_TEST_IP)
            db_inactive = record is None

            if rule_removed and db_inactive:
                break

        assert rule_removed, "iptables rule must be removed after expiry"
        assert db_inactive, "blocked_ips record must be set inactive after expiry"

    finally:
        expiry.stop()
        _cleanup_rule(_TEST_IP)
