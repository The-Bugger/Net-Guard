"""
test_integration_block.py — Full ThreatEvent → block flow integration test.

Requires: Linux, root/sudo, iptables.
Verifies: ThreatEvent → PreventionEngine → iptables rule applied → DB record created.

Requirements: 11.1, 11.2

NOTE: Run with: sudo pytest tests/integration/ -v
"""

from __future__ import annotations

import platform
import subprocess
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
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
        reason="Block integration tests require Linux",
    ),
    pytest.mark.skipif(
        not hasattr(__import__("os"), "geteuid") or __import__("os").geteuid() != 0,
        reason="Block integration tests require root privileges (iptables)",
    ),
]

_TEST_IP = "192.0.2.99"  # TEST-NET-1 — safe to block in test environment


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rule_exists(ip: str) -> bool:
    """Check if an iptables DROP rule exists for the given IP."""
    result = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
    )
    return result.returncode == 0


def _cleanup_rule(ip: str) -> None:
    """Remove iptables rule if it exists (cleanup after test)."""
    if _rule_exists(ip):
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
        )


@pytest.fixture
def in_memory_db():
    """Provide an in-memory SQLite engine for integration test isolation."""
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


def test_block_ip_creates_iptables_rule_and_db_record(in_memory_db):
    """
    Requirement 11.1: PreventionEngine must execute iptables -I INPUT -s <ip> -j DROP.
    Requirement 11.2: A blocked_ips record must be created with all required fields.
    """
    from backend.repositories.block_repository import BlockRepository
    from backend.repositories.event_repository import EventRepository
    from backend.services.whitelist_service import WhitelistManager
    from backend.repositories.whitelist_repository import WhitelistRepository
    from backend.services.prevention_service import PreventionEngine

    block_repo = BlockRepository(in_memory_db)
    whitelist_repo = WhitelistRepository(in_memory_db)
    whitelist = WhitelistManager(whitelist_repo)
    whitelist.sync_from_db()

    engine = PreventionEngine(
        block_repo=block_repo,
        whitelist_manager=whitelist,
        block_duration=30,
    )
    engine.verify_privileges()

    event_id = str(uuid.uuid4())
    try:
        result = engine.block_ip(_TEST_IP, "SYN Flood", event_id)

        assert result is True, "block_ip() must return True on success"
        assert _rule_exists(_TEST_IP), "iptables DROP rule must exist after block"

        # Verify DB record
        record = block_repo.get_active(_TEST_IP)
        assert record is not None, "blocked_ips record must exist"
        assert record["ip_address"] == _TEST_IP
        assert record["reason"] == "SYN Flood"
        assert record["active"] is True
        assert "blocked_at" in record
        assert "expires_at" in record
        assert record["event_id"] == event_id

    finally:
        _cleanup_rule(_TEST_IP)
        block_repo.set_inactive(_TEST_IP)


def test_whitelisted_ip_not_blocked(in_memory_db):
    """
    Requirement 11.1, 12.7: Whitelisted IPs must never be passed to iptables.
    """
    from backend.repositories.block_repository import BlockRepository
    from backend.services.whitelist_service import WhitelistManager
    from backend.repositories.whitelist_repository import WhitelistRepository
    from backend.services.prevention_service import PreventionEngine
    from detection.rules.base_rule import ThreatEvent, Explanation

    block_repo = BlockRepository(in_memory_db)
    whitelist_repo = WhitelistRepository(in_memory_db)
    whitelist = WhitelistManager(whitelist_repo)
    whitelist.add(_TEST_IP, description="test device")

    engine = PreventionEngine(
        block_repo=block_repo,
        whitelist_manager=whitelist,
        block_duration=30,
    )
    engine.verify_privileges()

    event = ThreatEvent(
        event_id=str(uuid.uuid4()),
        timestamp=_utc_now(),
        attack_type="SYN Flood",
        source_ip=_TEST_IP,
        destination_ip="10.0.0.1",
        source_port=None,
        destination_port=80,
        protocol="TCP",
        rule_name="SYN_FLOOD_001",
        severity="High",
        confidence=90,
        packet_count=200,
        evidence={},
        blocked=False,
    )
    explanation = Explanation(
        attack_name="SYN Flood",
        rule_triggered="SYN_FLOOD_001",
        plain_english_text="Test.",
        evidence={},
        confidence_score=90,
        severity="High",
        recommendation="Investigate.",
    )

    try:
        engine.handle_event(event, explanation)
        assert not _rule_exists(_TEST_IP), "Whitelisted IP must NOT have an iptables rule"
    finally:
        _cleanup_rule(_TEST_IP)
