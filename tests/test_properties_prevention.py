"""
test_properties_prevention.py — Property-based tests for PreventionEngine.

# Feature: netguard-idps, Property 31
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from backend.services.prevention_service import PreventionEngine


# ---------------------------------------------------------------------------
# IP address strategy (valid IPv4 only — iptables focus)
# ---------------------------------------------------------------------------

_ipv4 = st.builds(
    lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
    st.integers(1, 254),
    st.integers(0, 255),
    st.integers(0, 255),
    st.integers(1, 254),
)


# ---------------------------------------------------------------------------
# Property 31 — Whitelisted IPs are never passed to iptables
#
# Validates: Requirements 12.7, 11.1
# For ANY valid IP that the whitelist considers trusted,
# block_ip() must never invoke subprocess (iptables).
# ---------------------------------------------------------------------------

@given(ip=_ipv4, reason=st.text(min_size=1, max_size=50), event_id=st.uuids().map(str))
@settings(max_examples=100)
def test_property_31_whitelisted_ip_never_calls_iptables(ip, reason, event_id):
    """Property 31: block_ip() skips iptables for any whitelisted IP."""
    block_repo = MagicMock()
    block_repo.get_active.return_value = None

    whitelist = MagicMock()
    whitelist.is_whitelisted.return_value = True

    engine = PreventionEngine(block_repo, whitelist)

    with patch("subprocess.run") as mock_run:
        engine.handle_event(
            _make_event(ip, reason, event_id),
            _make_explanation(),
        )
        mock_run.assert_not_called(), (
            f"iptables called for whitelisted IP {ip}"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(source_ip, attack_type, event_id):
    from detection.rules.base_rule import ThreatEvent
    import uuid
    from datetime import datetime, timezone

    return ThreatEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        attack_type=attack_type,
        source_ip=source_ip,
        destination_ip="10.0.0.1",
        source_port=None,
        destination_port=None,
        protocol="TCP",
        rule_name="TEST_RULE",
        severity="High",
        confidence=90,
        packet_count=1,
        evidence={},
        blocked=False,
    )


def _make_explanation():
    from detection.rules.base_rule import Explanation
    return Explanation(
        attack_name="Test Attack",
        rule_triggered="TEST_RULE",
        plain_english_text="Test explanation for property test.",
        evidence={},
        confidence_score=90,
        severity="High",
        recommendation="Block the IP.",
    )
