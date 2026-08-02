"""
test_properties_enterprise.py — Property-based tests for Net-Guard Enterprise IDPS.

All properties use Hypothesis. Tag format:
  # Feature: net-guard-enterprise-idps, Property N: <text>

Requirements: 14.6, 14.1, 1.8, 1.1, 1.7, 1.5, 4.2, 4.7, 5.9, 9.1, 10.3, 12.4, 15.3
"""

from __future__ import annotations

import ipaddress
import string
import sys
import os
from unittest.mock import MagicMock, patch, call

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

# Ensure project root on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# Property 12: Password policy enforced consistently
# Feature: net-guard-enterprise-idps, Property 12: Password policy enforced consistently
# ---------------------------------------------------------------------------

from backend.services.auth_service import password_policy_valid, _password_policy_issues


@settings(max_examples=100)
@given(st.text())
def test_property12_password_policy_consistent(s: str):
    """Property 12: validator accepts s iff all four criteria hold, and is deterministic.

    Validates: Requirements 14.6
    """
    # Feature: net-guard-enterprise-idps, Property 12: Password policy enforced consistently
    result1 = password_policy_valid(s)
    result2 = password_policy_valid(s)
    assert result1 == result2, "Password policy must be deterministic"

    # Verify the specification exactly
    has_upper = any(c.isupper() for c in s)
    has_digit = any(c.isdigit() for c in s)
    has_punct = any(c in string.punctuation for c in s)
    expected = len(s) >= 12 and has_upper and has_digit and has_punct
    assert result1 == expected, (
        f"Policy mismatch for {s!r}: got {result1}, expected {expected}"
    )


# ---------------------------------------------------------------------------
# Property 4: Threat score is bounded and formula-correct
# Feature: net-guard-enterprise-idps, Property 4: Threat score is bounded and formula-correct
# ---------------------------------------------------------------------------

from backend.services.block_manager import BlockManager


@settings(max_examples=500)
@given(
    st.integers(min_value=0, max_value=10),
    st.integers(min_value=0, max_value=100),
    st.integers(min_value=0, max_value=10000),
)
def test_property4_threat_score_bounded_and_correct(severity: int, confidence: int, hit_count: int):
    """Property 4: Threat score in [0,100] and matches formula."""
    # Feature: net-guard-enterprise-idps, Property 4: Threat score is bounded and formula-correct
    score = BlockManager.compute_threat_score(severity, confidence, hit_count)
    assert 0 <= score <= 100, f"Score {score} out of range for ({severity},{confidence},{hit_count})"
    expected = min(100, round(severity / 10 * 40 + confidence * 0.30 + min(hit_count, 100) * 0.30))
    assert score == expected, f"Formula mismatch: got {score}, expected {expected}"


# ---------------------------------------------------------------------------
# Property 9: Composite risk score bounded and weights sum to 100%
# Feature: net-guard-enterprise-idps, Property 9: Composite risk score is bounded and weights sum to 100%
# ---------------------------------------------------------------------------

from backend.services.threat_intel_service import ThreatIntelService


@settings(max_examples=500)
@given(
    st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    st.floats(min_value=0.0, max_value=100.0, allow_nan=False),
    st.booleans(),
    st.integers(min_value=0, max_value=1000),
)
def test_property9_risk_score_bounded(severity: float, reputation: float, ioc_match: bool, recurrence: int):
    """Property 9: Composite risk score in [0,100] and formula-correct."""
    # Feature: net-guard-enterprise-idps, Property 9: Composite risk score is bounded and weights sum to 100%
    score = ThreatIntelService.compute_risk_score(severity, reputation, ioc_match, recurrence)
    assert 0 <= score <= 100, f"Risk score {score} out of range"
    expected = min(100, round(severity * 40 + reputation * 0.30 + (20 if ioc_match else 0) + min(recurrence, 10) * 1.0))
    assert score == expected, f"Formula mismatch: got {score}, expected {expected}"


# ---------------------------------------------------------------------------
# Property 5: Simulator generates only public routable IPs
# Feature: net-guard-enterprise-idps, Property 5: Simulator generates only public routable IPs
# ---------------------------------------------------------------------------

from backend.services.threat_simulator import ThreatSimulator


_SIMULATOR = ThreatSimulator(whitelist_set=set())

_CATEGORIES = [None, "aws", "azure", "gcp", "tor", "botnet", "vpn", "residential", "compromised", "cdn"]


@settings(max_examples=200)
@given(st.sampled_from(_CATEGORIES))
def test_property5_simulator_generates_public_ips(category):
    """Property 5: Generated IPs are always public routable."""
    # Feature: net-guard-enterprise-idps, Property 5: Simulator generates only public routable IPs
    profile = _SIMULATOR.generate_profile(source_category=category)
    ip_str = profile["ip"]
    addr = ipaddress.ip_address(ip_str)
    assert not addr.is_private,    f"Private IP generated: {ip_str}"
    assert not addr.is_loopback,   f"Loopback IP generated: {ip_str}"
    assert not addr.is_link_local, f"Link-local IP generated: {ip_str}"
    assert not addr.is_multicast,  f"Multicast IP generated: {ip_str}"


# ---------------------------------------------------------------------------
# Property 6: Simulator never injects whitelisted IPs
# Feature: net-guard-enterprise-idps, Property 6: Simulator never injects whitelisted IPs
# ---------------------------------------------------------------------------

@settings(max_examples=50)
@given(st.sets(
    st.ip_addresses(v=4).map(str).filter(
        lambda ip: not ipaddress.ip_address(ip).is_private
        and not ipaddress.ip_address(ip).is_loopback
    ),
    min_size=1, max_size=10,
))
def test_property6_no_whitelisted_ips_in_session(whitelist: set):
    """Property 6: Generated IPs are disjoint from whitelist, or whitelist_exhaustion emitted."""
    # Feature: net-guard-enterprise-idps, Property 6: Simulator never injects whitelisted IPs
    sim = ThreatSimulator(whitelist_set=whitelist)
    events = []
    profiles = sim.generate_session(count=5, _event_sink=events.append)
    generated_ips = {p["ip"] for p in profiles}
    # Either no overlap, or an exhaustion warning was emitted for that slot
    overlapping = generated_ips & whitelist
    if overlapping:
        # Must have emitted whitelist_exhaustion for each overlapping IP slot
        exhaustion_events = [e for e in events if e.get("type") == "whitelist_exhaustion"]
        assert exhaustion_events, (
            f"Whitelisted IPs {overlapping} appeared in session without exhaustion event"
        )


# ---------------------------------------------------------------------------
# Property 8: Anomaly detection fires iff deviation exceeds threshold
# Feature: net-guard-enterprise-idps, Property 8: Anomaly detection fires iff deviation exceeds threshold
# ---------------------------------------------------------------------------

from backend.services.anomaly_engine import AnomalyEngine


@settings(max_examples=200, deadline=1000)
@given(
    st.lists(st.floats(min_value=0.0, max_value=1000.0, allow_nan=False, allow_infinity=False), min_size=30, max_size=100),
    st.floats(min_value=0.0, max_value=2000.0, allow_nan=False, allow_infinity=False),
)
def test_property8_anomaly_threshold(baseline_samples: list, probe: float):
    """Property 8: Anomaly fires iff |probe-mean| > 3*std, never during warm-up."""
    # Feature: net-guard-enterprise-idps, Property 8: Anomaly detection fires iff deviation exceeds threshold
    engine = AnomalyEngine(baseline_window_seconds=1)  # very short for test

    # Feed baseline — bypass warm-up by feeding with a past timestamp trick
    import time
    ip = "10.0.0.1"
    # We inject samples directly into the engine internals for testability
    for v in baseline_samples:
        engine._ingest_raw(ip, v, time.monotonic() - 2)  # older than window

    # Now the engine should not be in warm-up (we've provided samples)
    # Check the probe
    result = engine.ingest(ip, probe, 0.0, 0.0)

    if engine.is_warming_up():
        assert result is None, "Must not flag during warm-up"
        return

    # Compute expected outcome
    import statistics
    if len(baseline_samples) < 2:
        return
    mean = statistics.mean(baseline_samples)
    try:
        std = statistics.stdev(baseline_samples)
    except statistics.StatisticsError:
        return
    if std == 0:
        return

    should_flag = abs(probe - mean) > 3 * std
    if should_flag:
        assert result is not None, f"Should have flagged {probe} (mean={mean:.2f}, std={std:.2f})"
    else:
        assert result is None, f"Should not have flagged {probe} (mean={mean:.2f}, std={std:.2f})"


# ---------------------------------------------------------------------------
# Property 10: PacketDecoder never propagates unhandled exceptions
# Feature: net-guard-enterprise-idps, Property 10: PacketDecoder never propagates unhandled exceptions
# ---------------------------------------------------------------------------

from detection.parsers.packet_decoder import PacketDecoder


_decoder = PacketDecoder()


@settings(max_examples=500, deadline=500)
@given(st.binary())
def test_property10_packet_decoder_never_raises(data: bytes):
    """Property 10: decode() always returns a Packet or None, never raises."""
    # Feature: net-guard-enterprise-idps, Property 10: PacketDecoder never propagates unhandled exceptions
    try:
        result = _decoder.decode(data)
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"PacketDecoder.decode raised {type(exc).__name__}: {exc}")
    # result is either None or a Packet-like object — both are acceptable
    assert result is None or hasattr(result, "src_ip"), (
        f"Unexpected return type: {type(result)}"
    )


# ---------------------------------------------------------------------------
# Property 11: ConfigurationManager never propagates unhandled exceptions
# Feature: net-guard-enterprise-idps, Property 11: ConfigurationManager never propagates unhandled exceptions
# ---------------------------------------------------------------------------

from backend.services.config_service import ConfigurationManager


_cm = ConfigurationManager()


@settings(max_examples=300, deadline=1000)
@given(st.dictionaries(
    st.text(max_size=30),
    st.one_of(st.none(), st.text(max_size=50), st.integers(), st.booleans()),
))
def test_property11_config_manager_never_raises(mapping: dict):
    """Property 11: load() and update() never raise except ValueError."""
    # Feature: net-guard-enterprise-idps, Property 11: ConfigurationManager never propagates unhandled exceptions
    # test _build_settings with arbitrary dict
    try:
        result = ConfigurationManager._build_settings(mapping)
        assert result is not None
    except ValueError:
        pass  # allowed
    except Exception as exc:
        pytest.fail(f"ConfigurationManager._build_settings raised unexpected {type(exc).__name__}: {exc}")

    # test validate_settings (pure, no IO)
    try:
        invalid_keys = _cm.validate_settings(mapping)
        assert isinstance(invalid_keys, list)
    except Exception as exc:
        pytest.fail(f"validate_settings raised unexpected {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Property 13: JWT gate blocks all non-public endpoints without valid token
# Feature: net-guard-enterprise-idps, Property 13: JWT authentication blocks all non-public endpoints without valid token
# ---------------------------------------------------------------------------

# Public routes that are exempt from JWT enforcement (mirrors _PUBLIC_PREFIXES in auth_middleware.py)
_JWT_PUBLIC_PREFIXES = (
    "/api/v1/auth/login",
    "/api/v1/auth/refresh",
    "/api/v1/health",
    "/socket.io",
)


def _make_jwt_test_app():
    """
    Build a minimal Flask app with a real-enough auth_service mock so that
    jwt_required_hook actually rejects bad tokens instead of failing open.
    """
    from conftest_app import make_test_app
    from backend.api import dependencies
    from unittest.mock import MagicMock

    app, mocks = make_test_app()

    # Wire a minimal auth_service stub: validate_token raises ValueError for anything
    # that is not a well-formed signed token.  Since we never mint a valid token here,
    # every call will raise → middleware returns 401.
    auth_mock = MagicMock()
    auth_mock.validate_token.side_effect = ValueError("INVALID_TOKEN")
    dependencies.register("auth_service", auth_mock)

    return app


def _collect_non_public_routes(app) -> list[str]:
    """
    Iterate app.url_map and return GET-reachable /api/v1/* paths that are not
    on the public exemption list and don't contain variable segments (for simplicity).
    """
    routes = []
    for rule in app.url_map.iter_rules():
        path = rule.rule
        # Only care about /api/v1/* routes
        if not path.startswith("/api/"):
            continue
        # Skip variable-segment paths — we want deterministic paths to hit
        if "<" in path:
            continue
        # Skip public paths
        if any(path.startswith(pub) for pub in _JWT_PUBLIC_PREFIXES):
            continue
        # Must support at least GET or POST (any HTTP method)
        if not (rule.methods & {"GET", "POST", "PUT", "DELETE", "PATCH"}):
            continue
        routes.append(path)
    return sorted(set(routes))


# Build the app once and extract the non-public routes at module load time
# so Hypothesis can use them as a sampled_from strategy.
_jwt_app = _make_jwt_test_app()
_non_public_routes = _collect_non_public_routes(_jwt_app)


@settings(max_examples=100)
@given(st.sampled_from(_non_public_routes))
def test_property13_jwt_gate_no_token(route: str):
    """Property 13 — missing Authorization header → 401 on every non-public route.

    Validates: Requirements 14.1
    """
    # Feature: net-guard-enterprise-idps, Property 13: JWT authentication blocks all non-public endpoints without valid token
    with _jwt_app.test_client() as c:
        resp = c.get(route)
    assert resp.status_code == 401, (
        f"Expected 401 for GET {route} (no token), got {resp.status_code}"
    )


@settings(max_examples=100)
@given(st.sampled_from(_non_public_routes))
def test_property13_jwt_gate_malformed_token(route: str):
    """Property 13 — malformed Bearer token → 401 on every non-public route.

    Validates: Requirements 14.1
    """
    # Feature: net-guard-enterprise-idps, Property 13: JWT authentication blocks all non-public endpoints without valid token
    with _jwt_app.test_client() as c:
        resp = c.get(route, headers={"Authorization": "Bearer not.a.real.token"})
    assert resp.status_code == 401, (
        f"Expected 401 for GET {route} (malformed token), got {resp.status_code}"
    )


@settings(max_examples=100)
@given(st.sampled_from(_non_public_routes))
def test_property13_jwt_gate_expired_token(route: str):
    """Property 13 — expired JWT → 401 on every non-public route.

    Validates: Requirements 14.1
    """
    # Feature: net-guard-enterprise-idps, Property 13: JWT authentication blocks all non-public endpoints without valid token
    import jwt as _jwt
    from datetime import datetime, timezone, timedelta

    # Mint a token that expired 1 hour ago
    expired_token = _jwt.encode(
        {"sub": "test", "role": "admin", "type": "access",
         "exp": datetime.now(timezone.utc) - timedelta(hours=1)},
        "wrong-secret",
        algorithm="HS256",
    )
    with _jwt_app.test_client() as c:
        resp = c.get(route, headers={"Authorization": f"Bearer {expired_token}"})
    assert resp.status_code == 401, (
        f"Expected 401 for GET {route} (expired token), got {resp.status_code}"
    )


@settings(max_examples=100)
@given(st.sampled_from(_non_public_routes))
def test_property13_jwt_gate_wrong_key(route: str):
    """Property 13 — token signed with wrong key → 401 on every non-public route.

    Validates: Requirements 14.1
    """
    # Feature: net-guard-enterprise-idps, Property 13: JWT authentication blocks all non-public endpoints without valid token
    import jwt as _jwt
    from datetime import datetime, timezone, timedelta

    # Mint a structurally valid but wrongly-signed token
    wrong_key_token = _jwt.encode(
        {"sub": "test", "role": "admin", "type": "access",
         "exp": datetime.now(timezone.utc) + timedelta(hours=8)},
        "definitely-the-wrong-signing-key",
        algorithm="HS256",
    )
    with _jwt_app.test_client() as c:
        resp = c.get(route, headers={"Authorization": f"Bearer {wrong_key_token}"})
    assert resp.status_code == 401, (
        f"Expected 401 for GET {route} (wrong-key token), got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# Property 14: Per-channel severity threshold correctly gates notifications
# Feature: net-guard-enterprise-idps, Property 14: Per-channel severity threshold correctly gates notifications
# ---------------------------------------------------------------------------

from backend.services.soar_engine import SEVERITY_ORDER


_SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]


@settings(max_examples=200)
@given(
    st.sampled_from(_SEVERITY_LEVELS),
    st.sampled_from(_SEVERITY_LEVELS),
)
def test_property14_severity_gating(event_severity: str, channel_threshold: str):
    """Property 14: SOAR dispatches iff event_severity >= channel_threshold."""
    # Feature: net-guard-enterprise-idps, Property 14: Per-channel severity threshold correctly gates notifications
    should_dispatch = SEVERITY_ORDER[event_severity] >= SEVERITY_ORDER[channel_threshold]

    from backend.services.soar_engine import SOAREngine
    dispatched = []

    svc = SOAREngine.__new__(SOAREngine)
    svc._settings_repo = MagicMock()
    svc._log_engine = MagicMock()
    svc._socketio_emit = MagicMock()
    svc._geoip_engine = MagicMock()

    result = svc._severity_passes(event_severity, channel_threshold)
    assert result == should_dispatch, (
        f"Severity gate wrong: event={event_severity}, threshold={channel_threshold}, "
        f"expected={should_dispatch}, got={result}"
    )





# ---------------------------------------------------------------------------
# Property 7: GeoIP cache prevents redundant API calls
# Feature: net-guard-enterprise-idps, Property 7: GeoIP cache prevents redundant API calls
# ---------------------------------------------------------------------------

from backend.services.geoip_engine import GeoIPEngine


@settings(max_examples=100)
@given(
    st.lists(st.ip_addresses(v=4), min_size=1, max_size=10),
    st.integers(min_value=1, max_value=5),
)
def test_property7_geoip_cache_deduplication(unique_ips, repeat_factor):
    """Property 7: external API calls == distinct IPs, even with repetitions.

    For any sequence of resolve() calls that includes repeated IPs, the number
    of external (_resolve_uncached) calls SHALL equal the number of distinct IPs,
    not the total call count.

    Validates: Requirements 5.9
    """
    # Feature: net-guard-enterprise-idps, Property 7: GeoIP cache prevents redundant API calls

    # Build a sequence with guaranteed repetitions: each distinct IP appears repeat_factor times.
    ip_strings = [str(ip) for ip in unique_ips]
    distinct_count = len(set(ip_strings))
    ip_sequence = ip_strings * repeat_factor  # e.g. [A, B, C, A, B, C] for factor=2

    engine = GeoIPEngine(settings_repo=None, cache_size=10_000, ttl_hours=24)

    # Patch Redis helpers to no-ops so the in-process dict cache is the only layer.
    dummy_result = {"ip": "0.0.0.0", "country": "XX", "lat": 0.0, "lon": 0.0,
                    "city": "", "asn": "", "isp": ""}

    with patch.object(engine, "_redis_get", return_value=None), \
         patch.object(engine, "_redis_set"), \
         patch.object(engine, "_resolve_uncached", return_value=dummy_result) as mock_uncached:

        for ip in ip_sequence:
            engine.resolve(ip)

    assert mock_uncached.call_count == distinct_count, (
        f"Expected {distinct_count} external calls for {len(ip_sequence)} IPs "
        f"({distinct_count} distinct), got {mock_uncached.call_count}"
    )


# ---------------------------------------------------------------------------
# Property 3: Whitelisted IPs are always rejected from blocking
# Feature: net-guard-enterprise-idps, Property 3: Whitelisted IPs are always rejected from blocking
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(st.ip_addresses(v=4))
def test_property3_whitelisted_ip_always_rejected(ip_addr):
    """Property 3: Any IP in the active whitelist is always rejected with WHITELISTED_IP.

    For any IP address that is present in the active whitelist, every block request
    targeting that IP SHALL return a WHITELISTED_IP error code and SHALL NOT create
    a block record or apply an iptables rule.

    Validates: Requirements 1.7
    """
    # Feature: net-guard-enterprise-idps, Property 3: Whitelisted IPs are always rejected from blocking
    ip_str = str(ip_addr)

    # Whitelist manager: always says the IP is whitelisted
    whitelist_mgr = MagicMock()
    whitelist_mgr.is_whitelisted.return_value = True

    # Mock repo and emit so we can assert they are never called
    block_repo = MagicMock()
    socketio_emit = MagicMock()

    mgr = BlockManager(
        block_repo=block_repo,
        whitelist_manager=whitelist_mgr,
        log_engine=MagicMock(),
        socketio_emit=socketio_emit,
    )

    with patch.object(mgr, "_apply_firewall", return_value=True) as mock_fw:
        result = mgr.block(ip_str, target_type="ip", reason="test", duration=3600,
                           operator="tester", severity=5, confidence=50)

    # Must return the WHITELISTED_IP error code
    assert result.get("error_code") == "WHITELISTED_IP", (
        f"Expected WHITELISTED_IP for whitelisted IP {ip_str}, got {result}"
    )
    assert result.get("success") is False, (
        f"Expected success=False for whitelisted IP {ip_str}, got {result}"
    )

    # Firewall must NOT have been touched
    mock_fw.assert_not_called()

    # DB must NOT have been written
    block_repo.insert_enterprise.assert_not_called()
    block_repo.extend_expiry.assert_not_called()

    # WebSocket must NOT have emitted a block event
    socketio_emit.assert_not_called()


# ---------------------------------------------------------------------------
# Property 1: Block atomicity — no partial state on failure
# Feature: net-guard-enterprise-idps, Property 1: Block atomicity — no partial state on failure
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(
    st.ip_addresses(v=4).map(str),
    st.text(min_size=1, max_size=100),
)
def test_property1_block_atomicity_db_failure(ip: str, reason: str):
    """Scenario A: iptables succeeds but DB insert fails → compensating DELETE issued, no record exists.

    Validates: Requirements 1.1, 1.14
    """
    # Feature: net-guard-enterprise-idps, Property 1: Block atomicity — no partial state on failure
    assume(not ipaddress.ip_address(ip).is_private)

    block_repo = MagicMock()
    block_repo.get_active.return_value = None           # no existing block (fresh IP)
    block_repo.count_hits.return_value = 0
    block_repo.insert_enterprise.return_value = None    # DB insert fails

    whitelist_mgr = MagicMock()
    whitelist_mgr.is_whitelisted.return_value = False

    manager = BlockManager(block_repo, whitelist_mgr, MagicMock())

    apply_calls = []

    def fake_apply_firewall(target, block, target_type="ip"):
        apply_calls.append((target, block))
        return True  # iptables always succeeds in this scenario

    manager._apply_firewall = fake_apply_firewall

    result = manager.block(target=ip, reason=reason)

    # Must report failure
    assert result["success"] is False, f"Expected failure when DB insert returns None, got {result}"
    assert result.get("error_code") == "DB_ERROR"

    # Compensating DELETE must have been issued after the initial INSERT rule
    block_calls   = [(t, b) for t, b in apply_calls if b is True]
    unblock_calls = [(t, b) for t, b in apply_calls if b is False]
    assert block_calls,   "iptables INSERT rule must have been attempted"
    assert unblock_calls, "Compensating iptables DELETE must have been issued on DB failure"
    assert unblock_calls[0][0] == ip, "Compensating DELETE must target the same IP"

    # DB insert was called (it was the step that failed by returning None)
    block_repo.insert_enterprise.assert_called_once()


@settings(max_examples=100)
@given(
    st.ip_addresses(v=4).map(str),
    st.text(min_size=1, max_size=100),
)
def test_property1_block_atomicity_firewall_failure(ip: str, reason: str):
    """Scenario B: iptables fails → DB insert is never attempted.

    Validates: Requirements 1.1, 1.14
    """
    # Feature: net-guard-enterprise-idps, Property 1: Block atomicity — no partial state on failure
    assume(not ipaddress.ip_address(ip).is_private)

    block_repo = MagicMock()
    block_repo.get_active.return_value = None
    block_repo.count_hits.return_value = 0

    whitelist_mgr = MagicMock()
    whitelist_mgr.is_whitelisted.return_value = False

    manager = BlockManager(block_repo, whitelist_mgr, MagicMock())
    manager._apply_firewall = MagicMock(return_value=False)  # iptables fails

    result = manager.block(target=ip, reason=reason)

    # Must report failure
    assert result["success"] is False
    assert result.get("error_code") == "FIREWALL_ERROR"

    # DB insert must never have been called
    block_repo.insert_enterprise.assert_not_called()


# ---------------------------------------------------------------------------
# Property 2: Duplicate block extends expiry, never duplicates
# Feature: net-guard-enterprise-idps, Property 2: Duplicate block extends expiry, never duplicates
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    st.ip_addresses(v=4),
    st.integers(min_value=1, max_value=3600),
    st.integers(min_value=1, max_value=3600),
)
def test_property2_duplicate_block_extends_expiry(raw_ip, first_duration: int, second_duration: int):
    """Property 2: Duplicate block extends expiry, never duplicates.

    For any IP that already has an active block, a second block request SHALL result
    in exactly one active record for that IP and the new expires_at SHALL be strictly
    later than the original expires_at.

    Validates: Requirements 1.5
    """
    # Feature: net-guard-enterprise-idps, Property 2: Duplicate block extends expiry, never duplicates
    ip = str(raw_ip)

    # ---- in-memory fake block_repo ----
    # Stores at most one active record per IP (mimics real DB behaviour).
    active_store: dict[str, dict] = {}
    insert_calls: list[str] = []

    class _FakeBlockRepo:
        def get_active(self, ip_address):
            return active_store.get(ip_address)

        def extend_expiry(self, ip_address, new_expires_at):
            if ip_address in active_store:
                active_store[ip_address]["expires_at"] = new_expires_at
            return True

        def insert_enterprise(self, record_data):
            ip_addr = record_data["ip_address"]
            # Track every insert to detect duplicates
            insert_calls.append(ip_addr)
            active_store[ip_addr] = {
                "id": len(active_store) + 1,
                "ip_address": ip_addr,
                "expires_at": record_data["expires_at"],
                "threat_score": record_data.get("threat_score", 0),
                "active": True,
            }
            return active_store[ip_addr]["id"]

        def count_hits(self, ip_address):
            return 0

    fake_repo = _FakeBlockRepo()
    whitelist_mock = MagicMock()
    whitelist_mock.is_whitelisted.return_value = False

    manager = BlockManager(
        block_repo=fake_repo,
        whitelist_manager=whitelist_mock,
        log_engine=MagicMock(),
        socketio_emit=None,
    )

    # Patch firewall calls so the test never touches iptables.
    with patch.object(manager, "_apply_firewall", return_value=True):
        # First block
        result1 = manager.block(ip, target_type="ip", duration=first_duration)
        assert result1["success"], f"First block failed: {result1}"

        original_expires = active_store[ip]["expires_at"]

        # Second block — must extend, not duplicate
        result2 = manager.block(ip, target_type="ip", duration=second_duration)
        assert result2["success"], f"Second block failed: {result2}"

    # Exactly one active record
    assert len(active_store) == 1, (
        f"Expected exactly 1 active record after duplicate block, got {len(active_store)}"
    )
    # No second insert was issued — only the first block should have called insert_enterprise
    assert len(insert_calls) == 1, (
        f"insert_enterprise called {len(insert_calls)} times; should be called only once"
    )
    # New expiry must be strictly later: extend_expiry now adds second_duration to the
    # original expires_at (not to now), so new_expires = original_expires + second_duration.
    # Since second_duration >= 1, new_expires is always strictly greater.
    new_expires = active_store[ip]["expires_at"]
    assert new_expires > original_expires, (
        f"New expires_at ({new_expires!r}) must be strictly later than original ({original_expires!r})"
    )
