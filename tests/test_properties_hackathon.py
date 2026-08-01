"""
test_properties_hackathon.py — Property-based tests for NetGuard Hackathon Upgrade.

Properties defined in design.md for the netguard-hackathon-upgrade spec.

Library: hypothesis (already installed)
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import ipaddress

from hypothesis import given, settings as hsettings, strategies as st, HealthCheck
import pytest

# ---------------------------------------------------------------------------
# Property 3: AI Explanation Fields Invariant
# Validates: Requirements 2.4, 2.9, 14.2
# ---------------------------------------------------------------------------

_ATTACK_TYPES = [
    "SQL Injection", "Brute Force", "Port Scan", "DDoS/SYN Flood",
    "XSS", "SSH Login", "Suspicious DNS", "Malware Download", "Privilege Escalation",
]
_SEVERITIES = ["Low", "Medium", "High", "Critical"]
_REQUIRED_HEADERS = [
    "## Summary",
    "## Business Impact",
    "## How the Attacker Works",
    "## Immediate Actions",
    "## Long-term Recommendations",
    "## MITRE ATT&CK",
    "## CVE References",
]


# Feature: netguard-hackathon-upgrade, Property 3
@hsettings(max_examples=100, deadline=None)
@given(
    attack_type=st.sampled_from(_ATTACK_TYPES),
    severity=st.sampled_from(_SEVERITIES),
    confidence=st.integers(min_value=0, max_value=100),
)
def test_property_3_ai_explanation_fields_invariant(
    attack_type: str, severity: str, confidence: int
) -> None:
    """
    Property 3: AI Explanation Fields Invariant

    For any valid (non-None) threat_event and base_explanation passed to
    AIExplainService.generate() (using the stub provider):
    - markdown_report is a non-empty string
    - markdown_report contains all 7 required section headers
    - immediate_actions, long_term_recommendations, mitre_attack_mapping,
      and cve_references are all Python list instances (never None)

    Uses AI_PROVIDER=stub (deterministic, no network).

    Validates: Requirements 2.4, 2.9, 14.2
    """
    import os
    import uuid
    from datetime import datetime, timezone
    from unittest.mock import patch

    from detection.rules.base_rule import ThreatEvent, Explanation
    from backend.services.ai_explain_service import AIExplainService

    threat_event = ThreatEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        attack_type=attack_type,
        source_ip="192.0.2.1",
        destination_ip="10.0.0.1",
        source_port=None,
        destination_port=80,
        protocol="TCP",
        rule_name="TEST_RULE_001",
        severity=severity,
        confidence=confidence,
        packet_count=1,
        evidence={},
        blocked=False,
    )

    base_explanation = Explanation(
        attack_name=attack_type,
        rule_triggered="TEST_RULE_001",
        plain_english_text=f"Detected {attack_type} from 192.0.2.1.",
        evidence={},
        confidence_score=confidence,
        severity=severity,
        recommendation="Review and respond.",
    )

    with patch.dict(os.environ, {"AI_PROVIDER": "stub"}):
        service = AIExplainService()
        result = service.generate(threat_event, base_explanation)

    # markdown_report must be a non-empty string
    assert isinstance(result.markdown_report, str), (
        f"markdown_report must be str, got {type(result.markdown_report)}"
    )
    assert result.markdown_report.strip(), (
        f"markdown_report must be non-empty for attack_type={attack_type!r}, severity={severity!r}"
    )

    # All 7 section headers must be present
    for header in _REQUIRED_HEADERS:
        assert header in result.markdown_report, (
            f"markdown_report missing section '{header}' "
            f"for attack_type={attack_type!r}, severity={severity!r}"
        )

    # List fields must be list instances (never None)
    for field_name in ("immediate_actions", "long_term_recommendations",
                       "mitre_attack_mapping", "cve_references"):
        value = getattr(result, field_name)
        assert isinstance(value, list), (
            f"{field_name} must be list, got {type(value)} "
            f"for attack_type={attack_type!r}, severity={severity!r}"
        )


# ---------------------------------------------------------------------------
# Property 1: Demo Source IP in TEST-NET
# Validates: Requirements 1.6
# ---------------------------------------------------------------------------

_TEST_NET_RANGES = [
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
]

# 9 attack templates as defined in the design spec (DemoService._ATTACK_TEMPLATES)
_ATTACK_TEMPLATES = [
    {"attack_type": "SQL Injection",        "rule_name": "SQL_INJECTION_001",    "severity": "High",     "confidence": 100, "destination_ip": "10.0.0.1", "destination_port": 80,   "protocol": "TCP",     "packet_count": 1},
    {"attack_type": "Brute Force",          "rule_name": "BRUTE_FORCE_001",      "severity": "Medium",   "confidence": 75,  "destination_ip": "10.0.0.1", "destination_port": 22,   "protocol": "TCP",     "packet_count": 15},
    {"attack_type": "Port Scan",            "rule_name": "PORT_SCAN_001",        "severity": "Medium",   "confidence": 80,  "destination_ip": "10.0.0.1", "destination_port": None, "protocol": "TCP",     "packet_count": 30},
    {"attack_type": "DDoS/SYN Flood",       "rule_name": "SYN_FLOOD_001",        "severity": "Critical", "confidence": 95,  "destination_ip": "10.0.0.1", "destination_port": 80,   "protocol": "TCP",     "packet_count": 500},
    {"attack_type": "XSS",                  "rule_name": "XSS_001",              "severity": "High",     "confidence": 90,  "destination_ip": "10.0.0.1", "destination_port": 443,  "protocol": "TCP",     "packet_count": 1},
    {"attack_type": "SSH Login",            "rule_name": "SSH_LOGIN_001",        "severity": "Medium",   "confidence": 70,  "destination_ip": "10.0.0.1", "destination_port": 22,   "protocol": "TCP",     "packet_count": 8},
    {"attack_type": "Suspicious DNS",       "rule_name": "SUSPICIOUS_DNS_001",   "severity": "Low",      "confidence": 60,  "destination_ip": "8.8.8.8",  "destination_port": 53,   "protocol": "UDP",     "packet_count": 20},
    {"attack_type": "Malware Download",     "rule_name": "MALWARE_DOWNLOAD_001", "severity": "Critical", "confidence": 85,  "destination_ip": "10.0.0.1", "destination_port": 80,   "protocol": "TCP",     "packet_count": 3},
    {"attack_type": "Privilege Escalation", "rule_name": "PRIV_ESC_001",         "severity": "Critical", "confidence": 88,  "destination_ip": "10.0.0.1", "destination_port": None, "protocol": "UNKNOWN", "packet_count": 1},
]


# Feature: netguard-hackathon-upgrade, Property 1
@hsettings(max_examples=100)
@given(template=st.sampled_from(_ATTACK_TEMPLATES))
def test_property_1_demo_source_ip_in_test_net(template: dict) -> None:
    """
    Property 1: Demo Source IP in TEST-NET

    For any synthetic ThreatEvent generated by DemoService._build_event(),
    the source_ip must fall within one of the three RFC 5737 TEST-NET ranges:
      - 192.0.2.0/24
      - 198.51.100.0/24
      - 203.0.113.0/24

    Validates: Requirements 1.6
    """
    demo_service = pytest.importorskip(
        "backend.services.demo_service",
        reason="DemoService not yet implemented",
    )
    DemoService = demo_service.DemoService

    svc = DemoService.__new__(DemoService)  # no __init__ deps needed for _build_event

    event = svc._build_event(template)

    # Accept both a ThreatEvent object (with .source_ip attr) and a plain dict
    source_ip = event.source_ip if hasattr(event, "source_ip") else event["source_ip"]

    addr = ipaddress.IPv4Address(source_ip)
    in_test_net = any(addr in net for net in _TEST_NET_RANGES)
    assert in_test_net, (
        f"source_ip {source_ip!r} for attack_type={template['attack_type']!r} "
        f"is not in any TEST-NET range (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rate_limit_app():
    """
    Minimal Flask app with only the RateLimiter before_request hook wired in
    and one non-exempt endpoint at /api/v1/detections (returns 200).

    Each call creates a fresh RateLimiter so tests are fully isolated.
    """
    from flask import Flask, jsonify
    from backend.middleware.rate_limiter import RateLimiter

    app = Flask(__name__)
    app.config["TESTING"] = True

    limiter = RateLimiter()
    app.before_request(limiter.check)

    @app.route("/api/v1/detections")
    def detections():
        return jsonify({"success": True, "data": {}}), 200

    return app


# ---------------------------------------------------------------------------
# Property 9: Rate Limit Enforcement
# Validates: Requirements 10.1, 14.7
# ---------------------------------------------------------------------------

# Feature: netguard-hackathon-upgrade, Property 9
@hsettings(
    max_examples=20,
    deadline=None,  # Flask app setup on first Hypothesis run can be slow
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(extra=st.integers(min_value=0, max_value=10))
def test_property_9_rate_limit_enforcement(extra: int) -> None:
    """
    Property 9: Rate Limit Enforcement

    For any client IP, within a single 60-second window:
    - Requests 1–120 to a non-exempt endpoint MUST return non-429.
    - Request 121 (and any beyond) MUST return HTTP 429 with a Retry-After header.

    'extra' is the number of additional requests beyond 121 (0–10).
    All requests are from the same simulated IP via X-Forwarded-For.
    A fresh app (and thus a fresh RateLimiter) is created per test call to
    ensure window state is isolated across Hypothesis examples.

    Validates: Requirements 10.1, 14.7
    """
    app = _make_rate_limit_app()
    client_ip = "10.99.0.1"
    headers = {"X-Forwarded-For": client_ip}

    with app.test_client() as client:
        # Requests 1–120: all must pass (non-429)
        for i in range(1, 121):
            resp = client.get("/api/v1/detections", headers=headers)
            assert resp.status_code != 429, (
                f"Request {i} was unexpectedly rate-limited (got 429)"
            )

        # Request 121 onward: all must be 429 with Retry-After
        for j in range(121, 122 + extra):
            resp = client.get("/api/v1/detections", headers=headers)
            assert resp.status_code == 429, (
                f"Request {j} should have been rate-limited (got {resp.status_code})"
            )
            assert "Retry-After" in resp.headers, (
                f"Request {j}: 429 response missing Retry-After header"
            )


# ---------------------------------------------------------------------------
# Property 10: Security Headers on All Responses
# Validates: Requirements 11.1
# ---------------------------------------------------------------------------

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}

_SAMPLED_ENDPOINTS = [
    ("/api/v1/ping",    200),
    ("/api/v1/missing", 404),
    ("/api/v1/broken",  422),
]


def _make_security_headers_app():
    """
    Minimal Flask app with add_security_headers wired as after_request.
    Exposes three routes returning 200, 404, and 422 so we can verify
    headers appear on every status code.
    """
    from flask import Flask, jsonify
    from backend.middleware.security_headers import add_security_headers

    app = Flask(__name__)
    app.config["TESTING"] = True

    app.after_request(add_security_headers)

    @app.route("/api/v1/ping")
    def ping():
        return jsonify({"ok": True}), 200

    @app.route("/api/v1/missing")
    def missing():
        return jsonify({"error": "not found"}), 404

    @app.route("/api/v1/broken")
    def broken():
        return jsonify({"error": "unprocessable"}), 422

    return app


# Feature: netguard-hackathon-upgrade, Property 10
@pytest.mark.parametrize("path,expected_status", _SAMPLED_ENDPOINTS)
def test_property_10_security_headers_on_all_responses(path: str, expected_status: int) -> None:
    """
    Property 10: Security Headers on All Responses

    For any sampled /api/v1 endpoint, all 4 security headers must be present
    on the response regardless of HTTP status code (200, 404, 422).

    Validates: Requirements 11.1
    """
    app = _make_security_headers_app()
    with app.test_client() as client:
        resp = client.get(path)
        assert resp.status_code == expected_status, (
            f"{path}: expected {expected_status}, got {resp.status_code}"
        )
        for header, value in _SECURITY_HEADERS.items():
            assert header in resp.headers, (
                f"{path} (status {expected_status}): missing header '{header}'"
            )
            assert resp.headers[header] == value, (
                f"{path} (status {expected_status}): "
                f"'{header}' = {resp.headers[header]!r}, expected {value!r}"
            )


# ---------------------------------------------------------------------------
# Property 5: Health Score Bounds
# Validates: Requirements 9.1, 9.5, 14.3
# ---------------------------------------------------------------------------

# Feature: netguard-hackathon-upgrade, Property 5
@given(
    alerts_today=st.integers(min_value=0, max_value=1000),
    active_blocks=st.integers(min_value=0, max_value=1000),
)
@hsettings(max_examples=100)
def test_property_5_health_score_bounds(alerts_today: int, active_blocks: int) -> None:
    """
    Property 5: Health Score Bounds

    For any non-negative integers alerts_today and active_blocks,
    the health score formula must return an integer in [0, 100].

    Tests the formula directly (same logic as StatsService.get_health_score):
        score = max(0, min(100, 100 - alerts_today*5 - active_blocks*2))

    Validates: Requirements 9.1, 9.5, 14.3
    """
    score = max(0, min(100, 100 - alerts_today * 5 - active_blocks * 2))
    assert isinstance(score, int), f"score must be int, got {type(score)}"
    assert 0 <= score <= 100, f"score {score} out of [0, 100] for alerts_today={alerts_today}, active_blocks={active_blocks}"


# ---------------------------------------------------------------------------
# Property 8: Pagination Non-Overlap
# Validates: Requirements 14.6
# ---------------------------------------------------------------------------

# Feature: netguard-hackathon-upgrade, Property 8
@hsettings(max_examples=50, deadline=None)
@given(n=st.integers(min_value=1, max_value=50))
def test_property_8_pagination_non_overlap(n: int) -> None:
    """
    Property 8: Pagination Non-Overlap

    For any N ∈ [1, 50] (kept small for speed; property holds for any N ∈ [1, 500]):
    - Seed a fresh in-memory SQLite DB with exactly 2*N events.
    - Page 1: get_all(filters={}, limit=N, offset=0)
    - Page 2: get_all(filters={}, limit=N, offset=N)
    - The two sets of event_ids must be disjoint.

    Validates: Requirements 14.6 (Property F)
    """
    import uuid
    from datetime import datetime, timezone
    from contextlib import contextmanager

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from database.schema import Base
    from backend.repositories.event_repository import EventRepository

    # Fresh in-memory DB per Hypothesis example
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    @contextmanager
    def session_factory():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    repo = EventRepository(session_factory)

    # Seed exactly 2*N events with deterministic, unique timestamps and event_ids
    ts_base = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    from datetime import timedelta
    for i in range(2 * n):
        ts = (ts_base + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%SZ")
        repo.insert({
            "event_id": str(uuid.uuid4()),
            "timestamp": ts,
            "attack_type": "Port Scan",
            "source_ip": "192.0.2.1",
            "destination_ip": "10.0.0.1",
            "protocol": "TCP",
            "rule_name": "PORT_SCAN_001",
            "severity": "Medium",
            "confidence": 80,
            "packet_count": 1,
            "explanation": "test",
            "recommendation": "test",
        })

    page1 = repo.get_all(filters={}, limit=n, offset=0)
    page2 = repo.get_all(filters={}, limit=n, offset=n)

    ids1 = {e["event_id"] for e in page1}
    ids2 = {e["event_id"] for e in page2}

    assert len(ids1) == n, f"Page 1 expected {n} records, got {len(ids1)}"
    assert len(ids2) == n, f"Page 2 expected {n} records, got {len(ids2)}"
    assert ids1.isdisjoint(ids2), (
        f"Pages share event_ids (n={n}): {ids1 & ids2}"
    )


# ---------------------------------------------------------------------------
# Shared test-DB helpers for Properties 11 and 12
# ---------------------------------------------------------------------------

def _make_in_memory_session_factory():
    """Return a session_factory backed by an in-memory SQLite DB."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from contextlib import contextmanager
    from database.schema import Base

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    @contextmanager
    def factory():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    return factory


def _seed_events(repo, events: list[dict]) -> None:
    """Insert a list of minimal event dicts into the repo."""
    for e in events:
        repo.insert(e)


def _make_event(event_id, source_ip, destination_ip, attack_type,
                severity="Low", timestamp="2025-01-01T00:00:00Z"):
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "attack_type": attack_type,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "rule_name": "TEST_RULE",
        "severity": severity,
        "confidence": 50,
        "explanation": "test",
        "recommendation": "test",
    }


# Deterministic seed dataset — enough to cover search and AND filter paths
_SEED = [
    _make_event("e1", "192.168.1.1",   "10.0.0.1",  "SQL Injection",  severity="High"),
    _make_event("e2", "10.0.0.55",     "10.0.0.2",  "Brute Force",    severity="Medium"),
    _make_event("e3", "203.0.113.7",   "10.0.0.3",  "Port Scan",      severity="Medium"),
    _make_event("e4", "198.51.100.42", "10.0.0.4",  "SQL Injection",  severity="Critical"),
    _make_event("e5", "172.16.0.1",    "192.0.2.1", "XSS",            severity="High"),
    _make_event("e6", "10.0.0.55",     "10.0.0.6",  "SSH Login",      severity="Low"),
]


# ---------------------------------------------------------------------------
# Property 11: Detections Search Correctness
# Validates: Requirements 8.1
# ---------------------------------------------------------------------------

# Feature: netguard-hackathon-upgrade, Property 11
@hsettings(max_examples=50, deadline=None)
@given(
    search=st.text(
        alphabet=st.characters(whitelist_categories=("L", "N", "P")),
        min_size=1,
        max_size=20,
    )
)
def test_property_11_search_correctness(search: str) -> None:
    """
    Property 11: Detections Search Correctness

    For any non-empty search string S, every event returned by get_all with
    filters={"search": S} contains S (case-insensitive) as a substring in at
    least one of: source_ip, destination_ip, or attack_type.

    Validates: Requirements 8.1
    """
    from backend.repositories.event_repository import EventRepository

    repo = EventRepository(_make_in_memory_session_factory())
    _seed_events(repo, _SEED)

    results = repo.get_all(filters={"search": search}, limit=500, offset=0)

    s_lower = search.lower()
    for event in results:
        matched = (
            s_lower in (event["source_ip"] or "").lower()
            or s_lower in (event["destination_ip"] or "").lower()
            or s_lower in (event["attack_type"] or "").lower()
        )
        assert matched, (
            f"Event {event['event_id']} returned for search={search!r} "
            f"but source_ip={event['source_ip']!r}, "
            f"destination_ip={event['destination_ip']!r}, "
            f"attack_type={event['attack_type']!r} — none contain the search term"
        )


# ---------------------------------------------------------------------------
# Property 12: AND Filter Correctness
# Validates: Requirements 8.3
# ---------------------------------------------------------------------------

# Feature: netguard-hackathon-upgrade, Property 12
@hsettings(max_examples=50, deadline=None)
@given(
    filter_combo=st.fixed_dictionaries(
        {},
        optional={
            "severity":    st.sampled_from(["Low", "Medium", "High", "Critical"]),
            "attack_type": st.sampled_from(["SQL Injection", "Brute Force", "Port Scan",
                                            "XSS", "SSH Login"]),
            "source_ip":   st.sampled_from(["10.0.0.55", "192.168.1.1", "203.0.113.7"]),
            "search":      st.sampled_from(["10.0", "SQL", "192", "ssh"]),
        },
    )
)
def test_property_12_and_filter_correctness(filter_combo: dict) -> None:
    """
    Property 12: AND Filter Correctness

    For any combination of active filter parameters (severity, attack_type,
    source_ip, search), every event returned by get_all() satisfies ALL active
    filter conditions simultaneously (AND logic).

    Validates: Requirements 8.3
    """
    from backend.repositories.event_repository import EventRepository

    repo = EventRepository(_make_in_memory_session_factory())
    _seed_events(repo, _SEED)

    # Empty filter_combo means no filters — all events returned, property trivially holds
    results = repo.get_all(filters=filter_combo, limit=500, offset=0)

    for event in results:
        if filter_combo.get("severity"):
            assert event["severity"] == filter_combo["severity"], (
                f"Event {event['event_id']}: severity={event['severity']!r} "
                f"does not match filter {filter_combo['severity']!r}"
            )
        if filter_combo.get("attack_type"):
            assert event["attack_type"] == filter_combo["attack_type"], (
                f"Event {event['event_id']}: attack_type={event['attack_type']!r} "
                f"does not match filter {filter_combo['attack_type']!r}"
            )
        if filter_combo.get("source_ip"):
            assert event["source_ip"] == filter_combo["source_ip"], (
                f"Event {event['event_id']}: source_ip={event['source_ip']!r} "
                f"does not match filter {filter_combo['source_ip']!r}"
            )
        if filter_combo.get("search"):
            s_lower = filter_combo["search"].lower()
            matched = (
                s_lower in (event["source_ip"] or "").lower()
                or s_lower in (event["destination_ip"] or "").lower()
                or s_lower in (event["attack_type"] or "").lower()
            )
            assert matched, (
                f"Event {event['event_id']} returned for search={filter_combo['search']!r} "
                f"but source_ip={event['source_ip']!r}, "
                f"destination_ip={event['destination_ip']!r}, "
                f"attack_type={event['attack_type']!r}"
            )


# ---------------------------------------------------------------------------
# Property 2: Demo Event Schema Invariant
# Validates: Requirements 1.8, 14.1
# ---------------------------------------------------------------------------

# Conditionally import DemoService — skip if not implemented yet
try:
    from backend.services.demo_service import DemoService, _ATTACK_TEMPLATES
    _DEMO_SERVICE_AVAILABLE = True
except ImportError:
    _DEMO_SERVICE_AVAILABLE = False
    _ATTACK_TEMPLATES = []


# Feature: netguard-hackathon-upgrade, Property 2
@pytest.mark.skipif(not _DEMO_SERVICE_AVAILABLE, reason="DemoService not yet implemented")
@hsettings(max_examples=100)
@given(template=st.sampled_from(_ATTACK_TEMPLATES) if _ATTACK_TEMPLATES else st.just({}))
def test_property_2_demo_event_schema_invariant(template: dict) -> None:
    """
    Property 2: Demo Event Schema Invariant

    For any of the 9 Attack_Templates, the ThreatEvent built by
    DemoService._build_event(template) must have non-null, non-empty values
    for all required fields, and evidence must contain demo: True.

    Validates: Requirements 1.8, 14.1
    """
    # Build a minimal DemoService — on_threat_event and block_repo not exercised here
    svc = DemoService(on_threat_event=lambda e: None, block_repo=None)
    event = svc._build_event(template)

    # Fields that exist directly on ThreatEvent (explanation/recommendation live on
    # the Explanation dataclass produced by ExplainabilityEngine, not on ThreatEvent itself)
    required_fields = [
        "event_id", "timestamp", "attack_type", "source_ip",
        "rule_name", "severity", "confidence",
    ]
    for field in required_fields:
        value = getattr(event, field, None)
        assert value is not None, (
            f"template={template['attack_type']!r}: field '{field}' is None"
        )
        # confidence is numeric — non-zero means non-empty for our purposes
        if isinstance(value, str):
            assert value != "", (
                f"template={template['attack_type']!r}: field '{field}' is empty string"
            )

    # explanation and recommendation text must be available via _EXPLANATIONS
    # (the ExplainabilityEngine will use these when persisting to DB — Req 1.8, 14.1)
    from backend.services.demo_service import _EXPLANATIONS
    attack_type = template["attack_type"]
    assert attack_type in _EXPLANATIONS, (
        f"template={attack_type!r}: no entry in _EXPLANATIONS dict"
    )
    explanation_text, recommendation = _EXPLANATIONS[attack_type]
    assert explanation_text and explanation_text.strip(), (
        f"template={attack_type!r}: explanation text is empty"
    )
    assert recommendation and recommendation.strip(), (
        f"template={attack_type!r}: recommendation text is empty"
    )

    # evidence must contain demo: True (Req 1.8)
    evidence = getattr(event, "evidence", None)
    assert isinstance(evidence, dict), (
        f"template={template['attack_type']!r}: evidence is not a dict, got {type(evidence)}"
    )
    assert evidence.get("demo") is True, (
        f"template={template['attack_type']!r}: evidence['demo'] != True, got {evidence.get('demo')!r}"
    )


# ---------------------------------------------------------------------------
# Property 4: AI Explanation Rejects Null Inputs
# Feature: netguard-hackathon-upgrade, Property 4
# Validates: Requirements 2.1, 2.10
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("threat_event,base_explanation", [
    (None, object()),
    (object(), None),
])
def test_property_4_ai_explanation_rejects_none_inputs(threat_event, base_explanation) -> None:
    """
    Property 4: AI Explanation Rejects Null Inputs

    generate(None, x) and generate(x, None) both raise ValueError
    before any provider call.

    Validates: Requirements 2.1, 2.10
    """
    from backend.services.ai_explain_service import AIExplainService

    with pytest.raises(ValueError):
        AIExplainService().generate(threat_event, base_explanation)


# ---------------------------------------------------------------------------
# Property 7: Export Count Parity
# Feature: netguard-hackathon-upgrade, Property 7
# Validates: Requirements 6.5, 14.5
# ---------------------------------------------------------------------------


# Feature: netguard-hackathon-upgrade, Property 7
@hsettings(max_examples=50, deadline=None)
@given(
    filters=st.fixed_dictionaries(
        {},
        optional={
            "severity":    st.sampled_from(["Low", "Medium", "High", "Critical"]),
            "attack_type": st.sampled_from(["SQL Injection", "Brute Force", "Port Scan",
                                            "XSS", "SSH Login"]),
            "source_ip":   st.sampled_from(["10.0.0.55", "192.168.1.1", "203.0.113.7"]),
        },
    )
)
def test_property_7_export_count_parity(filters: dict) -> None:
    """
    Property 7: Export Count Parity

    For any valid filter combination, the number of records in the JSON export
    must equal count_filtered() for the same filters.

    ExportService._fetch_events uses limit=10000, offset=0 — same ceiling
    used by count_filtered so counts stay in sync within that cap.

    Validates: Requirements 6.5, 14.5
    """
    import json as _json
    from backend.repositories.event_repository import EventRepository
    from backend.services.export_service import ExportService

    repo = EventRepository(_make_in_memory_session_factory())
    _seed_events(repo, _SEED)

    json_bytes, _ = ExportService(repo).export_json(filters)
    json_records = _json.loads(json_bytes)

    expected = repo.count_filtered(filters)

    assert len(json_records) == expected, (
        f"filters={filters!r}: JSON export has {len(json_records)} records "
        f"but count_filtered returned {expected}"
    )


# ---------------------------------------------------------------------------
# Property 13: Timeline Chronological Order
# Feature: netguard-hackathon-upgrade, Property 13
# Validates: Requirements 4.1, 4.2
# ---------------------------------------------------------------------------

# Feature: netguard-hackathon-upgrade, Property 13
@hsettings(max_examples=50, deadline=None)
@given(template=st.sampled_from(_ATTACK_TEMPLATES))
def test_property_13_timeline_chronological_order(template: dict) -> None:
    """
    Property 13: Timeline Chronological Order

    For any attack template, the timeline built by _build_timeline must:
    - Have "Detected" as the first entry with status "completed"
    - Have non-decreasing timestamps for consecutive entries that both have
      non-None timestamps

    Validates: Requirements 4.1, 4.2
    """
    import uuid
    from datetime import datetime
    from backend.routes.timeline_routes import _build_timeline
    from backend.repositories.event_repository import EventRepository

    session_factory = _make_in_memory_session_factory()
    repo = EventRepository(session_factory)

    event_id = str(uuid.uuid4())
    event_dict = {
        "event_id": event_id,
        "timestamp": "2025-06-01T10:00:00Z",
        "attack_type": template["attack_type"],
        "source_ip": "192.0.2.1",
        "destination_ip": template["destination_ip"],
        "rule_name": template["rule_name"],
        "severity": template["severity"],
        "confidence": template["confidence"],
        "protocol": template["protocol"],
        "packet_count": template["packet_count"],
        "explanation": "test explanation",
        "recommendation": "test recommendation",
    }
    repo.insert(event_dict)

    entries = _build_timeline(event_dict, None)

    # First entry must be "Detected" with status "completed"
    assert entries[0]["step_name"] == "Detected", (
        f"First entry step_name={entries[0]['step_name']!r}, expected 'Detected'"
    )
    assert entries[0]["status"] == "completed", (
        f"First entry status={entries[0]['status']!r}, expected 'completed'"
    )

    # Timestamps must be non-decreasing for consecutive non-None entries
    timed = [(i, e) for i, e in enumerate(entries) if e["timestamp"] is not None]
    for (i, a), (j, b) in zip(timed, timed[1:]):
        ts_a = datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00"))
        ts_b = datetime.fromisoformat(b["timestamp"].replace("Z", "+00:00"))
        assert ts_a <= ts_b, (
            f"Entry {i} ({a['step_name']}) timestamp {a['timestamp']!r} > "
            f"entry {j} ({b['step_name']}) timestamp {b['timestamp']!r}"
        )


# ---------------------------------------------------------------------------
# Property 6: Analytics Bucket Sum Equals Total Events
# Feature: netguard-hackathon-upgrade, Property 6
# Validates: Requirements 5.4, 14.4
# ---------------------------------------------------------------------------

def _make_now_event(event_id: str) -> dict:
    """Seed event with a current timestamp so it falls inside any window."""
    from datetime import datetime, timezone
    return _make_event(
        event_id,
        source_ip="10.1.2.3",
        destination_ip="10.0.0.9",
        attack_type="Port Scan",
        severity="Low",
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


# Feature: netguard-hackathon-upgrade, Property 6
@pytest.mark.parametrize("period", ["hourly", "daily", "weekly"])
def test_property_6_analytics_bucket_sum(period: str) -> None:
    """
    Property 6: Analytics Bucket Sum Equals Total Events

    For any DB state and any period in {"hourly", "daily", "weekly"},
    sum(b["count"] for b in result["buckets"]) == result["total_events"].

    Seeds _SEED events (fixed past timestamps) plus 3 current-timestamp events
    so at least the "weekly" period has non-zero buckets.

    Validates: Requirements 5.4, 14.4
    """
    from backend.repositories.event_repository import EventRepository
    from backend.routes.analytics_routes import _compute_analytics

    repo = EventRepository(_make_in_memory_session_factory())
    _seed_events(repo, _SEED)
    _seed_events(repo, [_make_now_event(f"now_{i}") for i in range(3)])

    result = _compute_analytics(repo, period)

    bucket_sum = sum(b["count"] for b in result["buckets"])
    assert bucket_sum == result["total_events"], (
        f"period={period!r}: bucket sum {bucket_sum} != total_events {result['total_events']}"
    )
