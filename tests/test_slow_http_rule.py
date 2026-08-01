"""
test_slow_http_rule.py — Unit tests for SlowHttpRule.

Covers:
(a) Single connection completes quickly → None
(b) threshold slow connections from one IP → ThreatEvent Medium
(c) >= 2x threshold → High
(d) process_packet never raises on malformed/truncated packet

Requirements: 7.1, 7.2, 7.3, 7.4, 7.6
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from detection.parsers.packet_decoder import Packet
from detection.rules.slow_http import SlowHttpRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_tcp_packet(
    src_ip: str = "10.0.0.1",
    src_port: int = 12345,
    dst_port: int = 80,
    flags: str = "S",
    payload: bytes = None,
) -> Packet:
    """Build a minimal TCP Packet."""
    return Packet(
        src_ip=src_ip,
        dst_ip="192.168.1.100",
        src_port=src_port,
        dst_port=dst_port,
        protocol="TCP",
        flags=flags,
        timestamp=_ts(),
        length=60 + (len(payload) if payload else 0),
        payload=payload,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def rule() -> SlowHttpRule:
    """Fresh SlowHttpRule with small threshold/timeout for fast testing."""
    r = SlowHttpRule()
    r.initialize()
    r._threshold = 3
    r._timeout = 1  # 1 second timeout for fast tests
    return r


def _open_connection(rule: SlowHttpRule, src_ip: str, src_port: int, dst_port: int = 80) -> None:
    """Send a SYN to open a tracked connection."""
    rule.process_packet(make_tcp_packet(
        src_ip=src_ip, src_port=src_port, dst_port=dst_port, flags="S"
    ))


def _force_stale(rule: SlowHttpRule, src_ip: str, src_port: int, dst_port: int = 80) -> None:
    """Backdate the connection's opened_at so it appears stale."""
    key = (src_ip, src_port, dst_port)
    if key in rule._connections:
        rule._connections[key]["opened_at"] -= rule._timeout + 5


# ---------------------------------------------------------------------------
# (a) Single connection that completes quickly → None
# ---------------------------------------------------------------------------

class TestCompletedConnection:
    def test_no_packets_returns_none(self, rule):
        assert rule.evaluate() is None

    def test_completed_connection_not_flagged(self, rule):
        """A connection that sends \\r\\n\\r\\n completes and should not trigger."""
        src_ip = "10.0.0.1"
        src_port = 10001
        _open_connection(rule, src_ip, src_port)
        # Complete the HTTP request
        rule.process_packet(make_tcp_packet(
            src_ip=src_ip, src_port=src_port, flags="",
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ))
        # Mark as stale (it's already completed, so it won't be counted)
        _force_stale(rule, src_ip, src_port)
        # Trigger scan
        rule._last_check = 0.0
        rule.process_packet(make_tcp_packet(
            src_ip=src_ip, src_port=src_port + 1, flags="S",
        ))
        assert rule.evaluate() is None

    def test_non_tcp_ignored(self, rule):
        pkt = Packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=None, dst_port=None,
            protocol="UDP", flags=None,
            timestamp=_ts(), length=50, payload=b"hello",
        )
        for _ in range(10):
            rule.process_packet(pkt)
        assert rule.evaluate() is None

    def test_wrong_dst_port_ignored(self, rule):
        """Connections to non-web ports (e.g. 22) must not be tracked."""
        for i in range(rule._threshold + 5):
            rule.process_packet(make_tcp_packet(
                src_ip="10.0.0.1", src_port=20000 + i, dst_port=22, flags="S"
            ))
        # Force stale and scan
        for i in range(rule._threshold + 5):
            key = ("10.0.0.1", 20000 + i, 22)
            if key in rule._connections:
                rule._connections[key]["opened_at"] -= 100
        rule._last_check = 0.0
        rule.process_packet(make_tcp_packet(src_ip="10.0.0.1", src_port=30000, dst_port=22, flags="S"))
        assert rule.evaluate() is None

    def test_fin_removes_connection(self, rule):
        """FIN packet removes the connection; it should not be detected later."""
        src_ip, src_port = "10.0.0.1", 11111
        _open_connection(rule, src_ip, src_port)
        rule.process_packet(make_tcp_packet(src_ip=src_ip, src_port=src_port, flags="FA"))
        assert (src_ip, src_port, 80) not in rule._connections

    def test_rst_removes_connection(self, rule):
        """RST packet removes the connection."""
        src_ip, src_port = "10.0.0.1", 11112
        _open_connection(rule, src_ip, src_port)
        rule.process_packet(make_tcp_packet(src_ip=src_ip, src_port=src_port, flags="R"))
        assert (src_ip, src_port, 80) not in rule._connections


# ---------------------------------------------------------------------------
# (b) threshold slow connections from one IP → ThreatEvent Medium
# ---------------------------------------------------------------------------

class TestThresholdMedium:
    def _setup_slow_connections(self, rule: SlowHttpRule, src_ip: str, count: int) -> None:
        """Open `count` connections and make them stale."""
        for i in range(count):
            src_port = 50000 + i
            _open_connection(rule, src_ip, src_port)
            _force_stale(rule, src_ip, src_port)

    def test_threshold_connections_triggers_event(self, rule):
        src_ip = "10.1.1.1"
        self._setup_slow_connections(rule, src_ip, rule._threshold)
        # Trigger the periodic scan
        rule._last_check = 0.0
        rule.process_packet(make_tcp_packet(src_ip=src_ip, src_port=60000, flags="S"))
        event = rule.evaluate()
        assert event is not None

    def test_threshold_severity_medium(self, rule):
        """count == threshold < 2×threshold → Medium."""
        src_ip = "10.1.1.2"
        self._setup_slow_connections(rule, src_ip, rule._threshold)
        rule._last_check = 0.0
        rule.process_packet(make_tcp_packet(src_ip=src_ip, src_port=60001, flags="S"))
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "Medium"

    def test_event_attack_type(self, rule):
        src_ip = "10.1.1.3"
        self._setup_slow_connections(rule, src_ip, rule._threshold)
        rule._last_check = 0.0
        rule.process_packet(make_tcp_packet(src_ip=src_ip, src_port=60002, flags="S"))
        event = rule.evaluate()
        assert event is not None
        assert event.attack_type == "Slow HTTP"
        assert event.rule_name == "SLOW_HTTP_001"
        assert event.protocol == "TCP"

    def test_evidence_fields_present(self, rule):
        src_ip = "10.1.1.4"
        self._setup_slow_connections(rule, src_ip, rule._threshold)
        rule._last_check = 0.0
        rule.process_packet(make_tcp_packet(src_ip=src_ip, src_port=60003, flags="S"))
        event = rule.evaluate()
        assert event is not None
        ev = event.evidence
        assert "concurrent_connections" in ev
        assert "threshold" in ev
        assert "connection_timeout_seconds" in ev
        assert "target_ports" in ev

    def test_evidence_values(self, rule):
        src_ip = "10.1.1.5"
        self._setup_slow_connections(rule, src_ip, rule._threshold)
        rule._last_check = 0.0
        rule.process_packet(make_tcp_packet(src_ip=src_ip, src_port=60004, flags="S"))
        event = rule.evaluate()
        assert event is not None
        ev = event.evidence
        assert ev["concurrent_connections"] == rule._threshold
        assert ev["threshold"] == rule._threshold
        assert ev["connection_timeout_seconds"] == rule._timeout
        assert 80 in ev["target_ports"]

    def test_below_threshold_returns_none(self, rule):
        src_ip = "10.1.1.6"
        self._setup_slow_connections(rule, src_ip, rule._threshold - 1)
        rule._last_check = 0.0
        rule.process_packet(make_tcp_packet(src_ip=src_ip, src_port=60005, flags="S"))
        assert rule.evaluate() is None

    def test_source_ip_on_event(self, rule):
        src_ip = "10.1.1.7"
        self._setup_slow_connections(rule, src_ip, rule._threshold)
        rule._last_check = 0.0
        rule.process_packet(make_tcp_packet(src_ip=src_ip, src_port=60006, flags="S"))
        event = rule.evaluate()
        assert event is not None
        assert event.source_ip == src_ip

    def test_port_443_tracked(self, rule):
        """Connections to port 443 must also be tracked."""
        src_ip = "10.1.1.8"
        for i in range(rule._threshold):
            src_port = 55000 + i
            rule.process_packet(make_tcp_packet(
                src_ip=src_ip, src_port=src_port, dst_port=443, flags="S"
            ))
            key = (src_ip, src_port, 443)
            if key in rule._connections:
                rule._connections[key]["opened_at"] -= rule._timeout + 5
        rule._last_check = 0.0
        rule.process_packet(make_tcp_packet(src_ip=src_ip, src_port=65000, dst_port=443, flags="S"))
        event = rule.evaluate()
        assert event is not None
        assert event.severity in ("Medium", "High")


# ---------------------------------------------------------------------------
# (c) >= 2x threshold → High
# ---------------------------------------------------------------------------

class TestHighSeverity:
    def _setup_slow_connections(self, rule: SlowHttpRule, src_ip: str, count: int) -> None:
        for i in range(count):
            src_port = 40000 + i
            _open_connection(rule, src_ip, src_port)
            _force_stale(rule, src_ip, src_port)

    def test_two_times_threshold_severity_high(self, rule):
        """count >= 2×threshold → High."""
        src_ip = "10.2.2.1"
        self._setup_slow_connections(rule, src_ip, rule._threshold * 2)
        rule._last_check = 0.0
        rule.process_packet(make_tcp_packet(src_ip=src_ip, src_port=49999, flags="S"))
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "High"

    def test_above_two_times_threshold_severity_high(self, rule):
        """count > 2×threshold still → High."""
        src_ip = "10.2.2.2"
        self._setup_slow_connections(rule, src_ip, rule._threshold * 3)
        rule._last_check = 0.0
        rule.process_packet(make_tcp_packet(src_ip=src_ip, src_port=49998, flags="S"))
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "High"

    def test_exactly_two_times_threshold_evidence(self, rule):
        src_ip = "10.2.2.3"
        count = rule._threshold * 2
        self._setup_slow_connections(rule, src_ip, count)
        rule._last_check = 0.0
        rule.process_packet(make_tcp_packet(src_ip=src_ip, src_port=49997, flags="S"))
        event = rule.evaluate()
        assert event is not None
        assert event.evidence["concurrent_connections"] == count


# ---------------------------------------------------------------------------
# (d) process_packet never raises on malformed/truncated packet
# ---------------------------------------------------------------------------

class TestNoRaiseOnMalformed:
    def test_none_flags(self, rule):
        """packet.flags=None must not raise."""
        pkt = make_tcp_packet(flags=None)
        rule.process_packet(pkt)  # must not raise

    def test_none_src_port(self, rule):
        """packet.src_port=None must not raise."""
        pkt = Packet(
            src_ip="1.2.3.4", dst_ip="5.6.7.8",
            src_port=None, dst_port=80,
            protocol="TCP", flags="S",
            timestamp=_ts(), length=60, payload=None,
        )
        rule.process_packet(pkt)

    def test_none_dst_port(self, rule):
        """packet.dst_port=None must not raise."""
        pkt = Packet(
            src_ip="1.2.3.4", dst_ip="5.6.7.8",
            src_port=1234, dst_port=None,
            protocol="TCP", flags="S",
            timestamp=_ts(), length=60, payload=None,
        )
        rule.process_packet(pkt)

    def test_empty_payload(self, rule):
        """Empty bytes payload must not raise."""
        pkt = make_tcp_packet(flags="", payload=b"")
        rule.process_packet(pkt)

    def test_truncated_payload(self, rule):
        """Truncated payload (no \\r\\n\\r\\n) must not raise."""
        pkt = make_tcp_packet(flags="", payload=b"GET / HTTP/1.1\r\nHos")
        rule.process_packet(pkt)

    def test_evaluate_on_fresh_rule_never_raises(self):
        """evaluate() on un-initialised rule must not raise."""
        r = SlowHttpRule()
        result = r.evaluate()
        assert result is None


# ---------------------------------------------------------------------------
# Explain
# ---------------------------------------------------------------------------

class TestExplain:
    def _make_event_for_ip(self, rule: SlowHttpRule, src_ip: str) -> object:
        for i in range(rule._threshold):
            src_port = 30000 + i
            _open_connection(rule, src_ip, src_port)
            _force_stale(rule, src_ip, src_port)
        rule._last_check = 0.0
        rule.process_packet(make_tcp_packet(src_ip=src_ip, src_port=39999, flags="S"))
        return rule.evaluate()

    def test_explain_text_under_500_chars(self, rule):
        event = self._make_event_for_ip(rule, "10.3.3.1")
        assert event is not None
        explanation = rule.explain(event)
        assert len(explanation.plain_english_text) <= 500

    def test_explain_returns_explanation_object(self, rule):
        from detection.rules.base_rule import Explanation
        event = self._make_event_for_ip(rule, "10.3.3.2")
        assert event is not None
        result = rule.explain(event)
        assert isinstance(result, Explanation)

    def test_explain_mentions_source_ip(self, rule):
        src_ip = "10.3.3.3"
        event = self._make_event_for_ip(rule, src_ip)
        assert event is not None
        explanation = rule.explain(event)
        assert src_ip in explanation.plain_english_text


# ---------------------------------------------------------------------------
# Cleanup / initialize lifecycle
# ---------------------------------------------------------------------------

class TestLifecycle:
    def test_cleanup_clears_state(self, rule):
        _open_connection(rule, "10.4.4.1", 20001)
        rule.cleanup()
        assert not rule._connections
        assert not rule._pending
        assert rule._last_check == 0.0
        assert rule.evaluate() is None

    def test_initialize_clears_state(self, rule):
        _open_connection(rule, "10.4.4.2", 20002)
        rule.initialize()
        assert not rule._connections
        assert not rule._pending
        assert rule.evaluate() is None

    def test_second_evaluate_returns_none(self, rule):
        """After the event is consumed, further evaluate() calls return None."""
        src_ip = "10.4.4.3"
        for i in range(rule._threshold):
            _open_connection(rule, src_ip, 25000 + i)
            _force_stale(rule, src_ip, 25000 + i)
        rule._last_check = 0.0
        rule.process_packet(make_tcp_packet(src_ip=src_ip, src_port=29999, flags="S"))
        assert rule.evaluate() is not None
        assert rule.evaluate() is None
