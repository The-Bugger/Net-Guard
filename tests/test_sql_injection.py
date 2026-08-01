"""
test_sql_injection.py — Unit tests for SqlInjectionRule.

Tests cover Requirements 6.1–6.6:
  6.1  Case-insensitive pattern matching for ' OR, UNION SELECT, DROP TABLE,
       --, xp_cmdshell in the TCP payload of HTTP traffic (port 80/443)
  6.2  First detection from source IP → severity "High"
  6.3  Repeated detection from same IP → severity "Critical"
  6.4  Evidence contains source_ip, destination_ip, http_method,
       request_url, matched_pattern
  6.5  Confidence always 100
  6.6  No minimum packet count — single matching payload triggers detection
"""

from __future__ import annotations

import pytest

from detection.parsers.packet_decoder import Packet
from detection.rules.sql_injection import SqlInjectionRule


# ---------------------------------------------------------------------------
# Packet factory helper
# ---------------------------------------------------------------------------

def make_http(
    src: str = "1.2.3.4",
    payload_str: str = "GET /?q=test HTTP/1.1\r\n",
    dst_port: int = 80,
    dst_ip: str = "10.0.0.1",
) -> Packet:
    """Build a minimal TCP packet that looks like an HTTP request."""
    return Packet(
        src_ip=src,
        dst_ip=dst_ip,
        src_port=5000,
        dst_port=dst_port,
        protocol="TCP",
        flags="PA",
        timestamp="2024-01-01T00:00:00Z",
        length=100,
        payload=payload_str.encode(),
    )


# ---------------------------------------------------------------------------
# Pattern detection tests (Req 6.1)
# ---------------------------------------------------------------------------

class TestPatternDetection:
    """Tests that each SQL injection pattern is detected correctly."""

    def _run(self, payload_str: str, dst_port: int = 80) -> object:
        """Helper: process one packet and return the event (or None)."""
        rule = SqlInjectionRule()
        rule.process_packet(make_http(payload_str=payload_str, dst_port=dst_port))
        return rule.evaluate()

    def test_or_pattern_detected(self):
        """Payload with ' OR 1=1 triggers an event."""
        payload = "GET /?id=1' OR 1=1-- HTTP/1.1\r\n"
        event = self._run(payload)
        assert event is not None
        assert event.attack_type == "SQL Injection"
        assert event.rule_name == "SQL_INJECTION_001"

    def test_union_select_detected(self):
        """Payload with UNION SELECT triggers an event."""
        payload = "GET /?q=1 UNION SELECT * FROM users HTTP/1.1\r\n"
        event = self._run(payload)
        assert event is not None
        assert event.attack_type == "SQL Injection"

    def test_drop_table_detected(self):
        """Payload with DROP TABLE triggers an event."""
        payload = "GET /?q=1;DROP TABLE users-- HTTP/1.1\r\n"
        event = self._run(payload)
        assert event is not None
        assert event.attack_type == "SQL Injection"

    def test_comment_pattern_detected(self):
        """Payload with -- (SQL comment) triggers an event."""
        payload = "GET /?user=admin'-- HTTP/1.1\r\n"
        event = self._run(payload)
        assert event is not None
        assert event.attack_type == "SQL Injection"

    def test_xp_cmdshell_detected(self):
        """Payload with xp_cmdshell triggers an event."""
        payload = "GET /?cmd=xp_cmdshell('whoami') HTTP/1.1\r\n"
        event = self._run(payload)
        assert event is not None
        assert event.attack_type == "SQL Injection"


# ---------------------------------------------------------------------------
# Case-insensitivity tests (Req 6.1)
# ---------------------------------------------------------------------------

class TestCaseInsensitivity:
    """Tests that detection is case-insensitive for all patterns."""

    def _run(self, payload_str: str) -> object:
        rule = SqlInjectionRule()
        rule.process_packet(make_http(payload_str=payload_str))
        return rule.evaluate()

    def test_case_insensitive_union_select_lowercase(self):
        """'union select' in lowercase triggers detection."""
        payload = "GET /?q=1 union select password FROM users HTTP/1.1\r\n"
        event = self._run(payload)
        assert event is not None

    def test_case_insensitive_union_select_mixed_case(self):
        """'Union Select' in mixed case triggers detection."""
        payload = "GET /?q=1 Union Select id FROM users HTTP/1.1\r\n"
        event = self._run(payload)
        assert event is not None

    def test_case_insensitive_drop_table_lowercase(self):
        """'drop table' in lowercase triggers detection."""
        payload = "GET /?q=1;drop table sessions-- HTTP/1.1\r\n"
        event = self._run(payload)
        assert event is not None

    def test_case_insensitive_xp_cmdshell_uppercase(self):
        """'XP_CMDSHELL' in uppercase triggers detection."""
        payload = "GET /?cmd=XP_CMDSHELL('dir') HTTP/1.1\r\n"
        event = self._run(payload)
        assert event is not None

    def test_case_insensitive_or_uppercase(self):
        """' OR' in uppercase triggers detection."""
        payload = "GET /?id=1' OR '1'='1 HTTP/1.1\r\n"
        event = self._run(payload)
        assert event is not None


# ---------------------------------------------------------------------------
# Negative / clean traffic tests (Req 6.1, 6.6)
# ---------------------------------------------------------------------------

class TestCleanTraffic:
    """Tests that normal, benign traffic does not produce events."""

    def test_clean_payload_no_event(self):
        """Normal GET request with no SQL patterns → None."""
        rule = SqlInjectionRule()
        rule.process_packet(make_http(payload_str="GET /index.html HTTP/1.1\r\n"))
        assert rule.evaluate() is None

    def test_post_request_no_sqli_no_event(self):
        """POST request with a normal body → None."""
        rule = SqlInjectionRule()
        payload = "POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=alice&password=secret"
        rule.process_packet(make_http(payload_str=payload))
        assert rule.evaluate() is None

    def test_empty_payload_no_event(self):
        """Packet with no payload → None."""
        rule = SqlInjectionRule()
        pkt = Packet(
            src_ip="1.2.3.4",
            dst_ip="10.0.0.1",
            src_port=5000,
            dst_port=80,
            protocol="TCP",
            flags="PA",
            timestamp="2024-01-01T00:00:00Z",
            length=40,
            payload=None,
        )
        rule.process_packet(pkt)
        assert rule.evaluate() is None


# ---------------------------------------------------------------------------
# Port filtering tests (Req 6.1)
# ---------------------------------------------------------------------------

class TestPortFiltering:
    """Tests that only HTTP ports (80, 443) are inspected."""

    def test_non_http_port_ignored_port_22(self):
        """SQL injection payload on port 22 (SSH) → None."""
        rule = SqlInjectionRule()
        payload = "UNION SELECT password FROM users"
        rule.process_packet(make_http(payload_str=payload, dst_port=22))
        assert rule.evaluate() is None

    def test_non_http_port_ignored_port_25(self):
        """SQL injection payload on port 25 (SMTP) → None."""
        rule = SqlInjectionRule()
        payload = "DROP TABLE users"
        rule.process_packet(make_http(payload_str=payload, dst_port=25))
        assert rule.evaluate() is None

    def test_non_http_port_ignored_port_3306(self):
        """SQL injection payload on port 3306 (MySQL) → None (not HTTP)."""
        rule = SqlInjectionRule()
        payload = "DROP TABLE users"
        rule.process_packet(make_http(payload_str=payload, dst_port=3306))
        assert rule.evaluate() is None

    def test_https_port_443_detected(self):
        """SQL injection payload on port 443 (HTTPS) → event emitted."""
        rule = SqlInjectionRule()
        payload = "GET /?q=1 UNION SELECT 1 HTTP/1.1\r\n"
        rule.process_packet(make_http(payload_str=payload, dst_port=443))
        assert rule.evaluate() is not None

    def test_http_port_80_detected(self):
        """SQL injection payload on port 80 (HTTP) → event emitted."""
        rule = SqlInjectionRule()
        payload = "GET /?q=1' OR '1'='1 HTTP/1.1\r\n"
        rule.process_packet(make_http(payload_str=payload, dst_port=80))
        assert rule.evaluate() is not None

    def test_non_tcp_protocol_ignored(self):
        """UDP packet to port 80 with SQLi payload → None (not TCP)."""
        rule = SqlInjectionRule()
        pkt = Packet(
            src_ip="1.2.3.4",
            dst_ip="10.0.0.1",
            src_port=5000,
            dst_port=80,
            protocol="UDP",
            flags=None,
            timestamp="2024-01-01T00:00:00Z",
            length=100,
            payload=b"UNION SELECT password FROM users",
        )
        rule.process_packet(pkt)
        assert rule.evaluate() is None


# ---------------------------------------------------------------------------
# Severity escalation tests (Req 6.2, 6.3)
# ---------------------------------------------------------------------------

class TestSeverityEscalation:
    """Tests for severity assignment and escalation on repeated detections."""

    def test_first_detection_high_severity(self):
        """First match from a new IP → severity 'High'."""
        rule = SqlInjectionRule()
        rule.process_packet(
            make_http(src="5.5.5.5", payload_str="GET /?q=1' OR 1=1-- HTTP/1.1\r\n")
        )
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "High"

    def test_repeat_detection_critical_severity(self):
        """Second match from the same IP → severity 'Critical'."""
        rule = SqlInjectionRule()
        src = "5.5.5.5"
        sqli_payload = "GET /?q=1 UNION SELECT 1 HTTP/1.1\r\n"

        # First hit
        rule.process_packet(make_http(src=src, payload_str=sqli_payload))
        first = rule.evaluate()
        assert first is not None
        assert first.severity == "High"

        # Second hit from same IP
        rule.process_packet(make_http(src=src, payload_str=sqli_payload))
        second = rule.evaluate()
        assert second is not None
        assert second.severity == "Critical"

    def test_different_ips_independent_severity(self):
        """First match from two different IPs each returns 'High'."""
        rule = SqlInjectionRule()
        sqli_payload = "GET /?q=1' OR 1=1 HTTP/1.1\r\n"

        rule.process_packet(make_http(src="1.1.1.1", payload_str=sqli_payload))
        event_a = rule.evaluate()
        assert event_a is not None
        assert event_a.severity == "High"

        rule.process_packet(make_http(src="2.2.2.2", payload_str=sqli_payload))
        event_b = rule.evaluate()
        assert event_b is not None
        assert event_b.severity == "High"

    def test_third_detection_still_critical(self):
        """Third and subsequent matches from same IP remain 'Critical'."""
        rule = SqlInjectionRule()
        src = "9.9.9.9"
        sqli_payload = "GET /?q=1;DROP TABLE users-- HTTP/1.1\r\n"

        rule.process_packet(make_http(src=src, payload_str=sqli_payload))
        rule.evaluate()  # first → High

        rule.process_packet(make_http(src=src, payload_str=sqli_payload))
        rule.evaluate()  # second → Critical

        rule.process_packet(make_http(src=src, payload_str=sqli_payload))
        third = rule.evaluate()
        assert third is not None
        assert third.severity == "Critical"


# ---------------------------------------------------------------------------
# Confidence tests (Req 6.5)
# ---------------------------------------------------------------------------

class TestConfidence:
    """Tests that confidence is always 100."""

    def test_confidence_always_100_or_pattern(self):
        """Event produced by ' OR pattern has confidence 100."""
        rule = SqlInjectionRule()
        rule.process_packet(
            make_http(payload_str="GET /?id=1' OR 1=1 HTTP/1.1\r\n")
        )
        event = rule.evaluate()
        assert event is not None
        assert event.confidence == 100

    def test_confidence_always_100_union_select(self):
        """Event produced by UNION SELECT pattern has confidence 100."""
        rule = SqlInjectionRule()
        rule.process_packet(
            make_http(payload_str="GET /?q=UNION SELECT 1 HTTP/1.1\r\n")
        )
        event = rule.evaluate()
        assert event is not None
        assert event.confidence == 100

    def test_confidence_always_100_on_repeat(self):
        """Second detection (Critical severity) also has confidence 100."""
        rule = SqlInjectionRule()
        src = "3.3.3.3"
        sqli_payload = "GET /?q=xp_cmdshell('dir') HTTP/1.1\r\n"

        rule.process_packet(make_http(src=src, payload_str=sqli_payload))
        rule.evaluate()  # first

        rule.process_packet(make_http(src=src, payload_str=sqli_payload))
        second = rule.evaluate()
        assert second is not None
        assert second.confidence == 100


# ---------------------------------------------------------------------------
# Evidence field tests (Req 6.4)
# ---------------------------------------------------------------------------

class TestEvidenceFields:
    """Tests that evidence contains all required fields with correct values."""

    def setup_method(self):
        """Create a triggered rule + event for all evidence tests."""
        self.rule = SqlInjectionRule()
        self.src_ip = "192.168.10.5"
        self.dst_ip = "10.0.0.1"
        payload = "GET /search?q=1' OR 1=1-- HTTP/1.1\r\nHost: victim.local\r\n\r\n"
        pkt = make_http(src=self.src_ip, payload_str=payload, dst_ip=self.dst_ip)
        self.rule.process_packet(pkt)
        self.event = self.rule.evaluate()
        assert self.event is not None, "Setup: expected event was not produced"

    def test_evidence_contains_source_ip(self):
        """Evidence includes source_ip matching the packet's src_ip."""
        assert "source_ip" in self.event.evidence
        assert self.event.evidence["source_ip"] == self.src_ip

    def test_evidence_contains_destination_ip(self):
        """Evidence includes destination_ip matching the packet's dst_ip."""
        assert "destination_ip" in self.event.evidence
        assert self.event.evidence["destination_ip"] == self.dst_ip

    def test_evidence_contains_http_method(self):
        """Evidence includes http_method parsed from the request line."""
        assert "http_method" in self.event.evidence
        assert self.event.evidence["http_method"] == "GET"

    def test_evidence_contains_request_url(self):
        """Evidence includes request_url parsed from the request line."""
        assert "request_url" in self.event.evidence
        assert self.event.evidence["request_url"] != ""
        assert self.event.evidence["request_url"] != "UNKNOWN"

    def test_evidence_contains_matched_pattern(self):
        """Evidence includes matched_pattern with the exact pattern label."""
        assert "matched_pattern" in self.event.evidence
        assert self.event.evidence["matched_pattern"] != ""

    def test_evidence_all_required_fields_present(self):
        """All five required evidence fields are present together."""
        required = {"source_ip", "destination_ip", "http_method",
                    "request_url", "matched_pattern"}
        assert required.issubset(set(self.event.evidence.keys()))

    def test_matched_pattern_value_is_or_for_or_payload(self):
        """matched_pattern is \"' OR\" for a ' OR payload."""
        assert self.event.evidence["matched_pattern"] == "' OR"

    def test_event_source_ip_matches_evidence(self):
        """event.source_ip matches evidence['source_ip']."""
        assert self.event.source_ip == self.event.evidence["source_ip"]

    def test_event_destination_ip_matches_evidence(self):
        """event.destination_ip matches evidence['destination_ip']."""
        assert self.event.destination_ip == self.event.evidence["destination_ip"]


# ---------------------------------------------------------------------------
# Single-packet trigger tests (Req 6.6)
# ---------------------------------------------------------------------------

class TestSinglePacketTrigger:
    """Tests that a single matching packet is sufficient to trigger detection."""

    def test_single_packet_triggers_detection(self):
        """Exactly one matching packet is enough; no minimum count required."""
        rule = SqlInjectionRule()
        rule.process_packet(
            make_http(payload_str="GET /?q=1 UNION SELECT 1 HTTP/1.1\r\n")
        )
        event = rule.evaluate()
        assert event is not None

    def test_packet_count_is_one(self):
        """event.packet_count == 1 for single-packet SQL injection detection."""
        rule = SqlInjectionRule()
        rule.process_packet(
            make_http(payload_str="GET /?q=1 UNION SELECT 1 HTTP/1.1\r\n")
        )
        event = rule.evaluate()
        assert event is not None
        assert event.packet_count == 1


# ---------------------------------------------------------------------------
# Rule lifecycle tests
# ---------------------------------------------------------------------------

class TestRuleLifecycle:
    """Tests for rule initialisation, cleanup, and metadata."""

    def test_rule_name_and_attack_type(self):
        """Rule metadata is correctly set."""
        rule = SqlInjectionRule()
        assert rule.rule_name == "SQL_INJECTION_001"
        assert rule.attack_type == "SQL Injection"

    def test_initialize_resets_state(self):
        """initialize() clears seen IPs and pending events."""
        rule = SqlInjectionRule()
        payload = "GET /?q=1' OR 1=1 HTTP/1.1\r\n"
        rule.process_packet(make_http(src="7.7.7.7", payload_str=payload))
        rule.initialize()
        # After initialize(), pending queue is cleared
        assert rule.evaluate() is None
        # And the IP should be treated as new again (no Critical escalation)
        rule.process_packet(make_http(src="7.7.7.7", payload_str=payload))
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "High"

    def test_cleanup_resets_state(self):
        """cleanup() clears all accumulated state."""
        rule = SqlInjectionRule()
        payload = "GET /?q=UNION SELECT 1 HTTP/1.1\r\n"
        rule.process_packet(make_http(src="8.8.8.8", payload_str=payload))
        rule.cleanup()
        assert rule.evaluate() is None

    def test_evaluate_returns_none_with_no_packets(self):
        """evaluate() with no packets processed returns None."""
        rule = SqlInjectionRule()
        assert rule.evaluate() is None

    def test_multiple_pending_events_are_dequeued_in_order(self):
        """Multiple packets → multiple events returned in FIFO order."""
        rule = SqlInjectionRule()
        src_a = "11.11.11.11"
        src_b = "22.22.22.22"

        rule.process_packet(make_http(src=src_a, payload_str="GET /?q=1' OR 1 HTTP/1.1\r\n"))
        rule.process_packet(make_http(src=src_b, payload_str="GET /?q=UNION SELECT 1 HTTP/1.1\r\n"))

        first = rule.evaluate()
        second = rule.evaluate()
        third = rule.evaluate()

        assert first is not None
        assert second is not None
        assert third is None
        assert first.source_ip == src_a
        assert second.source_ip == src_b


# ---------------------------------------------------------------------------
# Additional pattern coverage tests
# ---------------------------------------------------------------------------

class TestAdditionalPatterns:
    """Extra coverage for patterns embedded in different request parts."""

    def _get_event(self, payload_str: str) -> object:
        rule = SqlInjectionRule()
        rule.process_packet(make_http(payload_str=payload_str))
        return rule.evaluate()

    def test_sqli_in_post_body(self):
        """SQL injection in POST body is detected."""
        payload = (
            "POST /login HTTP/1.1\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
            "username=admin'--&password=anything"
        )
        event = self._get_event(payload)
        assert event is not None

    def test_sqli_union_select_in_post_body(self):
        """UNION SELECT in POST body is detected."""
        payload = (
            "POST /search HTTP/1.1\r\n"
            "Content-Type: application/json\r\n\r\n"
            '{"q": "1 UNION SELECT password FROM users"}'
        )
        event = self._get_event(payload)
        assert event is not None

    def test_matched_pattern_label_union_select(self):
        """matched_pattern is 'UNION SELECT' for a UNION SELECT payload."""
        rule = SqlInjectionRule()
        rule.process_packet(
            make_http(payload_str="GET /?q=1 UNION SELECT id FROM users HTTP/1.1\r\n")
        )
        event = rule.evaluate()
        assert event is not None
        assert event.evidence["matched_pattern"] == "UNION SELECT"

    def test_matched_pattern_label_drop_table(self):
        """matched_pattern is 'DROP TABLE' for a DROP TABLE payload."""
        rule = SqlInjectionRule()
        rule.process_packet(
            make_http(payload_str="GET /?q=1;DROP TABLE sessions-- HTTP/1.1\r\n")
        )
        event = rule.evaluate()
        assert event is not None
        assert event.evidence["matched_pattern"] == "DROP TABLE"

    def test_matched_pattern_label_double_dash(self):
        """matched_pattern is '--' for a comment-only payload."""
        rule = SqlInjectionRule()
        rule.process_packet(
            make_http(payload_str="GET /?user=admin'-- HTTP/1.1\r\n")
        )
        event = rule.evaluate()
        assert event is not None
        assert event.evidence["matched_pattern"] == "--"

    def test_matched_pattern_label_xp_cmdshell(self):
        """matched_pattern is 'xp_cmdshell' for an xp_cmdshell payload."""
        rule = SqlInjectionRule()
        rule.process_packet(
            make_http(payload_str="GET /?cmd=xp_cmdshell('whoami') HTTP/1.1\r\n")
        )
        event = rule.evaluate()
        assert event is not None
        assert event.evidence["matched_pattern"] == "xp_cmdshell"
