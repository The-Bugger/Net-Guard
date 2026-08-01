"""
test_dns_tunnel_rule.py — Unit tests for DnsTunnelRule.

Covers:
(a) Normal short query → None
(b) Long label (>50 chars) → ThreatEvent Medium
(c) High TXT rate → ThreatEvent Low
(d) High entropy → ThreatEvent Medium
(e) Multiple indicators → High severity
(f) Confidence always ≤ 80
(g) Never raises on malformed payload

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.8
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone

import pytest

from detection.parsers.packet_decoder import Packet
from detection.rules.dns_tunnel import DnsTunnelRule, _entropy, _parse_dns_qname


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_dns_payload(qname: str, qtype: int = 1) -> bytes:
    """
    Build a minimal DNS query payload with a 12-byte stub header followed
    by an encoded question section containing the given QNAME and QTYPE.

    This does NOT build a fully valid DNS wire message — it is only enough
    for _parse_dns_qname() to extract the first question entry.
    """
    # 12-byte DNS header (all zeros — ID, flags, counts)
    header = b"\x00" * 12
    # Encode QNAME as RFC 1035 labels
    encoded = b""
    for label in qname.split("."):
        encoded += bytes([len(label)]) + label.encode("ascii")
    encoded += b"\x00"  # name terminator
    # QTYPE (2 bytes big-endian) + QCLASS=1 (2 bytes)
    encoded += struct.pack("!HH", qtype, 1)
    return header + encoded


def make_udp_packet(
    src_ip: str = "10.0.0.1",
    dst_port: int = 53,
    qname: str = "example.com",
    qtype: int = 1,
    payload: bytes | None = None,
) -> Packet:
    """Build a minimal UDP Packet destined for DNS port 53."""
    if payload is None:
        payload = _make_dns_payload(qname, qtype)
    return Packet(
        src_ip=src_ip,
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=dst_port,
        protocol="UDP",
        flags=None,
        timestamp=_ts(),
        length=len(payload) + 28,
        payload=payload,
    )


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def rule() -> DnsTunnelRule:
    """Fresh DnsTunnelRule with tight thresholds for fast testing."""
    r = DnsTunnelRule()
    r.initialize()
    r._window = 60
    r._label_max_len = 50
    r._txt_rate_threshold = 2   # fire after >2 TXT queries
    r._entropy_threshold = 3.5
    return r


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------

class TestEntropy:
    def test_empty_string(self):
        assert _entropy("") == 0.0

    def test_single_char(self):
        # Only one distinct character → probability=1.0 → entropy=0
        assert _entropy("aaaaaa") == pytest.approx(0.0, abs=1e-9)

    def test_known_value(self):
        # "ab" → two equiprobable chars → entropy = 1.0 bit
        assert _entropy("ab") == pytest.approx(1.0, abs=1e-9)

    def test_high_entropy_random_like(self):
        # A string with many distinct chars should have entropy > 3 bits
        s = "abcdefghijklmnopqrstuvwxyz0123456789"
        assert _entropy(s) > 3.0


class TestParseDnsQname:
    def test_normal_label(self):
        payload = _make_dns_payload("example.com", qtype=1)
        qname, qtype = _parse_dns_qname(payload)
        assert qname == "example.com"
        assert qtype == 1

    def test_txt_qtype(self):
        payload = _make_dns_payload("tunnel.example.com", qtype=16)
        qname, qtype = _parse_dns_qname(payload)
        assert qname == "tunnel.example.com"
        assert qtype == 16

    def test_empty_payload(self):
        qname, qtype = _parse_dns_qname(b"")
        assert qname == ""
        assert qtype == 0

    def test_truncated_payload(self):
        qname, qtype = _parse_dns_qname(b"\x00" * 5)
        assert qname == ""
        assert qtype == 0

    def test_compression_pointer_bails(self):
        # Set top 2 bits of first label byte after 12-byte header
        header = b"\x00" * 12
        bad = header + bytes([0xC0, 0x0C])  # compression pointer
        qname, qtype = _parse_dns_qname(bad)
        assert qname == ""
        assert qtype == 0

    def test_never_raises_on_garbage(self):
        """Random garbage must not raise."""
        result = _parse_dns_qname(b"\xff\xfe\xfd\xfc" * 20)
        assert isinstance(result, tuple)


# ---------------------------------------------------------------------------
# (a) Normal short query → None
# ---------------------------------------------------------------------------

class TestNormalQuery:
    def test_single_short_query_no_event(self, rule):
        rule.process_packet(make_udp_packet(qname="google.com"))
        assert rule.evaluate() is None

    def test_non_udp_ignored(self, rule):
        pkt = Packet(
            src_ip="10.0.0.1", dst_ip="8.8.8.8",
            src_port=1234, dst_port=53,
            protocol="TCP", flags="S",
            timestamp=_ts(), length=60, payload=None,
        )
        rule.process_packet(pkt)
        assert rule.evaluate() is None

    def test_wrong_dst_port_ignored(self, rule):
        rule.process_packet(make_udp_packet(dst_port=80))
        assert rule.evaluate() is None

    def test_empty_payload_no_event(self, rule):
        pkt = make_udp_packet(payload=b"")
        rule.process_packet(pkt)
        assert rule.evaluate() is None


# ---------------------------------------------------------------------------
# (b) Long label (>50 chars) → ThreatEvent Medium
# ---------------------------------------------------------------------------

class TestLongLabel:
    def test_long_label_triggers_medium(self, rule):
        long_label = "a" * 51  # 51 > 50 (default label_max_len)
        rule.process_packet(make_udp_packet(qname=f"{long_label}.example.com"))
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "Medium"

    def test_exactly_at_limit_no_event(self, rule):
        """Label of exactly 50 chars must NOT fire (> not >=)."""
        label = "a" * 50
        rule.process_packet(make_udp_packet(qname=f"{label}.example.com"))
        assert rule.evaluate() is None

    def test_long_label_evidence(self, rule):
        long_label = "b" * 60
        rule.process_packet(make_udp_packet(qname=f"{long_label}.example.com"))
        event = rule.evaluate()
        assert event is not None
        assert event.evidence["max_label_length"] == 60
        assert "label_length" in event.evidence["triggered_indicators"]

    def test_event_fields(self, rule):
        long_label = "x" * 55
        rule.process_packet(make_udp_packet(qname=f"{long_label}.test.org"))
        event = rule.evaluate()
        assert event is not None
        assert event.attack_type == "DNS Tunneling"
        assert event.rule_name == "DNS_TUNNEL_001"
        assert event.protocol == "UDP"
        assert event.destination_port == 53


# ---------------------------------------------------------------------------
# (c) High TXT rate → ThreatEvent Low
# ---------------------------------------------------------------------------

class TestHighTxtRate:
    def test_txt_rate_triggers_low(self, rule):
        """Send > txt_rate_threshold (2) TXT queries — should fire Low."""
        for i in range(3):
            rule.process_packet(make_udp_packet(qname=f"q{i}.example.com", qtype=16))
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "Low"

    def test_txt_count_in_evidence(self, rule):
        for i in range(3):
            rule.process_packet(make_udp_packet(qname=f"q{i}.example.com", qtype=16))
        event = rule.evaluate()
        assert event is not None
        assert event.evidence["txt_query_count"] == 3
        assert "txt_rate" in event.evidence["triggered_indicators"]

    def test_null_qtype_counts_toward_txt_rate(self, rule):
        """QTYPE=10 (NULL) also counts toward the TXT rate threshold."""
        for i in range(3):
            rule.process_packet(make_udp_packet(qname=f"n{i}.example.com", qtype=10))
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "Low"

    def test_below_threshold_no_event(self, rule):
        """Exactly at threshold (not exceeding) must not fire."""
        for i in range(rule._txt_rate_threshold):
            rule.process_packet(make_udp_packet(qname=f"q{i}.example.com", qtype=16))
        assert rule.evaluate() is None


# ---------------------------------------------------------------------------
# (d) High entropy → ThreatEvent Medium
# ---------------------------------------------------------------------------

class TestHighEntropy:
    def _high_entropy_label(self) -> str:
        """
        Return a label whose Shannon entropy reliably exceeds 3.5 bits/char even
        when averaged with the other labels in the qname.

        We use 36 completely distinct chars (all 26 letters + 10 digits) in a
        single-occurrence label to maximise entropy (~5.17 bits). The qname
        contains ONLY this label (no TLD suffix) so the average is not diluted
        by low-entropy labels like 'example' or 'com'.
        """
        return "abcdefghijklmnopqrstuvwxyz0123456789"  # 36 distinct chars → ~5.17 bits

    def test_high_entropy_triggers_medium(self, rule):
        label = self._high_entropy_label()
        # Use as single-label qname to avoid dilution by low-entropy TLD labels
        rule.process_packet(make_udp_packet(qname=label))
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "Medium"

    def test_entropy_in_evidence(self, rule):
        label = self._high_entropy_label()
        rule.process_packet(make_udp_packet(qname=label))
        event = rule.evaluate()
        assert event is not None
        assert event.evidence["avg_entropy"] > 3.5
        assert "entropy" in event.evidence["triggered_indicators"]

    def test_low_entropy_label_no_event(self, rule):
        """Repeated single-char label has zero entropy — must not fire."""
        rule.process_packet(make_udp_packet(qname="aaaaaaa.example.com"))
        assert rule.evaluate() is None


# ---------------------------------------------------------------------------
# (e) Multiple indicators → High severity
# ---------------------------------------------------------------------------

class TestMultipleIndicators:
    def test_two_indicators_high(self, rule):
        """Long label (fires a) + high-entropy same label (fires c) → High.

        Use a single-label qname to avoid entropy dilution by TLD labels.
        The label is 55 chars with 36 distinct chars → entropy ≈ 5.17 bits.
        """
        # 36 distinct chars padded to 55 chars while keeping all chars distinct enough
        # Use all 26 letters + 10 digits + 19 more unique-ish chars via uppercase
        label = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQ"  # 53 chars, mix case
        # Ensure > 50 chars
        assert len(label) > 50
        rule.process_packet(make_udp_packet(qname=label))
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "High"
        assert len(event.evidence["triggered_indicators"]) >= 2

    def test_three_indicators_high(self, rule):
        """All three indicators fire → High (not higher than High)."""
        # 53-char label with high entropy (long + high entropy)
        label = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQ"
        # Send > txt_rate_threshold TXT queries with long high-entropy labels
        for i in range(3):
            rule.process_packet(make_udp_packet(qname=f"{label}", qtype=16))
        event = rule.evaluate()
        assert event is not None
        assert event.severity == "High"


# ---------------------------------------------------------------------------
# (f) Confidence always ≤ 80
# ---------------------------------------------------------------------------

class TestConfidenceCap:
    def test_single_indicator_confidence_le_80(self, rule):
        label = "a" * 51
        rule.process_packet(make_udp_packet(qname=f"{label}.example.com"))
        event = rule.evaluate()
        assert event is not None
        assert event.confidence <= 80

    def test_multiple_indicator_confidence_le_80(self, rule):
        label = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrs"  # 55 chars, high entropy
        for i in range(3):
            rule.process_packet(make_udp_packet(qname=f"{label}{i}.txt.example.com", qtype=16))
        event = rule.evaluate()
        assert event is not None
        assert event.confidence <= 80

    def test_confidence_positive(self, rule):
        """Confidence should be a meaningful positive number."""
        label = "a" * 51
        rule.process_packet(make_udp_packet(qname=f"{label}.example.com"))
        event = rule.evaluate()
        assert event is not None
        assert event.confidence > 0


# ---------------------------------------------------------------------------
# (g) Never raises on malformed payload
# ---------------------------------------------------------------------------

class TestNoRaiseOnMalformed:
    def test_none_payload(self, rule):
        pkt = make_udp_packet(payload=b"")
        rule.process_packet(pkt)  # must not raise

    def test_garbage_payload(self, rule):
        pkt = make_udp_packet(payload=b"\xff\xfe\xfd" * 30)
        rule.process_packet(pkt)  # must not raise

    def test_truncated_dns_header(self, rule):
        pkt = make_udp_packet(payload=b"\x00\x01\x02")
        rule.process_packet(pkt)  # must not raise

    def test_none_src_ip(self, rule):
        pkt = Packet(
            src_ip=None, dst_ip="8.8.8.8",
            src_port=50000, dst_port=53,
            protocol="UDP", flags=None,
            timestamp=_ts(), length=40,
            payload=_make_dns_payload("test.com"),
        )
        rule.process_packet(pkt)  # must not raise

    def test_evaluate_on_uninitialised_rule(self):
        """evaluate() on brand-new rule (no initialize()) must not raise."""
        r = DnsTunnelRule()
        result = r.evaluate()
        assert result is None


# ---------------------------------------------------------------------------
# Duplicate suppression and lifecycle
# ---------------------------------------------------------------------------

class TestLifecycle:
    def test_no_duplicate_events(self, rule):
        """Once an event is emitted for a src_ip, no second event for same IP."""
        label = "a" * 51
        for _ in range(3):
            rule.process_packet(make_udp_packet(qname=f"{label}.example.com"))
        event1 = rule.evaluate()
        assert event1 is not None
        assert rule.evaluate() is None

    def test_different_src_ips_independent(self, rule):
        """Each source IP is tracked independently."""
        label = "a" * 51
        rule.process_packet(make_udp_packet(src_ip="1.1.1.1", qname=f"{label}.example.com"))
        rule.process_packet(make_udp_packet(src_ip="2.2.2.2", qname=f"{label}.example.com"))
        event1 = rule.evaluate()
        event2 = rule.evaluate()
        assert event1 is not None
        assert event2 is not None
        src_ips = {event1.source_ip, event2.source_ip}
        assert src_ips == {"1.1.1.1", "2.2.2.2"}

    def test_cleanup_clears_state(self, rule):
        label = "a" * 51
        rule.process_packet(make_udp_packet(qname=f"{label}.example.com"))
        rule.cleanup()
        assert rule.evaluate() is None
        assert not rule._queries
        assert not rule._emitted

    def test_initialize_clears_state(self, rule):
        label = "a" * 51
        rule.process_packet(make_udp_packet(qname=f"{label}.example.com"))
        rule.initialize()
        assert rule.evaluate() is None


# ---------------------------------------------------------------------------
# Explain
# ---------------------------------------------------------------------------

class TestExplain:
    def test_explain_text_under_500_chars(self, rule):
        label = "a" * 51
        rule.process_packet(make_udp_packet(qname=f"{label}.example.com"))
        event = rule.evaluate()
        assert event is not None
        expl = rule.explain(event)
        assert len(expl.plain_english_text) <= 500

    def test_explain_returns_explanation_object(self, rule):
        from detection.rules.base_rule import Explanation
        label = "a" * 51
        rule.process_packet(make_udp_packet(qname=f"{label}.example.com"))
        event = rule.evaluate()
        assert event is not None
        result = rule.explain(event)
        assert isinstance(result, Explanation)

    def test_explain_mentions_source_ip(self, rule):
        label = "a" * 51
        rule.process_packet(make_udp_packet(src_ip="5.5.5.5", qname=f"{label}.example.com"))
        event = rule.evaluate()
        assert event is not None
        expl = rule.explain(event)
        assert "5.5.5.5" in expl.plain_english_text

    def test_generate_event_raises(self, rule):
        with pytest.raises(NotImplementedError):
            rule.generate_event()


# ---------------------------------------------------------------------------
# Evidence fields completeness
# ---------------------------------------------------------------------------

class TestEvidenceFields:
    def test_all_required_fields_present(self, rule):
        label = "a" * 51
        rule.process_packet(make_udp_packet(qname=f"{label}.example.com"))
        event = rule.evaluate()
        assert event is not None
        ev = event.evidence
        assert "triggered_indicators" in ev
        assert "max_label_length" in ev
        assert "txt_query_count" in ev
        assert "avg_entropy" in ev
        assert "sample_queries" in ev

    def test_sample_queries_capped_at_five(self, rule):
        label = "a" * 51
        for i in range(10):
            rule.process_packet(make_udp_packet(
                src_ip="9.9.9.9", qname=f"{label}-{i}.example.com"
            ))
        event = rule.evaluate()
        assert event is not None
        assert len(event.evidence["sample_queries"]) <= 5

    def test_avg_entropy_rounded_to_two_decimal_places(self, rule):
        # Use single-label qname to avoid dilution
        label = "abcdefghijklmnopqrstuvwxyz0123456789"
        rule.process_packet(make_udp_packet(qname=label))
        event = rule.evaluate()
        assert event is not None
        avg_ent = event.evidence["avg_entropy"]
        # Round-tripping through str to check 2 decimal places
        assert round(avg_ent, 2) == avg_ent
