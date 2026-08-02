"""Abstract base class and shared data structures for NetGuard detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

from detection.parsers.packet_decoder import Packet


@dataclass
class FlowData:
    """Per-source-IP accumulator shared across volumetric rules."""
    timestamps: deque = field(default_factory=lambda: deque())
    ports: set = field(default_factory=set)
    macs: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)


@dataclass
class ThreatEvent:
    """Structured threat event emitted by a detection rule on confirmed detection."""
    event_id: str
    timestamp: str
    attack_type: str
    source_ip: str
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    rule_name: str
    severity: str
    confidence: int
    packet_count: int
    evidence: dict
    blocked: bool = False
    mitre_tactic: str = ""
    mitre_technique: str = ""


@dataclass
class Explanation:
    """Human-readable explanation attached to every ThreatEvent."""
    attack_name: str
    rule_triggered: str
    plain_english_text: str
    evidence: dict
    confidence_score: int
    severity: str
    recommendation: str


class BaseRule(ABC):
    """
    Abstract base class for all NetGuard detection rules.

    The Detection_Engine calls these methods on every packet:

        rule.process_packet(packet)
        event = rule.evaluate()

    Subclasses must not raise exceptions to the caller.
    """

    rule_name: str = ""
    attack_type: str = ""
    enabled: bool = True

    def __init__(self) -> None:
        self.rule_name: str = self.__class__.rule_name
        self.attack_type: str = self.__class__.attack_type
        self.enabled: bool = True

    @abstractmethod
    def initialize(self) -> None:
        """One-time initialisation before the first packet is processed."""

    @abstractmethod
    def process_packet(self, packet: Packet) -> None:
        """Update internal state for the given packet. Must not raise."""

    @abstractmethod
    def evaluate(self) -> Optional[ThreatEvent]:
        """Check thresholds and return a ThreatEvent, or None. Must not raise."""

    @abstractmethod
    def generate_event(self) -> ThreatEvent:
        """Build a ThreatEvent from current accumulated evidence."""

    @abstractmethod
    def explain(self, event: ThreatEvent) -> Explanation:
        """Generate a human-readable Explanation for the given ThreatEvent."""

    @abstractmethod
    def cleanup(self) -> None:
        """Release resources and reset state."""
