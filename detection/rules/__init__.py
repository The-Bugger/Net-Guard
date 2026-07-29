"""
detection/rules/__init__.py — Public API for the detection rules package.

All rules and shared data structures are imported from here so that
other modules only need a single canonical import path.
"""

from detection.rules.base_rule import (
    BaseRule,
    Explanation,
    FlowData,
    ThreatEvent,
)

__all__ = [
    "BaseRule",
    "Explanation",
    "FlowData",
    "ThreatEvent",
]
