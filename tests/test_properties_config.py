# Feature: netguard-idps, Property 1
"""
test_properties_config.py — Property-based tests for ConfigurationManager.

Property 1: Settings Validation and Persistence
  - Numeric settings within their defined ranges are accepted, applied in-memory,
    and persisted to config.yaml.
  - Numeric settings outside their defined ranges are rejected; validate_settings
    returns the offending field names and update() raises ValueError.
  - When config.yaml is absent, load() applies built-in defaults so that
    monitoring can still start without any exception.

Validates: Requirements 1.3, 1.4, 1.5, 1.6
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
import yaml

from hypothesis import given, settings as hyp_settings, assume, HealthCheck
from hypothesis import strategies as st

from backend.services.config_service import ConfigurationManager, Settings, _INT_RANGES

# ---------------------------------------------------------------------------
# Constants mirroring the ranges defined in config_service._INT_RANGES
# ---------------------------------------------------------------------------

RANGE_MAP: dict[str, tuple[int, int | None]] = dict(_INT_RANGES)

# For out-of-range strategies we need a concrete large upper bound when max is None.
_LARGE_UPPER = 100_000

# Shortcut: all integer setting names that have a finite max
_BOUNDED_FIELDS = [k for k, (mn, mx) in RANGE_MAP.items() if mx is not None]
# Shortcut: all integer setting names (min bound only — no max)
_UNBOUNDED_FIELDS = [k for k, (mn, mx) in RANGE_MAP.items() if mx is None]
_ALL_INT_FIELDS = list(RANGE_MAP.keys())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cm(tmp_path: Path, initial_yaml: dict | None = None) -> ConfigurationManager:
    """Create a ConfigurationManager backed by a temp config.yaml."""
    config_file = tmp_path / "config.yaml"
    if initial_yaml is not None:
        config_file.write_text(
            yaml.dump(initial_yaml, default_flow_style=False), encoding="utf-8"
        )
    return ConfigurationManager(config_path=config_file)


def _in_range(field: str, value: int) -> bool:
    mn, mx = RANGE_MAP[field]
    if value < mn:
        return False
    if mx is not None and value > mx:
        return False
    return True


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

def _valid_value_for(field: str) -> st.SearchStrategy[int]:
    """Generate integers strictly within the valid range for *field*."""
    mn, mx = RANGE_MAP[field]
    effective_max = mx if mx is not None else _LARGE_UPPER
    return st.integers(min_value=mn, max_value=effective_max)


def _invalid_value_for(field: str) -> st.SearchStrategy[int]:
    """Generate integers strictly outside the valid range for *field*."""
    mn, mx = RANGE_MAP[field]
    if mx is not None:
        # below min OR above max
        return st.one_of(
            st.integers(max_value=mn - 1),
            st.integers(min_value=mx + 1, max_value=mx + _LARGE_UPPER),
        )
    else:
        # only below min is invalid (no upper bound)
        return st.integers(max_value=mn - 1)


# ---------------------------------------------------------------------------
# Property 1a — valid value is accepted and persisted
# ---------------------------------------------------------------------------

@given(
    field=st.sampled_from(_ALL_INT_FIELDS),
    data=st.data(),
)
@hyp_settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_valid_setting_accepted_and_persisted(field, data, tmp_path):
    """
    **Validates: Requirements 1.3, 1.4**

    For any integer setting whose value is within its defined range:
      - validate_settings() returns an empty list (no errors).
      - update() does not raise.
      - get() returns the new value immediately (in-memory).
      - config.yaml is re-written with the new value.
    """
    value = data.draw(_valid_value_for(field))

    cm = _make_cm(tmp_path, initial_yaml={})
    cm.load()

    # validate_settings must return no errors
    errors = cm.validate_settings({field: value})
    assert errors == [], (
        f"validate_settings rejected in-range value {value} for '{field}': {errors}"
    )

    # update() must not raise
    cm.update({field: value})

    # in-memory value must reflect the update
    assert cm.get(field) == value, (
        f"get('{field}') returned {cm.get(field)!r} instead of {value!r}"
    )

    # persisted value must match
    config_file = tmp_path / "config.yaml"
    assert config_file.exists(), "config.yaml was not created by update()"
    persisted = yaml.safe_load(config_file.read_text(encoding="utf-8"))
    assert persisted[field] == value, (
        f"Persisted '{field}' = {persisted[field]!r}, expected {value!r}"
    )


# ---------------------------------------------------------------------------
# Property 1b — out-of-range value is rejected without mutating state
# ---------------------------------------------------------------------------

@given(
    field=st.sampled_from(_ALL_INT_FIELDS),
    data=st.data(),
)
@hyp_settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_invalid_setting_rejected_with_error(field, data, tmp_path):
    """
    **Validates: Requirements 1.5**

    For any integer setting whose value is outside its defined range:
      - validate_settings() returns a non-empty list containing the field name.
      - update() raises ValueError.
      - The in-memory state is unchanged after the failed update attempt.
    """
    invalid_value = data.draw(_invalid_value_for(field))

    # Confirm the generated value is actually out of range (guard against edge cases)
    assume(not _in_range(field, invalid_value))

    cm = _make_cm(tmp_path, initial_yaml={})
    cm.load()
    original_value = cm.get(field)

    # validate_settings must flag the field
    errors = cm.validate_settings({field: invalid_value})
    assert field in errors, (
        f"validate_settings did not flag '{field}' for out-of-range value {invalid_value}"
    )

    # update() must raise ValueError
    with pytest.raises(ValueError):
        cm.update({field: invalid_value})

    # in-memory value must be unchanged
    assert cm.get(field) == original_value, (
        f"Failed update mutated '{field}': was {original_value!r}, "
        f"now {cm.get(field)!r}"
    )


# ---------------------------------------------------------------------------
# Property 1c — absent config.yaml causes defaults to be applied
# ---------------------------------------------------------------------------

def test_missing_config_yaml_yields_defaults(tmp_path):
    """
    **Validates: Requirements 1.6**

    When config.yaml does not exist, load() must:
      - Return a Settings object equal to the built-in defaults.
      - Not raise any exception.

    Runs 100 independent trials using different nonexistent paths to satisfy
    the max_examples=100 spirit of the property test suite.
    """
    defaults = Settings()

    # Run 100 trials with independent ConfigurationManager instances
    for i in range(100):
        # Point CM at a path that does not exist
        nonexistent = tmp_path / f"nonexistent_dir_{i}" / "config.yaml"
        cm = ConfigurationManager(config_path=nonexistent)

        # Must not raise
        returned = cm.load()

        # All integer fields must match their built-in defaults
        for field in _ALL_INT_FIELDS:
            actual = getattr(returned, field)
            expected = getattr(defaults, field)
            assert actual == expected, (
                f"Trial {i}: After missing config.yaml: '{field}' = {actual!r}, "
                f"expected default {expected!r}"
            )

        # rules_enabled must match defaults
        assert returned.rules_enabled == defaults.rules_enabled, (
            f"Trial {i}: rules_enabled mismatch: "
            f"{returned.rules_enabled!r} vs {defaults.rules_enabled!r}"
        )

        # get() must also reflect the defaults (loaded into internal state)
        for field in _ALL_INT_FIELDS:
            assert cm.get(field) == getattr(defaults, field), (
                f"Trial {i}: cm.get('{field}') returned {cm.get(field)!r}, "
                f"expected {getattr(defaults, field)!r}"
            )


# ---------------------------------------------------------------------------
# Property 1d — multiple simultaneous valid updates all accepted
# ---------------------------------------------------------------------------

@given(
    # Pick a random subset of fields and valid values for each
    updates=st.fixed_dictionaries(
        {
            field: _valid_value_for(field)
            for field in _ALL_INT_FIELDS
        }
    )
)
@hyp_settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_bulk_valid_updates_all_accepted(updates, tmp_path):
    """
    **Validates: Requirements 1.3, 1.4**

    A dict containing all integer settings, each within range, must be accepted
    in a single update() call with no validation errors.
    """
    cm = _make_cm(tmp_path, initial_yaml={})
    cm.load()

    errors = cm.validate_settings(updates)
    assert errors == [], f"validate_settings rejected valid bulk update: {errors}"

    # Must not raise
    cm.update(updates)

    # All values must be reflected in memory and on disk
    config_file = tmp_path / "config.yaml"
    persisted = yaml.safe_load(config_file.read_text(encoding="utf-8"))

    for field, value in updates.items():
        assert cm.get(field) == value
        assert persisted[field] == value


# ---------------------------------------------------------------------------
# Property 1e — rejected update leaves config.yaml unchanged
# ---------------------------------------------------------------------------

@given(
    field=st.sampled_from(_ALL_INT_FIELDS),
    data=st.data(),
)
@hyp_settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_rejected_update_does_not_modify_config_yaml(field, data, tmp_path):
    """
    **Validates: Requirements 1.5**

    When update() raises because a value is out of range, config.yaml content
    must remain unchanged from its pre-update state.
    """
    invalid_value = data.draw(_invalid_value_for(field))
    assume(not _in_range(field, invalid_value))

    cm = _make_cm(tmp_path, initial_yaml={})
    cm.load()

    # Capture a baseline by performing one valid save first so the file exists
    valid_value = data.draw(_valid_value_for(field))
    cm.update({field: valid_value})

    config_file = tmp_path / "config.yaml"
    content_before = config_file.read_text(encoding="utf-8")

    with pytest.raises(ValueError):
        cm.update({field: invalid_value})

    content_after = config_file.read_text(encoding="utf-8")
    assert content_before == content_after, (
        f"config.yaml was modified by a rejected update of '{field}' = {invalid_value!r}"
    )
