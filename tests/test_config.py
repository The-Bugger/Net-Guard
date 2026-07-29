"""
test_config.py — Unit tests for ConfigurationManager.

Tests load valid YAML, missing file defaults, malformed YAML,
validate in/out of range, update, and persistence.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from backend.services.config_service import ConfigurationManager, Settings


# ---------------------------------------------------------------------------
# Load
# ---------------------------------------------------------------------------

class TestLoad:

    def test_load_valid_yaml(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            "syn_flood_threshold: 200\n"
            "syn_flood_window: 5\n"
            "block_duration: 300\n"
            "rules_enabled:\n"
            "  syn_flood: true\n"
            "  port_scan: false\n",
            encoding="utf-8",
        )
        cm = ConfigurationManager(config_path=cfg_file)
        settings = cm.load()
        assert settings.syn_flood_threshold == 200
        assert settings.syn_flood_window == 5
        assert settings.block_duration == 300
        assert settings.rules_enabled["syn_flood"] is True
        assert settings.rules_enabled["port_scan"] is False

    def test_missing_file_returns_defaults(self, tmp_path):
        cfg_file = tmp_path / "nonexistent.yaml"
        cm = ConfigurationManager(config_path=cfg_file)
        settings = cm.load()
        assert settings.syn_flood_threshold == 100
        assert settings.syn_flood_window == 3
        assert settings.block_duration == 120

    def test_malformed_yaml_returns_defaults(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(":::invalid: [yaml{{{", encoding="utf-8")
        cm = ConfigurationManager(config_path=cfg_file)
        settings = cm.load()
        assert settings.syn_flood_threshold == 100

    def test_non_dict_yaml_returns_defaults(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("- item1\n- item2\n", encoding="utf-8")
        cm = ConfigurationManager(config_path=cfg_file)
        settings = cm.load()
        assert settings.syn_flood_threshold == 100

    def test_partial_yaml_uses_defaults_for_missing(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("syn_flood_threshold: 500\n", encoding="utf-8")
        cm = ConfigurationManager(config_path=cfg_file)
        settings = cm.load()
        assert settings.syn_flood_threshold == 500
        assert settings.port_scan_threshold == 20  # default


# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------

class TestValidate:

    def test_valid_settings_returns_empty(self):
        cm = ConfigurationManager()
        invalid = cm.validate_settings({"syn_flood_threshold": 200})
        assert invalid == []

    def test_out_of_range_returns_field(self):
        cm = ConfigurationManager()
        invalid = cm.validate_settings({"syn_flood_window": 999})
        assert "syn_flood_window" in invalid

    def test_below_minimum_returns_field(self):
        cm = ConfigurationManager()
        invalid = cm.validate_settings({"block_duration": 0})
        assert "block_duration" in invalid

    def test_unknown_key_returns_field(self):
        cm = ConfigurationManager()
        invalid = cm.validate_settings({"nonexistent_key": 42})
        assert "nonexistent_key" in invalid

    def test_boolean_not_accepted_as_int(self):
        cm = ConfigurationManager()
        invalid = cm.validate_settings({"syn_flood_threshold": True})
        assert "syn_flood_threshold" in invalid

    def test_multiple_invalid_fields(self):
        cm = ConfigurationManager()
        invalid = cm.validate_settings({
            "syn_flood_window": 999,
            "block_duration": -1,
        })
        assert len(invalid) == 2


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------

class TestUpdate:

    def test_update_applies_values(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("syn_flood_threshold: 100\n", encoding="utf-8")
        cm = ConfigurationManager(config_path=cfg_file)
        cm.load()
        cm.update({"syn_flood_threshold": 250})
        assert cm.get("syn_flood_threshold") == 250

    def test_update_raises_on_invalid(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("syn_flood_threshold: 100\n", encoding="utf-8")
        cm = ConfigurationManager(config_path=cfg_file)
        cm.load()
        with pytest.raises(ValueError, match="Invalid configuration"):
            cm.update({"syn_flood_window": 999})

    def test_update_persists_to_yaml(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("syn_flood_threshold: 100\n", encoding="utf-8")
        cm = ConfigurationManager(config_path=cfg_file)
        cm.load()
        cm.update({"syn_flood_threshold": 300})
        # Read back from file
        cm2 = ConfigurationManager(config_path=cfg_file)
        settings = cm2.load()
        assert settings.syn_flood_threshold == 300

    def test_update_rules_enabled(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("syn_flood_threshold: 100\n", encoding="utf-8")
        cm = ConfigurationManager(config_path=cfg_file)
        cm.load()
        cm.update({"rules_enabled": {"syn_flood": False}})
        assert cm.get("rules_enabled")["syn_flood"] is False


# ---------------------------------------------------------------------------
# Get
# ---------------------------------------------------------------------------

class TestGet:

    def test_get_existing_key(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("syn_flood_threshold: 100\n", encoding="utf-8")
        cm = ConfigurationManager(config_path=cfg_file)
        cm.load()
        assert cm.get("syn_flood_threshold") == 100

    def test_get_unknown_key_returns_none(self):
        cm = ConfigurationManager()
        cm.load()
        assert cm.get("nonexistent_key") is None
