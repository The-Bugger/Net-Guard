"""
config_service.py — Configuration_Manager for NetGuard IDPS.

Reads and writes config/config.yaml. Falls back to built-in defaults when the
file is absent or unparseable. Applies updated values in-memory and persists
them to YAML without requiring an application restart.

Requirements: 1.2, 1.3, 1.4, 1.5, 1.6
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# Project root is two levels above this file: backend/services/ -> backend/ -> root
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent
_CONFIG_PATH: Path = _PROJECT_ROOT / "config" / "config.yaml"
_LOGS_DIR: Path = _PROJECT_ROOT / "logs"
_ERRORS_LOG: Path = _LOGS_DIR / "errors.log"

# ---------------------------------------------------------------------------
# Module-level logger (errors.log handler added lazily in _get_logger())
# ---------------------------------------------------------------------------

_logger_lock = threading.Lock()
_logger: logging.Logger | None = None


def _get_logger() -> logging.Logger:
    """Return (and lazily initialise) the module logger writing to errors.log."""
    global _logger
    if _logger is not None:
        return _logger

    with _logger_lock:
        if _logger is not None:
            return _logger

        logger = logging.getLogger("netguard.config_service")
        logger.setLevel(logging.DEBUG)

        if not logger.handlers:
            _LOGS_DIR.mkdir(parents=True, exist_ok=True)
            handler = logging.FileHandler(_ERRORS_LOG, encoding="utf-8")
            handler.setLevel(logging.WARNING)
            formatter = logging.Formatter(
                "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        _logger = logger
        return _logger


# ---------------------------------------------------------------------------
# Default rules_enabled dict
# ---------------------------------------------------------------------------

_DEFAULT_RULES_ENABLED: dict[str, bool] = {
    "syn_flood": True,
    "port_scan": True,
    "sql_injection": True,
    "brute_force": True,
    "arp_spoof": True,
}


# ---------------------------------------------------------------------------
# Settings dataclass
# ---------------------------------------------------------------------------

@dataclass
class Settings:
    """
    Canonical representation of all NetGuard runtime settings.

    All fields mirror the keys in config/config.yaml.  The defaults here
    are the authoritative built-in fallback values (Requirement 1.3).
    """

    network_interface: str = ""
    """Network interface to monitor (any non-empty string; no default)."""

    syn_flood_threshold: int = 100
    """SYN flood packet threshold (≥ 1)."""

    syn_flood_window: int = 3
    """SYN flood sliding-window duration in seconds (1–60)."""

    port_scan_threshold: int = 20
    """Port scan unique-port threshold (≥ 1)."""

    port_scan_window: int = 10
    """Port scan sliding-window duration in seconds (1–60)."""

    brute_force_threshold: int = 10
    """Brute-force failure threshold (≥ 1)."""

    brute_force_window: int = 60
    """Brute-force sliding-window duration in seconds (1–300)."""

    block_duration: int = 120
    """Auto-block duration in seconds (1–3600)."""

    dashboard_refresh_interval: int = 1
    """Dashboard polling interval in seconds (1–60)."""

    rules_enabled: dict[str, bool] = field(
        default_factory=lambda: dict(_DEFAULT_RULES_ENABLED)
    )
    """Per-rule enabled flags; default all True."""

    debug: bool = False
    """Enable debug mode."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

# Maps setting key → (min_inclusive, max_inclusive | None)
# None for max means no upper bound.
_INT_RANGES: dict[str, tuple[int, int | None]] = {
    "syn_flood_threshold": (1, None),
    "syn_flood_window": (1, 60),
    "port_scan_threshold": (1, None),
    "port_scan_window": (1, 60),
    "brute_force_threshold": (1, None),
    "brute_force_window": (1, 300),
    "block_duration": (1, 3600),
    "dashboard_refresh_interval": (1, 60),
}

# All recognised top-level keys (excluding rules_enabled sub-keys)
_VALID_KEYS: frozenset[str] = frozenset(
    {
        "network_interface",
        "syn_flood_threshold",
        "syn_flood_window",
        "port_scan_threshold",
        "port_scan_window",
        "brute_force_threshold",
        "brute_force_window",
        "block_duration",
        "dashboard_refresh_interval",
        "rules_enabled",
        "debug",
    }
)


# ---------------------------------------------------------------------------
# ConfigurationManager
# ---------------------------------------------------------------------------

class ConfigurationManager:
    """
    Manages loading, validation, and persistence of NetGuard runtime settings.

    Thread-safe: all reads and writes on the shared Settings object are
    protected by an internal threading.Lock.

    Usage::

        cm = ConfigurationManager()
        settings = cm.load()
        value = cm.get("syn_flood_threshold")
        cm.update({"syn_flood_threshold": 200})
    """

    def __init__(
        self,
        config_path: Path | None = None,
    ) -> None:
        self._config_path: Path = config_path or _CONFIG_PATH
        self._lock: threading.Lock = threading.Lock()
        self._settings: Settings = Settings()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self) -> Settings:
        """
        Load settings from config/config.yaml.

        On a missing or unparseable file, log CRITICAL to logs/errors.log and
        return the built-in defaults so that monitoring can still start
        (Requirement 1.6).

        Returns:
            Settings: The loaded (or default) settings object.
        """
        logger = _get_logger()

        raw: dict[str, Any] = {}
        try:
            text = self._config_path.read_text(encoding="utf-8")
            parsed = yaml.safe_load(text)
            if not isinstance(parsed, dict):
                raise ValueError(
                    f"Expected a YAML mapping, got {type(parsed).__name__}"
                )
            raw = parsed
        except FileNotFoundError:
            logger.critical(
                "config.yaml not found at '%s'. Applying built-in defaults.",
                self._config_path,
            )
        except yaml.YAMLError as exc:
            logger.critical(
                "config.yaml is not valid YAML at '%s': %s. Applying built-in defaults.",
                self._config_path,
                exc,
            )
        except Exception as exc:  # noqa: BLE001
            logger.critical(
                "Unexpected error reading config.yaml at '%s': %s. Applying built-in defaults.",
                self._config_path,
                exc,
            )

        settings = self._build_settings(raw)

        with self._lock:
            self._settings = settings

        return settings

    def get(self, key: str) -> Any:
        """
        Return the current value for a single settings key.

        Args:
            key: One of the recognised Settings field names.

        Returns:
            The current value, or None if the key does not exist.
        """
        with self._lock:
            return getattr(self._settings, key, None)

    def update(self, updates: dict[str, Any]) -> None:
        """
        Validate *updates*, apply them in-memory, and persist to config.yaml.

        Args:
            updates: A mapping of setting key → new value.

        Raises:
            ValueError: If one or more values are outside their defined ranges.
                        The message lists all invalid field names.
        """
        invalid = self.validate_settings(updates)
        if invalid:
            raise ValueError(
                f"Invalid configuration values for field(s): {', '.join(invalid)}"
            )

        with self._lock:
            self._apply_updates(self._settings, updates)
            self._persist(self._settings)

    def validate_settings(self, updates: dict[str, Any]) -> list[str]:
        """
        Validate a dict of proposed setting updates.

        Checks:
        - Key must be a recognised Settings field name.
        - Integer fields must be within their defined min/max bounds.

        Args:
            updates: Proposed setting key/value pairs.

        Returns:
            A list of invalid field names.  An empty list means all valid.
        """
        invalid: list[str] = []

        for key, value in updates.items():
            if key not in _VALID_KEYS:
                invalid.append(key)
                continue

            if key in _INT_RANGES:
                min_val, max_val = _INT_RANGES[key]
                if not isinstance(value, int) or isinstance(value, bool):
                    invalid.append(key)
                    continue
                if value < min_val:
                    invalid.append(key)
                    continue
                if max_val is not None and value > max_val:
                    invalid.append(key)
                    continue

        return invalid

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_settings(raw: dict[str, Any]) -> Settings:
        """Construct a Settings object from the raw YAML dict, using defaults for missing keys."""
        defaults = Settings()

        rules_raw = raw.get("rules_enabled", {})
        if not isinstance(rules_raw, dict):
            rules_raw = {}

        rules_enabled: dict[str, bool] = {}
        for rule_key, default_val in _DEFAULT_RULES_ENABLED.items():
            rules_enabled[rule_key] = bool(rules_raw.get(rule_key, default_val))

        def _int(key: str) -> int:
            val = raw.get(key, getattr(defaults, key))
            try:
                return int(val)
            except (TypeError, ValueError):
                return getattr(defaults, key)

        return Settings(
            network_interface=str(raw.get("network_interface", defaults.network_interface)),
            syn_flood_threshold=_int("syn_flood_threshold"),
            syn_flood_window=_int("syn_flood_window"),
            port_scan_threshold=_int("port_scan_threshold"),
            port_scan_window=_int("port_scan_window"),
            brute_force_threshold=_int("brute_force_threshold"),
            brute_force_window=_int("brute_force_window"),
            block_duration=_int("block_duration"),
            dashboard_refresh_interval=_int("dashboard_refresh_interval"),
            rules_enabled=rules_enabled,
            debug=bool(raw.get("debug", defaults.debug)),
        )

    @staticmethod
    def _apply_updates(settings: Settings, updates: dict[str, Any]) -> None:
        """Apply validated updates to the Settings object in-place."""
        for key, value in updates.items():
            if key == "rules_enabled":
                if isinstance(value, dict):
                    for rule_key, rule_val in value.items():
                        settings.rules_enabled[rule_key] = bool(rule_val)
            else:
                setattr(settings, key, value)

    def _persist(self, settings: Settings) -> None:
        """
        Write the current settings to config.yaml.

        Converts the Settings dataclass to a plain dict and dumps it as YAML,
        preserving the documented header comment.
        """
        logger = _get_logger()

        data = asdict(settings)

        header = (
            "# NetGuard Configuration\n"
            "# All settings below have documented defaults.\n"
            "# Changes applied via PUT /api/v1/settings take effect immediately without restart.\n\n"
        )

        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            yaml_text = yaml.dump(
                data,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
            )
            self._config_path.write_text(header + yaml_text, encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Failed to persist settings to '%s': %s",
                self._config_path,
                exc,
            )
            raise
