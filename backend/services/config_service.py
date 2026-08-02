"""
Configuration manager for NetGuard IDPS.

Reads and writes config/config.yaml. Falls back to built-in defaults when the
file is absent or unparseable. Thread-safe; applies updates in-memory and
persists them to YAML without requiring an application restart.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import yaml

_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent
_CONFIG_PATH: Path  = _PROJECT_ROOT / "config" / "config.yaml"
_LOGS_DIR: Path     = _PROJECT_ROOT / "logs"
_ERRORS_LOG: Path   = _LOGS_DIR / "errors.log"

_logger_lock = threading.Lock()
_logger: logging.Logger | None = None


def _get_logger() -> logging.Logger:
    """Return (lazily initialised) the module logger writing to errors.log."""
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
            handler.setFormatter(logging.Formatter(
                "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            ))
            logger.addHandler(handler)
        _logger = logger
        return _logger


_DEFAULT_RULES_ENABLED: dict[str, bool] = {
    "syn_flood":     True,
    "port_scan":     True,
    "sql_injection": True,
    "brute_force":   True,
    "arp_spoof":     True,
    "icmp_flood":    True,
    "slow_http":     True,
    "dns_tunnel":    True,
}


@dataclass
class Settings:
    """All NetGuard runtime settings with built-in defaults."""
    network_interface: str = ""
    syn_flood_threshold: int = 100
    syn_flood_window: int = 3
    port_scan_threshold: int = 20
    port_scan_window: int = 10
    brute_force_threshold: int = 10
    brute_force_window: int = 60
    icmp_flood_threshold: int = 100
    icmp_flood_window: int = 3
    slow_http_threshold: int = 10
    slow_http_window: int = 10
    block_duration: int = 120
    dashboard_refresh_interval: int = 1
    rules_enabled: dict[str, bool] = field(default_factory=lambda: dict(_DEFAULT_RULES_ENABLED))
    debug: bool = False


# Allowed integer ranges: key → (min, max | None)
_INT_RANGES: dict[str, tuple[int, int | None]] = {
    "syn_flood_threshold":        (1, None),
    "syn_flood_window":           (1, 60),
    "port_scan_threshold":        (1, None),
    "port_scan_window":           (1, 60),
    "brute_force_threshold":      (1, None),
    "brute_force_window":         (1, 300),
    "icmp_flood_threshold":       (1, None),
    "icmp_flood_window":          (1, 60),
    "slow_http_threshold":        (1, None),
    "slow_http_window":           (1, 60),
    "block_duration":             (1, 3600),
    "dashboard_refresh_interval": (1, 60),
}

_VALID_KEYS: frozenset[str] = frozenset({
    "network_interface", "syn_flood_threshold", "syn_flood_window",
    "port_scan_threshold", "port_scan_window", "brute_force_threshold",
    "brute_force_window", "icmp_flood_threshold", "icmp_flood_window",
    "slow_http_threshold", "slow_http_window", "block_duration",
    "dashboard_refresh_interval", "rules_enabled", "debug",
})


class ConfigurationManager:
    """
    Thread-safe manager for loading, validating, and persisting NetGuard settings.

    Usage:
        cm = ConfigurationManager()
        settings = cm.load()
        value = cm.get("syn_flood_threshold")
        cm.update({"syn_flood_threshold": 200})
    """

    def __init__(self, config_path: Path | None = None) -> None:
        self._config_path: Path = config_path or _CONFIG_PATH
        self._lock: threading.Lock = threading.Lock()
        self._settings: Settings = Settings()

    def load(self) -> Settings:
        """
        Load settings from config.yaml.

        On a missing or unparseable file, logs CRITICAL and returns built-in
        defaults so monitoring can still start.
        """
        logger = _get_logger()
        raw: dict[str, Any] = {}
        try:
            text = self._config_path.read_text(encoding="utf-8")
            parsed = yaml.safe_load(text)
            if not isinstance(parsed, dict):
                raise ValueError(f"Expected a YAML mapping, got {type(parsed).__name__}")
            raw = parsed
        except FileNotFoundError:
            logger.critical("config.yaml not found at '%s'. Applying built-in defaults.", self._config_path)
        except yaml.YAMLError as exc:
            logger.critical("config.yaml is not valid YAML at '%s': %s. Applying built-in defaults.", self._config_path, exc)
        except Exception as exc:  # noqa: BLE001
            logger.critical("Unexpected error reading config.yaml at '%s': %s. Applying built-in defaults.", self._config_path, exc)

        try:
            settings = self._build_settings(raw)
        except ValueError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.error("ConfigurationManager.load: unexpected error building settings: %s", exc)
            settings = Settings()

        with self._lock:
            self._settings = settings
        return settings

    def get(self, key: str) -> Any:
        """Return the current value for a settings key, or None if unknown."""
        with self._lock:
            return getattr(self._settings, key, None)

    def update(self, updates: dict[str, Any]) -> None:
        """
        Validate, apply in-memory, and persist updates to config.yaml.

        Raises ValueError listing all invalid field names.
        """
        try:
            if not isinstance(updates, dict):
                raise ValueError("updates must be a dict")
            invalid = self.validate_settings(updates)
            if invalid:
                raise ValueError(f"Invalid configuration values for field(s): {', '.join(invalid)}")
        except ValueError:
            raise
        except Exception as exc:  # noqa: BLE001
            _get_logger().error("ConfigurationManager.update: unexpected error in validation: %s", exc)
            return

        try:
            with self._lock:
                self._apply_updates(self._settings, updates)
                self._persist(self._settings)
        except ValueError:
            raise
        except Exception as exc:  # noqa: BLE001
            _get_logger().error("ConfigurationManager.update: unexpected error applying updates: %s", exc)

    def validate_settings(self, updates: dict[str, Any]) -> list[str]:
        """Return a list of invalid field names in updates. Empty list means all valid."""
        try:
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
        except Exception:  # noqa: BLE001
            return []

    @staticmethod
    def _build_settings(raw: dict[str, Any]) -> Settings:
        """Construct Settings from raw YAML dict. May raise ValueError."""
        try:
            return ConfigurationManager._build_settings_inner(raw)
        except ValueError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"Unexpected error building settings: {exc}") from exc

    @staticmethod
    def _build_settings_inner(raw: dict[str, Any]) -> Settings:
        defaults = Settings()
        rules_raw = raw.get("rules_enabled", {})
        if not isinstance(rules_raw, dict):
            rules_raw = {}
        rules_enabled: dict[str, bool] = {
            k: bool(rules_raw.get(k, v)) for k, v in _DEFAULT_RULES_ENABLED.items()
        }

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
            icmp_flood_threshold=_int("icmp_flood_threshold"),
            icmp_flood_window=_int("icmp_flood_window"),
            slow_http_threshold=_int("slow_http_threshold"),
            slow_http_window=_int("slow_http_window"),
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
        """Write current settings to config.yaml."""
        logger = _get_logger()
        data = asdict(settings)
        header = (
            "# NetGuard Configuration\n"
            "# All settings below have documented defaults.\n"
            "# Changes applied via PUT /api/v1/settings take effect immediately without restart.\n\n"
        )
        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            yaml_text = yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)
            self._config_path.write_text(header + yaml_text, encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to persist settings to '%s': %s", self._config_path, exc)
            raise
