"""
plugin_registry.py — Lightweight plugin discovery and lifecycle manager.

Plugins live in plugins/<name>/ and expose:
  PLUGIN_META = {"name": "...", "version": "...", "description": "..."}
  def register(app): ...

Requirements: 6.8, 13.6
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from pathlib import Path

logger = logging.getLogger("netguard.plugin_registry")

_PLUGINS_DIR = Path(__file__).resolve().parent.parent.parent / "plugins"


class PluginRegistry:
    """Discovers, enables, disables, and loads plugins from the plugins/ directory."""

    def __init__(self, settings_repo) -> None:
        self._settings = settings_repo
        self._plugins: dict[str, dict] = {}   # name → meta + state
        self._loaded: dict[str, object] = {}   # name → module
        self.discover()

    def discover(self) -> list[dict]:
        """Scan plugins/ directory and register all valid plugins."""
        self._plugins.clear()
        if not _PLUGINS_DIR.exists():
            _PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
            return []
        for plugin_dir in sorted(_PLUGINS_DIR.iterdir()):
            if not plugin_dir.is_dir():
                continue
            init_file = plugin_dir / "__init__.py"
            if not init_file.exists():
                continue
            name = plugin_dir.name
            try:
                spec = importlib.util.spec_from_file_location(f"plugins.{name}", init_file)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                meta = getattr(mod, "PLUGIN_META", {})
                # Load enabled state from settings
                enabled = False
                if self._settings:
                    enabled = self._settings.get(f"plugin.{name}.enabled") == "true"
                self._plugins[name] = {
                    "name": meta.get("name", name),
                    "version": meta.get("version", "0.0.1"),
                    "description": meta.get("description", ""),
                    "enabled": enabled,
                    "_module": mod,
                }
                logger.info("PluginRegistry: discovered plugin '%s' (enabled=%s)", name, enabled)
            except Exception as exc:
                logger.error("PluginRegistry: error loading plugin '%s': %s", name, exc)
        return self.list_plugins()

    def enable(self, name: str) -> bool:
        if name not in self._plugins:
            return False
        self._plugins[name]["enabled"] = True
        if self._settings:
            self._settings.set(f"plugin.{name}.enabled", "true")
        return True

    def disable(self, name: str) -> bool:
        if name not in self._plugins:
            return False
        self._plugins[name]["enabled"] = False
        if self._settings:
            self._settings.set(f"plugin.{name}.enabled", "false")
        return True

    def load(self, name: str, app=None) -> bool:
        """Call plugin's register(app) function."""
        plugin = self._plugins.get(name)
        if not plugin:
            return False
        mod = plugin.get("_module")
        if not mod:
            return False
        try:
            register = getattr(mod, "register", None)
            if register and app:
                register(app)
            self._loaded[name] = mod
            return True
        except Exception as exc:
            logger.error("PluginRegistry.load('%s') failed: %s", name, exc)
            return False

    def list_plugins(self) -> list[dict]:
        return [
            {
                "name": v["name"],
                "version": v["version"],
                "description": v["description"],
                "enabled": v["enabled"],
            }
            for v in self._plugins.values()
        ]
