"""
dependencies.py — Application-wide shared service instances for NetGuard.

All services are stored here after initialisation in main.py so that route
blueprints can access them without circular imports.

Pattern: blueprints call `from backend.api.dependencies import get_*`
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.services.config_service import ConfigurationManager
    from backend.services.monitor_service import MonitorService, MonitoringState
    from backend.services.detection_service import DetectionEngine
    from backend.services.prevention_service import PreventionEngine
    from backend.services.whitelist_service import WhitelistManager
    from backend.services.log_service import LoggingEngine
    from backend.services.stats_service import StatsService
    from backend.repositories.event_repository import EventRepository
    from backend.repositories.block_repository import BlockRepository
    from backend.repositories.log_repository import LogRepository

# Module-level containers (populated by main.py before app start)
_services: dict = {}


def register(name: str, instance) -> None:
    """Register a service instance by name."""
    _services[name] = instance


def get(name: str):
    """Retrieve a registered service instance."""
    return _services.get(name)


# Convenience accessors

def get_config():
    return _services.get("config")

def get_monitor_service():
    return _services.get("monitor_service")

def get_monitoring_state():
    return _services.get("monitoring_state")

def get_detection_engine():
    return _services.get("detection_engine")

def get_prevention_engine():
    return _services.get("prevention_engine")

def get_whitelist_manager():
    return _services.get("whitelist_manager")

def get_log_engine():
    return _services.get("log_engine")

def get_stats_service():
    return _services.get("stats_service")

def get_event_repo():
    return _services.get("event_repo")

def get_block_repo():
    return _services.get("block_repo")

def get_log_repo():
    return _services.get("log_repo")

def get_security_advisor():
    return _services.get("security_advisor")
