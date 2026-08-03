"""
dependencies.py — Application-wide shared service instances for NetGuard.

All services are stored here after initialisation in main.py so that route
blueprints can access them without circular imports.

Pattern: blueprints call `from backend.api.dependencies import get_*`

Note: accessors return Optional[...] because services are registered at
startup; routes should guard against None where a service may be absent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from backend.services.config_service import ConfigurationManager
    from backend.services.monitor_service import MonitorService, MonitoringState
    from backend.services.detection_service import DetectionEngine
    from backend.services.prevention_service import PreventionEngine
    from backend.services.whitelist_service import WhitelistManager
    from backend.services.log_service import LoggingEngine
    from backend.services.stats_service import StatsService
    from backend.services.block_manager import BlockManager
    from backend.services.audit_service import AuditService
    from backend.services.auth_service import AuthService
    from backend.services.ai_explain_service import AIExplainService
    from backend.services.lan_scan_service import LanScanService
    from backend.services.security_advisor import SecurityAdvisor
    from backend.services.compliance_reporter import ComplianceReporter
    from backend.services.threat_simulator import ThreatSimulator
    from backend.services.attack_lab_service import AttackLabService
    from backend.services.geoip_engine import GeoIPEngine
    from backend.services.threat_intel_service import ThreatIntelService
    from backend.services.anomaly_engine import AnomalyEngine
    from backend.services.plugin_registry import PluginRegistry
    from backend.services.soar_engine import SOAREngine
    from backend.services.scheduler_service import SchedulerService
    from backend.repositories.event_repository import EventRepository
    from backend.repositories.block_repository import BlockRepository
    from backend.repositories.log_repository import LogRepository
    from backend.repositories.settings_repository import SettingsRepository
    from backend.repositories.whitelist_repository import WhitelistRepository

# Module-level container (populated by main.py before app start)
_services: dict = {}


def register(name: str, instance) -> None:
    """Register a service instance by name."""
    _services[name] = instance


def get(name: str):
    """Retrieve a registered service instance (None if not registered)."""
    return _services.get(name)


# Convenience accessors — one per service registered in main.py

def get_config() -> Optional["ConfigurationManager"]:
    return _services.get("config")

def get_monitor_service() -> Optional["MonitorService"]:
    return _services.get("monitor_service")

def get_monitoring_state() -> Optional["MonitoringState"]:
    return _services.get("monitoring_state")

def get_detection_engine() -> Optional["DetectionEngine"]:
    return _services.get("detection_engine")

def get_prevention_engine() -> Optional["PreventionEngine"]:
    return _services.get("prevention_engine")

def get_whitelist_manager() -> Optional["WhitelistManager"]:
    return _services.get("whitelist_manager")

def get_log_engine() -> Optional["LoggingEngine"]:
    return _services.get("log_engine")

def get_stats_service() -> Optional["StatsService"]:
    return _services.get("stats_service")

def get_event_repo() -> Optional["EventRepository"]:
    return _services.get("event_repo")

def get_block_repo() -> Optional["BlockRepository"]:
    return _services.get("block_repo")

def get_log_repo() -> Optional["LogRepository"]:
    return _services.get("log_repo")

def get_settings_repo() -> Optional["SettingsRepository"]:
    return _services.get("settings_repo")

def get_whitelist_repo() -> Optional["WhitelistRepository"]:
    return _services.get("whitelist_repo")

def get_block_manager() -> Optional["BlockManager"]:
    return _services.get("block_manager")

def get_audit_service() -> Optional["AuditService"]:
    return _services.get("audit_service")

def get_auth_service() -> Optional["AuthService"]:
    return _services.get("auth_service")

def get_ai_explain_service() -> Optional["AIExplainService"]:
    return _services.get("ai_explain_service")

def get_lan_scan_service() -> Optional["LanScanService"]:
    return _services.get("lan_scan_service")

def get_security_advisor() -> Optional["SecurityAdvisor"]:
    return _services.get("security_advisor")

def get_compliance_reporter() -> Optional["ComplianceReporter"]:
    return _services.get("compliance_reporter")

def get_threat_simulator() -> Optional["ThreatSimulator"]:
    return _services.get("threat_simulator")

def get_attack_lab_service() -> Optional["AttackLabService"]:
    return _services.get("attack_lab_service")

def get_geoip_engine() -> Optional["GeoIPEngine"]:
    return _services.get("geoip_engine")

def get_threat_intel_service() -> Optional["ThreatIntelService"]:
    return _services.get("threat_intel_service")

def get_anomaly_engine() -> Optional["AnomalyEngine"]:
    return _services.get("anomaly_engine")

def get_plugin_registry() -> Optional["PluginRegistry"]:
    return _services.get("plugin_registry")

def get_soar_engine() -> Optional["SOAREngine"]:
    return _services.get("soar_engine")

def get_scheduler_service() -> Optional["SchedulerService"]:
    return _services.get("scheduler_service")
