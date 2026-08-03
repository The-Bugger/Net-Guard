"""NetGuard IDPS application entry point."""

from __future__ import annotations

# Eventlet monkey-patches select/socket, which corrupts Scapy's pcap fd handling
# on Windows and causes monitor/start to hang. Use threading mode on Windows;
# keep eventlet on Linux where it works correctly.
import sys as _sys
import os as _os
if _sys.platform == "win32":
    _os.environ["SOCKETIO_ASYNC_MODE"] = "threading"
elif _sys.version_info < (3, 14):
    import eventlet
    eventlet.monkey_patch()
else:
    _os.environ.setdefault("SOCKETIO_ASYNC_MODE", "threading")

import logging
import os
import queue
import sys
from contextlib import contextmanager
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Configuration
from backend.services.config_service import ConfigurationManager
from backend.services.log_service import setup_logging, LoggingEngine

config_manager = ConfigurationManager()
settings = config_manager.load()

# Logging
log_level = os.environ.get("LOG_LEVEL", "INFO")
setup_logging()
logger = logging.getLogger("netguard.main")
logger.setLevel(log_level)
logger.info("NetGuard IDPS starting up...")

# Database
from database.init_db import initialize_db, get_engine
from sqlalchemy.orm import sessionmaker, Session

db_url = os.environ.get("DATABASE_URL", f"sqlite:///{_PROJECT_ROOT}/database/netguard.db")
if db_url.startswith("sqlite:///") and not db_url.startswith("sqlite:////"):
    db_path = _PROJECT_ROOT / "database" / "netguard.db"
    db_url = f"sqlite:///{db_path}"

initialize_db(db_url)
engine = get_engine(db_url)


@contextmanager
def session_factory():
    """Provide a transactional SQLAlchemy session."""
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


logger.info("Database initialised at: %s", db_url)

# Repositories
from backend.repositories.event_repository import EventRepository
from backend.repositories.block_repository import BlockRepository
from backend.repositories.whitelist_repository import WhitelistRepository
from backend.repositories.log_repository import LogRepository
from backend.repositories.settings_repository import SettingsRepository

event_repo    = EventRepository(session_factory)
block_repo    = BlockRepository(session_factory)
whitelist_repo = WhitelistRepository(session_factory)
log_repo      = LogRepository(session_factory)
settings_repo = SettingsRepository(session_factory)

# Services
from backend.services.log_service import LoggingEngine
from backend.services.whitelist_service import WhitelistManager
from backend.services.monitor_service import MonitorService, MonitoringState
from backend.services.stats_service import StatsService
from backend.services.prevention_service import PreventionEngine
from backend.services.expiry_service import ExpiryThread
from backend.services.detection_service import DetectionEngine
from backend.services.explain_service import ExplainabilityEngine

monitoring_state = MonitoringState()
packet_queue: queue.Queue = queue.Queue(maxsize=10000)
event_queue: queue.Queue  = queue.Queue(maxsize=1000)

log_engine = LoggingEngine(event_queue=event_queue, event_repo=event_repo, log_repo=log_repo)

whitelist_manager = WhitelistManager(whitelist_repo)
whitelist_manager.sync_from_db()

stats_service  = StatsService(event_repo, block_repo, monitoring_state, whitelist_manager=whitelist_manager)
explain_engine = ExplainabilityEngine(whitelist_manager)


def _on_threat_event(threat_event):
    """Callback invoked by DetectionEngine for every confirmed ThreatEvent."""
    try:
        explanation = explain_engine.explain(threat_event)
        threat_event.blocked = False

        # Hand off to LoggingEngine for async DB persistence.
        # Do NOT also call event_repo.insert() here — that would double-write
        # the same event_id and cause a UNIQUE constraint failure.
        log_engine.log_event(threat_event, explanation)
        stats_service.invalidate_cache()

        prevention_engine.handle_event(threat_event, explanation)

        _emit_socketio("new_threat", {
            "event_id":       threat_event.event_id,
            "attack_type":    threat_event.attack_type,
            "source_ip":      threat_event.source_ip,
            "severity":       threat_event.severity,
            "confidence":     threat_event.confidence,
            "timestamp":      threat_event.timestamp,
            "explanation":    explanation.plain_english_text,
            "recommendation": explanation.recommendation,
            "rule_name":      threat_event.rule_name,
            "evidence":       threat_event.evidence,
        })
    except Exception as exc:
        logger.error("on_threat_event error: %s", exc, exc_info=True)


def _emit_socketio(event_name: str, data: dict) -> None:
    """Safely emit a SocketIO event."""
    try:
        from backend.api import socketio
        socketio.emit(event_name, data)
    except Exception as exc:
        logger.debug("SocketIO emit failed: %s", exc)


prevention_engine = PreventionEngine(
    block_repo=block_repo,
    whitelist_manager=whitelist_manager,
    log_engine=log_engine,
    block_duration=settings.block_duration,
    socketio_emit=_emit_socketio,
)

try:
    prevention_engine.verify_privileges()
except RuntimeError as exc:
    logger.critical("Firewall privilege check failed: %s", exc)
    logger.warning("Continuing without firewall blocking capability.")

detection_engine = DetectionEngine(
    packet_queue=packet_queue,
    on_event=_on_threat_event,
    config_manager=config_manager,
)

from detection.capture.sniffer import CaptureEngine
capture_engine = CaptureEngine(
    packet_queue,
    socketio_emit=_emit_socketio,
    stats_service=stats_service,
)

monitor_service = MonitorService(
    capture_engine=capture_engine,
    detection_engine=detection_engine,
    state=monitoring_state,
    log_engine=log_engine,
    socketio_emit=_emit_socketio,
)

expiry_thread = ExpiryThread(
    block_repo=block_repo,
    log_engine=log_engine,
    socketio_emit=_emit_socketio,
)

# Register all services in the dependency container
from backend.api import dependencies
dependencies.register("config",            config_manager)
dependencies.register("monitoring_state",  monitoring_state)
dependencies.register("monitor_service",   monitor_service)
dependencies.register("detection_engine",  detection_engine)
dependencies.register("prevention_engine", prevention_engine)
dependencies.register("whitelist_manager", whitelist_manager)
dependencies.register("log_engine",        log_engine)
dependencies.register("stats_service",     stats_service)
dependencies.register("event_repo",        event_repo)
dependencies.register("block_repo",        block_repo)
dependencies.register("log_repo",          log_repo)
dependencies.register("settings_repo",     settings_repo)
dependencies.register("whitelist_repo",    whitelist_repo)

from backend.services.block_manager import BlockManager
block_manager = BlockManager(
    block_repo=block_repo,
    whitelist_manager=whitelist_manager,
    log_engine=log_engine,
    socketio_emit=_emit_socketio,
)
block_manager.restore_on_startup()
dependencies.register("block_manager", block_manager)

from backend.services.audit_service import AuditService
audit_service = AuditService(session_factory)
dependencies.register("audit_service", audit_service)

from backend.services.auth_service import AuthService
auth_service = AuthService(settings_repo, audit_service)
dependencies.register("auth_service", auth_service)

from backend.services.ai_explain_service import AIExplainService
ai_explain_service = AIExplainService()
dependencies.register("ai_explain_service", ai_explain_service)

from backend.services.lan_scan_service import LanScanService
lan_scan_service = LanScanService()
dependencies.register("lan_scan_service", lan_scan_service)

from backend.services.security_advisor import SecurityAdvisor
security_advisor = SecurityAdvisor()
dependencies.register("security_advisor", security_advisor)

from backend.services.compliance_reporter import ComplianceReporter
compliance_reporter = ComplianceReporter()
dependencies.register("compliance_reporter", compliance_reporter)

from backend.services.threat_simulator import ThreatSimulator
threat_simulator = ThreatSimulator(
    whitelist_set={e["ip_address"] for e in whitelist_manager.get_all()}
)
dependencies.register("threat_simulator", threat_simulator)

from backend.services.attack_lab_service import AttackLabService
attack_lab_service = AttackLabService(packet_queue=packet_queue, threat_simulator=threat_simulator)
dependencies.register("attack_lab_service", attack_lab_service)

from backend.services.geoip_engine import GeoIPEngine
geoip_engine = GeoIPEngine(settings_repo=settings_repo)
dependencies.register("geoip_engine", geoip_engine)

from backend.services.threat_intel_service import ThreatIntelService
threat_intel_service = ThreatIntelService(event_repo, settings_repo, log_engine)
dependencies.register("threat_intel_service", threat_intel_service)

from backend.services.anomaly_engine import AnomalyEngine
anomaly_engine = AnomalyEngine(
    baseline_window_seconds=float(os.environ.get("ANOMALY_BASELINE_WINDOW", "300"))
)
dependencies.register("anomaly_engine", anomaly_engine)

from backend.services.plugin_registry import PluginRegistry
plugin_registry = PluginRegistry(settings_repo)
dependencies.register("plugin_registry", plugin_registry)

from backend.services.soar_engine import SOAREngine
soar_engine = SOAREngine(
    settings_repo=settings_repo,
    log_engine=log_engine,
    socketio_emit=_emit_socketio,
    geoip_engine=geoip_engine,
)
dependencies.register("soar_engine", soar_engine)

from backend.services.scheduler_service import SchedulerService
scheduler_service = SchedulerService(
    attack_lab_service=attack_lab_service,
    log_engine=log_engine,
    socketio_emit=_emit_socketio,
)
dependencies.register("scheduler_service", scheduler_service)

# Flask app
from backend.api import create_app, socketio as _socketio

app = create_app()


@_socketio.on("connect")
def on_client_connect():
    logger.debug("Dashboard client connected.")


@_socketio.on("disconnect")
def on_client_disconnect():
    logger.debug("Dashboard client disconnected.")


@_socketio.on("request_live_stats")
def on_request_live_stats():
    data = stats_service.get_live_stats()
    data["health_score"] = stats_service.get_health_score()
    _socketio.emit("live_stats", data)


def _background_live_stats():
    """Emit live_stats to all clients every refresh interval."""
    refresh = settings.dashboard_refresh_interval or 1
    _last_health_score = None
    while True:
        _socketio.sleep(refresh)
        try:
            data = stats_service.get_live_stats()
            current_score = stats_service.get_health_score()
            if _last_health_score is None or abs(current_score - _last_health_score) >= 5:
                data["health_score"] = current_score
                _last_health_score = current_score
            _socketio.sleep(0)  # yield to socketio thread
            _socketio.emit("live_stats", data)
        except Exception as exc:
            logger.debug("live_stats emit error: %s", exc)


if __name__ == "__main__":
    logger.info("Starting background services...")
    log_engine.start()
    expiry_thread.start()
    detection_engine.start()

    scheduler_service.wire_session(session_factory)
    scheduler_service.start()

    _socketio.start_background_task(_background_live_stats)

    log_engine.log_system(
        "INFO", "main", "STARTUP",
        "NetGuard IDPS started successfully.",
        metadata={"db_url": db_url, "log_level": log_level},
    )

    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", 5000))
    debug = settings.debug

    # TLS: when TLS_CERT_FILE and TLS_KEY_FILE are set, serve HTTPS (TLS 1.2+ minimum)
    tls_cert = os.environ.get("TLS_CERT_FILE", "")
    tls_key  = os.environ.get("TLS_KEY_FILE", "")
    ssl_context = None
    if tls_cert and tls_key:
        import ssl as _ssl
        _ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        _ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
        _ctx.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
        ssl_context = _ctx
        logger.info("TLS enabled — cert=%s (TLS 1.2+ minimum)", tls_cert)
        logger.info("Dashboard available at https://localhost:%d", port)
        logger.info("API base URL: https://localhost:%d/api/v1", port)
    else:
        logger.info("Dashboard available at http://localhost:%d", port)
        logger.info("API base URL: http://localhost:%d/api/v1", port)

    run_kwargs = dict(host=host, port=port, debug=debug, use_reloader=False)
    if ssl_context is not None:
        run_kwargs["ssl_context"] = ssl_context
    _socketio.run(app, **run_kwargs)
