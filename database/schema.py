"""
SQLAlchemy ORM models for NetGuard IDPS database schema.

This module defines six database models using SQLAlchemy 2.x declarative style:
- Event: Detection events with attack details and explanations
- BlockedIP: Active and historical firewall blocks
- WhitelistEntry: Trusted IPs that bypass automatic blocking
- DetectionRule: Configurable detection rules and thresholds
- Setting: System configuration key-value pairs
- SystemLog: Application operational logs

All models use DeclarativeBase and include appropriate indexes, constraints,
and relationships for efficient querying and data integrity.
"""

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


class Event(Base):
    """
    Detection events table.
    
    Stores every detected attack with full context, evidence, explanation,
    and recommended actions. Links to blocked_ips via event_id.
    """
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    event_id: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False
    )
    timestamp: Mapped[str] = mapped_column(String(30), nullable=False)
    attack_type: Mapped[str] = mapped_column(String(50), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    protocol: Mapped[str] = mapped_column(String(10), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    blocked: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (
        CheckConstraint(
            "confidence BETWEEN 0 AND 100",
            name="ck_confidence_range"
        ),
        Index("idx_events_timestamp", "timestamp"),
        Index("idx_events_source_ip", "source_ip"),
        Index("idx_events_attack_type", "attack_type"),
        Index("idx_events_severity", "severity"),
    )

    def __repr__(self) -> str:
        return (
            f"<Event(id={self.id}, event_id='{self.event_id}', "
            f"attack_type='{self.attack_type}', source_ip='{self.source_ip}', "
            f"severity='{self.severity}')>"
        )


class BlockedIP(Base):
    """
    Blocked IPs table.
    
    Tracks active and historical firewall blocks with expiration times.
    Links to events via event_id foreign key.
    """
    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    event_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("events.event_id"),
        nullable=False
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    blocked_at: Mapped[str] = mapped_column(String(30), nullable=False)
    expires_at: Mapped[str] = mapped_column(String(30), nullable=False)
    unblock_time: Mapped[str | None] = mapped_column(
        String(30), nullable=True
    )
    reason: Mapped[str] = mapped_column(String(50), nullable=False)
    active: Mapped[int] = mapped_column(Integer, default=1)
    # Enterprise columns (Task 3.1 / Req 1.6, 1.8, 1.3)
    block_type: Mapped[str] = mapped_column(String(20), nullable=False, default="ip")
    threat_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    operator_id: Mapped[str] = mapped_column(String(100), nullable=False, default="system")
    audit_entry_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        Index("idx_blocked_ip", "ip_address"),
        Index("idx_active_block", "active"),
        Index("idx_block_type", "block_type"),
    )

    def __repr__(self) -> str:
        return (
            f"<BlockedIP(id={self.id}, ip_address='{self.ip_address}', "
            f"active={self.active}, expires_at='{self.expires_at}')>"
        )


class WhitelistEntry(Base):
    """
    Whitelist table.
    
    Stores trusted IP addresses that should never be automatically blocked.
    Checked at runtime before applying firewall rules.
    """
    __tablename__ = "whitelist"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    ip_address: Mapped[str] = mapped_column(
        String(45), unique=True, nullable=False
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(30), nullable=False)
    created_by: Mapped[str] = mapped_column(String(100), default="admin")

    __table_args__ = (
        Index("idx_whitelist_ip", "ip_address"),
    )

    def __repr__(self) -> str:
        return (
            f"<WhitelistEntry(id={self.id}, ip_address='{self.ip_address}', "
            f"created_by='{self.created_by}')>"
        )


class DetectionRule(Base):
    """
    Detection rules table.
    
    Stores configurable detection rules with thresholds, severity levels,
    and block durations. Rules can be enabled/disabled without code changes.
    """
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    rule_name: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False
    )
    attack_type: Mapped[str] = mapped_column(String(50), nullable=False)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    block_duration: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[int] = mapped_column(Integer, default=1)
    priority: Mapped[int] = mapped_column(Integer, default=1)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<DetectionRule(id={self.id}, rule_name='{self.rule_name}', "
            f"attack_type='{self.attack_type}', enabled={self.enabled})>"
        )


class Setting(Base):
    """
    Settings table.
    
    Stores application configuration as key-value pairs.
    Updated at runtime without requiring application restart.
    """
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[str] = mapped_column(String(30), nullable=False)

    def __repr__(self) -> str:
        return f"<Setting(key='{self.key}', value='{self.value}')>"


class SystemLog(Base):
    """
    System logs table.
    
    Stores operational logs with severity levels, module context,
    and optional metadata. Supports dashboard log viewer and troubleshooting.
    """
    __tablename__ = "system_logs"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    timestamp: Mapped[str] = mapped_column(String(30), nullable=False)
    level: Mapped[str] = mapped_column(String(10), nullable=False)
    module: Mapped[str] = mapped_column(String(50), nullable=False)
    event: Mapped[str] = mapped_column(String(100), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    meta: Mapped[str | None] = mapped_column("metadata", Text, nullable=True)

    __table_args__ = (
        Index("idx_logs_level", "level"),
        Index("idx_logs_timestamp", "timestamp"),
    )

    def __repr__(self) -> str:
        return (
            f"<SystemLog(id={self.id}, level='{self.level}', "
            f"module='{self.module}', event='{self.event}')>"
        )


# ---------------------------------------------------------------------------
# Enterprise models (Task 1.2)
# ---------------------------------------------------------------------------

class ScheduledJob(Base):
    """APScheduler job mirror for API queries."""
    __tablename__ = "scheduled_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    attack_type: Mapped[str] = mapped_column(String(50), nullable=False)
    config_json: Mapped[str] = mapped_column(Text, nullable=False)
    recurrence_rule: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")
    scheduled_at: Mapped[str] = mapped_column(String(30), nullable=False)
    executed_at: Mapped[str | None] = mapped_column(String(30), nullable=True)
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)
    campaign_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    def __repr__(self) -> str:
        return f"<ScheduledJob(id='{self.id}', attack_type='{self.attack_type}', status='{self.status}')>"


class UserAccount(Base):
    """User accounts for JWT-based authentication and RBAC."""
    __tablename__ = "user_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="viewer")
    mfa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mfa_enabled: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[str] = mapped_column(String(30), nullable=False)
    last_login: Mapped[str | None] = mapped_column(String(30), nullable=True)
    active: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (Index("idx_user_username", "username"),)

    def __repr__(self) -> str:
        return f"<UserAccount(id={self.id}, username='{self.username}', role='{self.role}')>"


class AuditLog(Base):
    """Append-only audit log — no UPDATE/DELETE via API."""
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[str] = mapped_column(String(30), nullable=False)
    username: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_path: Mapped[str] = mapped_column(String(500), nullable=False)
    detail_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (Index("idx_audit_timestamp", "timestamp"),)

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, username='{self.username}', action='{self.action}')>"


class EnrichmentResult(Base):
    """Threat intel enrichment results per event."""
    __tablename__ = "enrichment_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    source: Mapped[str] = mapped_column(String(30), nullable=False)
    fetched_at: Mapped[str] = mapped_column(String(30), nullable=False)
    result_json: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ioc_match: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ioc_identifiers: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="ok")

    __table_args__ = (Index("idx_enrichment_event_id", "event_id"),)

    def __repr__(self) -> str:
        return f"<EnrichmentResult(id={self.id}, event_id='{self.event_id}', source='{self.source}')>"


class ComplianceReport(Base):
    """Cached compliance report blobs."""
    __tablename__ = "compliance_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    framework: Mapped[str] = mapped_column(String(30), nullable=False)
    generated_at: Mapped[str] = mapped_column(String(30), nullable=False)
    report_json: Mapped[str] = mapped_column(Text, nullable=False)

    def __repr__(self) -> str:
        return f"<ComplianceReport(id={self.id}, framework='{self.framework}', generated_at='{self.generated_at}')>"


class IOCStore(Base):
    """Active Indicators of Compromise."""
    __tablename__ = "ioc_store"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc_type: Mapped[str] = mapped_column(String(20), nullable=False)
    ioc_value: Mapped[str] = mapped_column(String(500), nullable=False)
    added_at: Mapped[str] = mapped_column(String(30), nullable=False)
    source: Mapped[str] = mapped_column(String(30), nullable=False, default="manual")
    last_seen: Mapped[str] = mapped_column(String(30), nullable=False)

    __table_args__ = (
        Index("idx_ioc_value", "ioc_value"),
    )

    def __repr__(self) -> str:
        return f"<IOCStore(id={self.id}, ioc_type='{self.ioc_type}', ioc_value='{self.ioc_value}')>"
