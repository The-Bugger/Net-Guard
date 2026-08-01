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

    __table_args__ = (
        Index("idx_blocked_ip", "ip_address"),
        Index("idx_active_block", "active"),
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
    metadata: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("idx_logs_level", "level"),
        Index("idx_logs_timestamp", "timestamp"),
    )

    def __repr__(self) -> str:
        return (
            f"<SystemLog(id={self.id}, level='{self.level}', "
            f"module='{self.module}', event='{self.event}')>"
        )
