"""
RASP (Runtime Application Self-Protection) Models
Database models for RASP functionality including agents, attacks, rules, and vulnerabilities
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON, Float, UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from datetime import datetime
from typing import Optional, List
from enum import Enum
import uuid
from app.core.database import Base


class AgentStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    UPDATING = "updating"


class AttackSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    IGNORED = "ignored"


class PatchStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    EXPIRED = "expired"


class RASPAgent(Base):
    """RASP Agent model for monitoring applications"""
    __tablename__ = "rasp_agents"

    agent_id = Column(Integer, primary_key=True, index=True)
    app_name = Column(String(255), nullable=False, index=True)
    language = Column(String(50), nullable=False, index=True)
    version = Column(String(50), nullable=False)
    last_seen = Column(DateTime, default=func.now(), onupdate=func.now())
    status = Column(String(50), default=AgentStatus.ACTIVE, index=True)
    config = Column(JSON, default={})
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    attacks = relationship("RASPAttack", back_populates="agent", cascade="all, delete-orphan")
    vulnerabilities = relationship("RASPVulnerability", back_populates="agent", cascade="all, delete-orphan")
    virtual_patches = relationship("RASPVirtualPatch", back_populates="agent", cascade="all, delete-orphan")
    telemetry = relationship("RASPTelemetry", back_populates="agent", cascade="all, delete-orphan")
    alerts = relationship("RASPAlert", back_populates="agent", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<RASPAgent(agent_id={self.agent_id}, app_name='{self.app_name}', language='{self.language}')>"

    @classmethod
    async def get_by_id(cls, db: AsyncSession, agent_id: int) -> Optional["RASPAgent"]:
        result = await db.execute(select(cls).where(cls.agent_id == agent_id))
        return result.scalar_one_or_none()

    @classmethod
    async def get_active_agents(cls, db: AsyncSession) -> List["RASPAgent"]:
        result = await db.execute(select(cls).where(cls.status == AgentStatus.ACTIVE))
        return result.scalars().all()


class RASPAttack(Base):
    """RASP Attack model for logging detected attacks"""
    __tablename__ = "rasp_attacks"

    attack_id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("rasp_agents.agent_id"), nullable=False, index=True)
    timestamp = Column(DateTime, default=func.now(), index=True)
    source_ip = Column(String(50), index=True)
    url = Column(Text)
    payload = Column(Text)
    vuln_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(50), nullable=False, index=True)
    stack_trace = Column(Text)
    blocked = Column(Boolean, default=False, index=True)
    context = Column(JSON, default={})
    request_data = Column(JSON, default={})
    response_data = Column(JSON, default={})
    created_at = Column(DateTime, default=func.now())

    # Relationships
    agent = relationship("RASPAgent", back_populates="attacks")
    alerts = relationship("RASPAlert", back_populates="attack", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<RASPAttack(attack_id={self.attack_id}, vuln_type='{self.vuln_type}', severity='{self.severity}', blocked={self.blocked})>"

    @classmethod
    async def get_by_id(cls, db: AsyncSession, attack_id: int) -> Optional["RASPAttack"]:
        result = await db.execute(select(cls).where(cls.attack_id == attack_id))
        return result.scalar_one_or_none()

    @classmethod
    async def get_recent_attacks(cls, db: AsyncSession, hours: int = 24) -> List["RASPAttack"]:
        from datetime import timedelta
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        result = await db.execute(select(cls).where(cls.timestamp >= cutoff_time))
        return result.scalars().all()


class RASPRule(Base):
    """RASP Rule model for detection rules"""
    __tablename__ = "rasp_rules"

    rule_id = Column(Integer, primary_key=True, index=True)
    vuln_type = Column(String(50), nullable=False, index=True)
    language = Column(String(50), nullable=False, index=True)
    pattern = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False)
    auto_block = Column(Boolean, default=False)
    description = Column(Text)
    enabled = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<RASPRule(rule_id={self.rule_id}, vuln_type='{self.vuln_type}', language='{self.language}')>"

    @classmethod
    async def get_enabled_rules(cls, db: AsyncSession, language: Optional[str] = None) -> List["RASPRule"]:
        query = select(cls).where(cls.enabled == True)
        if language:
            query = query.where(cls.language == language)
        result = await db.execute(query)
        return result.scalars().all()


class RASPVulnerability(Base):
    """RASP Vulnerability model for discovered vulnerabilities"""
    __tablename__ = "rasp_vulnerabilities"

    vuln_id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("rasp_agents.agent_id"), nullable=False, index=True)
    vuln_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(50), nullable=False, index=True)
    status = Column(String(50), default=VulnerabilityStatus.OPEN, index=True)
    description = Column(Text)
    affected_file = Column(String(255))
    affected_line = Column(Integer)
    affected_method = Column(String(255))
    cwe_id = Column(String(20))
    owasp_category = Column(String(50))
    evidence = Column(JSON, default={})
    remediation = Column(Text)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    agent = relationship("RASPAgent", back_populates="vulnerabilities")
    virtual_patches = relationship("RASPVirtualPatch", back_populates="vulnerability", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<RASPVulnerability(vuln_id={self.vuln_id}, vuln_type='{self.vuln_type}', severity='{self.severity}')>"

    @classmethod
    async def get_by_id(cls, db: AsyncSession, vuln_id: int) -> Optional["RASPVulnerability"]:
        result = await db.execute(select(cls).where(cls.vuln_id == vuln_id))
        return result.scalar_one_or_none()

    @classmethod
    async def get_open_vulnerabilities(cls, db: AsyncSession, agent_id: Optional[int] = None) -> List["RASPVulnerability"]:
        query = select(cls).where(cls.status == VulnerabilityStatus.OPEN)
        if agent_id:
            query = query.where(cls.agent_id == agent_id)
        result = await db.execute(query)
        return result.scalars().all()


class RASPVirtualPatch(Base):
    """RASP Virtual Patch model for temporary vulnerability fixes"""
    __tablename__ = "rasp_virtual_patches"

    patch_id = Column(Integer, primary_key=True, index=True)
    vuln_id = Column(Integer, ForeignKey("rasp_vulnerabilities.vuln_id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("rasp_agents.agent_id"), nullable=False, index=True)
    patch_type = Column(String(50), nullable=False)
    patch_config = Column(JSON, nullable=False)
    status = Column(String(50), default=PatchStatus.ACTIVE, index=True)
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime)
    created_by = Column(Integer)

    # Relationships
    vulnerability = relationship("RASPVulnerability", back_populates="virtual_patches")
    agent = relationship("RASPAgent", back_populates="virtual_patches")

    def __repr__(self):
        return f"<RASPVirtualPatch(patch_id={self.patch_id}, patch_type='{self.patch_type}', status='{self.status}')>"


class RASPTelemetry(Base):
    """RASP Telemetry model for performance and behavior metrics"""
    __tablename__ = "rasp_telemetry"

    telemetry_id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("rasp_agents.agent_id"), nullable=False, index=True)
    timestamp = Column(DateTime, default=func.now(), index=True)
    metric_name = Column(String(100), nullable=False, index=True)
    metric_value = Column(Float)
    metric_data = Column(JSON, default={})
    created_at = Column(DateTime, default=func.now())

    # Relationships
    agent = relationship("RASPAgent", back_populates="telemetry")

    def __repr__(self):
        return f"<RASPTelemetry(telemetry_id={self.telemetry_id}, metric_name='{self.metric_name}', value={self.metric_value})>"


class RASPAlert(Base):
    """RASP Alert model for security alerts and notifications"""
    __tablename__ = "rasp_alerts"

    alert_id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("rasp_agents.agent_id"), nullable=False, index=True)
    attack_id = Column(Integer, ForeignKey("rasp_attacks.attack_id"), nullable=True, index=True)
    alert_type = Column(String(50), nullable=False)
    severity = Column(String(50), nullable=False, index=True)
    message = Column(Text, nullable=False)
    status = Column(String(50), default=AlertStatus.NEW, index=True)
    acknowledged_by = Column(Integer)
    acknowledged_at = Column(DateTime)
    created_at = Column(DateTime, default=func.now())

    # Relationships
    agent = relationship("RASPAgent", back_populates="alerts")
    attack = relationship("RASPAttack", back_populates="alerts")

    def __repr__(self):
        return f"<RASPAlert(alert_id={self.alert_id}, alert_type='{self.alert_type}', severity='{self.severity}')>"

    @classmethod
    async def get_new_alerts(cls, db: AsyncSession, agent_id: Optional[int] = None) -> List["RASPAlert"]:
        query = select(cls).where(cls.status == AlertStatus.NEW)
        if agent_id:
            query = query.where(cls.agent_id == agent_id)
        result = await db.execute(query)
        return result.scalars().all()


class RASPIntegration(Base):
    """RASP Integration model for SIEM/SOAR integrations"""
    __tablename__ = "rasp_integrations"

    integration_id = Column(Integer, primary_key=True, index=True)
    integration_type = Column(String(50), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    config = Column(JSON, nullable=False)
    enabled = Column(Boolean, default=True, index=True)
    last_sync = Column(DateTime)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<RASPIntegration(integration_id={self.integration_id}, type='{self.integration_type}', name='{self.name}')>"

    @classmethod
    async def get_enabled_integrations(cls, db: AsyncSession, integration_type: Optional[str] = None) -> List["RASPIntegration"]:
        query = select(cls).where(cls.enabled == True)
        if integration_type:
            query = query.where(cls.integration_type == integration_type)
        result = await db.execute(query)
        return result.scalars().all() 