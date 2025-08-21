"""
RASP (Runtime Application Self-Protection) Models
Database models for RASP functionality including agents, attacks, rules, and vulnerabilities
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, JSON, ForeignKey, Float, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import enum

class RASPEnvironment(str, enum.Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"

class RASPLanguage(str, enum.Enum):
    JAVA = "java"
    NODEJS = "nodejs"
    PYTHON = "python"
    DOTNET = "dotnet"
    GO = "go"
    PHP = "php"

class RASPIncidentStatus(str, enum.Enum):
    OPEN = "open"
    TRIAGE = "triage"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    IGNORED = "ignored"

class RASPIncidentSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class RASPAction(str, enum.Enum):
    BLOCKED = "blocked"
    ALLOWED = "allowed"
    MONITORED = "monitored"
    THROTTLED = "throttled"

class RASPRuleAction(str, enum.Enum):
    BLOCK = "block"
    MONITOR = "monitor"
    THROTTLE = "throttle"
    ALERT = "alert"

class RASPApp(Base):
    __tablename__ = "rasp_apps"
    
    id = Column(String(50), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    owner = Column(String(255), nullable=False)
    repo_url = Column(String(500))
    tags = Column(JSON)
    risk_score = Column(Float, default=0.0)
    framework = Column(String(100))
    language = Column(Enum(RASPLanguage))
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    agents = relationship("RASPAgent", back_populates="app")
    incidents = relationship("RASPIncident", back_populates="app")
    vulnerabilities = relationship("RASPVulnerability", back_populates="app")
    traces = relationship("RASPTrace", back_populates="app")
    policies = relationship("RASPPolicy", back_populates="app")

class RASPAgent(Base):
    __tablename__ = "rasp_agents"
    
    id = Column(String(50), primary_key=True, index=True)
    app_id = Column(String(50), ForeignKey("rasp_apps.id"), nullable=False)
    host = Column(String(255), nullable=False)
    pid = Column(Integer)
    container_id = Column(String(100))
    language = Column(Enum(RASPLanguage), nullable=False)
    agent_version = Column(String(50), nullable=False)
    env = Column(Enum(RASPEnvironment), nullable=False)
    status = Column(String(50), default="active")
    last_heartbeat = Column(DateTime(timezone=True))
    pairing_token = Column(String(255))
    config = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    app = relationship("RASPApp", back_populates="agents")
    events = relationship("RASPEvent", back_populates="agent")

class RASPIncident(Base):
    __tablename__ = "rasp_incidents"
    
    id = Column(String(50), primary_key=True, index=True)
    app_id = Column(String(50), ForeignKey("rasp_apps.id"), nullable=False)
    signature = Column(String(255), nullable=False)
    severity = Column(Enum(RASPIncidentSeverity), nullable=False)
    status = Column(Enum(RASPIncidentStatus), default=RASPIncidentStatus.OPEN)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    action_taken = Column(Enum(RASPAction), nullable=False)
    evidence = Column(JSON)
    stack_trace = Column(JSON)
    request_data = Column(JSON)
    session_id = Column(String(255))
    user_id = Column(String(255))
    ip_address = Column(String(45))
    path = Column(String(500))
    method = Column(String(10))
    analyst_id = Column(String(50))
    tags = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    app = relationship("RASPApp", back_populates="incidents")
    comments = relationship("RASPIncidentComment", back_populates="incident")
    actions = relationship("RASPIncidentAction", back_populates="incident")

class RASPIncidentComment(Base):
    __tablename__ = "rasp_incident_comments"
    
    id = Column(String(50), primary_key=True, index=True)
    incident_id = Column(String(50), ForeignKey("rasp_incidents.id"), nullable=False)
    analyst_id = Column(String(50), nullable=False)
    comment = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    incident = relationship("RASPIncident", back_populates="comments")

class RASPIncidentAction(Base):
    __tablename__ = "rasp_incident_actions"
    
    id = Column(String(50), primary_key=True, index=True)
    incident_id = Column(String(50), ForeignKey("rasp_incidents.id"), nullable=False)
    action_type = Column(String(50), nullable=False)  # block_signature, ignore, mark_fp, create_ticket
    details = Column(JSON)
    analyst_id = Column(String(50), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    incident = relationship("RASPIncident", back_populates="actions")

class RASPPolicy(Base):
    __tablename__ = "rasp_policies"
    
    id = Column(String(50), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    app_id = Column(String(50), ForeignKey("rasp_apps.id"), nullable=True)  # null for global policies
    is_global = Column(Boolean, default=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    app = relationship("RASPApp", back_populates="policies")
    rules = relationship("RASPRule", back_populates="policy")

class RASPRule(Base):
    __tablename__ = "rasp_rules"
    
    id = Column(String(50), primary_key=True, index=True)
    policy_id = Column(String(50), ForeignKey("rasp_policies.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    condition = Column(JSON, nullable=False)  # rule condition logic
    action = Column(Enum(RASPRuleAction), nullable=False)
    priority = Column(Integer, default=100)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    policy = relationship("RASPPolicy", back_populates="rules")

class RASPEvent(Base):
    __tablename__ = "rasp_events"
    
    id = Column(String(50), primary_key=True, index=True)
    agent_id = Column(String(50), ForeignKey("rasp_agents.id"), nullable=False)
    event_type = Column(String(50), nullable=False)  # attack, trace, heartbeat
    signature = Column(String(255))
    timestamp = Column(DateTime(timezone=True), nullable=False)
    request_data = Column(JSON)
    stack_trace = Column(JSON)
    evidence = Column(Text)
    action_taken = Column(Enum(RASPAction))
    severity = Column(Enum(RASPIncidentSeverity))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    agent = relationship("RASPAgent", back_populates="events")

class RASPTrace(Base):
    __tablename__ = "rasp_traces"
    
    id = Column(String(50), primary_key=True, index=True)
    app_id = Column(String(50), ForeignKey("rasp_apps.id"), nullable=False)
    trace_id = Column(String(255), nullable=False)
    session_id = Column(String(255))
    user_id = Column(String(255))
    path = Column(String(500))
    method = Column(String(10))
    duration_ms = Column(Integer)
    events = Column(JSON)  # trace events with timestamps
    annotations = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    app = relationship("RASPApp", back_populates="traces")

class RASPVulnerability(Base):
    __tablename__ = "rasp_vulnerabilities"
    
    id = Column(String(50), primary_key=True, index=True)
    app_id = Column(String(50), ForeignKey("rasp_apps.id"), nullable=False)
    type = Column(String(100), nullable=False)
    cwe = Column(String(20))
    severity = Column(Enum(RASPIncidentSeverity), nullable=False)
    status = Column(String(50), default="open")
    evidence = Column(JSON)
    remediation_guidance = Column(Text)
    exploitability_score = Column(Float)
    occurrence_count = Column(Integer, default=1)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    app = relationship("RASPApp", back_populates="vulnerabilities")

class RASPIntegration(Base):
    __tablename__ = "rasp_integrations"
    
    id = Column(String(50), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    type = Column(String(50), nullable=False)  # siem, ticketing, chatops, webhook
    config = Column(JSON, nullable=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class RASPMetric(Base):
    __tablename__ = "rasp_metrics"
    
    id = Column(String(50), primary_key=True, index=True)
    app_id = Column(String(50), ForeignKey("rasp_apps.id"), nullable=True)
    metric_name = Column(String(100), nullable=False)
    metric_value = Column(Float, nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    labels = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    app = relationship("RASPApp") 