"""
RASP (Runtime Application Self-Protection) Schemas
Pydantic models for request/response validation and serialization
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum

# Enums
class RASPEnvironment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"

class RASPLanguage(str, Enum):
    JAVA = "java"
    NODEJS = "nodejs"
    PYTHON = "python"
    DOTNET = "dotnet"
    GO = "go"
    PHP = "php"

class RASPIncidentStatus(str, Enum):
    OPEN = "open"
    TRIAGE = "triage"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    IGNORED = "ignored"

class RASPIncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class RASPAction(str, Enum):
    BLOCKED = "blocked"
    ALLOWED = "allowed"
    MONITORED = "monitored"
    THROTTLED = "throttled"

class RASPRuleAction(str, Enum):
    BLOCK = "block"
    MONITOR = "monitor"
    THROTTLE = "throttle"
    ALERT = "alert"

# Base schemas
class RASPAppBase(BaseModel):
    name: str = Field(..., description="Application name")
    owner: str = Field(..., description="Application owner")
    repo_url: Optional[str] = Field(None, description="Repository URL")
    tags: Optional[List[str]] = Field(None, description="Application tags")
    framework: Optional[str] = Field(None, description="Application framework")
    language: Optional[RASPLanguage] = Field(None, description="Programming language")
    description: Optional[str] = Field(None, description="Application description")

class RASPAppCreate(RASPAppBase):
    pass

class RASPAppUpdate(BaseModel):
    name: Optional[str] = None
    owner: Optional[str] = None
    repo_url: Optional[str] = None
    tags: Optional[List[str]] = None
    framework: Optional[str] = None
    language: Optional[RASPLanguage] = None
    description: Optional[str] = None

class RASPApp(RASPAppBase):
    id: str
    risk_score: float
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

# Agent schemas
class RASPAgentBase(BaseModel):
    app_id: str = Field(..., description="Application ID")
    host: str = Field(..., description="Host name")
    pid: Optional[int] = Field(None, description="Process ID")
    container_id: Optional[str] = Field(None, description="Container ID")
    language: RASPLanguage = Field(..., description="Programming language")
    agent_version: str = Field(..., description="Agent version")
    env: RASPEnvironment = Field(..., description="Environment")

class RASPAgentRegister(RASPAgentBase):
    pass

class RASPAgentUpdate(BaseModel):
    status: Optional[str] = None
    config: Optional[Dict[str, Any]] = None

class RASPAgent(RASPAgentBase):
    id: str
    status: str
    last_heartbeat: Optional[datetime] = None
    pairing_token: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

# Incident schemas
class RASPIncidentBase(BaseModel):
    app_id: str = Field(..., description="Application ID")
    signature: str = Field(..., description="Attack signature")
    severity: RASPIncidentSeverity = Field(..., description="Incident severity")
    action_taken: RASPAction = Field(..., description="Action taken")
    evidence: Optional[Dict[str, Any]] = Field(None, description="Attack evidence")
    stack_trace: Optional[List[Dict[str, Any]]] = Field(None, description="Stack trace")
    request_data: Optional[Dict[str, Any]] = Field(None, description="Request data")
    session_id: Optional[str] = Field(None, description="Session ID")
    user_id: Optional[str] = Field(None, description="User ID")
    ip_address: Optional[str] = Field(None, description="IP address")
    path: Optional[str] = Field(None, description="Request path")
    method: Optional[str] = Field(None, description="HTTP method")
    tags: Optional[List[str]] = Field(None, description="Incident tags")

class RASPIncidentCreate(RASPIncidentBase):
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)

class RASPIncidentUpdate(BaseModel):
    status: Optional[RASPIncidentStatus] = None
    tags: Optional[List[str]] = None
    analyst_id: Optional[str] = None

class RASPIncident(RASPIncidentBase):
    id: str
    status: RASPIncidentStatus
    first_seen: datetime
    last_seen: datetime
    analyst_id: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

# Incident comment schemas
class RASPIncidentCommentCreate(BaseModel):
    comment: str = Field(..., description="Comment text")

class RASPIncidentComment(RASPIncidentCommentCreate):
    id: str
    incident_id: str
    analyst_id: str
    created_at: datetime
    
    class Config:
        from_attributes = True

# Incident action schemas
class RASPIncidentActionCreate(BaseModel):
    action_type: str = Field(..., description="Action type")
    details: Optional[Dict[str, Any]] = Field(None, description="Action details")

class RASPIncidentAction(RASPIncidentActionCreate):
    id: str
    incident_id: str
    analyst_id: str
    created_at: datetime
    
    class Config:
        from_attributes = True

# Policy schemas
class RASPPolicyBase(BaseModel):
    name: str = Field(..., description="Policy name")
    description: Optional[str] = Field(None, description="Policy description")
    app_id: Optional[str] = Field(None, description="Application ID (null for global)")
    is_global: bool = Field(False, description="Is global policy")
    enabled: bool = Field(True, description="Policy enabled")

class RASPPolicyCreate(RASPPolicyBase):
    pass

class RASPPolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None

class RASPPolicy(RASPPolicyBase):
    id: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

# Rule schemas
class RASPRuleBase(BaseModel):
    name: str = Field(..., description="Rule name")
    description: Optional[str] = Field(None, description="Rule description")
    condition: Dict[str, Any] = Field(..., description="Rule condition")
    action: RASPRuleAction = Field(..., description="Rule action")
    priority: int = Field(100, description="Rule priority")
    enabled: bool = Field(True, description="Rule enabled")

class RASPRuleCreate(RASPRuleBase):
    policy_id: str = Field(..., description="Policy ID")

class RASPRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    condition: Optional[Dict[str, Any]] = None
    action: Optional[RASPRuleAction] = None
    priority: Optional[int] = None
    enabled: Optional[bool] = None

class RASPRule(RASPRuleBase):
    id: str
    policy_id: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

# Event schemas
class RASPEventBase(BaseModel):
    event_type: str = Field(..., description="Event type")
    signature: Optional[str] = Field(None, description="Attack signature")
    timestamp: datetime = Field(..., description="Event timestamp")
    request_data: Optional[Dict[str, Any]] = Field(None, description="Request data")
    stack_trace: Optional[List[Dict[str, Any]]] = Field(None, description="Stack trace")
    evidence: Optional[str] = Field(None, description="Attack evidence")
    action_taken: Optional[RASPAction] = Field(None, description="Action taken")
    severity: Optional[RASPIncidentSeverity] = Field(None, description="Event severity")

class RASPEventCreate(RASPEventBase):
    agent_id: str = Field(..., description="Agent ID")

class RASPEvent(RASPEventBase):
    id: str
    agent_id: str
    created_at: datetime
    
    class Config:
        from_attributes = True

# Trace schemas
class RASPTraceBase(BaseModel):
    app_id: str = Field(..., description="Application ID")
    trace_id: str = Field(..., description="Trace ID")
    session_id: Optional[str] = Field(None, description="Session ID")
    user_id: Optional[str] = Field(None, description="User ID")
    path: Optional[str] = Field(None, description="Request path")
    method: Optional[str] = Field(None, description="HTTP method")
    duration_ms: Optional[int] = Field(None, description="Request duration in ms")
    events: Optional[List[Dict[str, Any]]] = Field(None, description="Trace events")
    annotations: Optional[Dict[str, Any]] = Field(None, description="Trace annotations")

class RASPTraceCreate(RASPTraceBase):
    pass

class RASPTrace(RASPTraceBase):
    id: str
    created_at: datetime
    
    class Config:
        from_attributes = True

# Vulnerability schemas
class RASPVulnerabilityBase(BaseModel):
    app_id: str = Field(..., description="Application ID")
    type: str = Field(..., description="Vulnerability type")
    cwe: Optional[str] = Field(None, description="CWE ID")
    severity: RASPIncidentSeverity = Field(..., description="Vulnerability severity")
    status: str = Field("open", description="Vulnerability status")
    evidence: Optional[Dict[str, Any]] = Field(None, description="Vulnerability evidence")
    remediation_guidance: Optional[str] = Field(None, description="Remediation guidance")
    exploitability_score: Optional[float] = Field(None, description="Exploitability score")
    occurrence_count: int = Field(1, description="Occurrence count")

class RASPVulnerabilityCreate(RASPVulnerabilityBase):
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)

class RASPVulnerabilityUpdate(BaseModel):
    status: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    remediation_guidance: Optional[str] = None
    exploitability_score: Optional[float] = None
    occurrence_count: Optional[int] = None

class RASPVulnerability(RASPVulnerabilityBase):
    id: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

# Integration schemas
class RASPIntegrationBase(BaseModel):
    name: str = Field(..., description="Integration name")
    type: str = Field(..., description="Integration type")
    config: Dict[str, Any] = Field(..., description="Integration configuration")
    enabled: bool = Field(True, description="Integration enabled")

class RASPIntegrationCreate(RASPIntegrationBase):
    pass

class RASPIntegrationUpdate(BaseModel):
    name: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None

class RASPIntegration(RASPIntegrationBase):
    id: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

# Metric schemas
class RASPMetricBase(BaseModel):
    metric_name: str = Field(..., description="Metric name")
    metric_value: float = Field(..., description="Metric value")
    timestamp: datetime = Field(..., description="Metric timestamp")
    labels: Optional[Dict[str, Any]] = Field(None, description="Metric labels")

class RASPMetricCreate(RASPMetricBase):
    app_id: Optional[str] = Field(None, description="Application ID")

class RASPMetric(RASPMetricBase):
    id: str
    app_id: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True

# Dashboard schemas
class RASPDashboardOverview(BaseModel):
    apps_count: int
    agents_count: int
    attacks_last_24h: int
    blocked_last_24h: int
    top_apps: List[Dict[str, Any]]

class RASPMetricsRequest(BaseModel):
    app_id: Optional[str] = None
    since: datetime
    until: datetime
    metric: str

class RASPMetricsResponse(BaseModel):
    data: List[Dict[str, Any]]
    labels: List[str]

# Agent heartbeat schemas
class RASPAgentHeartbeat(BaseModel):
    agent_id: str
    cpu: Optional[float] = None
    mem_mb: Optional[int] = None
    last_error: Optional[str] = None

# Agent events batch schemas
class RASPEventsBatch(BaseModel):
    agent_id: str
    events: List[RASPEventBase]
    agent_metrics: Optional[Dict[str, Any]] = None

# Rule simulation schemas
class RASPRuleSimulation(BaseModel):
    sample_request: Dict[str, Any] = Field(..., description="Sample request to test")

class RASPRuleSimulationResponse(BaseModel):
    would_match: bool
    matched_rules: List[str]
    explanation: str

# List response schemas
class RASPListResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    size: int
    pages: int

# Filter schemas
class RASPIncidentFilter(BaseModel):
    severity: Optional[RASPIncidentSeverity] = None
    status: Optional[RASPIncidentStatus] = None
    app_id: Optional[str] = None
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    signature: Optional[str] = None
    ip_address: Optional[str] = None
    user_id: Optional[str] = None

class RASPAppFilter(BaseModel):
    framework: Optional[str] = None
    language: Optional[RASPLanguage] = None
    environment: Optional[RASPEnvironment] = None
    tags: Optional[List[str]] = None
    risk_score_min: Optional[float] = None
    risk_score_max: Optional[float] = None

class RASPAgentFilter(BaseModel):
    app_id: Optional[str] = None
    status: Optional[str] = None
    language: Optional[RASPLanguage] = None
    environment: Optional[RASPEnvironment] = None 