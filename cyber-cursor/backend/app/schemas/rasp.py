"""
RASP (Runtime Application Self-Protection) Schemas
Pydantic models for request/response validation and serialization
"""
from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


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


# Agent Schemas
class AgentBase(BaseModel):
    app_name: str = Field(..., description="Application name")
    language: str = Field(..., description="Programming language")
    version: str = Field(..., description="Agent version")
    config: Dict[str, Any] = Field(default_factory=dict, description="Agent configuration")


class AgentCreate(AgentBase):
    pass


class AgentUpdate(BaseModel):
    app_name: Optional[str] = Field(None, description="Application name")
    language: Optional[str] = Field(None, description="Programming language")
    version: Optional[str] = Field(None, description="Agent version")
    status: Optional[AgentStatus] = Field(None, description="Agent status")
    config: Optional[Dict[str, Any]] = Field(None, description="Agent configuration")


class AgentResponse(AgentBase):
    agent_id: int
    status: AgentStatus
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Attack Schemas
class AttackBase(BaseModel):
    agent_id: int = Field(..., description="Agent ID")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    url: Optional[str] = Field(None, description="Target URL")
    payload: Optional[str] = Field(None, description="Attack payload")
    vuln_type: str = Field(..., description="Vulnerability type")
    severity: AttackSeverity = Field(..., description="Attack severity")
    stack_trace: Optional[str] = Field(None, description="Stack trace")
    blocked: bool = Field(False, description="Whether attack was blocked")
    context: Dict[str, Any] = Field(default_factory=dict, description="Attack context")
    request_data: Dict[str, Any] = Field(default_factory=dict, description="Request data")
    response_data: Dict[str, Any] = Field(default_factory=dict, description="Response data")


class AttackCreate(AttackBase):
    pass


class AttackResponse(AttackBase):
    attack_id: int
    timestamp: datetime
    created_at: datetime

    class Config:
        from_attributes = True


# Rule Schemas
class RuleBase(BaseModel):
    vuln_type: str = Field(..., description="Vulnerability type")
    language: str = Field(..., description="Programming language")
    pattern: str = Field(..., description="Detection pattern")
    severity: AttackSeverity = Field(..., description="Rule severity")
    auto_block: bool = Field(False, description="Auto-block attacks")
    description: Optional[str] = Field(None, description="Rule description")


class RuleCreate(RuleBase):
    pass


class RuleUpdate(BaseModel):
    vuln_type: Optional[str] = Field(None, description="Vulnerability type")
    language: Optional[str] = Field(None, description="Programming language")
    pattern: Optional[str] = Field(None, description="Detection pattern")
    severity: Optional[AttackSeverity] = Field(None, description="Rule severity")
    auto_block: Optional[bool] = Field(None, description="Auto-block attacks")
    description: Optional[str] = Field(None, description="Rule description")
    enabled: Optional[bool] = Field(None, description="Rule enabled status")


class RuleResponse(RuleBase):
    rule_id: int
    enabled: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Vulnerability Schemas
class VulnerabilityBase(BaseModel):
    agent_id: int = Field(..., description="Agent ID")
    vuln_type: str = Field(..., description="Vulnerability type")
    severity: AttackSeverity = Field(..., description="Vulnerability severity")
    description: Optional[str] = Field(None, description="Vulnerability description")
    affected_file: Optional[str] = Field(None, description="Affected file")
    affected_line: Optional[int] = Field(None, description="Affected line number")
    affected_method: Optional[str] = Field(None, description="Affected method")
    cwe_id: Optional[str] = Field(None, description="CWE ID")
    owasp_category: Optional[str] = Field(None, description="OWASP category")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Evidence data")
    remediation: Optional[str] = Field(None, description="Remediation guidance")


class VulnerabilityUpdate(BaseModel):
    status: Optional[VulnerabilityStatus] = Field(None, description="Vulnerability status")
    description: Optional[str] = Field(None, description="Vulnerability description")
    affected_file: Optional[str] = Field(None, description="Affected file")
    affected_line: Optional[int] = Field(None, description="Affected line number")
    affected_method: Optional[str] = Field(None, description="Affected method")
    cwe_id: Optional[str] = Field(None, description="CWE ID")
    owasp_category: Optional[str] = Field(None, description="OWASP category")
    evidence: Optional[Dict[str, Any]] = Field(None, description="Evidence data")
    remediation: Optional[str] = Field(None, description="Remediation guidance")


class VulnerabilityResponse(VulnerabilityBase):
    vuln_id: int
    status: VulnerabilityStatus
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Virtual Patch Schemas
class VirtualPatchBase(BaseModel):
    vuln_id: int = Field(..., description="Vulnerability ID")
    agent_id: int = Field(..., description="Agent ID")
    patch_type: str = Field(..., description="Patch type")
    patch_config: Dict[str, Any] = Field(..., description="Patch configuration")
    expires_at: Optional[datetime] = Field(None, description="Patch expiration")


class VirtualPatchCreate(VirtualPatchBase):
    pass


class VirtualPatchResponse(VirtualPatchBase):
    patch_id: int
    status: PatchStatus
    created_at: datetime
    created_by: Optional[int]

    class Config:
        from_attributes = True


# Alert Schemas
class AlertBase(BaseModel):
    agent_id: int = Field(..., description="Agent ID")
    attack_id: Optional[int] = Field(None, description="Attack ID")
    alert_type: str = Field(..., description="Alert type")
    severity: AttackSeverity = Field(..., description="Alert severity")
    message: str = Field(..., description="Alert message")


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = Field(None, description="Alert status")
    acknowledged_by: Optional[int] = Field(None, description="User who acknowledged")
    message: Optional[str] = Field(None, description="Alert message")


class AlertResponse(AlertBase):
    alert_id: int
    status: AlertStatus
    acknowledged_by: Optional[int]
    acknowledged_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


# Integration Schemas
class IntegrationBase(BaseModel):
    integration_type: str = Field(..., description="Integration type")
    name: str = Field(..., description="Integration name")
    config: Dict[str, Any] = Field(..., description="Integration configuration")


class IntegrationCreate(IntegrationBase):
    pass


class IntegrationResponse(IntegrationBase):
    integration_id: int
    enabled: bool
    last_sync: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Dashboard Schemas
class DashboardOverview(BaseModel):
    total_agents: int
    active_agents: int
    total_attacks: int
    blocked_attacks: int
    total_vulnerabilities: int
    open_vulnerabilities: int
    total_alerts: int
    new_alerts: int
    recent_attacks_by_type: Dict[str, int]
    recent_attacks_by_severity: Dict[str, int]


class AttackSummary(BaseModel):
    total_attacks: int
    blocked_attacks: int
    successful_attacks: int
    attacks_by_type: Dict[str, int]
    attacks_by_severity: Dict[str, int]
    attacks_by_agent: Dict[str, int]
    recent_trend: List[Dict[str, Any]]


class AgentStatusSummary(BaseModel):
    agent_id: int
    app_name: str
    language: str
    version: str
    status: AgentStatus
    last_seen: datetime
    connection_status: str
    recent_attacks: int
    open_vulnerabilities: int


# Telemetry Schemas
class TelemetryData(BaseModel):
    agent_id: int
    metric_name: str
    metric_value: Optional[float]
    metric_data: Dict[str, Any] = Field(default_factory=dict)


class HeartbeatData(BaseModel):
    agent_id: int
    timestamp: datetime
    status: AgentStatus
    telemetry: List[TelemetryData] = Field(default_factory=list)
    config: Dict[str, Any] = Field(default_factory=dict)


# Webhook Schemas
class WebhookData(BaseModel):
    event_type: str
    timestamp: datetime
    data: Dict[str, Any]
    source: Optional[str] = None


# Validation Schemas
class RuleValidation(BaseModel):
    pattern: str
    test_payloads: List[str] = Field(default_factory=list)
    expected_matches: List[bool] = Field(default_factory=list)

    @validator('test_payloads', 'expected_matches')
    def validate_test_data(cls, v, values):
        if 'test_payloads' in values and 'expected_matches' in values:
            if len(values['test_payloads']) != len(values['expected_matches']):
                raise ValueError("test_payloads and expected_matches must have the same length")
        return v


# Search and Filter Schemas
class AttackFilter(BaseModel):
    agent_id: Optional[int] = None
    vuln_type: Optional[str] = None
    severity: Optional[AttackSeverity] = None
    blocked: Optional[bool] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    source_ip: Optional[str] = None


class VulnerabilityFilter(BaseModel):
    agent_id: Optional[int] = None
    status: Optional[VulnerabilityStatus] = None
    severity: Optional[AttackSeverity] = None
    vuln_type: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None


class AlertFilter(BaseModel):
    agent_id: Optional[int] = None
    status: Optional[AlertStatus] = None
    severity: Optional[AttackSeverity] = None
    alert_type: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


# Export Schemas
class ExportRequest(BaseModel):
    data_type: str = Field(..., description="Type of data to export")
    format: str = Field(..., description="Export format (json, csv, pdf)")
    filters: Optional[Dict[str, Any]] = Field(None, description="Export filters")
    include_details: bool = Field(True, description="Include detailed information")


class ExportResponse(BaseModel):
    export_id: str
    status: str
    download_url: Optional[str] = None
    created_at: datetime
    expires_at: datetime 