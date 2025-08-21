from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from enum import Enum
import uuid

# Enums
class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    OCI = "oci"
    KUBERNETES = "kubernetes"

class ConnectorStatus(str, Enum):
    PENDING = "pending"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    SYNCING = "syncing"

class FindingStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"

class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class PolicyFramework(str, Enum):
    CIS = "cis"
    NIST = "nist"
    PCI_DSS = "pci_dss"
    ISO27001 = "iso27001"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    CUSTOM = "custom"

class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class JobType(str, Enum):
    SYNC = "sync"
    SCAN = "scan"
    POLICY_EVAL = "policy_evaluation"
    REMEDIATION = "remediation"

# Base schemas
class OrganizationBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    settings: Optional[Dict[str, Any]] = Field(default_factory=dict)

class OrganizationCreate(OrganizationBase):
    pass

class OrganizationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None

class OrganizationResponse(OrganizationBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class ProjectBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    settings: Optional[Dict[str, Any]] = Field(default_factory=dict)

class ProjectCreate(ProjectBase):
    org_id: uuid.UUID

class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None

class ProjectResponse(ProjectBase):
    id: uuid.UUID
    org_id: uuid.UUID
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class ConnectorBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: CloudProvider
    config: Dict[str, Any]
    sync_interval: Optional[int] = Field(default=3600, ge=300)  # Min 5 minutes

class ConnectorCreate(ConnectorBase):
    project_id: uuid.UUID

class ConnectorUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    config: Optional[Dict[str, Any]] = None
    sync_interval: Optional[int] = Field(None, ge=300)

class ConnectorResponse(ConnectorBase):
    id: uuid.UUID
    project_id: uuid.UUID
    status: ConnectorStatus
    last_synced: Optional[datetime] = None
    permissions_check: Dict[str, Any] = Field(default_factory=dict)
    error_details: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class AssetBase(BaseModel):
    resource_id: str = Field(..., min_length=1, max_length=255)
    resource_type: str = Field(..., min_length=1, max_length=100)
    name: Optional[str] = Field(None, max_length=255)
    region: Optional[str] = Field(None, max_length=100)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    tags: Optional[Dict[str, Any]] = Field(default_factory=dict)
    relationships: Optional[Dict[str, Any]] = Field(default_factory=dict)

class AssetCreate(AssetBase):
    connector_id: Optional[uuid.UUID] = None
    project_id: uuid.UUID
    cloud: Optional[CloudProvider] = None

class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    metadata: Optional[Dict[str, Any]] = None
    tags: Optional[Dict[str, Any]] = None
    relationships: Optional[Dict[str, Any]] = None

class AssetResponse(AssetBase):
    id: uuid.UUID
    connector_id: Optional[uuid.UUID] = None
    project_id: uuid.UUID
    cloud: Optional[CloudProvider] = None
    first_seen: datetime
    last_seen: datetime
    risk_score: float = 0.0

    class Config:
        from_attributes = True

class PolicyBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    framework: PolicyFramework = PolicyFramework.CUSTOM
    rule: Dict[str, Any]
    severity: FindingSeverity = FindingSeverity.MEDIUM
    category: Optional[str] = Field(None, max_length=100)
    compliance_standards: Optional[List[str]] = Field(default_factory=list)
    remediation_steps: Optional[str] = None
    auto_remediable: bool = False

class PolicyCreate(PolicyBase):
    pass

class PolicyUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    rule: Optional[Dict[str, Any]] = None
    severity: Optional[FindingSeverity] = None
    category: Optional[str] = Field(None, max_length=100)
    compliance_standards: Optional[List[str]] = None
    remediation_steps: Optional[str] = None
    auto_remediable: Optional[bool] = None
    enabled: Optional[bool] = None

class PolicyResponse(PolicyBase):
    id: uuid.UUID
    enabled: bool
    created_by: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class FindingBase(BaseModel):
    severity: FindingSeverity
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = Field(default_factory=dict)
    risk_score: Optional[float] = Field(None, ge=0, le=100)
    owner_id: Optional[uuid.UUID] = None
    comments: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    remediation_notes: Optional[str] = None

class FindingCreate(FindingBase):
    asset_id: uuid.UUID
    policy_id: uuid.UUID

class FindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None
    severity: Optional[FindingSeverity] = None
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    owner_id: Optional[uuid.UUID] = None
    comments: Optional[List[Dict[str, Any]]] = None
    remediation_notes: Optional[str] = None

class FindingResponse(FindingBase):
    id: uuid.UUID
    asset_id: uuid.UUID
    policy_id: uuid.UUID
    status: FindingStatus
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class JobBase(BaseModel):
    type: JobType
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)

class JobCreate(JobBase):
    project_id: uuid.UUID
    connector_id: Optional[uuid.UUID] = None

class JobUpdate(BaseModel):
    status: Optional[JobStatus] = None
    progress: Optional[int] = Field(None, ge=0, le=100)
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

class JobResponse(JobBase):
    id: uuid.UUID
    connector_id: Optional[uuid.UUID] = None
    project_id: uuid.UUID
    status: JobStatus
    progress: int = 0
    result: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True

class RemediationBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    steps: List[Dict[str, Any]]
    auto_remediable: bool = False

class RemediationCreate(RemediationBase):
    finding_id: uuid.UUID

class RemediationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    steps: Optional[List[Dict[str, Any]]] = None
    status: Optional[str] = None

class RemediationResponse(RemediationBase):
    id: uuid.UUID
    finding_id: uuid.UUID
    status: str
    executed_by: Optional[uuid.UUID] = None
    executed_at: Optional[datetime] = None
    result: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    class Config:
        from_attributes = True

class IntegrationBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: str = Field(..., min_length=1, max_length=100)
    config: Dict[str, Any]
    enabled: bool = True

class IntegrationCreate(IntegrationBase):
    project_id: uuid.UUID

class IntegrationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    config: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None

class IntegrationResponse(IntegrationBase):
    id: uuid.UUID
    project_id: uuid.UUID
    last_test: Optional[datetime] = None
    test_status: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class AlertRuleBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    conditions: Dict[str, Any]
    integrations: List[uuid.UUID] = Field(default_factory=list)
    enabled: bool = True

class AlertRuleCreate(AlertRuleBase):
    project_id: uuid.UUID

class AlertRuleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    integrations: Optional[List[uuid.UUID]] = None
    enabled: Optional[bool] = None

class AlertRuleResponse(AlertRuleBase):
    id: uuid.UUID
    project_id: uuid.UUID
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class ComplianceFrameworkBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    version: Optional[str] = Field(None, max_length=50)
    description: Optional[str] = None
    controls: List[Dict[str, Any]]
    policy_mappings: Optional[Dict[str, Any]] = Field(default_factory=dict)

class ComplianceFrameworkCreate(ComplianceFrameworkBase):
    pass

class ComplianceFrameworkUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    version: Optional[str] = Field(None, max_length=50)
    description: Optional[str] = None
    controls: Optional[List[Dict[str, Any]]] = None
    policy_mappings: Optional[Dict[str, Any]] = None

class ComplianceFrameworkResponse(ComplianceFrameworkBase):
    id: uuid.UUID
    created_at: datetime

    class Config:
        from_attributes = True

class ComplianceReportBase(BaseModel):
    framework_id: uuid.UUID
    score: float = Field(0.0, ge=0, le=100)
    total_controls: int = 0
    passed_controls: int = 0
    failed_controls: int = 0
    report_data: Optional[Dict[str, Any]] = Field(default_factory=dict)

class ComplianceReportCreate(ComplianceReportBase):
    project_id: uuid.UUID

class ComplianceReportUpdate(BaseModel):
    score: Optional[float] = Field(None, ge=0, le=100)
    total_controls: Optional[int] = Field(None, ge=0)
    passed_controls: Optional[int] = Field(None, ge=0)
    failed_controls: Optional[int] = Field(None, ge=0)
    report_data: Optional[Dict[str, Any]] = None

class ComplianceReportResponse(ComplianceReportBase):
    id: uuid.UUID
    project_id: uuid.UUID
    generated_at: datetime

    class Config:
        from_attributes = True

# Dashboard and summary schemas
class DashboardSummary(BaseModel):
    total_assets: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    compliance_score: float
    last_sync: Optional[datetime] = None

class RiskHeatmapItem(BaseModel):
    asset_id: uuid.UUID
    asset_name: str
    resource_type: str
    risk_score: float
    findings_count: int
    critical_findings: int

class RiskHeatmapResponse(BaseModel):
    items: List[RiskHeatmapItem]
    total_assets: int
    high_risk_assets: int

class FindingSummary(BaseModel):
    id: uuid.UUID
    title: str
    severity: FindingSeverity
    asset_name: str
    resource_type: str
    created_at: datetime
    status: FindingStatus

class DashboardResponse(BaseModel):
    summary: DashboardSummary
    latest_findings: List[FindingSummary]
    risk_heatmap: RiskHeatmapResponse
    top_misconfigs: List[Dict[str, Any]]

# Bulk operations
class BulkFindingUpdate(BaseModel):
    finding_ids: List[uuid.UUID]
    status: Optional[FindingStatus] = None
    owner_id: Optional[uuid.UUID] = None
    comments: Optional[str] = None

class BulkFindingResponse(BaseModel):
    updated_count: int
    failed_count: int
    failed_ids: List[uuid.UUID]

# Policy evaluation
class PolicyEvaluationRequest(BaseModel):
    asset_id: Optional[uuid.UUID] = None
    policy_id: Optional[uuid.UUID] = None
    dry_run: bool = False

class PolicyEvaluationResponse(BaseModel):
    job_id: uuid.UUID
    status: str
    message: str

# Connector sync
class ConnectorSyncRequest(BaseModel):
    force: bool = False
    regions: Optional[List[str]] = None

class ConnectorSyncResponse(BaseModel):
    job_id: uuid.UUID
    status: str
    message: str

# Search and filtering
class AssetSearchParams(BaseModel):
    cloud: Optional[CloudProvider] = None
    type: Optional[str] = None
    region: Optional[str] = None
    tags: Optional[Dict[str, str]] = None
    risk_score_min: Optional[float] = None
    risk_score_max: Optional[float] = None
    page: int = Field(1, ge=1)
    per_page: int = Field(50, ge=1, le=100)

class FindingSearchParams(BaseModel):
    severity: Optional[FindingSeverity] = None
    status: Optional[FindingStatus] = None
    asset_id: Optional[uuid.UUID] = None
    policy_id: Optional[uuid.UUID] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    page: int = Field(1, ge=1)
    per_page: int = Field(50, ge=1, le=100)

# Pagination
class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    per_page: int
    pages: int

# Error responses
class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None

class AssetRelationshipBase(BaseModel):
    parent_asset_id: uuid.UUID
    child_asset_id: uuid.UUID
    relationship_type: str = Field(..., min_length=1, max_length=100)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

class AssetRelationshipCreate(AssetRelationshipBase):
    pass

class AssetRelationshipResponse(AssetRelationshipBase):
    id: uuid.UUID
    created_at: datetime

    class Config:
        from_attributes = True

class PolicyEvaluationResultBase(BaseModel):
    asset_id: uuid.UUID
    policy_id: uuid.UUID
    result: bool
    evidence: Optional[Dict[str, Any]] = Field(default_factory=dict)
    execution_time_ms: Optional[int] = None

class PolicyEvaluationResultCreate(PolicyEvaluationResultBase):
    pass

class PolicyEvaluationResultResponse(PolicyEvaluationResultBase):
    id: uuid.UUID
    evaluation_date: datetime

    class Config:
        from_attributes = True

class ComplianceControlBase(BaseModel):
    framework_id: uuid.UUID
    control_id: str = Field(..., min_length=1, max_length=100)
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    category: Optional[str] = Field(None, max_length=100)
    requirements: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    policy_mappings: Optional[List[uuid.UUID]] = Field(default_factory=list)

class ComplianceControlCreate(ComplianceControlBase):
    pass

class ComplianceControlResponse(ComplianceControlBase):
    id: uuid.UUID
    created_at: datetime

    class Config:
        from_attributes = True

class ComplianceMappingBase(BaseModel):
    control_id: uuid.UUID
    policy_id: uuid.UUID
    mapping_type: str = Field(default="direct", max_length=50)
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    notes: Optional[str] = None

class ComplianceMappingCreate(ComplianceMappingBase):
    pass

class ComplianceMappingResponse(ComplianceMappingBase):
    id: uuid.UUID
    created_at: datetime

    class Config:
        from_attributes = True

class IntegrationWebhookBase(BaseModel):
    integration_id: uuid.UUID
    webhook_url: str = Field(..., min_length=1, max_length=500)
    secret_key: Optional[str] = Field(None, max_length=255)
    events: Optional[List[str]] = Field(default_factory=list)
    enabled: bool = True

class IntegrationWebhookCreate(IntegrationWebhookBase):
    pass

class IntegrationWebhookResponse(IntegrationWebhookBase):
    id: uuid.UUID
    last_delivery: Optional[datetime] = None
    delivery_count: int
    failure_count: int
    created_at: datetime

    class Config:
        from_attributes = True

class ScanTemplateBase(BaseModel):
    project_id: uuid.UUID
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    scan_config: Dict[str, Any]
    schedule: Optional[str] = Field(None, max_length=100)
    enabled: bool = True

class ScanTemplateCreate(ScanTemplateBase):
    pass

class ScanTemplateUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    scan_config: Optional[Dict[str, Any]] = None
    schedule: Optional[str] = Field(None, max_length=100)
    enabled: Optional[bool] = None

class ScanTemplateResponse(ScanTemplateBase):
    id: uuid.UUID
    created_by: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class RemediationPlaybookBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    category: Optional[str] = Field(None, max_length=100)
    steps: List[Dict[str, Any]]
    prerequisites: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    estimated_time: Optional[int] = None
    risk_level: Optional[str] = Field(None, max_length=50)
    auto_approval: bool = False

class RemediationPlaybookCreate(RemediationPlaybookBase):
    pass

class RemediationPlaybookUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    category: Optional[str] = Field(None, max_length=100)
    steps: Optional[List[Dict[str, Any]]] = None
    prerequisites: Optional[List[Dict[str, Any]]] = None
    estimated_time: Optional[int] = None
    risk_level: Optional[str] = Field(None, max_length=50)
    auto_approval: Optional[bool] = None

class RemediationPlaybookResponse(RemediationPlaybookBase):
    id: uuid.UUID
    created_by: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class RemediationExecutionBase(BaseModel):
    playbook_id: uuid.UUID
    finding_id: uuid.UUID
    status: str = Field(default="pending", max_length=50)
    execution_log: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    result: Optional[Dict[str, Any]] = Field(default_factory=dict)
    error_message: Optional[str] = None

class RemediationExecutionCreate(RemediationExecutionBase):
    pass

class RemediationExecutionResponse(RemediationExecutionBase):
    id: uuid.UUID
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    executed_by: Optional[uuid.UUID] = None
    created_at: datetime

    class Config:
        from_attributes = True

class RiskAssessmentBase(BaseModel):
    asset_id: uuid.UUID
    overall_score: float = Field(..., ge=0.0, le=100.0)
    factors: Optional[Dict[str, Any]] = Field(default_factory=dict)
    recommendations: Optional[List[Dict[str, Any]]] = Field(default_factory=list)

class RiskAssessmentCreate(RiskAssessmentBase):
    pass

class RiskAssessmentResponse(RiskAssessmentBase):
    id: uuid.UUID
    assessment_date: datetime
    assessed_by: Optional[uuid.UUID] = None

    class Config:
        from_attributes = True

# Enhanced response models
class AssetDetailResponse(AssetResponse):
    relationships: Optional[List[AssetRelationshipResponse]] = []
    findings: Optional[List[FindingResponse]] = []
    risk_assessments: Optional[List[RiskAssessmentResponse]] = []

class PolicyDetailResponse(PolicyResponse):
    evaluation_results: Optional[List[PolicyEvaluationResultResponse]] = []
    compliance_mappings: Optional[List[ComplianceMappingResponse]] = []

class ComplianceFrameworkDetailResponse(ComplianceFrameworkResponse):
    controls: Optional[List[ComplianceControlResponse]] = []
    policy_mappings: Optional[List[ComplianceMappingResponse]] = []
