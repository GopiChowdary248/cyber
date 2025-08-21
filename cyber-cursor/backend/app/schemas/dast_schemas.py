from pydantic import BaseModel, Field, validator, HttpUrl
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from uuid import UUID
from enum import Enum

# ============================================================================
# ENUMS
# ============================================================================

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"

class IssueSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IssueStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"

class AttackType(str, Enum):
    SNIPER = "sniper"
    BATTERING_RAM = "battering_ram"
    PITCHFORK = "pitchfork"
    CLUSTER_BOMB = "cluster_bomb"

class MatchType(str, Enum):
    REGEX = "regex"
    STRING = "string"
    WILDCARD = "wildcard"

class ApplyTo(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"
    BOTH = "both"

class UserRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"

class NotificationSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

# ============================================================================
# BASE SCHEMAS
# ============================================================================

class BaseSchema(BaseModel):
    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v)
        }

class TimestampSchema(BaseSchema):
    created_at: datetime
    updated_at: Optional[datetime] = None

# ============================================================================
# PROJECT SCHEMAS
# ============================================================================

class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    target_urls: List[str] = Field(..., min_items=1)
    scope_config: Optional[Dict[str, Any]] = {}

class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    target_urls: Optional[List[str]] = None
    scope_config: Optional[Dict[str, Any]] = None
    status: Optional[str] = None

class ProjectResponse(BaseSchema):
    id: UUID
    name: str
    description: Optional[str]
    target_urls: List[str]
    scope_config: Dict[str, Any]
    status: str
    created_by: UUID
    created_at: datetime
    updated_at: Optional[datetime]

class ProjectStatus(BaseSchema):
    project_id: UUID
    total_scans: int
    active_scans: int
    completed_scans: int
    total_issues: int
    issues_by_severity: Dict[str, int]
    last_scan_date: Optional[datetime]
    proxy_status: str
    crawler_status: str

# ============================================================================
# SCAN PROFILE SCHEMAS
# ============================================================================

class ProfileCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    modules: List[str] = Field(..., min_items=1)
    settings: Dict[str, Any] = Field(..., min_items=1)
    is_default: bool = False

class ProfileUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    modules: Optional[List[str]] = None
    settings: Optional[Dict[str, Any]] = None
    is_default: Optional[bool] = None

class ProfileResponse(BaseSchema):
    id: UUID
    project_id: UUID
    name: str
    description: Optional[str]
    modules: List[str]
    settings: Dict[str, Any]
    is_default: bool
    created_by: UUID
    created_at: datetime
    updated_at: Optional[datetime]

# ============================================================================
# SCAN SCHEMAS
# ============================================================================

class ScanCreate(BaseModel):
    profile_id: UUID
    name: str = Field(..., min_length=1, max_length=255)
    target_urls: List[str] = Field(..., min_items=1)
    scan_config: Optional[Dict[str, Any]] = {}

class ScanUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    target_urls: Optional[List[str]] = None
    scan_config: Optional[Dict[str, Any]] = None
    status: Optional[ScanStatus] = None
    progress: Optional[float] = Field(None, ge=0.0, le=100.0)

class ScanResponse(BaseSchema):
    id: UUID
    project_id: UUID
    profile_id: UUID
    name: str
    target_urls: List[str]
    status: ScanStatus
    progress: float
    total_requests: int
    completed_requests: int
    issues_found: int
    scan_config: Dict[str, Any]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_by: UUID
    created_at: datetime
    updated_at: Optional[datetime]

# ============================================================================
# ISSUE SCHEMAS
# ============================================================================

class IssueCreate(BaseModel):
    scan_id: UUID
    type: str = Field(..., min_length=1, max_length=100)
    severity: IssueSeverity
    title: str = Field(..., min_length=1, max_length=500)
    description: str
    url: str = Field(..., min_length=1, max_length=2000)
    evidence: Optional[str] = None
    confidence: float = Field(..., ge=0.0, le=100.0)
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    tags: Optional[List[str]] = []

class IssueUpdate(BaseModel):
    type: Optional[str] = Field(None, min_length=1, max_length=100)
    severity: Optional[IssueSeverity] = None
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    url: Optional[str] = Field(None, min_length=1, max_length=2000)
    evidence: Optional[str] = None
    confidence: Optional[float] = Field(None, ge=0.0, le=100.0)
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    status: Optional[IssueStatus] = None
    tags: Optional[List[str]] = None

class IssueResponse(BaseSchema):
    id: UUID
    scan_id: UUID
    type: str
    severity: IssueSeverity
    title: str
    description: str
    url: str
    evidence: Optional[str]
    confidence: float
    cwe_id: Optional[str]
    cvss_score: Optional[float]
    status: IssueStatus
    tags: List[str]
    discovered_at: datetime
    created_at: datetime
    updated_at: Optional[datetime]

# ============================================================================
# HTTP HISTORY SCHEMAS
# ============================================================================

class HttpHistoryEntry(BaseModel):
    id: UUID
    method: str
    url: str
    host: str
    port: int
    protocol: str
    status_code: Optional[int]
    content_type: Optional[str]
    request_size: int
    response_size: int
    duration: int
    timestamp: datetime
    tags: List[str]
    highlighted: bool

class HttpHistoryResponse(BaseModel):
    entries: List[HttpHistoryEntry]
    total: int
    page: int
    page_size: int
    total_pages: int

class HttpEntryDetail(BaseSchema):
    id: UUID
    project_id: UUID
    method: str
    url: str
    host: str
    port: int
    protocol: str
    request_headers: Dict[str, Any]
    request_body: Optional[str]
    request_params: Dict[str, Any]
    request_size: int
    response_headers: Optional[Dict[str, Any]]
    response_body: Optional[str]
    response_size: int
    status_code: Optional[int]
    content_type: Optional[str]
    duration: int
    timestamp: datetime
    tags: List[str]
    notes: Optional[str]
    highlighted: bool

# ============================================================================
# CRAWLER SCHEMAS
# ============================================================================

class CrawlConfig(BaseModel):
    start_urls: List[str] = Field(..., min_items=1)
    max_depth: int = Field(3, ge=1, le=10)
    max_pages: int = Field(1000, ge=1, le=100000)
    follow_redirects: bool = True
    verify_ssl: bool = True
    user_agent: Optional[str] = None
    delay: float = Field(0.0, ge=0.0, le=10.0)
    include_patterns: Optional[List[str]] = []
    exclude_patterns: Optional[List[str]] = []
    custom_headers: Optional[Dict[str, str]] = {}

class CrawlResult(BaseSchema):
    id: UUID
    project_id: UUID
    url: str
    method: str
    status_code: Optional[int]
    content_type: Optional[str]
    title: Optional[str]
    depth: int
    parent_url: Optional[str]
    discovered_at: datetime
    last_accessed: Optional[datetime]
    in_scope: bool
    tags: List[str]
    notes: Optional[str]

class CrawlResultResponse(BaseModel):
    results: List[CrawlResult]
    total: int
    page: int
    page_size: int
    total_pages: int

class CrawlerStatus(BaseModel):
    status: str  # idle, running, paused, completed, failed
    progress: float
    total_urls: int
    discovered_urls: int
    in_scope_urls: int
    started_at: Optional[datetime]
    estimated_completion: Optional[datetime]
    current_url: Optional[str]
    errors: List[str]

# ============================================================================
# RULES SCHEMAS
# ============================================================================

class RuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    match_pattern: str = Field(..., min_length=1, max_length=1000)
    replace_pattern: str = Field(..., min_length=1, max_length=1000)
    match_type: MatchType = MatchType.REGEX
    apply_to: ApplyTo = ApplyTo.BOTH
    enabled: bool = True
    priority: int = Field(0, ge=0, le=100)

class RuleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    match_pattern: Optional[str] = Field(None, min_length=1, max_length=1000)
    replace_pattern: Optional[str] = Field(None, min_length=1, max_length=1000)
    match_type: Optional[MatchType] = None
    apply_to: Optional[ApplyTo] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = Field(None, ge=0, le=100)

class RuleResponse(BaseSchema):
    id: UUID
    project_id: UUID
    name: str
    description: Optional[str]
    match_pattern: str
    replace_pattern: str
    match_type: MatchType
    apply_to: ApplyTo
    enabled: bool
    priority: int
    created_by: UUID
    created_at: datetime
    updated_at: Optional[datetime]

# ============================================================================
# INTRUDER SCHEMAS
# ============================================================================

class PayloadSet(BaseModel):
    name: str
    payloads: List[str]
    position: str
    type: str

class AttackPosition(BaseModel):
    parameter: str
    start: int
    end: int
    type: str  # parameter, header, body

class IntruderAttackCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    target_url: str = Field(..., min_length=1, max_length=2000)
    attack_type: AttackType
    payload_sets: List[PayloadSet] = Field(..., min_items=1)
    positions: List[AttackPosition] = Field(..., min_items=1)
    settings: Optional[Dict[str, Any]] = {}

class IntruderAttackUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    target_url: Optional[str] = Field(None, min_length=1, max_length=2000)
    attack_type: Optional[AttackType] = None
    payload_sets: Optional[List[PayloadSet]] = None
    positions: Optional[List[AttackPosition]] = None
    settings: Optional[Dict[str, Any]] = None
    status: Optional[str] = None

class IntruderAttackResponse(BaseSchema):
    id: UUID
    project_id: UUID
    name: str
    target_url: str
    attack_type: AttackType
    payload_sets: List[PayloadSet]
    positions: List[AttackPosition]
    status: str
    progress: float
    total_requests: int
    completed_requests: int
    successful_requests: int
    failed_requests: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_by: UUID
    created_at: datetime
    updated_at: Optional[datetime]

class IntruderResult(BaseSchema):
    id: UUID
    attack_id: UUID
    payload: str
    status_code: Optional[int]
    response_size: int
    response_time: int
    response_headers: Optional[Dict[str, Any]]
    response_body: Optional[str]
    content_type: Optional[str]
    error: Optional[str]
    timestamp: datetime
    highlighted: bool
    notes: Optional[str]

# ============================================================================
# REPEATER SCHEMAS
# ============================================================================

class RepeaterRequestCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    method: str = Field(..., min_length=1, max_length=10)
    url: str = Field(..., min_length=1, max_length=2000)
    headers: Dict[str, str] = Field(..., min_items=1)
    body: Optional[str] = None
    params: Optional[Dict[str, Any]] = {}

class RepeaterRequestUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    method: Optional[str] = Field(None, min_length=1, max_length=10)
    url: Optional[str] = Field(None, min_length=1, max_length=2000)
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None
    params: Optional[Dict[str, Any]] = None

class RepeaterRequestResponse(BaseSchema):
    id: UUID
    project_id: UUID
    name: str
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    params: Dict[str, Any]
    created_by: UUID
    created_at: datetime
    updated_at: Optional[datetime]

class RepeaterResponse(BaseSchema):
    id: UUID
    request_id: UUID
    status_code: int
    headers: Dict[str, Any]
    body: Optional[str]
    content_type: Optional[str]
    size: int
    duration: int
    timestamp: datetime
    error: Optional[str]

# ============================================================================
# PROXY SCHEMAS
# ============================================================================

class ProxyConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = Field(8080, ge=1024, le=65535)
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    intercept_requests: bool = True
    intercept_responses: bool = False
    auto_save: bool = True
    max_history: int = Field(10000, ge=100, le=100000)

class ProxyStatus(BaseModel):
    status: str  # stopped, running, error
    host: str
    port: int
    ssl_enabled: bool
    intercept_requests: bool
    intercept_responses: bool
    total_requests: int
    total_responses: int
    started_at: Optional[datetime]
    uptime: Optional[int]  # seconds
    error: Optional[str]

# ============================================================================
# SITE MAP SCHEMAS
# ============================================================================

class SiteMapNode(BaseModel):
    url: str
    method: str
    status_code: Optional[int]
    content_type: Optional[str]
    title: Optional[str]
    depth: int
    in_scope: bool
    children: List['SiteMapNode'] = []
    tags: List[str] = []
    notes: Optional[str] = None

class SiteMapResponse(BaseModel):
    nodes: List[SiteMapNode]
    total_nodes: int
    in_scope_nodes: int
    out_of_scope_nodes: int
    view_mode: str

class ScopeConfig(BaseModel):
    include_patterns: List[str] = []
    exclude_patterns: List[str] = []
    allowed_ports: List[int] = [80, 443, 8080, 8443]
    allowed_protocols: List[str] = ["http", "https"]
    file_extensions: List[str] = []
    max_depth: int = Field(10, ge=1, le=50)
    follow_subdomains: bool = True
    follow_external_links: bool = False

# ============================================================================
# EXPORT & REPORTING SCHEMAS
# ============================================================================

class ExportConfig(BaseModel):
    format: str = Field(..., regex="^(json|csv|xml|pdf|html|docx)$")
    include_issues: bool = True
    include_traffic: bool = False
    include_crawl_results: bool = False
    filters: Optional[Dict[str, Any]] = {}
    date_range: Optional[Dict[str, datetime]] = None

class ExportResponse(BaseModel):
    download_url: str
    filename: str
    size: int
    expires_at: datetime

# ============================================================================
# NOTIFICATION SCHEMAS
# ============================================================================

class NotificationCreate(BaseModel):
    project_id: UUID
    user_id: UUID
    type: str
    title: str = Field(..., min_length=1, max_length=255)
    message: str
    severity: NotificationSeverity = NotificationSeverity.INFO
    action_url: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = {}

class NotificationResponse(BaseSchema):
    id: UUID
    project_id: UUID
    user_id: UUID
    type: str
    title: str
    message: str
    severity: NotificationSeverity
    read: bool
    action_url: Optional[str]
    metadata: Dict[str, Any]
    created_at: datetime
    read_at: Optional[datetime]

# ============================================================================
# AUDIT & COMPLIANCE SCHEMAS
# ============================================================================

class AuditLogEntry(BaseSchema):
    id: UUID
    project_id: UUID
    user_id: UUID
    action: str
    resource_type: str
    resource_id: Optional[UUID]
    details: Dict[str, Any]
    ip_address: Optional[str]
    user_agent: Optional[str]
    timestamp: datetime

class AuditLogResponse(BaseModel):
    entries: List[AuditLogEntry]
    total: int
    page: int
    page_size: int
    total_pages: int

# ============================================================================
# USER PERMISSIONS SCHEMAS
# ============================================================================

class UserPermissionCreate(BaseModel):
    user_id: UUID
    project_id: UUID
    role: UserRole
    permissions: Optional[Dict[str, Any]] = {}
    expires_at: Optional[datetime] = None

class UserPermissionUpdate(BaseModel):
    role: Optional[UserRole] = None
    permissions: Optional[Dict[str, Any]] = None
    expires_at: Optional[datetime] = None

class UserPermissionResponse(BaseSchema):
    id: UUID
    user_id: UUID
    project_id: UUID
    role: UserRole
    permissions: Dict[str, Any]
    granted_by: UUID
    granted_at: datetime
    expires_at: Optional[datetime]

# ============================================================================
# WEBSOCKET SCHEMAS
# ============================================================================

class WebSocketMessage(BaseModel):
    type: str  # scan_update, traffic_update, notification, etc.
    data: Dict[str, Any]
    timestamp: datetime
    project_id: Optional[UUID] = None

class WebSocketConnection(BaseModel):
    project_id: UUID
    user_id: UUID
    connection_id: str
    connected_at: datetime

# ============================================================================
# PAGINATION & FILTERING SCHEMAS
# ============================================================================

class PaginationParams(BaseModel):
    page: int = Field(1, ge=1)
    page_size: int = Field(100, ge=1, le=1000)

class FilterParams(BaseModel):
    search: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    type: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    tags: Optional[List[str]] = None
    user_id: Optional[UUID] = None

class SortParams(BaseModel):
    field: str = "created_at"
    direction: str = "desc"  # asc, desc

    @validator('direction')
    def validate_direction(cls, v):
        if v not in ['asc', 'desc']:
            raise ValueError('direction must be either "asc" or "desc"')
        return v
