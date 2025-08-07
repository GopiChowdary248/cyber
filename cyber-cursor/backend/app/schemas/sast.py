from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum

# ============================================================================
# ENUMS
# ============================================================================

class IssueSeverity(str, Enum):
    BLOCKER = "BLOCKER"
    CRITICAL = "CRITICAL"
    MAJOR = "MAJOR"
    MINOR = "MINOR"
    INFO = "INFO"

class IssueType(str, Enum):
    BUG = "BUG"
    VULNERABILITY = "VULNERABILITY"
    CODE_SMELL = "CODE_SMELL"
    SECURITY_HOTSPOT = "SECURITY_HOTSPOT"

class IssueStatus(str, Enum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    REOPENED = "REOPENED"

class IssueResolution(str, Enum):
    UNRESOLVED = "UNRESOLVED"
    FIXED = "FIXED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    WON_FIX = "WON_FIX"
    REMOVED = "REMOVED"

class QualityGateStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARN = "WARN"

class Rating(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"

class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

# ============================================================================
# PROJECT SCHEMAS
# ============================================================================

class SASTProjectBase(BaseModel):
    name: str = Field(..., description="Project name")
    key: str = Field(..., description="Unique project key")
    language: str = Field(..., description="Primary programming language")
    repository_url: Optional[str] = Field(None, description="Repository URL")
    branch: Optional[str] = Field("main", description="Default branch")

class SASTProjectCreate(BaseModel):
    name: str
    key: str
    language: str
    repository_url: Optional[str] = None
    branch: Optional[str] = "main"

class SASTProjectDuplicate(BaseModel):
    name: str
    key: str

class SASTProjectUpdate(BaseModel):
    name: Optional[str] = None
    key: Optional[str] = None
    language: Optional[str] = None
    repository_url: Optional[str] = None
    branch: Optional[str] = None

class SASTProjectDelete(BaseModel):
    confirm: bool = True

class SASTProjectResponse(BaseModel):
    id: int
    name: str
    key: str
    language: str
    repository_url: Optional[str] = None
    branch: str
    quality_gate: Optional[QualityGateStatus] = None
    maintainability_rating: Optional[Rating] = None
    security_rating: Optional[Rating] = None
    reliability_rating: Optional[Rating] = None
    vulnerability_count: int = 0
    bug_count: int = 0
    code_smell_count: int = 0
    security_hotspot_count: int = 0
    lines_of_code: int = 0
    coverage: float = 0.0
    technical_debt: int = 0
    created_by: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_analysis: Optional[datetime] = None
    last_scan: Optional[Dict[str, Any]] = None
    issues: Optional[Dict[str, int]] = None

    class Config:
        from_attributes = True

class SASTProjectListResponse(BaseModel):
    projects: List[SASTProjectResponse]
    total: int
    page: int
    pages: int

    class Config:
        from_attributes = True

# ============================================================================
# ISSUE SCHEMAS
# ============================================================================

class SASTIssueBase(BaseModel):
    rule_id: str = Field(..., description="Rule identifier")
    rule_name: str = Field(..., description="Rule name")
    rule_category: Optional[str] = Field(None, description="Rule category")
    message: str = Field(..., description="Issue message")
    description: Optional[str] = Field(None, description="Detailed description")
    file_path: str = Field(..., description="File path")
    line_number: int = Field(..., description="Line number")
    start_line: Optional[int] = Field(None, description="Start line")
    end_line: Optional[int] = Field(None, description="End line")
    severity: IssueSeverity
    type: IssueType
    status: IssueStatus = IssueStatus.OPEN
    resolution: IssueResolution = IssueResolution.UNRESOLVED
    assignee: Optional[str] = Field(None, description="Assigned user")
    author: Optional[str] = Field(None, description="Issue author")
    effort: int = Field(0, description="Effort to fix in minutes")
    debt: int = Field(0, description="Technical debt in minutes")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    cvss_score: Optional[float] = Field(None, description="CVSS score")
    owasp_category: Optional[str] = Field(None, description="OWASP category")
    tags: Optional[List[str]] = Field(None, description="Issue tags")

class SASTIssueCreate(SASTIssueBase):
    project_id: int

class SASTIssueUpdate(BaseModel):
    status: Optional[IssueStatus] = None
    resolution: Optional[IssueResolution] = None
    assignee: Optional[str] = None
    effort: Optional[int] = None
    debt: Optional[int] = None
    tags: Optional[List[str]] = None

class SASTIssueResponse(SASTIssueBase):
    id: int
    project_id: int
    project_name: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class SASTIssueList(BaseModel):
    issues: List[SASTIssueResponse]
    total: int
    page: int
    size: int

class SASTBulkActionRequest(BaseModel):
    issue_ids: List[int] = Field(..., description="List of issue IDs")
    action: str = Field(..., description="Action to perform")
    assignee: Optional[str] = Field(None, description="Assignee for assign action")
    resolution: Optional[str] = Field(None, description="Resolution for resolve action")

class SASTBulkActionResponse(BaseModel):
    message: str
    updated_count: int

# ============================================================================
# SCAN SCHEMAS
# ============================================================================

class SASTScanBase(BaseModel):
    scan_type: str = Field(..., description="Type of scan")
    branch: str = Field(..., description="Branch to scan")

class SASTScanCreate(SASTScanBase):
    project_id: int

class SASTScanResponse(SASTScanBase):
    id: int
    project_id: int
    project_name: Optional[str] = None
    status: ScanStatus
    progress: float
    total_files: int
    scanned_files: int
    issues_found: int
    vulnerabilities_found: int
    bugs_found: int
    code_smells_found: int
    security_hotspots_found: int
    started_by: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration: Optional[int] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True

class SASTScanList(BaseModel):
    scans: List[SASTScanResponse]
    total: int
    page: int
    size: int

# ============================================================================
# RULE SCHEMAS
# ============================================================================

class SASTRuleBase(BaseModel):
    rule_id: str = Field(..., description="Unique rule identifier")
    name: str = Field(..., description="Rule name")
    description: Optional[str] = Field(None, description="Rule description")
    category: str = Field(..., description="Rule category")
    subcategory: Optional[str] = Field(None, description="Rule subcategory")
    severity: IssueSeverity
    type: IssueType
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    owasp_category: Optional[str] = Field(None, description="OWASP category")
    tags: Optional[List[str]] = Field(None, description="Rule tags")
    enabled: bool = True
    effort: int = Field(0, description="Default effort in minutes")
    languages: Optional[List[str]] = Field(None, description="Supported languages")

class SASTRuleCreate(SASTRuleBase):
    pass

class SASTRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    subcategory: Optional[str] = None
    severity: Optional[IssueSeverity] = None
    type: Optional[IssueType] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    tags: Optional[List[str]] = None
    enabled: Optional[bool] = None
    effort: Optional[int] = None
    languages: Optional[List[str]] = None

class SASTRuleResponse(SASTRuleBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class SASTRuleList(BaseModel):
    rules: List[SASTRuleResponse]
    total: int
    page: int
    size: int

# ============================================================================
# QUALITY GATE SCHEMAS
# ============================================================================

class SASTQualityGateCondition(BaseModel):
    status: str = Field(..., description="Condition status (OK, ERROR, WARN)")
    value: int = Field(..., description="Current value")
    threshold: int = Field(..., description="Threshold value")

class SASTQualityGate(BaseModel):
    project_id: int
    status: QualityGateStatus
    conditions: Dict[str, SASTQualityGateCondition]

class SASTQualityGateUpdate(BaseModel):
    max_blocker_issues: Optional[int] = None
    max_critical_issues: Optional[int] = None
    max_major_issues: Optional[int] = None
    max_debt_ratio: Optional[float] = None
    min_maintainability_rating: Optional[Rating] = None
    min_security_rating: Optional[Rating] = None
    min_reliability_rating: Optional[Rating] = None

# ============================================================================
# DASHBOARD SCHEMAS
# ============================================================================

class SASTSeverityCounts(BaseModel):
    blocker: int = 0
    critical: int = 0
    major: int = 0
    minor: int = 0
    info: int = 0

class SASTTypeCounts(BaseModel):
    vulnerability: int = 0
    bug: int = 0
    code_smell: int = 0
    security_hotspot: int = 0

class SASTQualityMetrics(BaseModel):
    blocker_critical_issues: int = 0
    security_rating: str = "A"

class SASTDashboardStats(BaseModel):
    total_projects: int
    total_issues: int
    severity_counts: SASTSeverityCounts
    type_counts: SASTTypeCounts
    recent_scans: List[SASTScanResponse]
    quality_metrics: SASTQualityMetrics

# ============================================================================
# SEARCH AND FILTER SCHEMAS
# ============================================================================

class SASTIssueFilter(BaseModel):
    search: Optional[str] = None
    project_id: Optional[int] = None
    severity: Optional[IssueSeverity] = None
    type: Optional[IssueType] = None
    status: Optional[IssueStatus] = None
    resolution: Optional[IssueResolution] = None
    assignee: Optional[str] = None
    author: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    tags: Optional[List[str]] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None

class SASTIssueSort(BaseModel):
    field: str = Field("severity", description="Sort field")
    order: str = Field("desc", description="Sort order (asc/desc)")

class SASTIssueSearchRequest(BaseModel):
    filter: Optional[SASTIssueFilter] = None
    sort: Optional[SASTIssueSort] = None
    page: int = Field(1, ge=1)
    size: int = Field(50, ge=1, le=1000)

# ============================================================================
# REPORT SCHEMAS
# ============================================================================

class SASTReportFormat(str, Enum):
    JSON = "json"
    PDF = "pdf"
    HTML = "html"
    CSV = "csv"

class SASTReportType(str, Enum):
    SUMMARY = "summary"
    DETAILED = "detailed"
    EXECUTIVE = "executive"
    COMPLIANCE = "compliance"

class SASTReportRequest(BaseModel):
    project_id: int
    report_type: SASTReportType
    format: SASTReportFormat
    include_resolved: bool = False
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None

class SASTReportResponse(BaseModel):
    id: int
    project_id: int
    report_type: SASTReportType
    format: SASTReportFormat
    download_url: Optional[str] = None
    generated_at: datetime
    expires_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# ============================================================================
# NOTIFICATION SCHEMAS
# ============================================================================

class SASTNotificationType(str, Enum):
    NEW_ISSUE = "new_issue"
    ISSUE_RESOLVED = "issue_resolved"
    SCAN_COMPLETED = "scan_completed"
    QUALITY_GATE_FAILED = "quality_gate_failed"

class SASTNotification(BaseModel):
    id: int
    type: SASTNotificationType
    project_id: int
    project_name: str
    message: str
    created_at: datetime
    read: bool = False

    class Config:
        from_attributes = True

class SASTNotificationList(BaseModel):
    notifications: List[SASTNotification]
    total: int
    unread_count: int 