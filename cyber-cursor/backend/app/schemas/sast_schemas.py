"""
SAST Schemas for request/response models
"""

from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class VulnerabilitySeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VulnerabilityStatus(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"

class AutoFixStatus(str, Enum):
    AVAILABLE = "available"
    NOT_AVAILABLE = "not_available"
    APPLIED = "applied"
    FAILED = "failed"

# Request Models
class SASTProjectCreate(BaseModel):
    name: str = Field(..., description="Project name")
    repository_url: Optional[str] = Field(None, description="Repository URL")
    language: str = Field(..., description="Primary programming language")
    description: Optional[str] = Field(None, description="Project description")
    scan_config: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Scan configuration")
    rules_config: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Rules configuration")

class SASTScanCreate(BaseModel):
    project_id: str = Field(..., description="Project ID")
    scan_type: str = Field(default="static", description="Type of scan")
    scan_config: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Scan configuration")
    rules_enabled: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Enabled rules")

class VulnerabilityCreate(BaseModel):
    scan_id: str = Field(..., description="Scan ID")
    project_id: str = Field(..., description="Project ID")
    title: str = Field(..., description="Vulnerability title")
    description: str = Field(..., description="Vulnerability description")
    severity: VulnerabilitySeverity = Field(..., description="Vulnerability severity")
    file_path: str = Field(..., description="File path")
    line_number: int = Field(..., description="Line number")
    cwe_id: str = Field(..., description="CWE ID")
    vulnerable_code: str = Field(..., description="Vulnerable code snippet")

# Response Models
class SASTProjectResponse(BaseModel):
    id: str
    name: str
    repository_url: Optional[str]
    language: str
    description: Optional[str]
    scan_config: Optional[Dict[str, Any]]
    rules_config: Optional[Dict[str, Any]]
    total_scans: Optional[int]
    avg_vulnerabilities: Optional[float]
    security_score: Optional[float]
    is_active: Optional[bool]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    last_scan: Optional[datetime]

    class Config:
        from_attributes = True

class SASTScanResponse(BaseModel):
    id: str
    project_id: str
    scan_type: str
    status: ScanStatus
    scan_config: Optional[Dict[str, Any]]
    rules_enabled: Optional[Dict[str, Any]]
    vulnerabilities_found: Optional[int]
    files_scanned: Optional[int]
    lines_of_code: Optional[int]
    scan_duration: Optional[float]
    scan_logs: Optional[Dict[str, Any]]
    scan_summary: Optional[Dict[str, Any]]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class VulnerabilityResponse(BaseModel):
    id: str
    scan_id: str
    project_id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    status: Optional[VulnerabilityStatus]
    file_path: str
    line_number: int
    column_number: Optional[int]
    function_name: Optional[str]
    cwe_id: str
    owasp_category: Optional[str]
    language: Optional[str]
    vulnerable_code: str
    fixed_code: Optional[str]
    context_before: Optional[str]
    context_after: Optional[str]
    auto_fix_available: Optional[bool]
    auto_fix_status: Optional[AutoFixStatus]
    auto_fix_suggestion: Optional[str]
    tags: Optional[Dict[str, Any]]
    vuln_metadata: Optional[Dict[str, Any]]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    fixed_at: Optional[datetime]

    class Config:
        from_attributes = True

class SASTOverviewResponse(BaseModel):
    overview: Dict[str, Any]

class SASTProjectsResponse(BaseModel):
    projects: List[SASTProjectResponse]

class SASTVulnerabilitiesResponse(BaseModel):
    vulnerabilities: List[VulnerabilityResponse]

class SASTProjectDetailResponse(BaseModel):
    project: Dict[str, Any]

class SASTScanHistoryResponse(BaseModel):
    scans: List[SASTScanResponse]

class SASTStatisticsResponse(BaseModel):
    total_projects: int
    total_scans: int
    total_vulnerabilities: int
    vulnerabilities_by_severity: Dict[str, int]
    security_score: float
    recent_scans: List[Dict[str, Any]]
    top_vulnerabilities: List[Dict[str, Any]]

class SASTReportResponse(BaseModel):
    report_id: str
    project_id: str
    scan_id: str
    report_type: str
    report_data: Dict[str, Any]
    generated_at: datetime
    download_url: Optional[str]

# Dashboard Models
class SASTDashboardStats(BaseModel):
    total_projects: int
    active_scans: int
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    security_score: float
    recent_activity: List[Dict[str, Any]]

class SASTProjectSummary(BaseModel):
    id: str
    name: str
    language: str
    last_scan: Optional[datetime]
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    security_score: float
    status: str

class SASTScanSummary(BaseModel):
    id: str
    project_name: str
    scan_type: str
    status: ScanStatus
    vulnerabilities_found: int
    scan_duration: float
    started_at: datetime
    completed_at: Optional[datetime]

# Filter Models
class SASTVulnerabilityFilter(BaseModel):
    severity: Optional[VulnerabilitySeverity]
    status: Optional[VulnerabilityStatus]
    cwe_id: Optional[str]
    file_path: Optional[str]
    language: Optional[str]
    project_id: Optional[str]
    scan_id: Optional[str]

class SASTScanFilter(BaseModel):
    project_id: Optional[str]
    status: Optional[ScanStatus]
    scan_type: Optional[str]
    date_from: Optional[datetime]
    date_to: Optional[datetime]

# Configuration Models
class SASTScanConfiguration(BaseModel):
    include_patterns: List[str] = Field(default_factory=list)
    exclude_patterns: List[str] = Field(default_factory=list)
    max_file_size: int = Field(default=10485760)  # 10MB
    timeout: int = Field(default=3600)  # 1 hour
    parallel_scans: int = Field(default=4)
    enable_auto_fix: bool = Field(default=False)
    custom_rules: List[Dict[str, Any]] = Field(default_factory=list)

class SASTRulesConfiguration(BaseModel):
    enabled_rules: List[str] = Field(default_factory=list)
    rule_severity_overrides: Dict[str, VulnerabilitySeverity] = Field(default_factory=dict)
    custom_patterns: List[Dict[str, Any]] = Field(default_factory=list)
    ignore_patterns: List[str] = Field(default_factory=list) 