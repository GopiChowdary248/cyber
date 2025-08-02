"""
SAST (Static Application Security Testing) Pydantic Schemas
Defines request and response models for SAST API endpoints
"""

from pydantic import BaseModel, Field, validator
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum

class SeverityLevel(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanStatus(str, Enum):
    """Scan status values"""
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class VulnerabilityStatus(str, Enum):
    """Vulnerability status values"""
    OPEN = "open"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"
    IN_PROGRESS = "in_progress"

class ScanType(str, Enum):
    """Scan type values"""
    FULL = "full"
    QUICK = "quick"
    INCREMENTAL = "incremental"

class ReportType(str, Enum):
    """Report type values"""
    PDF = "pdf"
    CSV = "csv"
    JSON = "json"
    HTML = "html"

# Project Schemas
class ProjectCreate(BaseModel):
    """Schema for creating a new project"""
    name: str = Field(..., min_length=1, max_length=255, description="Project name")
    description: Optional[str] = Field(None, max_length=1000, description="Project description")
    repo_url: Optional[str] = Field(None, description="Git repository URL")
    language: Optional[str] = Field(None, description="Primary programming language")
    framework: Optional[str] = Field(None, description="Framework used")
    
    @validator('repo_url')
    def validate_repo_url(cls, v):
        if v and not (v.startswith('http') or v.startswith('git@')):
            raise ValueError('Repository URL must be a valid HTTP or SSH URL')
        return v

class ProjectUpdate(BaseModel):
    """Schema for updating a project"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    repo_url: Optional[str] = Field(None)
    language: Optional[str] = Field(None)
    framework: Optional[str] = Field(None)
    
    @validator('repo_url')
    def validate_repo_url(cls, v):
        if v and not (v.startswith('http') or v.startswith('git@')):
            raise ValueError('Repository URL must be a valid HTTP or SSH URL')
        return v

class ProjectResponse(BaseModel):
    """Schema for project response"""
    id: int
    name: str
    description: Optional[str]
    repo_url: Optional[str]
    language: Optional[str]
    framework: Optional[str]
    created_at: datetime
    updated_at: datetime
    created_by: Optional[int]
    
    class Config:
        from_attributes = True

# Scan Schemas
class ScanCreate(BaseModel):
    """Schema for creating a new scan"""
    project_id: int = Field(..., description="Project ID to scan")
    scan_type: ScanType = Field(ScanType.FULL, description="Type of scan to perform")
    scan_config: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Scan configuration")
    tools_enabled: Optional[List[str]] = Field(None, description="List of tools to enable")
    severity_threshold: Optional[SeverityLevel] = Field(None, description="Minimum severity to report")
    
    @validator('tools_enabled')
    def validate_tools(cls, v):
        if v:
            valid_tools = ['bandit', 'pylint', 'semgrep', 'eslint', 'pylint']
            for tool in v:
                if tool not in valid_tools:
                    raise ValueError(f'Invalid tool: {tool}. Must be one of: {valid_tools}')
        return v

class ScanResponse(BaseModel):
    """Schema for scan response"""
    id: int
    project_id: int
    triggered_by: str
    start_time: datetime
    end_time: Optional[datetime]
    status: ScanStatus
    scan_type: ScanType
    scan_config: Dict[str, Any]
    total_files: Optional[int]
    scanned_files: Optional[int]
    vulnerabilities_found: Optional[int]
    created_at: datetime
    
    class Config:
        from_attributes = True

class ScanProgress(BaseModel):
    """Schema for scan progress"""
    scan_id: int
    status: ScanStatus
    start_time: datetime
    end_time: Optional[datetime]
    total_files: int
    scanned_files: int
    vulnerabilities_found: int
    progress_percentage: float

# Vulnerability Schemas
class VulnerabilityResponse(BaseModel):
    """Schema for vulnerability response"""
    id: int
    scan_id: int
    file_path: str
    line_no: Optional[int]
    column_no: Optional[int]
    vulnerability: str
    severity: SeverityLevel
    recommendation: Optional[str]
    tool_name: str
    cwe_id: Optional[str]
    confidence: str
    status: VulnerabilityStatus
    detected_at: datetime
    
    class Config:
        from_attributes = True

class VulnerabilityUpdate(BaseModel):
    """Schema for updating vulnerability status"""
    status: VulnerabilityStatus
    notes: Optional[str] = Field(None, max_length=1000)

# Summary Schemas
class ScanSummary(BaseModel):
    """Schema for scan summary"""
    scan_id: int
    project_name: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    risk_score: float
    scan_duration: Optional[float]
    languages_detected: List[str]
    tools_used: List[str]
    most_common_vulnerabilities: List[Dict[str, Any]]
    severity_distribution: Dict[str, int]

class ProjectSummary(BaseModel):
    """Schema for project summary"""
    project_id: int
    project_name: str
    total_scans: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    average_risk_score: float
    last_scan_date: Optional[datetime]
    scan_trends: List[Dict[str, Any]]
    vulnerability_trends: List[Dict[str, Any]]

class SASTSummary(BaseModel):
    """Schema for overall SAST summary"""
    total_projects: int
    total_scans: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    average_risk_score: float
    most_common_vulnerabilities: List[Dict[str, Any]]
    scan_trends: List[Dict[str, Any]]
    vulnerability_trends: List[Dict[str, Any]]
    top_projects_by_risk: List[Dict[str, Any]]

# Report Schemas
class ReportRequest(BaseModel):
    """Schema for report generation request"""
    scan_id: int
    report_type: ReportType
    include_details: bool = Field(True, description="Include detailed vulnerability information")
    include_recommendations: bool = Field(True, description="Include remediation recommendations")
    include_code_snippets: bool = Field(False, description="Include code snippets in report")
    custom_title: Optional[str] = Field(None, description="Custom report title")

class ReportResponse(BaseModel):
    """Schema for report response"""
    report_id: int
    scan_id: int
    report_type: ReportType
    file_path: str
    file_size: int
    generated_at: datetime
    download_url: str

# Configuration Schemas
class SASTConfig(BaseModel):
    """Schema for SAST configuration"""
    tools_config: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    severity_threshold: SeverityLevel = Field(SeverityLevel.LOW)
    max_scan_duration: int = Field(3600, description="Maximum scan duration in seconds")
    parallel_scans: int = Field(3, description="Maximum parallel scans")
    auto_scan_on_push: bool = Field(False, description="Automatically scan on code push")
    exclude_patterns: List[str] = Field(default_factory=list, description="File patterns to exclude")
    include_patterns: List[str] = Field(default_factory=list, description="File patterns to include")

class ToolConfig(BaseModel):
    """Schema for individual tool configuration"""
    enabled: bool = Field(True, description="Whether the tool is enabled")
    config_file: Optional[str] = Field(None, description="Path to tool configuration file")
    custom_rules: Optional[List[str]] = Field(None, description="Custom rules to apply")
    timeout: int = Field(300, description="Tool timeout in seconds")

# Webhook Schemas
class GitHubWebhookPayload(BaseModel):
    """Schema for GitHub webhook payload"""
    ref: str
    ref_type: str
    repository: Dict[str, Any]
    sender: Dict[str, Any]
    commits: Optional[List[Dict[str, Any]]] = None
    
    class Config:
        extra = "allow"  # Allow additional fields from GitHub

class WebhookResponse(BaseModel):
    """Schema for webhook response"""
    success: bool
    message: str
    scan_id: Optional[int] = None
    project_id: Optional[int] = None

# Error Schemas
class SASTError(BaseModel):
    """Schema for SAST error response"""
    error_code: str
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# Filter Schemas
class VulnerabilityFilter(BaseModel):
    """Schema for vulnerability filtering"""
    severity: Optional[SeverityLevel] = None
    tool_name: Optional[str] = None
    status: Optional[VulnerabilityStatus] = None
    file_path: Optional[str] = None
    cwe_id: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None

class ScanFilter(BaseModel):
    """Schema for scan filtering"""
    project_id: Optional[int] = None
    status: Optional[ScanStatus] = None
    scan_type: Optional[ScanType] = None
    triggered_by: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None

# Analytics Schemas
class VulnerabilityTrend(BaseModel):
    """Schema for vulnerability trend data"""
    date: datetime
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int

class ScanTrend(BaseModel):
    """Schema for scan trend data"""
    date: datetime
    total_scans: int
    completed_scans: int
    failed_scans: int
    average_duration: float

class RiskMetrics(BaseModel):
    """Schema for risk metrics"""
    risk_score: float
    risk_level: str
    factors: List[Dict[str, Any]]
    recommendations: List[str] 