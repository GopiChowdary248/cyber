from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

# Enums
class ProjectType(str, Enum):
    SAST = "sast"
    DAST = "dast"
    RASP = "rasp"
    CLOUD = "cloud"
    GENERAL = "general"

class RepositoryType(str, Enum):
    GIT = "git"
    SVN = "svn"
    ZIP = "zip"
    LOCAL = "local"

class ProjectStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"
    DELETED = "deleted"

# Base schemas
class ProjectBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Project name")
    key: str = Field(..., min_length=1, max_length=255, description="Unique project key")
    description: Optional[str] = Field(None, description="Project description")
    project_type: ProjectType = Field(ProjectType.GENERAL, description="Project type")
    repository_type: Optional[RepositoryType] = Field(None, description="Repository type")
    repository_url: Optional[str] = Field(None, max_length=500, description="Repository URL")
    repository_branch: Optional[str] = Field("main", max_length=100, description="Repository branch")
    language: Optional[str] = Field(None, max_length=50, description="Primary programming language")
    framework: Optional[str] = Field(None, max_length=100, description="Framework used")
    tags: Optional[List[str]] = Field(None, description="Project tags")
    security_level: Optional[str] = Field("standard", description="Security level")
    compliance_frameworks: Optional[List[str]] = Field(None, description="Compliance frameworks")

    @validator('key')
    def validate_key(cls, v):
        """Validate project key format"""
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Project key must contain only alphanumeric characters, underscores, and hyphens')
        return v.lower()

class ProjectCreate(ProjectBase):
    owner_id: Optional[int] = Field(None, description="Project owner ID")
    team_id: Optional[int] = Field(None, description="Team ID")

class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    project_type: Optional[ProjectType] = None
    repository_type: Optional[RepositoryType] = None
    repository_url: Optional[str] = Field(None, max_length=500)
    repository_branch: Optional[str] = Field(None, max_length=100)
    language: Optional[str] = Field(None, max_length=50)
    framework: Optional[str] = Field(None, max_length=100)
    tags: Optional[List[str]] = None
    security_level: Optional[str] = None
    compliance_frameworks: Optional[List[str]] = None
    status: Optional[ProjectStatus] = None
    owner_id: Optional[int] = None
    team_id: Optional[int] = None

class ProjectResponse(ProjectBase):
    id: int
    status: ProjectStatus
    created_by: int
    owner_id: int
    team_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    last_scan: Optional[datetime]
    last_sync: Optional[datetime]
    metadata: Optional[Dict[str, Any]]

    class Config:
        from_attributes = True

class ProjectList(BaseModel):
    projects: List[ProjectResponse]
    total: int
    page: int
    size: int
    pages: int

# Scan schemas
class ProjectScanBase(BaseModel):
    scan_type: str = Field(..., description="Type of scan")
    scan_name: str = Field(..., max_length=255, description="Scan name")
    scan_config: Optional[Dict[str, Any]] = Field(None, description="Scan configuration")

class ProjectScanCreate(ProjectScanBase):
    project_id: int = Field(..., description="Project ID")

class ProjectScanUpdate(BaseModel):
    status: Optional[str] = None
    progress: Optional[int] = Field(None, ge=0, le=100)
    total_issues: Optional[int] = Field(None, ge=0)
    critical_issues: Optional[int] = Field(None, ge=0)
    high_issues: Optional[int] = Field(None, ge=0)
    medium_issues: Optional[int] = Field(None, ge=0)
    low_issues: Optional[int] = Field(None, ge=0)
    scan_duration: Optional[int] = Field(None, ge=0)
    files_scanned: Optional[int] = Field(None, ge=0)
    lines_scanned: Optional[int] = Field(None, ge=0)
    error_message: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    completed_at: Optional[datetime] = None

class ProjectScanResponse(ProjectScanBase):
    id: int
    project_id: int
    status: str
    progress: int
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    scan_duration: Optional[int]
    files_scanned: int
    lines_scanned: int
    error_message: Optional[str]
    started_by: int
    started_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True

class ProjectScanList(BaseModel):
    scans: List[ProjectScanResponse]
    total: int
    page: int
    size: int
    pages: int

# Issue schemas
class ProjectIssueBase(BaseModel):
    issue_type: str = Field(..., description="Type of issue")
    severity: str = Field(..., description="Issue severity")
    status: str = Field("open", description="Issue status")
    title: str = Field(..., max_length=500, description="Issue title")
    description: Optional[str] = Field(None, description="Issue description")
    recommendation: Optional[str] = Field(None, description="Recommendation to fix")
    file_path: Optional[str] = Field(None, max_length=500, description="File path")
    line_number: Optional[int] = Field(None, ge=1, description="Line number")
    start_line: Optional[int] = Field(None, ge=1, description="Start line")
    end_line: Optional[int] = Field(None, ge=1, description="End line")
    cwe_id: Optional[str] = Field(None, max_length=20, description="CWE ID")
    cvss_score: Optional[float] = Field(None, ge=0, le=10, description="CVSS score")
    owasp_category: Optional[str] = Field(None, max_length=100, description="OWASP category")

class ProjectIssueCreate(ProjectIssueBase):
    project_id: int = Field(..., description="Project ID")
    scan_id: Optional[int] = Field(None, description="Scan ID")
    assigned_to: Optional[int] = Field(None, description="Assigned user ID")

class ProjectIssueUpdate(BaseModel):
    status: Optional[str] = None
    title: Optional[str] = Field(None, max_length=500)
    description: Optional[str] = None
    recommendation: Optional[str] = None
    assigned_to: Optional[int] = None
    resolved_at: Optional[datetime] = None

class ProjectIssueResponse(ProjectIssueBase):
    id: int
    project_id: int
    scan_id: Optional[int]
    assigned_to: Optional[int]
    created_by: Optional[int]
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True

class ProjectIssueList(BaseModel):
    issues: List[ProjectIssueResponse]
    total: int
    page: int
    size: int
    pages: int

# Team schemas
class TeamBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Team name")
    description: Optional[str] = Field(None, description="Team description")
    team_type: str = Field("development", description="Team type")

class TeamCreate(TeamBase):
    pass

class TeamUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    team_type: Optional[str] = None
    is_active: Optional[bool] = None

class TeamResponse(TeamBase):
    id: int
    is_active: bool
    created_by: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class TeamMemberBase(BaseModel):
    role: str = Field("member", description="Team member role")

class TeamMemberCreate(TeamMemberBase):
    user_id: int = Field(..., description="User ID")

class TeamMemberResponse(TeamMemberBase):
    id: int
    team_id: int
    user_id: int
    joined_at: datetime

    class Config:
        from_attributes = True

# Statistics and summary schemas
class ProjectStats(BaseModel):
    total_projects: int
    active_projects: int
    total_scans: int
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    projects_by_type: Dict[str, int]
    recent_scans: List[ProjectScanResponse]

class ProjectSummary(BaseModel):
    project: ProjectResponse
    stats: ProjectStats
    recent_scans: List[ProjectScanResponse]
    recent_issues: List[ProjectIssueResponse]

# Upload schemas
class CodeUploadRequest(BaseModel):
    project_id: int = Field(..., description="Project ID")
    upload_type: str = Field(..., description="Upload type: zip, git, or local")
    source_path: Optional[str] = Field(None, description="Source path for local uploads")
    git_url: Optional[str] = Field(None, description="Git repository URL")
    git_branch: Optional[str] = Field("main", description="Git branch")
    git_username: Optional[str] = Field(None, description="Git username")
    git_token: Optional[str] = Field(None, description="Git access token")

class CodeUploadResponse(BaseModel):
    upload_id: str
    status: str
    message: str
    source_path: Optional[str]
    files_count: Optional[int]
    total_size: Optional[int]
    scan_id: Optional[int] = Field(None, description="ID of the scan created after upload")

# Search and filter schemas
class ProjectFilter(BaseModel):
    project_type: Optional[ProjectType] = None
    status: Optional[ProjectStatus] = None
    language: Optional[str] = None
    framework: Optional[str] = None
    tags: Optional[List[str]] = None
    created_by: Optional[int] = None
    owner_id: Optional[int] = None
    team_id: Optional[int] = None
    search: Optional[str] = None

class ProjectSearchRequest(BaseModel):
    query: str = Field(..., min_length=1, description="Search query")
    filters: Optional[ProjectFilter] = None
    page: int = Field(1, ge=1, description="Page number")
    size: int = Field(20, ge=1, le=100, description="Page size")
    sort_by: str = Field("created_at", description="Sort field")
    sort_order: str = Field("desc", description="Sort order: asc or desc") 