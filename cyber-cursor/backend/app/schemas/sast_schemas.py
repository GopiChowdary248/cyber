"""
Pydantic schemas for SAST (Static Application Security Testing) API
Enhanced with SonarQube-like comprehensive functionality
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

# ============================================================================
# Enums
# ============================================================================

class VulnerabilitySeverity(str, Enum):
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

class SecurityHotspotStatus(str, Enum):
    TO_REVIEW = "TO_REVIEW"
    REVIEWED = "REVIEWED"
    SAFE = "SAFE"
    FIXED = "FIXED"

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
# Base Models
# ============================================================================

class SASTProjectBase(BaseModel):
    name: str = Field(..., description="Project name")
    key: str = Field(..., description="Unique project key")
    language: str = Field(..., description="Primary programming language")
    repository_url: Optional[str] = Field(None, description="Repository URL")
    branch: str = Field("main", description="Default branch")

class SASTScanBase(BaseModel):
    scan_type: str = Field(..., description="Type of scan (full, incremental, etc.)")
    branch: str = Field("main", description="Branch to scan")

class SASTIssueBase(BaseModel):
    rule_id: str = Field(..., description="Rule identifier")
    rule_name: str = Field(..., description="Rule name")
    message: str = Field(..., description="Issue message")
    file_path: str = Field(..., description="File path")
    line_number: int = Field(..., description="Line number")
    severity: VulnerabilitySeverity = Field(..., description="Issue severity")
    type: IssueType = Field(..., description="Issue type")

class SecurityHotspotBase(BaseModel):
    rule_id: str = Field(..., description="Rule identifier")
    rule_name: str = Field(..., description="Rule name")
    message: str = Field(..., description="Hotspot message")
    file_path: str = Field(..., description="File path")
    line_number: int = Field(..., description="Line number")
    status: SecurityHotspotStatus = Field(SecurityHotspotStatus.TO_REVIEW, description="Hotspot status")

class QualityGateBase(BaseModel):
    max_blocker_issues: int = Field(0, description="Maximum blocker issues allowed")
    max_critical_issues: int = Field(5, description="Maximum critical issues allowed")
    max_major_issues: int = Field(20, description="Maximum major issues allowed")
    max_minor_issues: int = Field(100, description="Maximum minor issues allowed")
    max_info_issues: int = Field(500, description="Maximum info issues allowed")
    min_coverage: float = Field(80.0, description="Minimum code coverage percentage")
    min_branch_coverage: float = Field(80.0, description="Minimum branch coverage percentage")
    max_debt_ratio: float = Field(5.0, description="Maximum technical debt ratio")
    max_technical_debt: int = Field(1440, description="Maximum technical debt in minutes")
    max_duplicated_lines: int = Field(1000, description="Maximum duplicated lines")
    max_duplicated_blocks: int = Field(100, description="Maximum duplicated blocks")
    min_maintainability_rating: Rating = Field(Rating.C, description="Minimum maintainability rating")
    min_security_rating: Rating = Field(Rating.C, description="Minimum security rating")
    min_reliability_rating: Rating = Field(Rating.C, description="Minimum reliability rating")

# ============================================================================
# Create Models
# ============================================================================

class SASTProjectCreate(SASTProjectBase):
    description: Optional[str] = Field(None, description="Project description")

class SASTScanCreate(SASTScanBase):
    project_id: str = Field(..., description="Project ID")

class SASTIssueCreate(SASTIssueBase):
    project_id: str = Field(..., description="Project ID")
    scan_id: Optional[str] = Field(None, description="Scan ID")
    description: Optional[str] = Field(None, description="Issue description")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    cvss_score: Optional[float] = Field(None, description="CVSS score")
    owasp_category: Optional[str] = Field(None, description="OWASP category")
    tags: Optional[List[str]] = Field(None, description="Issue tags")

class SecurityHotspotCreate(SecurityHotspotBase):
    project_id: str = Field(..., description="Project ID")
    scan_id: Optional[str] = Field(None, description="Scan ID")
    description: Optional[str] = Field(None, description="Hotspot description")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    cvss_score: Optional[float] = Field(None, description="CVSS score")
    owasp_category: Optional[str] = Field(None, description="OWASP category")
    tags: Optional[List[str]] = Field(None, description="Hotspot tags")

class QualityGateCreate(QualityGateBase):
    project_id: str = Field(..., description="Project ID")

# ============================================================================
# Response Models
# ============================================================================

class SASTProjectResponse(SASTProjectBase):
    id: str = Field(..., description="Project ID")
    description: Optional[str] = Field(None, description="Project description")
    quality_gate: QualityGateStatus = Field(QualityGateStatus.PASSED, description="Quality gate status")
    maintainability_rating: Rating = Field(Rating.A, description="Maintainability rating")
    security_rating: Rating = Field(Rating.A, description="Security rating")
    reliability_rating: Rating = Field(Rating.A, description="Reliability rating")
    vulnerability_count: int = Field(0, description="Number of vulnerabilities")
    bug_count: int = Field(0, description="Number of bugs")
    code_smell_count: int = Field(0, description="Number of code smells")
    security_hotspot_count: int = Field(0, description="Number of security hotspots")
    lines_of_code: int = Field(0, description="Lines of code")
    coverage: float = Field(0.0, description="Code coverage percentage")
    technical_debt: int = Field(0, description="Technical debt in minutes")
    debt_ratio: float = Field(0.0, description="Technical debt ratio")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")
    last_analysis: Optional[datetime] = Field(None, description="Last analysis timestamp")

class SASTScanResponse(SASTScanBase):
    id: str = Field(..., description="Scan ID")
    project_id: str = Field(..., description="Project ID")
    status: ScanStatus = Field(ScanStatus.PENDING, description="Scan status")
    progress: float = Field(0.0, description="Scan progress (0-100)")
    total_files: int = Field(0, description="Total files to scan")
    scanned_files: int = Field(0, description="Files scanned")
    issues_found: int = Field(0, description="Issues found")
    vulnerabilities_found: int = Field(0, description="Vulnerabilities found")
    bugs_found: int = Field(0, description="Bugs found")
    code_smells_found: int = Field(0, description="Code smells found")
    security_hotspots_found: int = Field(0, description="Security hotspots found")
    lines_of_code: int = Field(0, description="Lines of code")
    coverage: float = Field(0.0, description="Code coverage percentage")
    technical_debt: int = Field(0, description="Technical debt in minutes")
    started_at: Optional[datetime] = Field(None, description="Scan start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Scan completion timestamp")
    duration: Optional[int] = Field(None, description="Scan duration in seconds")

class SASTIssueResponse(SASTIssueBase):
    id: str = Field(..., description="Issue ID")
    project_id: str = Field(..., description="Project ID")
    scan_id: Optional[str] = Field(None, description="Scan ID")
    description: Optional[str] = Field(None, description="Issue description")
    status: IssueStatus = Field(IssueStatus.OPEN, description="Issue status")
    assignee: Optional[str] = Field(None, description="Issue assignee")
    author: Optional[str] = Field(None, description="Issue author")
    effort: int = Field(0, description="Effort to fix in minutes")
    debt: int = Field(0, description="Technical debt in minutes")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    cvss_score: Optional[float] = Field(None, description="CVSS score")
    owasp_category: Optional[str] = Field(None, description="OWASP category")
    tags: Optional[List[str]] = Field(None, description="Issue tags")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")

class SecurityHotspotResponse(SecurityHotspotBase):
    id: str = Field(..., description="Hotspot ID")
    project_id: str = Field(..., description="Project ID")
    scan_id: Optional[str] = Field(None, description="Scan ID")
    description: Optional[str] = Field(None, description="Hotspot description")
    resolution: Optional[str] = Field(None, description="Hotspot resolution")
    reviewed_by: Optional[str] = Field(None, description="Reviewed by")
    reviewed_at: Optional[datetime] = Field(None, description="Review timestamp")
    review_comment: Optional[str] = Field(None, description="Review comment")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    cvss_score: Optional[float] = Field(None, description="CVSS score")
    owasp_category: Optional[str] = Field(None, description="OWASP category")
    tags: Optional[List[str]] = Field(None, description="Hotspot tags")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")

class QualityGateResponse(QualityGateBase):
    id: str = Field(..., description="Quality gate ID")
    project_id: str = Field(..., description="Project ID")
    status: QualityGateStatus = Field(QualityGateStatus.PASSED, description="Quality gate status")
    last_evaluation: Optional[datetime] = Field(None, description="Last evaluation timestamp")
    evaluation_results: Optional[Dict[str, Any]] = Field(None, description="Evaluation results")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")

class CodeCoverageResponse(BaseModel):
    id: str = Field(..., description="Coverage ID")
    project_id: str = Field(..., description="Project ID")
    scan_id: Optional[str] = Field(None, description="Scan ID")
    file_path: str = Field(..., description="File path")
    lines_to_cover: int = Field(0, description="Lines to cover")
    uncovered_lines: int = Field(0, description="Uncovered lines")
    covered_lines: int = Field(0, description="Covered lines")
    line_coverage: float = Field(0.0, description="Line coverage percentage")
    conditions_to_cover: int = Field(0, description="Conditions to cover")
    uncovered_conditions: int = Field(0, description="Uncovered conditions")
    covered_conditions: int = Field(0, description="Covered conditions")
    branch_coverage: float = Field(0.0, description="Branch coverage percentage")
    overall_coverage: float = Field(0.0, description="Overall coverage percentage")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")

class DuplicationResponse(BaseModel):
    id: str = Field(..., description="Duplication ID")
    project_id: str = Field(..., description="Project ID")
    scan_id: Optional[str] = Field(None, description="Scan ID")
    file_path: str = Field(..., description="File path")
    start_line: int = Field(..., description="Start line")
    end_line: int = Field(..., description="End line")
    duplicated_lines: int = Field(0, description="Number of duplicated lines")
    duplicated_code: Optional[str] = Field(None, description="Duplicated code")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")

# ============================================================================
# List Response Models
# ============================================================================

class SASTProjectsResponse(BaseModel):
    projects: List[SASTProjectResponse] = Field(..., description="List of projects")

class SASTScansResponse(BaseModel):
    scans: List[SASTScanResponse] = Field(..., description="List of scans")

class SASTVulnerabilitiesResponse(BaseModel):
    vulnerabilities: List[SASTIssueResponse] = Field(..., description="List of vulnerabilities")

class SecurityHotspotsResponse(BaseModel):
    hotspots: List[SecurityHotspotResponse] = Field(..., description="List of security hotspots")

class QualityGatesResponse(BaseModel):
    quality_gates: List[QualityGateResponse] = Field(..., description="List of quality gates")

class CodeCoveragesResponse(BaseModel):
    coverages: List[CodeCoverageResponse] = Field(..., description="List of code coverages")

class DuplicationsResponse(BaseModel):
    duplications: List[DuplicationResponse] = Field(..., description="List of duplications")

# ============================================================================
# Dashboard & Overview Models
# ============================================================================

class SASTOverviewData(BaseModel):
    totalProjects: int = Field(0, description="Total number of projects")
    totalScans: int = Field(0, description="Total number of scans")
    activeScans: int = Field(0, description="Number of active scans")
    totalVulnerabilities: int = Field(0, description="Total number of vulnerabilities")
    vulnerabilitiesBySeverity: Dict[str, int] = Field(..., description="Vulnerabilities by severity")
    securityScore: int = Field(0, description="Overall security score")

class SASTOverviewResponse(BaseModel):
    overview: SASTOverviewData = Field(..., description="SAST overview data")

class SASTDashboardStats(BaseModel):
    total_projects: int = Field(0, description="Total number of projects")
    active_scans: int = Field(0, description="Number of active scans")
    total_issues: int = Field(0, description="Total number of issues")
    critical_issues: int = Field(0, description="Number of critical issues")
    high_issues: int = Field(0, description="Number of high issues")
    medium_issues: int = Field(0, description="Number of medium issues")
    low_issues: int = Field(0, description="Number of low issues")
    info_issues: int = Field(0, description="Number of info issues")
    security_rating: str = Field("A", description="Security rating (A-E)")
    reliability_rating: str = Field("A", description="Reliability rating (A-E)")
    maintainability_rating: str = Field("A", description="Maintainability rating (A-E)")
    coverage_percentage: float = Field(0.0, description="Code coverage percentage")
    technical_debt_hours: int = Field(0, description="Technical debt in hours")
    last_scan_date: Optional[str] = Field(None, description="Last scan date")
    scan_success_rate: float = Field(0.0, description="Scan success rate percentage")
    average_scan_duration: float = Field(0.0, description="Average scan duration in minutes")
    total_lines_of_code: int = Field(0, description="Total lines of code")
    duplicated_lines: int = Field(0, description="Duplicated lines")
    duplicated_lines_density: float = Field(0.0, description="Duplicated lines density percentage")
    uncovered_lines: int = Field(0, description="Uncovered lines")
    uncovered_conditions: int = Field(0, description="Uncovered conditions")
    security_hotspots: int = Field(0, description="Number of security hotspots")
    security_hotspots_reviewed: int = Field(0, description="Number of reviewed security hotspots")
    vulnerabilities: int = Field(0, description="Number of vulnerabilities")
    bugs: int = Field(0, description="Number of bugs")
    code_smells: int = Field(0, description="Number of code smells")
    recent_activity: List[Dict[str, Any]] = Field(..., description="Recent activity")

class SASTStatisticsResponse(BaseModel):
    total_projects: int = Field(0, description="Total number of projects")
    total_scans: int = Field(0, description="Total number of scans")
    total_vulnerabilities: int = Field(0, description="Total number of vulnerabilities")
    vulnerabilities_by_severity: Dict[str, int] = Field(..., description="Vulnerabilities by severity")
    security_score: int = Field(0, description="Overall security score")
    recent_scans: List[Dict[str, Any]] = Field(..., description="Recent scans")
    top_vulnerabilities: List[Dict[str, Any]] = Field(..., description="Top vulnerabilities")

# ============================================================================
# Detail Response Models
# ============================================================================

class SASTProjectDetailResponse(BaseModel):
    project: SASTProjectResponse = Field(..., description="Project details")

class SASTScanHistoryResponse(BaseModel):
    scans: List[SASTScanResponse] = Field(..., description="Scan history")

# ============================================================================
# Filter Models
# ============================================================================

class SASTVulnerabilityFilter(BaseModel):
    severity: Optional[VulnerabilitySeverity] = Field(None, description="Filter by severity")
    type: Optional[IssueType] = Field(None, description="Filter by issue type")
    status: Optional[IssueStatus] = Field(None, description="Filter by status")
    project_id: Optional[str] = Field(None, description="Filter by project ID")
    cwe_id: Optional[str] = Field(None, description="Filter by CWE ID")
    owasp_category: Optional[str] = Field(None, description="Filter by OWASP category")

class SASTScanFilter(BaseModel):
    status: Optional[ScanStatus] = Field(None, description="Filter by scan status")
    project_id: Optional[str] = Field(None, description="Filter by project ID")
    scan_type: Optional[str] = Field(None, description="Filter by scan type")
    date_from: Optional[datetime] = Field(None, description="Filter from date")
    date_to: Optional[datetime] = Field(None, description="Filter to date")

class SecurityHotspotFilter(BaseModel):
    status: Optional[SecurityHotspotStatus] = Field(None, description="Filter by hotspot status")
    project_id: Optional[str] = Field(None, description="Filter by project ID")
    cwe_id: Optional[str] = Field(None, description="Filter by CWE ID")
    owasp_category: Optional[str] = Field(None, description="Filter by OWASP category")

# ============================================================================
# Configuration Models
# ============================================================================

class SASTProjectConfiguration(BaseModel):
    project_id: str = Field(..., description="Project ID")
    scan_patterns: Optional[List[str]] = Field(None, description="Scan patterns")
    excluded_files: Optional[List[str]] = Field(None, description="Excluded files")
    excluded_directories: Optional[List[str]] = Field(None, description="Excluded directories")
    enabled_rules: Optional[List[str]] = Field(None, description="Enabled rule IDs")
    disabled_rules: Optional[List[str]] = Field(None, description="Disabled rule IDs")
    rule_severities: Optional[Dict[str, str]] = Field(None, description="Rule severity overrides")
    quality_gate_id: Optional[str] = Field(None, description="Quality gate ID")

class SASTRuleConfiguration(BaseModel):
    rule_id: str = Field(..., description="Rule ID")
    enabled: bool = Field(True, description="Rule enabled status")
    severity: Optional[VulnerabilitySeverity] = Field(None, description="Rule severity")
    effort: Optional[int] = Field(None, description="Default effort in minutes")
    languages: Optional[List[str]] = Field(None, description="Supported languages") 