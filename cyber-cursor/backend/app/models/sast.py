#!/usr/bin/env python3
"""
Database models for SAST (Static Application Security Testing)
Enhanced with SonarQube-like comprehensive functionality
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Float, ForeignKey, Enum, JSON, Date, Index
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from datetime import datetime
from typing import Optional, List
import enum

from app.core.database import Base

class IssueSeverity(str, enum.Enum):
    BLOCKER = "BLOCKER"
    CRITICAL = "CRITICAL"
    MAJOR = "MAJOR"
    MINOR = "MINOR"
    INFO = "INFO"

class IssueType(str, enum.Enum):
    BUG = "BUG"
    VULNERABILITY = "VULNERABILITY"
    CODE_SMELL = "CODE_SMELL"
    SECURITY_HOTSPOT = "SECURITY_HOTSPOT"

class IssueStatus(str, enum.Enum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    REOPENED = "REOPENED"

class IssueResolution(str, enum.Enum):
    FIXED = "FIXED"
    WONTFIX = "WONTFIX"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED = "ACCEPTED"

class QualityGateStatus(str, enum.Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"

class Rating(str, enum.Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"

class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class SecurityHotspotStatus(str, enum.Enum):
    TO_REVIEW = "TO_REVIEW"
    REVIEWED = "REVIEWED"
    FIXED = "FIXED"

class SecurityHotspotResolution(str, enum.Enum):
    FIXED = "FIXED"
    SAFE = "SAFE"
    ACKNOWLEDGED = "ACKNOWLEDGED"

# ============================================================================
# Core SAST Models
# ============================================================================

class SASTProject(Base):
    __tablename__ = "sast_projects"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    key = Column(String(255), unique=True, index=True, nullable=False)
    language = Column(String(50), nullable=False)
    repository_url = Column(String(500), nullable=True)
    branch = Column(String(100), default="main")
    
    # Quality metrics
    quality_gate = Column(Enum(QualityGateStatus), default=QualityGateStatus.PASSED)
    maintainability_rating = Column(Enum(Rating), default=Rating.A)
    security_rating = Column(Enum(Rating), default=Rating.A)
    reliability_rating = Column(Enum(Rating), default=Rating.A)
    
    # Counts
    vulnerability_count = Column(Integer, default=0)
    bug_count = Column(Integer, default=0)
    code_smell_count = Column(Integer, default=0)
    security_hotspot_count = Column(Integer, default=0)
    
    # Code metrics
    lines_of_code = Column(Integer, default=0)
    lines_of_comment = Column(Integer, default=0)
    duplicated_lines = Column(Integer, default=0)
    duplicated_blocks = Column(Integer, default=0)
    
    # Coverage metrics
    coverage = Column(Float, default=0.0)
    uncovered_lines = Column(Integer, default=0)
    uncovered_conditions = Column(Integer, default=0)
    
    # Technical debt
    technical_debt = Column(Integer, default=0)  # minutes
    debt_ratio = Column(Float, default=0.0)  # percentage
    
    # Metadata
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    last_analysis = Column(DateTime, nullable=True)
    
    # Relationships
    issues = relationship("SASTIssue", back_populates="project")
    scans = relationship("SASTScan", back_populates="project")
    quality_gates = relationship("SASTQualityGate", back_populates="project")
    security_hotspots = relationship("SASTSecurityHotspot", back_populates="project")
    code_coverages = relationship("SASTCodeCoverage", back_populates="project")
    duplications = relationship("SASTDuplication", back_populates="project")
    
    @classmethod
    async def get_by_key(cls, db: AsyncSession, key: str) -> Optional["SASTProject"]:
        """Get project by key"""
        result = await db.execute(select(cls).where(cls.key == key))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, project_id: int) -> Optional["SASTProject"]:
        """Get project by ID"""
        result = await db.execute(select(cls).where(cls.id == project_id))
        return result.scalar_one_or_none()

class SASTIssue(Base):
    __tablename__ = "sast_issues"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("sast_scans.id"), nullable=True)
    
    # Issue details
    rule_id = Column(String(255), nullable=False)
    rule_name = Column(String(255), nullable=False)
    rule_category = Column(String(100), nullable=True)
    message = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    
    # Location
    file_path = Column(String(500), nullable=False)
    line_number = Column(Integer, nullable=False)
    start_line = Column(Integer, nullable=True)
    end_line = Column(Integer, nullable=True)
    start_column = Column(Integer, nullable=True)
    end_column = Column(Integer, nullable=True)
    
    # Classification
    severity = Column(Enum(IssueSeverity), nullable=False)
    type = Column(Enum(IssueType), nullable=False)
    status = Column(Enum(IssueStatus), default=IssueStatus.OPEN)
    resolution = Column(Enum(IssueResolution), default=IssueResolution.FALSE_POSITIVE)
    
    # Assignment
    assignee = Column(String(100), nullable=True)
    author = Column(String(100), nullable=True)
    
    # Metrics
    effort = Column(Integer, default=0)  # minutes to fix
    debt = Column(Integer, default=0)    # technical debt in minutes
    
    # Security metadata
    cwe_id = Column(String(20), nullable=True)
    cvss_score = Column(Float, nullable=True)
    owasp_category = Column(String(100), nullable=True)
    tags = Column(JSON, nullable=True)  # JSON array of tags
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    project = relationship("SASTProject", back_populates="issues")
    scan = relationship("SASTScan", back_populates="issues")
    
    @classmethod
    async def get_by_project(cls, db: AsyncSession, project_id: int, skip: int = 0, limit: int = 100) -> List["SASTIssue"]:
        """Get issues for a project"""
        result = await db.execute(
            select(cls)
            .where(cls.project_id == project_id)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    @classmethod
    async def get_by_severity(cls, db: AsyncSession, severity: IssueSeverity) -> List["SASTIssue"]:
        """Get issues by severity"""
        result = await db.execute(select(cls).where(cls.severity == severity))
        return result.scalars().all()

class SASTScan(Base):
    __tablename__ = "sast_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    
    # Scan details
    scan_type = Column(String(50), nullable=False)  # full, incremental, etc.
    branch = Column(String(100), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    
    # Incremental analysis
    is_incremental = Column(Boolean, default=False)
    base_scan_id = Column(Integer, ForeignKey("sast_scans.id"), nullable=True)
    changed_files = Column(JSON, nullable=True)  # List of changed file paths
    new_files = Column(JSON, nullable=True)     # List of new file paths
    deleted_files = Column(JSON, nullable=True)  # List of deleted file paths
    
    # Progress
    progress = Column(Float, default=0.0)  # 0-100
    total_files = Column(Integer, default=0)
    scanned_files = Column(Integer, default=0)
    
    # Results
    issues_found = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    bugs_found = Column(Integer, default=0)
    code_smells_found = Column(Integer, default=0)
    security_hotspots_found = Column(Integer, default=0)
    
    # Code metrics
    lines_of_code = Column(Integer, default=0)
    lines_of_comment = Column(Integer, default=0)
    duplicated_lines = Column(Integer, default=0)
    duplicated_blocks = Column(Integer, default=0)
    
    # Coverage metrics
    coverage = Column(Float, default=0.0)
    uncovered_lines = Column(Integer, default=0)
    uncovered_conditions = Column(Integer, default=0)
    
    # Technical debt
    technical_debt = Column(Integer, default=0)  # minutes
    debt_ratio = Column(Float, default=0.0)  # percentage
    
    # Timing
    started_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    started_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)
    duration = Column(Integer, nullable=True)  # seconds
    
    # Error handling
    error_message = Column(Text, nullable=True)
    
    # Relationships
    project = relationship("SASTProject", back_populates="scans")
    issues = relationship("SASTIssue", back_populates="scan")
    base_scan = relationship("SASTScan", remote_side=[id])
    incremental_scans = relationship("SASTScan", back_populates="base_scan")
    
    @classmethod
    async def get_recent_scans(cls, db: AsyncSession, project_id: int, limit: int = 10) -> List["SASTScan"]:
        """Get recent scans for a project"""
        result = await db.execute(
            select(cls)
            .where(cls.project_id == project_id)
            .order_by(cls.started_at.desc())
            .limit(limit)
        )
        return result.scalars().all()

# ============================================================================
# Security Hotspots
# ============================================================================

class SASTSecurityHotspot(Base):
    __tablename__ = "sast_security_hotspots"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("sast_scans.id"), nullable=True)
    
    # Hotspot details
    rule_id = Column(String(255), nullable=False)
    rule_name = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    
    # Location
    file_path = Column(String(500), nullable=False)
    line_number = Column(Integer, nullable=False)
    start_line = Column(Integer, nullable=True)
    end_line = Column(Integer, nullable=True)
    
    # Classification
    status = Column(Enum(SecurityHotspotStatus), default=SecurityHotspotStatus.TO_REVIEW)
    resolution = Column(Enum(SecurityHotspotResolution), nullable=True)
    
    # Security metadata
    cwe_id = Column(String(20), nullable=True)
    cvss_score = Column(Float, nullable=True)
    owasp_category = Column(String(100), nullable=True)
    tags = Column(JSON, nullable=True)  # JSON array of tags
    
    # Risk assessment
    risk_level = Column(String(20), default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    probability = Column(Float, default=0.5)  # 0.0 - 1.0
    impact = Column(Float, default=0.5)      # 0.0 - 1.0
    risk_score = Column(Float, default=0.0)  # Calculated risk score
    
    # Review information
    reviewed_by = Column(String(100), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_comment = Column(Text, nullable=True)
    review_priority = Column(Integer, default=5)  # 1-10, higher is more urgent
    
    # Assignment
    assigned_to = Column(String(100), nullable=True)
    assigned_at = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    project = relationship("SASTProject", back_populates="security_hotspots")
    scan = relationship("SASTScan")
    reviews = relationship("SASTHotspotReview", back_populates="hotspot", cascade="all, delete-orphan")

class SASTHotspotReview(Base):
    """Security hotspot review history and comments"""
    __tablename__ = "sast_hotspot_reviews"
    
    id = Column(Integer, primary_key=True, index=True)
    hotspot_id = Column(Integer, ForeignKey("sast_security_hotspots.id"), nullable=False)
    
    # Review details
    reviewer = Column(String(100), nullable=False)
    review_action = Column(String(50), nullable=False)  # 'REVIEWED', 'ASSIGNED', 'COMMENTED'
    review_status = Column(Enum(SecurityHotspotStatus), nullable=True)
    review_resolution = Column(Enum(SecurityHotspotResolution), nullable=True)
    
    # Review content
    comment = Column(Text, nullable=True)
    risk_assessment = Column(JSON, nullable=True)  # Risk assessment details
    
    # Metadata
    review_date = Column(DateTime, default=func.now())
    review_duration = Column(Integer, nullable=True)  # Time spent reviewing in minutes
    
    # Relationships
    hotspot = relationship("SASTSecurityHotspot", back_populates="reviews")
    
    # Indexes
    __table_args__ = (
        Index('idx_hotspot_reviews_hotspot', 'hotspot_id'),
        Index('idx_hotspot_reviews_reviewer', 'reviewer'),
        Index('idx_hotspot_reviews_date', 'review_date'),
    )

# ============================================================================
# Code Coverage
# ============================================================================

class SASTCodeCoverage(Base):
    __tablename__ = "sast_code_coverage"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("sast_scans.id"), nullable=True)
    
    # File information
    file_path = Column(String(500), nullable=False)
    
    # Coverage metrics
    lines_to_cover = Column(Integer, default=0)
    uncovered_lines = Column(Integer, default=0)
    covered_lines = Column(Integer, default=0)
    line_coverage = Column(Float, default=0.0)
    
    conditions_to_cover = Column(Integer, default=0)
    uncovered_conditions = Column(Integer, default=0)
    covered_conditions = Column(Integer, default=0)
    branch_coverage = Column(Float, default=0.0)
    
    # Overall coverage
    overall_coverage = Column(Float, default=0.0)
    
    # Detailed coverage data (JSON)
    detailed_coverage = Column(JSON, nullable=True)  # Store line-by-line coverage data
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    project = relationship("SASTProject", back_populates="code_coverages")
    scan = relationship("SASTScan")
    line_details = relationship("SASTLineCoverage", back_populates="coverage", cascade="all, delete-orphan")

class SASTLineCoverage(Base):
    """Detailed line-by-line coverage data"""
    __tablename__ = "sast_line_coverage"
    
    id = Column(Integer, primary_key=True, index=True)
    coverage_id = Column(Integer, ForeignKey("sast_code_coverage.id"), nullable=False)
    
    # Line information
    line_number = Column(Integer, nullable=False)
    hits = Column(Integer, default=0)  # Number of times this line was executed
    covered = Column(Boolean, default=False)
    
    # Branch coverage (if applicable)
    branches = Column(JSON, nullable=True)  # Store branch coverage data
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    coverage = relationship("SASTCodeCoverage", back_populates="line_details")
    
    # Composite index for efficient queries
    __table_args__ = (
        Index('idx_coverage_line', 'coverage_id', 'line_number'),
    )

class SASTSavedFilter(Base):
    """Saved filters for issues, hotspots, etc."""
    __tablename__ = "sast_saved_filters"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=True)  # null for global filters
    
    # Filter metadata
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    filter_type = Column(String(50), nullable=False)  # 'issues', 'hotspots', 'coverage', etc.
    
    # Filter criteria (JSON)
    filter_criteria = Column(JSON, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    user = relationship("User")
    project = relationship("SASTProject")
    
    # Indexes
    __table_args__ = (
        Index('idx_saved_filter_user_type', 'user_id', 'filter_type'),
        Index('idx_saved_filter_project', 'project_id'),
    )

# ============================================================================
# Code Duplications
# ============================================================================

class SASTDuplication(Base):
    __tablename__ = "sast_duplications"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("sast_scans.id"), nullable=False)
    file_path = Column(String, nullable=False)
    duplicated_lines = Column(Integer, nullable=False)
    duplicated_blocks = Column(Integer, nullable=False)
    duplication_density = Column(Float, nullable=False)
    language = Column(String, nullable=False)
    last_modified = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    project = relationship("SASTProject", back_populates="duplications")
    scan = relationship("SASTScan")

class SASTDuplicationBlock(Base):
    __tablename__ = "sast_duplication_blocks"
    
    id = Column(Integer, primary_key=True, index=True)
    duplication_id = Column(Integer, ForeignKey("sast_duplications.id"), nullable=False)
    file_path = Column(String, nullable=False)
    start_line = Column(Integer, nullable=False)
    end_line = Column(Integer, nullable=False)
    code_snippet = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# ============================================================================
# Security Reports Models
# ============================================================================

class SASTSecurityReport(Base):
    __tablename__ = "sast_security_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("sast_scans.id"), nullable=False)
    overall_security_rating = Column(Enum(Rating), nullable=False)
    security_score = Column(Integer, nullable=False)
    vulnerabilities_count = Column(Integer, nullable=False)
    critical_vulnerabilities = Column(Integer, nullable=False)
    major_vulnerabilities = Column(Integer, nullable=False)
    minor_vulnerabilities = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SASTOWASPMapping(Base):
    __tablename__ = "sast_owasp_mappings"
    
    id = Column(Integer, primary_key=True, index=True)
    security_report_id = Column(Integer, ForeignKey("sast_security_reports.id"), nullable=False)
    category = Column(String, nullable=False)  # e.g., "A01:2021 - Broken Access Control"
    count = Column(Integer, nullable=False)
    severity = Column(Enum(IssueSeverity), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class SASTCWEMapping(Base):
    __tablename__ = "sast_cwe_mappings"
    
    id = Column(Integer, primary_key=True, index=True)
    security_report_id = Column(Integer, ForeignKey("sast_security_reports.id"), nullable=False)
    cwe_id = Column(String, nullable=False)  # e.g., "CWE-89"
    name = Column(String, nullable=False)
    count = Column(Integer, nullable=False)
    severity = Column(Enum(IssueSeverity), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# ============================================================================
# Reliability Models
# ============================================================================

class SASTReliabilityReport(Base):
    __tablename__ = "sast_reliability_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("sast_scans.id"), nullable=False)
    reliability_rating = Column(Enum(Rating), nullable=False)
    bug_count = Column(Integer, nullable=False)
    bug_density = Column(Float, nullable=False)
    new_bugs = Column(Integer, nullable=False)
    resolved_bugs = Column(Integer, nullable=False)
    blocker_bugs = Column(Integer, nullable=False)
    critical_bugs = Column(Integer, nullable=False)
    major_bugs = Column(Integer, nullable=False)
    minor_bugs = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# ============================================================================
# Issues Comments (workflow notes)
# ============================================================================

class SASTIssueComment(Base):
    __tablename__ = "sast_issue_comments"

    id = Column(Integer, primary_key=True, index=True)
    issue_id = Column(Integer, ForeignKey("sast_issues.id"), nullable=False, index=True)
    author = Column(String(100), nullable=True)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    @classmethod
    async def list_for_issue(cls, db: AsyncSession, issue_id: int) -> List["SASTIssueComment"]:
        result = await db.execute(select(cls).where(cls.issue_id == issue_id).order_by(cls.created_at.asc()))
        return result.scalars().all()
    
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SASTBugCategory(Base):
    __tablename__ = "sast_bug_categories"
    
    id = Column(Integer, primary_key=True, index=True)
    reliability_report_id = Column(Integer, ForeignKey("sast_reliability_reports.id"), nullable=False)
    category = Column(String, nullable=False)  # e.g., "Null Pointer Exception"
    count = Column(Integer, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# ============================================================================
# Maintainability Models
# ============================================================================

class SASTMaintainabilityReport(Base):
    __tablename__ = "sast_maintainability_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("sast_scans.id"), nullable=False)
    maintainability_rating = Column(Enum(Rating), nullable=False)
    code_smell_count = Column(Integer, nullable=False)
    code_smell_density = Column(Float, nullable=False)
    complexity = Column(Float, nullable=False)
    cognitive_complexity = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SASTCodeSmellCategory(Base):
    __tablename__ = "sast_code_smell_categories"
    
    id = Column(Integer, primary_key=True, index=True)
    maintainability_report_id = Column(Integer, ForeignKey("sast_maintainability_reports.id"), nullable=False)
    category = Column(String, nullable=False)  # e.g., "Code Smells", "Unused Code"
    count = Column(Integer, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# ============================================================================
# Activity Models
# ============================================================================

class SASTActivity(Base):
    __tablename__ = "sast_activities"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    activity_type = Column(String, nullable=False)  # "COMMIT", "ISSUE", "HOTSPOT"
    author = Column(String, nullable=False)
    message = Column(Text, nullable=True)
    timestamp = Column(DateTime, nullable=False)
    activity_metadata = Column(JSON, nullable=True)  # Store additional data like files changed, lines added, etc.
    created_at = Column(DateTime, default=datetime.utcnow)

class SASTContributor(Base):
    __tablename__ = "sast_contributors"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    username = Column(String, nullable=False)
    email = Column(String, nullable=False)
    commits_count = Column(Integer, default=0)
    issues_count = Column(Integer, default=0)
    hotspots_count = Column(Integer, default=0)
    last_activity = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ============================================================================
# Administration Models
# ============================================================================

class SASTProjectSettings(Base):
    __tablename__ = "sast_project_settings"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    scan_schedule = Column(String, nullable=True)  # Cron expression
    auto_scan = Column(Boolean, default=True)
    quality_profile = Column(String, nullable=True)  # stores profile ID or key
    quality_gate = Column(String, nullable=True)
    exclusions = Column(JSON, nullable=True)  # Array of exclusion patterns
    notifications_email = Column(Boolean, default=True)
    notifications_slack = Column(Boolean, default=False)
    notifications_webhook = Column(String, nullable=True)
    integration_github = Column(Boolean, default=False)
    integration_gitlab = Column(Boolean, default=False)
    integration_bitbucket = Column(Boolean, default=False)
    integration_jenkins = Column(Boolean, default=False)
    integration_provider = Column(String, nullable=True)  # github | gitlab
    integration_repo = Column(String, nullable=True)      # owner/repo or namespace/project
    integration_branch = Column(String, nullable=True)
    # New code period settings
    new_code_mode = Column(String, nullable=True)  # prev-version | days | since-date
    new_code_days = Column(Integer, nullable=True)
    new_code_since = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SASTProjectPermission(Base):
    __tablename__ = "sast_project_permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    group_name = Column(String, nullable=True)  # For group permissions
    role = Column(String, nullable=False)  # "Admin", "User", "Viewer"
    permissions = Column(JSON, nullable=True)  # Array of specific permissions
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ============================================================================
# Project Favorites and Metadata
# ============================================================================

class SASTProjectFavorite(Base):
    __tablename__ = "sast_project_favorites"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class SASTProjectMetadata(Base):
    __tablename__ = "sast_project_metadata"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    homepage_url = Column(String(500), nullable=True)
    visibility = Column(String(20), default="private")  # public | private
    tags = Column(JSON, nullable=True)  # array of strings
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SASTFileChange(Base):
    """Track file changes for incremental analysis"""
    __tablename__ = "sast_file_changes"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("sast_scans.id"), nullable=True)
    
    # File information
    file_path = Column(String(500), nullable=False)
    change_type = Column(String(20), nullable=False)  # 'added', 'modified', 'deleted'
    
    # Change details
    old_hash = Column(String(64), nullable=True)  # SHA-256 hash of previous version
    new_hash = Column(String(64), nullable=True)  # SHA-256 hash of current version
    lines_added = Column(Integer, default=0)
    lines_removed = Column(Integer, default=0)
    
    # Git information
    commit_hash = Column(String(40), nullable=True)
    commit_message = Column(Text, nullable=True)
    author = Column(String(100), nullable=True)
    
    # Timestamps
    detected_at = Column(DateTime, default=func.now())
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    project = relationship("SASTProject")
    scan = relationship("SASTScan")
    
    # Indexes
    __table_args__ = (
        Index('idx_file_changes_project_scan', 'project_id', 'scan_id'),
        Index('idx_file_changes_path', 'file_path'),
        Index('idx_file_changes_type', 'change_type'),
    )

class SASTBackgroundJob(Base):
    """Background jobs for long-running SAST operations"""
    __tablename__ = "sast_background_jobs"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    
    # Job details
    job_type = Column(String(50), nullable=False)  # 'scan', 'analysis', 'coverage', etc.
    status = Column(String(20), default='pending')  # 'pending', 'running', 'completed', 'failed'
    priority = Column(Integer, default=5)  # 1-10, higher is more important
    
    # Job parameters
    parameters = Column(JSON, nullable=True)  # Job-specific parameters
    result = Column(JSON, nullable=True)     # Job result/output
    
    # Progress tracking
    progress = Column(Float, default=0.0)  # 0-100
    current_step = Column(String(100), nullable=True)
    total_steps = Column(Integer, default=0)
    
    # Error handling
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    
    # Timing
    created_at = Column(DateTime, default=func.now())
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    scheduled_at = Column(DateTime, nullable=True)
    
    # Worker information
    worker_id = Column(String(100), nullable=True)
    worker_pid = Column(Integer, nullable=True)
    
    # Relationships
    project = relationship("SASTProject")
    
    # Indexes
    __table_args__ = (
        Index('idx_background_jobs_project_status', 'project_id', 'status'),
        Index('idx_background_jobs_priority', 'priority'),
        Index('idx_background_jobs_type', 'job_type'),
        Index('idx_background_jobs_scheduled', 'scheduled_at'),
    )

# ============================================================================
# Metrics and Trends Models
# ============================================================================

class SASTProjectMetrics(Base):
    __tablename__ = "sast_project_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("sast_scans.id"), nullable=False)
    lines_of_code = Column(Integer, nullable=False)
    files_count = Column(Integer, nullable=False)
    functions_count = Column(Integer, nullable=False)
    classes_count = Column(Integer, nullable=False)
    complexity = Column(Float, nullable=False)
    maintainability_rating = Column(Enum(Rating), nullable=False)
    security_rating = Column(Enum(Rating), nullable=False)
    reliability_rating = Column(Enum(Rating), nullable=False)
    coverage = Column(Float, nullable=False)
    duplication_density = Column(Float, nullable=False)
    total_issues = Column(Integer, nullable=False)
    bugs_count = Column(Integer, nullable=False)
    vulnerabilities_count = Column(Integer, nullable=False)
    code_smells_count = Column(Integer, nullable=False)
    security_hotspots_count = Column(Integer, nullable=False)
    total_debt = Column(Integer, nullable=False)  # in minutes
    debt_ratio = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class SASTProjectTrend(Base):
    __tablename__ = "sast_project_trends"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    date = Column(Date, nullable=False)
    total_issues = Column(Integer, nullable=False)
    bugs_count = Column(Integer, nullable=False)
    vulnerabilities_count = Column(Integer, nullable=False)
    code_smells_count = Column(Integer, nullable=False)
    coverage = Column(Float, nullable=False)
    duplication_density = Column(Float, nullable=False)
    complexity = Column(Float, nullable=False)
    maintainability_rating = Column(Enum(Rating), nullable=False)
    security_rating = Column(Enum(Rating), nullable=False)
    reliability_rating = Column(Enum(Rating), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# ============================================================================
# Rules Management
# ============================================================================

class SASTRule(Base):
    __tablename__ = "sast_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Classification
    category = Column(String(100), nullable=False)
    subcategory = Column(String(100), nullable=True)
    severity = Column(Enum(IssueSeverity), nullable=False)
    type = Column(Enum(IssueType), nullable=False)
    
    # Security metadata
    cwe_id = Column(String(20), nullable=True)
    owasp_category = Column(String(100), nullable=True)
    tags = Column(JSON, nullable=True)  # JSON array of tags
    
    # Configuration
    enabled = Column(Boolean, default=True)
    effort = Column(Integer, default=0)  # default effort in minutes
    
    # Language support
    languages = Column(JSON, nullable=True)  # JSON array of supported languages
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    @classmethod
    async def get_by_category(cls, db: AsyncSession, category: str) -> List["SASTRule"]:
        """Get rules by category"""
        result = await db.execute(select(cls).where(cls.category == category))
        return result.scalars().all()
    
    @classmethod
    async def get_enabled_rules(cls, db: AsyncSession) -> List["SASTRule"]:
        """Get all enabled rules"""
        result = await db.execute(select(cls).where(cls.enabled == True))
        return result.scalars().all()

# ============================================================================
# Rule Profiles
# ============================================================================

class SASTRuleProfile(Base):
    __tablename__ = "sast_rule_profiles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True)
    language = Column(String(50), nullable=False)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SASTRuleProfileRule(Base):
    __tablename__ = "sast_rule_profile_rules"

    id = Column(Integer, primary_key=True, index=True)
    profile_id = Column(Integer, ForeignKey("sast_rule_profiles.id"), nullable=False)
    rule_id = Column(Integer, ForeignKey("sast_rules.id"), nullable=False)
    enabled = Column(Boolean, default=True)
    severity_override = Column(String(20), nullable=True)  # CRITICAL/HIGH/MEDIUM/LOW/INFO
    created_at = Column(DateTime, default=datetime.utcnow)

# ============================================================================
# Taint / Data Flow Models
# ============================================================================

class SASTTaintFlow(Base):
    __tablename__ = "sast_taint_flows"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("sast_scans.id"), nullable=True)
    issue_id = Column(Integer, ForeignKey("sast_issues.id"), nullable=True)
    source = Column(String(255), nullable=True)
    sink = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class SASTTaintStep(Base):
    __tablename__ = "sast_taint_steps"

    id = Column(Integer, primary_key=True, index=True)
    flow_id = Column(Integer, ForeignKey("sast_taint_flows.id"), nullable=False)
    file_path = Column(String(500), nullable=False)
    line_number = Column(Integer, nullable=False)
    function_name = Column(String(255), nullable=True)
    code_snippet = Column(Text, nullable=True)
    order_index = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


# ============================================================================
# Quality Gates
# ============================================================================

class SASTQualityGate(Base):
    __tablename__ = "sast_quality_gates"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    
    # Gate conditions
    max_blocker_issues = Column(Integer, default=0)
    max_critical_issues = Column(Integer, default=5)
    max_major_issues = Column(Integer, default=20)
    max_minor_issues = Column(Integer, default=100)
    max_info_issues = Column(Integer, default=500)
    
    # Coverage conditions
    min_coverage = Column(Float, default=80.0)
    min_branch_coverage = Column(Float, default=80.0)
    
    # Technical debt conditions
    max_debt_ratio = Column(Float, default=5.0)  # percentage
    max_technical_debt = Column(Integer, default=1440)  # minutes (1 day)
    
    # Duplication conditions
    max_duplicated_lines = Column(Integer, default=1000)
    max_duplicated_blocks = Column(Integer, default=100)
    
    # Rating conditions
    min_maintainability_rating = Column(Enum(Rating), default=Rating.C)
    min_security_rating = Column(Enum(Rating), default=Rating.C)
    min_reliability_rating = Column(Enum(Rating), default=Rating.C)
    
    # Status
    status = Column(Enum(QualityGateStatus), default=QualityGateStatus.PASSED)
    last_evaluation = Column(DateTime, nullable=True)
    
    # Evaluation results
    evaluation_results = Column(JSON, nullable=True)  # JSON with condition results
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    project = relationship("SASTProject", back_populates="quality_gates")
    
    @classmethod
    async def get_by_project(cls, db: AsyncSession, project_id: int) -> Optional["SASTQualityGate"]:
        """Get quality gate for a project"""
        result = await db.execute(select(cls).where(cls.project_id == project_id))
        return result.scalar_one_or_none()

# ============================================================================
# Project Configuration
# ============================================================================

class SASTProjectConfiguration(Base):
    __tablename__ = "sast_project_configurations"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False)
    
    # Scan configuration
    scan_patterns = Column(JSON, nullable=True)  # JSON array of include/exclude patterns
    excluded_files = Column(JSON, nullable=True)  # JSON array of excluded files
    excluded_directories = Column(JSON, nullable=True)  # JSON array of excluded directories
    
    # Rule configuration
    enabled_rules = Column(JSON, nullable=True)  # JSON array of enabled rule IDs
    disabled_rules = Column(JSON, nullable=True)  # JSON array of disabled rule IDs
    rule_severities = Column(JSON, nullable=True)  # JSON object with rule_id -> severity mapping
    
    # Quality gate configuration
    quality_gate_id = Column(Integer, ForeignKey("sast_quality_gates.id"), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    project = relationship("SASTProject")
    quality_gate = relationship("SASTQualityGate")
    
    @classmethod
    async def get_by_project(cls, db: AsyncSession, project_id: int) -> Optional["SASTProjectConfiguration"]:
        """Get configuration for a project"""
        result = await db.execute(select(cls).where(cls.project_id == project_id))
        return result.scalar_one_or_none() 

# ============================================================================
# Baseline (New Code definition)
# ============================================================================

class BaselineType(str, enum.Enum):
    DATE = "DATE"          # Use a calendar date as baseline (leak period)
    BRANCH = "BRANCH"      # Use another branch/ref as baseline


class SASTBaseline(Base):
    __tablename__ = "sast_baselines"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("sast_projects.id"), nullable=False, index=True)
    baseline_type = Column(Enum(BaselineType), nullable=False, default=BaselineType.DATE)
    value = Column(String(255), nullable=False)  # ISO date string or branch/ref name
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @classmethod
    async def get_for_project(cls, db: AsyncSession, project_id: int) -> Optional["SASTBaseline"]:
        result = await db.execute(select(cls).where(cls.project_id == project_id))
        return result.scalars().first()

    @classmethod
    async def upsert_for_project(
        cls,
        db: AsyncSession,
        *,
        project_id: int,
        baseline_type: BaselineType,
        value: str,
    ) -> "SASTBaseline":
        row = await cls.get_for_project(db, project_id)
        if row:
            row.baseline_type = baseline_type
            row.value = value
        else:
            row = cls(project_id=project_id, baseline_type=baseline_type, value=value)
            db.add(row)
        await db.commit()
        await db.refresh(row)
        return row 