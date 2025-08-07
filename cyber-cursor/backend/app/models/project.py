from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON, Enum, Float
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from datetime import datetime
from typing import Optional, List
from enum import Enum as PyEnum

from app.core.database import Base

class ProjectType(str, PyEnum):
    """Project types for different security tools"""
    SAST = "sast"
    DAST = "dast"
    RASP = "rasp"
    CLOUD = "cloud"
    GENERAL = "general"

class RepositoryType(str, PyEnum):
    """Repository types for source code management"""
    GIT = "git"
    SVN = "svn"
    ZIP = "zip"
    LOCAL = "local"

class ProjectStatus(str, PyEnum):
    """Project status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"
    DELETED = "deleted"

class Project(Base):
    """General Project model for managing projects across all security tools"""
    __tablename__ = "projects"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    key = Column(String(255), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    
    # Project type and status
    project_type = Column(Enum(ProjectType), default=ProjectType.GENERAL)
    status = Column(Enum(ProjectStatus), default=ProjectStatus.ACTIVE)
    
    # Repository information
    repository_type = Column(Enum(RepositoryType), nullable=True)
    repository_url = Column(String(500), nullable=True)
    repository_branch = Column(String(100), default="main")
    repository_username = Column(String(255), nullable=True)
    repository_token = Column(String(500), nullable=True)  # Encrypted
    
    # Source code information
    source_path = Column(String(500), nullable=True)  # Local path or extracted path
    language = Column(String(50), nullable=True)
    framework = Column(String(100), nullable=True)
    
    # Project metadata
    tags = Column(JSON, nullable=True)  # JSON array of tags
    project_metadata = Column(JSON, nullable=True)  # Additional project metadata
    
    # Security settings
    security_level = Column(String(50), default="standard")  # standard, high, critical
    compliance_frameworks = Column(JSON, nullable=True)  # JSON array of frameworks
    
    # Ownership and permissions
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    team_id = Column(Integer, ForeignKey("teams.id"), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    last_scan = Column(DateTime, nullable=True)
    last_sync = Column(DateTime, nullable=True)
    
    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    owner = relationship("User", foreign_keys=[owner_id])
    team = relationship("Team", back_populates="projects")
    scans = relationship("ProjectScan", back_populates="project")
    issues = relationship("ProjectIssue", back_populates="project")
    
    @classmethod
    async def get_by_key(cls, db: AsyncSession, key: str) -> Optional["Project"]:
        """Get project by key"""
        result = await db.execute(select(cls).where(cls.key == key))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, project_id: int) -> Optional["Project"]:
        """Get project by ID"""
        result = await db.execute(select(cls).where(cls.id == project_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_type(cls, db: AsyncSession, project_type: ProjectType, skip: int = 0, limit: int = 100) -> List["Project"]:
        """Get projects by type"""
        result = await db.execute(
            select(cls)
            .where(cls.project_type == project_type)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    @classmethod
    async def get_by_user(cls, db: AsyncSession, user_id: int, skip: int = 0, limit: int = 100) -> List["Project"]:
        """Get projects by user (owner or team member)"""
        result = await db.execute(
            select(cls)
            .where(
                (cls.owner_id == user_id) | 
                (cls.created_by == user_id)
            )
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    @classmethod
    async def create_project(cls, db: AsyncSession, **kwargs) -> "Project":
        """Create a new project"""
        project = cls(**kwargs)
        db.add(project)
        await db.commit()
        await db.refresh(project)
        return project

class ProjectScan(Base):
    """Project scan history and results"""
    __tablename__ = "project_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    
    # Scan details
    scan_type = Column(String(50), nullable=False)  # sast, dast, security, etc.
    scan_name = Column(String(255), nullable=False)
    scan_config = Column(JSON, nullable=True)  # Scan configuration
    
    # Status and progress
    status = Column(String(50), default="pending")  # pending, running, completed, failed
    progress = Column(Integer, default=0)  # 0-100
    
    # Results
    total_issues = Column(Integer, default=0)
    critical_issues = Column(Integer, default=0)
    high_issues = Column(Integer, default=0)
    medium_issues = Column(Integer, default=0)
    low_issues = Column(Integer, default=0)
    
    # Scan metadata
    scan_duration = Column(Integer, nullable=True)  # seconds
    files_scanned = Column(Integer, default=0)
    lines_scanned = Column(Integer, default=0)
    
    # Error handling
    error_message = Column(Text, nullable=True)
    error_details = Column(JSON, nullable=True)
    
    # Timestamps
    started_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    started_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)
    
    # Relationships
    project = relationship("Project", back_populates="scans")
    starter = relationship("User", foreign_keys=[started_by])
    issues = relationship("ProjectIssue", back_populates="scan")
    
    @classmethod
    async def get_by_project(cls, db: AsyncSession, project_id: int, skip: int = 0, limit: int = 100) -> List["ProjectScan"]:
        """Get scans for a project"""
        result = await db.execute(
            select(cls)
            .where(cls.project_id == project_id)
            .order_by(cls.started_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    @classmethod
    async def get_recent_scans(cls, db: AsyncSession, project_id: int, limit: int = 10) -> List["ProjectScan"]:
        """Get recent scans for a project"""
        result = await db.execute(
            select(cls)
            .where(cls.project_id == project_id)
            .order_by(cls.started_at.desc())
            .limit(limit)
        )
        return result.scalars().all()

class ProjectIssue(Base):
    """Issues found during project scans"""
    __tablename__ = "project_issues"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("project_scans.id"), nullable=True)
    
    # Issue details
    issue_type = Column(String(50), nullable=False)  # vulnerability, bug, code_smell, etc.
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    status = Column(String(20), default="open")  # open, confirmed, resolved, closed
    
    # Issue information
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    
    # Location
    file_path = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)
    start_line = Column(Integer, nullable=True)
    end_line = Column(Integer, nullable=True)
    
    # Security metadata
    cwe_id = Column(String(20), nullable=True)
    cvss_score = Column(Float, nullable=True)
    owasp_category = Column(String(100), nullable=True)
    
    # Assignment and tracking
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    resolved_at = Column(DateTime, nullable=True)
    
    # Relationships
    project = relationship("Project", back_populates="issues")
    scan = relationship("ProjectScan", back_populates="issues")
    assignee = relationship("User", foreign_keys=[assigned_to])
    creator = relationship("User", foreign_keys=[created_by])
    
    @classmethod
    async def get_by_project(cls, db: AsyncSession, project_id: int, skip: int = 0, limit: int = 100) -> List["ProjectIssue"]:
        """Get issues for a project"""
        result = await db.execute(
            select(cls)
            .where(cls.project_id == project_id)
            .order_by(cls.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    @classmethod
    async def get_by_severity(cls, db: AsyncSession, project_id: int, severity: str) -> List["ProjectIssue"]:
        """Get issues by severity for a project"""
        result = await db.execute(
            select(cls)
            .where(cls.project_id == project_id, cls.severity == severity)
            .order_by(cls.created_at.desc())
        )
        return result.scalars().all()

class Team(Base):
    """Teams for project organization"""
    __tablename__ = "teams"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Team settings
    is_active = Column(Boolean, default=True)
    team_type = Column(String(50), default="development")  # development, security, operations
    
    # Ownership
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    projects = relationship("Project", back_populates="team")
    members = relationship("TeamMember", back_populates="team")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, team_id: int) -> Optional["Team"]:
        """Get team by ID"""
        result = await db.execute(select(cls).where(cls.id == team_id))
        return result.scalar_one_or_none()

class TeamMember(Base):
    """Team membership"""
    __tablename__ = "team_members"
    
    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Role in team
    role = Column(String(50), default="member")  # owner, admin, member, viewer
    
    # Timestamps
    joined_at = Column(DateTime, default=func.now())
    
    # Relationships
    team = relationship("Team", back_populates="members")
    user = relationship("User")
    
    @classmethod
    async def get_team_members(cls, db: AsyncSession, team_id: int) -> List["TeamMember"]:
        """Get team members"""
        result = await db.execute(
            select(cls)
            .where(cls.team_id == team_id)
            .order_by(cls.joined_at)
        )
        return result.scalars().all() 