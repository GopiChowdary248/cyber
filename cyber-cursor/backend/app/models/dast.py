from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON, Float, UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from datetime import datetime
from typing import Optional, List
from enum import Enum
import uuid

from app.core.database import Base

class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"

class VulnerabilitySeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VulnerabilityStatus(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    IGNORED = "ignored"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"

class AuthType(str, Enum):
    NONE = "none"
    COOKIE = "cookie"
    JWT = "jwt"
    OAUTH2 = "oauth2"
    BASIC = "basic"
    API_KEY = "api_key"

class ScanType(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    FULL = "full"
    CUSTOM = "custom"

class DASTProject(Base):
    __tablename__ = "dast_projects"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    target_url = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    
    # Authentication configuration
    auth_type = Column(String(20), default=AuthType.NONE)
    auth_config = Column(JSON, nullable=True)  # Authentication configuration
    
    # Scan configuration
    scan_config = Column(JSON, nullable=True)  # Scan settings
    scope_config = Column(JSON, nullable=True)  # URL scope configuration
    
    # Project metadata
    is_active = Column(Boolean, default=True)
    tags = Column(JSON, nullable=True)  # Array of tags
    
    # Statistics
    total_scans = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    security_score = Column(Float, nullable=True)  # 0-100 security score
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    last_scan = Column(DateTime, nullable=True)
    
    # Relationships
    scans = relationship("DASTScan", back_populates="project")
    vulnerabilities = relationship("DASTVulnerability", back_populates="project")
    
    # Created by
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, project_id: str) -> Optional["DASTProject"]:
        """Get DAST project by ID"""
        result = await db.execute(select(cls).where(cls.id == project_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_all(cls, db: AsyncSession, skip: int = 0, limit: int = 100) -> List["DASTProject"]:
        """Get all DAST projects with pagination"""
        result = await db.execute(select(cls).offset(skip).limit(limit))
        return result.scalars().all()
    
    def __repr__(self):
        return f"<DASTProject(id={self.id}, name='{self.name}', target_url='{self.target_url}')>"

class DASTScan(Base):
    __tablename__ = "dast_scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    
    # Scan details
    scan_type = Column(String(20), nullable=False, default=ScanType.FULL)
    status = Column(String(20), default=ScanStatus.QUEUED)
    
    # Scan configuration
    scan_config = Column(JSON, nullable=True)  # Scan configuration
    auth_config = Column(JSON, nullable=True)  # Authentication for this scan
    
    # Scan results
    vulnerabilities_found = Column(Integer, default=0)
    urls_scanned = Column(Integer, default=0)
    requests_made = Column(Integer, default=0)
    scan_duration = Column(Float, nullable=True)  # Duration in seconds
    
    # Scan metadata
    scan_logs = Column(JSON, nullable=True)  # Detailed scan logs
    scan_summary = Column(JSON, nullable=True)  # Scan summary statistics
    evidence_files = Column(JSON, nullable=True)  # Paths to evidence files
    
    # Timestamps
    started_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    project = relationship("DASTProject", back_populates="scans")
    vulnerabilities = relationship("DASTVulnerability", back_populates="scan")
    
    # Initiated by
    initiated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, scan_id: str) -> Optional["DASTScan"]:
        """Get DAST scan by ID"""
        result = await db.execute(select(cls).where(cls.id == scan_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_project(cls, db: AsyncSession, project_id: str, skip: int = 0, limit: int = 100) -> List["DASTScan"]:
        """Get scans by project ID"""
        result = await db.execute(
            select(cls).where(cls.project_id == project_id).offset(skip).limit(limit)
        )
        return result.scalars().all()
    
    @classmethod
    async def get_by_status(cls, db: AsyncSession, status: str) -> List["DASTScan"]:
        """Get scans by status"""
        result = await db.execute(select(cls).where(cls.status == status))
        return result.scalars().all()
    
    def __repr__(self):
        return f"<DASTScan(id={self.id}, project_id={self.project_id}, status='{self.status}')>"

class DASTVulnerability(Base):
    __tablename__ = "dast_vulnerabilities"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("dast_scans.id"), nullable=False)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    
    # Vulnerability details
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False)
    status = Column(String(20), default=VulnerabilityStatus.OPEN)
    
    # Request details
    url = Column(Text, nullable=False)
    http_method = Column(String(10), nullable=False)
    param_name = Column(String(100), nullable=True)
    param_value = Column(Text, nullable=True)
    
    # Vulnerability classification
    cwe_id = Column(String(20), nullable=True)
    owasp_category = Column(String(100), nullable=True)
    vuln_type = Column(String(50), nullable=True)  # sqli, xss, csrf, etc.
    
    # Evidence and payload
    payload = Column(Text, nullable=True)
    evidence = Column(JSON, nullable=True)  # Detailed evidence
    proof_of_concept = Column(Text, nullable=True)
    
    # Response analysis
    response_code = Column(Integer, nullable=True)
    response_time = Column(Float, nullable=True)
    response_size = Column(Integer, nullable=True)
    
    # Additional metadata
    tags = Column(JSON, nullable=True)  # Array of tags
    metadata = Column(JSON, nullable=True)  # Additional vulnerability metadata
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    fixed_at = Column(DateTime, nullable=True)
    
    # Relationships
    scan = relationship("DASTScan", back_populates="vulnerabilities")
    project = relationship("DASTProject", back_populates="vulnerabilities")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, vulnerability_id: str) -> Optional["DASTVulnerability"]:
        """Get vulnerability by ID"""
        result = await db.execute(select(cls).where(cls.id == vulnerability_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_scan(cls, db: AsyncSession, scan_id: str) -> List["DASTVulnerability"]:
        """Get vulnerabilities by scan ID"""
        result = await db.execute(select(cls).where(cls.scan_id == scan_id))
        return result.scalars().all()
    
    @classmethod
    async def get_by_severity(cls, db: AsyncSession, severity: str) -> List["DASTVulnerability"]:
        """Get vulnerabilities by severity"""
        result = await db.execute(select(cls).where(cls.severity == severity))
        return result.scalars().all()
    
    @classmethod
    async def get_by_project(cls, db: AsyncSession, project_id: str, skip: int = 0, limit: int = 100) -> List["DASTVulnerability"]:
        """Get vulnerabilities by project ID"""
        result = await db.execute(
            select(cls).where(cls.project_id == project_id).offset(skip).limit(limit)
        )
        return result.scalars().all()
    
    def __repr__(self):
        return f"<DASTVulnerability(id={self.id}, title='{self.title}', severity='{self.severity}')>"

class DASTPayload(Base):
    __tablename__ = "dast_payloads"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    vuln_type = Column(String(50), nullable=False)  # sqli, xss, cmdi, lfi, etc.
    payload = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    
    # Payload classification
    severity = Column(String(20), nullable=False)
    cwe_id = Column(String(20), nullable=True)
    owasp_category = Column(String(100), nullable=True)
    
    # Payload metadata
    language = Column(String(50), nullable=True)  # Target language if applicable
    tags = Column(JSON, nullable=True)  # Array of tags
    metadata = Column(JSON, nullable=True)  # Additional payload metadata
    
    # Status
    is_active = Column(Boolean, default=True)
    is_custom = Column(Boolean, default=False)  # Custom vs built-in payload
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Created by (for custom payloads)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, payload_id: str) -> Optional["DASTPayload"]:
        """Get payload by ID"""
        result = await db.execute(select(cls).where(cls.id == payload_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_type(cls, db: AsyncSession, vuln_type: str) -> List["DASTPayload"]:
        """Get payloads by vulnerability type"""
        result = await db.execute(select(cls).where(cls.vuln_type == vuln_type, cls.is_active == True))
        return result.scalars().all()
    
    @classmethod
    async def get_by_severity(cls, db: AsyncSession, severity: str) -> List["DASTPayload"]:
        """Get payloads by severity"""
        result = await db.execute(select(cls).where(cls.severity == severity, cls.is_active == True))
        return result.scalars().all()
    
    @classmethod
    async def get_active_payloads(cls, db: AsyncSession) -> List["DASTPayload"]:
        """Get all active payloads"""
        result = await db.execute(select(cls).where(cls.is_active == True))
        return result.scalars().all()
    
    def __repr__(self):
        return f"<DASTPayload(id={self.id}, name='{self.name}', vuln_type='{self.vuln_type}')>"

class DASTReport(Base):
    __tablename__ = "dast_reports"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("dast_scans.id"), nullable=False)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    
    # Report details
    report_type = Column(String(50), nullable=False)  # summary, detailed, executive
    format = Column(String(20), nullable=False)  # json, pdf, html, csv
    
    # Report content
    report_data = Column(JSON, nullable=True)  # Report data in JSON format
    report_file_path = Column(Text, nullable=True)  # Path to generated report file
    
    # Report metadata
    generated_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=True)  # Report expiration date
    
    # Status
    is_public = Column(Boolean, default=False)  # Public vs private report
    download_count = Column(Integer, default=0)  # Number of downloads
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    scan = relationship("DASTScan")
    project = relationship("DASTProject")
    
    # Generated by
    generated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, report_id: str) -> Optional["DASTReport"]:
        """Get report by ID"""
        result = await db.execute(select(cls).where(cls.id == report_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_scan(cls, db: AsyncSession, scan_id: str) -> List["DASTReport"]:
        """Get reports by scan ID"""
        result = await db.execute(select(cls).where(cls.scan_id == scan_id))
        return result.scalars().all()
    
    @classmethod
    async def get_by_project(cls, db: AsyncSession, project_id: str) -> List["DASTReport"]:
        """Get reports by project ID"""
        result = await db.execute(select(cls).where(cls.project_id == project_id))
        return result.scalars().all()
    
    def __repr__(self):
        return f"<DASTReport(id={self.id}, scan_id={self.scan_id}, type='{self.report_type}')>"

class DASTSession(Base):
    __tablename__ = "dast_sessions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    
    # Session details
    session_name = Column(String(255), nullable=False)
    session_type = Column(String(50), nullable=False)  # proxy, spider, scanner
    
    # Session configuration
    session_config = Column(JSON, nullable=True)  # Session configuration
    auth_config = Column(JSON, nullable=True)  # Authentication configuration
    
    # Session data
    requests_log = Column(JSON, nullable=True)  # Log of all requests
    responses_log = Column(JSON, nullable=True)  # Log of all responses
    cookies = Column(JSON, nullable=True)  # Session cookies
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    last_activity = Column(DateTime, nullable=True)
    
    # Relationships
    project = relationship("DASTProject")
    
    # Created by
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, session_id: str) -> Optional["DASTSession"]:
        """Get session by ID"""
        result = await db.execute(select(cls).where(cls.id == session_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_active_sessions(cls, db: AsyncSession) -> List["DASTSession"]:
        """Get all active sessions"""
        result = await db.execute(select(cls).where(cls.is_active == True))
        return result.scalars().all()
    
    def __repr__(self):
        return f"<DASTSession(id={self.id}, name='{self.session_name}', type='{self.session_type}')>" 