#!/usr/bin/env python3
"""
Database models for SAST (Static Application Security Testing)
"""

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

class AutoFixStatus(str, Enum):
    AVAILABLE = "available"
    APPLIED = "applied"
    NOT_AVAILABLE = "not_available"
    FAILED = "failed"

class SASTProject(Base):
    __tablename__ = "sast_projects"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    repository_url = Column(Text, nullable=True)
    language = Column(String(50), nullable=True)
    description = Column(Text, nullable=True)
    
    # Project configuration
    scan_config = Column(JSON, nullable=True)  # Scan configuration settings
    rules_config = Column(JSON, nullable=True)  # Custom rules configuration
    
    # Statistics
    total_scans = Column(Integer, default=0)
    avg_vulnerabilities = Column(Float, default=0.0)
    security_score = Column(Float, nullable=True)  # 0-100 security score
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    last_scan = Column(DateTime, nullable=True)
    
    # Relationships
    scans = relationship("SASTScan", back_populates="project")
    vulnerabilities = relationship("SASTVulnerability", back_populates="project")
    
    # Created by
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, project_id: str) -> Optional["SASTProject"]:
        """Get SAST project by ID"""
        result = await db.execute(select(cls).where(cls.id == project_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_all(cls, db: AsyncSession, skip: int = 0, limit: int = 100) -> List["SASTProject"]:
        """Get all SAST projects with pagination"""
        result = await db.execute(select(cls).offset(skip).limit(limit))
        return result.scalars().all()
    
    @classmethod
    async def get_by_language(cls, db: AsyncSession, language: str) -> List["SASTProject"]:
        """Get projects by programming language"""
        result = await db.execute(select(cls).where(cls.language == language))
        return result.scalars().all()
    
    def __repr__(self):
        return f"<SASTProject(id={self.id}, name='{self.name}', language='{self.language}')>"

class SASTScan(Base):
    __tablename__ = "sast_scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("sast_projects.id"), nullable=False)
    
    # Scan details
    scan_type = Column(String(50), nullable=False)  # full, incremental, custom
    status = Column(String(20), default=ScanStatus.QUEUED)
    
    # Scan configuration
    scan_config = Column(JSON, nullable=True)  # Scan configuration
    rules_enabled = Column(JSON, nullable=True)  # List of enabled rule IDs
    
    # Scan results
    vulnerabilities_found = Column(Integer, default=0)
    files_scanned = Column(Integer, default=0)
    lines_of_code = Column(Integer, default=0)
    scan_duration = Column(Float, nullable=True)  # Duration in seconds
    
    # Scan metadata
    scan_logs = Column(JSON, nullable=True)  # Detailed scan logs
    scan_summary = Column(JSON, nullable=True)  # Scan summary statistics
    
    # Timestamps
    started_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    project = relationship("SASTProject", back_populates="scans")
    vulnerabilities = relationship("SASTVulnerability", back_populates="scan")
    
    # Initiated by
    initiated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, scan_id: str) -> Optional["SASTScan"]:
        """Get SAST scan by ID"""
        result = await db.execute(select(cls).where(cls.id == scan_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_project(cls, db: AsyncSession, project_id: str, skip: int = 0, limit: int = 100) -> List["SASTScan"]:
        """Get scans by project ID"""
        result = await db.execute(
            select(cls).where(cls.project_id == project_id).offset(skip).limit(limit)
        )
        return result.scalars().all()
    
    @classmethod
    async def get_by_status(cls, db: AsyncSession, status: str) -> List["SASTScan"]:
        """Get scans by status"""
        result = await db.execute(select(cls).where(cls.status == status))
        return result.scalars().all()
    
    def __repr__(self):
        return f"<SASTScan(id={self.id}, project_id={self.project_id}, status='{self.status}')>"

class SASTVulnerability(Base):
    __tablename__ = "sast_vulnerabilities"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("sast_scans.id"), nullable=False)
    project_id = Column(UUID(as_uuid=True), ForeignKey("sast_projects.id"), nullable=False)
    
    # Vulnerability details
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False)
    status = Column(String(20), default=VulnerabilityStatus.OPEN)
    
    # Code location
    file_path = Column(Text, nullable=False)
    line_number = Column(Integer, nullable=False)
    column_number = Column(Integer, nullable=True)
    function_name = Column(String(255), nullable=True)
    
    # Vulnerability classification
    cwe_id = Column(String(20), nullable=True)
    owasp_category = Column(String(100), nullable=True)
    language = Column(String(50), nullable=True)
    
    # Code snippets
    vulnerable_code = Column(Text, nullable=True)
    fixed_code = Column(Text, nullable=True)
    context_before = Column(Text, nullable=True)
    context_after = Column(Text, nullable=True)
    
    # Auto-fix information
    auto_fix_available = Column(Boolean, default=False)
    auto_fix_status = Column(String(20), default=AutoFixStatus.NOT_AVAILABLE)
    auto_fix_suggestion = Column(Text, nullable=True)
    
    # Additional metadata
    tags = Column(JSON, nullable=True)  # Array of tags
    vuln_metadata = Column(JSON, nullable=True)  # Additional vulnerability metadata
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    fixed_at = Column(DateTime, nullable=True)
    
    # Relationships
    scan = relationship("SASTScan", back_populates="vulnerabilities")
    project = relationship("SASTProject", back_populates="vulnerabilities")
    rule = relationship("SASTRule", back_populates="vulnerabilities")
    rule_id = Column(UUID(as_uuid=True), ForeignKey("sast_rules.id"), nullable=True)
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, vulnerability_id: str) -> Optional["SASTVulnerability"]:
        """Get vulnerability by ID"""
        result = await db.execute(select(cls).where(cls.id == vulnerability_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_scan(cls, db: AsyncSession, scan_id: str) -> List["SASTVulnerability"]:
        """Get vulnerabilities by scan ID"""
        result = await db.execute(select(cls).where(cls.scan_id == scan_id))
        return result.scalars().all()
    
    @classmethod
    async def get_by_severity(cls, db: AsyncSession, severity: str) -> List["SASTVulnerability"]:
        """Get vulnerabilities by severity"""
        result = await db.execute(select(cls).where(cls.severity == severity))
        return result.scalars().all()
    
    @classmethod
    async def get_by_project(cls, db: AsyncSession, project_id: str, skip: int = 0, limit: int = 100) -> List["SASTVulnerability"]:
        """Get vulnerabilities by project ID"""
        result = await db.execute(
            select(cls).where(cls.project_id == project_id).offset(skip).limit(limit)
        )
        return result.scalars().all()
    
    def __repr__(self):
        return f"<SASTVulnerability(id={self.id}, title='{self.title}', severity='{self.severity}')>"

class SASTRule(Base):
    __tablename__ = "sast_rules"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Rule configuration
    language = Column(String(50), nullable=False)
    regex_pattern = Column(Text, nullable=True)
    ast_pattern = Column(JSON, nullable=True)  # AST-based pattern matching
    
    # Classification
    severity = Column(String(20), nullable=False)
    cwe_id = Column(String(20), nullable=True)
    owasp_category = Column(String(100), nullable=True)
    
    # Auto-fix configuration
    auto_fix_available = Column(Boolean, default=False)
    auto_fix_template = Column(Text, nullable=True)  # Auto-fix code template
    recommendation = Column(Text, nullable=True)
    
    # Rule metadata
    tags = Column(JSON, nullable=True)  # Array of tags
    rule_metadata = Column(JSON, nullable=True)  # Additional rule metadata
    
    # Status
    is_active = Column(Boolean, default=True)
    is_custom = Column(Boolean, default=False)  # Custom vs built-in rule
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    vulnerabilities = relationship("SASTVulnerability", back_populates="rule")
    
    # Created by (for custom rules)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, rule_id: str) -> Optional["SASTRule"]:
        """Get rule by ID"""
        result = await db.execute(select(cls).where(cls.id == rule_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_language(cls, db: AsyncSession, language: str) -> List["SASTRule"]:
        """Get rules by programming language"""
        result = await db.execute(select(cls).where(cls.language == language, cls.is_active == True))
        return result.scalars().all()
    
    @classmethod
    async def get_by_severity(cls, db: AsyncSession, severity: str) -> List["SASTRule"]:
        """Get rules by severity"""
        result = await db.execute(select(cls).where(cls.severity == severity, cls.is_active == True))
        return result.scalars().all()
    
    @classmethod
    async def get_active_rules(cls, db: AsyncSession) -> List["SASTRule"]:
        """Get all active rules"""
        result = await db.execute(select(cls).where(cls.is_active == True))
        return result.scalars().all()
    
    def __repr__(self):
        return f"<SASTRule(id={self.id}, name='{self.name}', language='{self.language}')>"

class SASTReport(Base):
    __tablename__ = "sast_reports"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("sast_scans.id"), nullable=False)
    project_id = Column(UUID(as_uuid=True), ForeignKey("sast_projects.id"), nullable=False)
    
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
    scan = relationship("SASTScan")
    project = relationship("SASTProject")
    
    # Generated by
    generated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, report_id: str) -> Optional["SASTReport"]:
        """Get report by ID"""
        result = await db.execute(select(cls).where(cls.id == report_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_scan(cls, db: AsyncSession, scan_id: str) -> List["SASTReport"]:
        """Get reports by scan ID"""
        result = await db.execute(select(cls).where(cls.scan_id == scan_id))
        return result.scalars().all()
    
    @classmethod
    async def get_by_project(cls, db: AsyncSession, project_id: str) -> List["SASTReport"]:
        """Get reports by project ID"""
        result = await db.execute(select(cls).where(cls.project_id == project_id))
        return result.scalars().all()
    
    def __repr__(self):
        return f"<SASTReport(id={self.id}, scan_id={self.scan_id}, type='{self.report_type}')>" 