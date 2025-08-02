#!/usr/bin/env python3
"""
Database models for SAST (Static Application Security Testing)
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Float, JSON, ForeignKey, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

Base = declarative_base()

class SASTScan(Base):
    """SAST scan history table"""
    __tablename__ = 'sast_scans'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_name = Column(String(255), nullable=False)
    project_path = Column(String(500), nullable=False)
    triggered_by = Column(String(100), nullable=False)  # user_id
    start_time = Column(DateTime, default=datetime.utcnow, nullable=False)
    end_time = Column(DateTime)
    status = Column(String(50), default='running')  # running, completed, failed
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    scan_duration = Column(Float)  # in seconds
    languages_detected = Column(JSON)  # list of detected languages
    tools_used = Column(JSON)  # list of tools used
    scan_config = Column(JSON)  # scan configuration
    error_message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    vulnerabilities = relationship("SASTVulnerability", back_populates="scan")
    recommendations = relationship("SASTRecommendation", back_populates="scan")
    
    # Indexes
    __table_args__ = (
        Index('idx_sast_scans_project', 'project_name'),
        Index('idx_sast_scans_status', 'status'),
        Index('idx_sast_scans_triggered_by', 'triggered_by'),
        Index('idx_sast_scans_created_at', 'created_at'),
    )

class SASTVulnerability(Base):
    """SAST vulnerability results table"""
    __tablename__ = 'sast_vulnerabilities'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey('sast_scans.id'), nullable=False)
    original_id = Column(String(255))  # ID from the scanning tool
    file_name = Column(String(500), nullable=False)
    line_number = Column(Integer, nullable=False)
    column = Column(Integer)
    severity = Column(String(50), nullable=False)  # critical, high, medium, low
    vulnerability_type = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    recommendation = Column(Text)
    rule_id = Column(String(255))
    tool = Column(String(100), nullable=False)  # bandit, pylint, semgrep, etc.
    cwe_id = Column(String(50))
    scan_date = Column(DateTime, default=datetime.utcnow)
    code_snippet = Column(Text)
    context = Column(JSON)  # additional context from the tool
    risk_score = Column(Float)  # calculated risk score
    status = Column(String(50), default='open')  # open, fixed, false_positive, ignored
    assigned_to = Column(String(100))  # user_id
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scan = relationship("SASTScan", back_populates="vulnerabilities")
    recommendations = relationship("SASTRecommendation", back_populates="vulnerability")
    
    # Indexes
    __table_args__ = (
        Index('idx_sast_vulns_scan_id', 'scan_id'),
        Index('idx_sast_vulns_severity', 'severity'),
        Index('idx_sast_vulns_tool', 'tool'),
        Index('idx_sast_vulns_status', 'status'),
        Index('idx_sast_vulns_file', 'file_name'),
        Index('idx_sast_vulns_type', 'vulnerability_type'),
    )

class SASTRecommendation(Base):
    """AI-generated recommendations for vulnerabilities"""
    __tablename__ = 'sast_recommendations'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey('sast_scans.id'), nullable=False)
    vulnerability_id = Column(String(36), ForeignKey('sast_vulnerabilities.id'), nullable=False)
    recommendation_type = Column(String(50), nullable=False)  # fix, explanation, best_practice
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    code_fix = Column(Text)
    before_code = Column(Text)
    after_code = Column(Text)
    confidence_score = Column(Float, nullable=False)
    reasoning = Column(Text)
    tags = Column(JSON)  # list of tags
    ai_model = Column(String(100))  # gpt-3.5-turbo, etc.
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("SASTScan", back_populates="recommendations")
    vulnerability = relationship("SASTVulnerability", back_populates="recommendations")
    
    # Indexes
    __table_args__ = (
        Index('idx_sast_recs_vuln_id', 'vulnerability_id'),
        Index('idx_sast_recs_scan_id', 'scan_id'),
        Index('idx_sast_recs_type', 'recommendation_type'),
        Index('idx_sast_recs_confidence', 'confidence_score'),
    )

class SASTProject(Base):
    """SAST project configuration and metadata"""
    __tablename__ = 'sast_projects'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text)
    repository_url = Column(String(500))
    branch = Column(String(100), default='main')
    language = Column(String(100))  # primary language
    languages = Column(JSON)  # list of all languages
    scan_config = Column(JSON)  # default scan configuration
    risk_threshold = Column(Float, default=30.0)  # risk score threshold for CI/CD
    auto_scan = Column(Boolean, default=False)  # enable automatic scanning
    scan_schedule = Column(String(100))  # cron expression for scheduled scans
    created_by = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Indexes
    __table_args__ = (
        Index('idx_sast_projects_name', 'name'),
        Index('idx_sast_projects_created_by', 'created_by'),
    )

class SASTScanConfig(Base):
    """SAST scan configuration templates"""
    __tablename__ = 'sast_scan_configs'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    description = Column(Text)
    config_type = Column(String(50), nullable=False)  # default, custom, template
    language = Column(String(100))  # specific language or 'all'
    tools_enabled = Column(JSON)  # list of enabled tools
    tool_configs = Column(JSON)  # specific configurations for each tool
    severity_threshold = Column(String(50), default='low')  # minimum severity to report
    exclude_patterns = Column(JSON)  # patterns to exclude from scanning
    include_patterns = Column(JSON)  # patterns to include in scanning
    timeout = Column(Integer, default=3600)  # scan timeout in seconds
    max_file_size = Column(Integer, default=10485760)  # max file size in bytes
    created_by = Column(String(100), nullable=False)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Indexes
    __table_args__ = (
        Index('idx_sast_configs_name', 'name'),
        Index('idx_sast_configs_type', 'config_type'),
        Index('idx_sast_configs_language', 'language'),
    )

class SASTReport(Base):
    """SAST scan reports and exports"""
    __tablename__ = 'sast_reports'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey('sast_scans.id'), nullable=False)
    report_type = Column(String(50), nullable=False)  # pdf, csv, json, html
    format = Column(String(50), nullable=False)
    file_path = Column(String(500))  # path to generated report file
    file_size = Column(Integer)  # file size in bytes
    download_url = Column(String(500))  # URL for downloading the report
    generated_by = Column(String(100), nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)  # when the report expires
    is_public = Column(Boolean, default=False)  # whether report is publicly accessible
    
    # Indexes
    __table_args__ = (
        Index('idx_sast_reports_scan_id', 'scan_id'),
        Index('idx_sast_reports_type', 'report_type'),
        Index('idx_sast_reports_generated_by', 'generated_by'),
        Index('idx_sast_reports_expires_at', 'expires_at'),
    )

class SASTIntegration(Base):
    """SAST integration configurations (GitHub, GitLab, Jenkins, etc.)"""
    __tablename__ = 'sast_integrations'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    integration_type = Column(String(50), nullable=False)  # github, gitlab, jenkins, azure_devops
    config = Column(JSON, nullable=False)  # integration-specific configuration
    webhook_url = Column(String(500))  # webhook URL for the integration
    webhook_secret = Column(String(255))  # webhook secret for verification
    is_active = Column(Boolean, default=True)
    last_sync = Column(DateTime)  # last successful sync
    created_by = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Indexes
    __table_args__ = (
        Index('idx_sast_integrations_type', 'integration_type'),
        Index('idx_sast_integrations_active', 'is_active'),
        Index('idx_sast_integrations_created_by', 'created_by'),
    )

class SASTNotification(Base):
    """SAST scan notifications and alerts"""
    __tablename__ = 'sast_notifications'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey('sast_scans.id'), nullable=False)
    notification_type = Column(String(50), nullable=False)  # scan_complete, vulnerability_found, threshold_exceeded
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(50), default='info')  # info, warning, error, critical
    recipients = Column(JSON)  # list of recipient user IDs or email addresses
    sent_at = Column(DateTime, default=datetime.utcnow)
    read_at = Column(DateTime)  # when notification was read
    is_read = Column(Boolean, default=False)
    action_url = Column(String(500))  # URL to take action on the notification
    
    # Indexes
    __table_args__ = (
        Index('idx_sast_notifications_scan_id', 'scan_id'),
        Index('idx_sast_notifications_type', 'notification_type'),
        Index('idx_sast_notifications_severity', 'severity'),
        Index('idx_sast_notifications_sent_at', 'sent_at'),
        Index('idx_sast_notifications_read', 'is_read'),
    )

# Pydantic models for API responses
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class SASTScanCreate(BaseModel):
    project_name: str
    project_path: str
    scan_config: Optional[Dict[str, Any]] = None

class SASTScanResponse(BaseModel):
    id: str
    project_name: str
    status: str
    start_time: datetime
    end_time: Optional[datetime]
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_duration: Optional[float]
    languages_detected: Optional[List[str]]
    tools_used: Optional[List[str]]
    created_at: datetime

class SASTVulnerabilityResponse(BaseModel):
    id: str
    scan_id: str
    file_name: str
    line_number: int
    column: Optional[int]
    severity: str
    vulnerability_type: str
    description: str
    recommendation: Optional[str]
    rule_id: Optional[str]
    tool: str
    cwe_id: Optional[str]
    scan_date: datetime
    code_snippet: Optional[str]
    risk_score: Optional[float]
    status: str
    assigned_to: Optional[str]
    created_at: datetime

class SASTRecommendationResponse(BaseModel):
    id: str
    vulnerability_id: str
    recommendation_type: str
    title: str
    description: str
    code_fix: Optional[str]
    before_code: Optional[str]
    after_code: Optional[str]
    confidence_score: float
    reasoning: Optional[str]
    tags: List[str]
    ai_model: Optional[str]
    created_at: datetime

class SASTScanSummary(BaseModel):
    total_scans: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    average_risk_score: float
    most_common_vulnerabilities: List[Dict[str, Any]]
    scan_trends: List[Dict[str, Any]] 