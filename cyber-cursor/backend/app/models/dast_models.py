from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, Float, 
    JSON, ForeignKey, Index, UniqueConstraint, CheckConstraint
)
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB
from sqlalchemy.sql import func
import uuid
from datetime import datetime

Base = declarative_base()

# ============================================================================
# CORE DAST MODELS
# ============================================================================

class DASTProject(Base):
    """DAST Project - Main container for all DAST activities"""
    __tablename__ = "dast_projects"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    target_urls = Column(ARRAY(String), nullable=False)
    scope_config = Column(JSONB, default={})
    status = Column(String(50), default="active")
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    scans = relationship("DASTScan", back_populates="project", cascade="all, delete-orphan")
    http_entries = relationship("DASTHttpEntry", back_populates="project", cascade="all, delete-orphan")
    crawl_results = relationship("DASTCrawlResult", back_populates="project", cascade="all, delete-orphan")
    rules = relationship("DASTMatchReplaceRule", back_populates="project", cascade="all, delete-orphan")
    scan_profiles = relationship("DASTScanProfile", back_populates="project", cascade="all, delete-orphan")
    intruder_attacks = relationship("DASTIntruderAttack", back_populates="project", cascade="all, delete-orphan")
    repeater_requests = relationship("DASTRepeaterRequest", back_populates="project", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index("idx_dast_projects_created_by", "created_by"),
        Index("idx_dast_projects_status", "status"),
        Index("idx_dast_projects_created_at", "created_at"),
    )

class DASTScanProfile(Base):
    """Scan profiles for different types of security scans"""
    __tablename__ = "dast_scan_profiles"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    modules = Column(ARRAY(String), nullable=False)
    settings = Column(JSONB, nullable=False)
    is_default = Column(Boolean, default=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    project = relationship("DASTProject", back_populates="scan_profiles")
    scans = relationship("DASTScan", back_populates="profile")
    
    # Constraints
    __table_args__ = (
        UniqueConstraint("project_id", "name", name="uq_scan_profile_name_per_project"),
        Index("idx_scan_profiles_project_id", "project_id"),
        Index("idx_scan_profiles_is_default", "is_default"),
    )

class DASTScan(Base):
    """Security scan instances"""
    __tablename__ = "dast_scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    profile_id = Column(UUID(as_uuid=True), ForeignKey("dast_scan_profiles.id"), nullable=False)
    name = Column(String(255), nullable=False)
    target_urls = Column(ARRAY(String), nullable=False)
    status = Column(String(50), default="pending")  # pending, running, completed, failed, paused
    progress = Column(Float, default=0.0)
    total_requests = Column(Integer, default=0)
    completed_requests = Column(Integer, default=0)
    issues_found = Column(Integer, default=0)
    scan_config = Column(JSONB, default={})
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    project = relationship("DASTProject", back_populates="scans")
    profile = relationship("DASTScanProfile", back_populates="scans")
    issues = relationship("DASTScanIssue", back_populates="scan", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index("idx_dast_scans_project_id", "project_id"),
        Index("idx_dast_scans_status", "status"),
        Index("idx_dast_scans_created_by", "created_by"),
        Index("idx_dast_scans_started_at", "started_at"),
        CheckConstraint("progress >= 0.0 AND progress <= 100.0", name="chk_scan_progress"),
    )

class DASTScanIssue(Base):
    """Security issues found during scans"""
    __tablename__ = "dast_scan_issues"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("dast_scans.id"), nullable=False)
    type = Column(String(100), nullable=False)  # sql_injection, xss, csrf, etc.
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    url = Column(String(2000), nullable=False)
    evidence = Column(Text)
    confidence = Column(Float, nullable=False)  # 0.0 to 100.0
    cwe_id = Column(String(20))
    cvss_score = Column(Float)
    status = Column(String(50), default="open")  # open, confirmed, false_positive, fixed
    tags = Column(ARRAY(String), default=[])
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    scan = relationship("DASTScan", back_populates="issues")
    
    # Indexes
    __table_args__ = (
        Index("idx_scan_issues_scan_id", "scan_id"),
        Index("idx_scan_issues_type", "type"),
        Index("idx_scan_issues_severity", "severity"),
        Index("idx_scan_issues_status", "status"),
        Index("idx_scan_issues_discovered_at", "discovered_at"),
        CheckConstraint("confidence >= 0.0 AND confidence <= 100.0", name="chk_issue_confidence"),
        CheckConstraint("cvss_score >= 0.0 AND cvss_score <= 10.0", name="chk_cvss_score"),
    )

# ============================================================================
# TRAFFIC ANALYSIS MODELS
# ============================================================================

class DASTHttpEntry(Base):
    """HTTP request/response entries captured by proxy"""
    __tablename__ = "dast_http_entries"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    method = Column(String(10), nullable=False)
    url = Column(String(2000), nullable=False)
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False)  # http, https
    request_headers = Column(JSONB, nullable=False)
    request_body = Column(Text)
    request_params = Column(JSONB, default={})
    request_size = Column(Integer, default=0)
    response_headers = Column(JSONB)
    response_body = Column(Text)
    response_size = Column(Integer, default=0)
    status_code = Column(Integer)
    content_type = Column(String(100))
    duration = Column(Integer, default=0)  # milliseconds
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    tags = Column(ARRAY(String), default=[])
    notes = Column(Text)
    highlighted = Column(Boolean, default=False)
    
    # Relationships
    project = relationship("DASTProject", back_populates="http_entries")
    
    # Indexes
    __table_args__ = (
        Index("idx_http_entries_project_id", "project_id"),
        Index("idx_http_entries_method", "method"),
        Index("idx_http_entries_status_code", "status_code"),
        Index("idx_http_entries_host", "host"),
        Index("idx_http_entries_timestamp", "timestamp"),
        Index("idx_http_entries_url_gin", "url", postgresql_using="gin"),
        Index("idx_http_entries_request_headers_gin", "request_headers", postgresql_using="gin"),
        Index("idx_http_entries_response_headers_gin", "response_headers", postgresql_using="gin"),
    )

# ============================================================================
# CRAWLER & SITE MAPPING MODELS
# ============================================================================

class DASTCrawlResult(Base):
    """Results from web crawler"""
    __tablename__ = "dast_crawl_results"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    url = Column(String(2000), nullable=False)
    method = Column(String(10), nullable=False)
    status_code = Column(Integer)
    content_type = Column(String(100))
    title = Column(String(500))
    depth = Column(Integer, default=0)
    parent_url = Column(String(2000))
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    last_accessed = Column(DateTime(timezone=True))
    in_scope = Column(Boolean, default=True)
    tags = Column(ARRAY(String), default=[])
    notes = Column(Text)
    
    # Relationships
    project = relationship("DASTProject", back_populates="crawl_results")
    
    # Indexes
    __table_args__ = (
        Index("idx_crawl_results_project_id", "project_id"),
        Index("idx_crawl_results_url", "url"),
        Index("idx_crawl_results_depth", "depth"),
        Index("idx_crawl_results_in_scope", "in_scope"),
        Index("idx_crawl_results_discovered_at", "discovered_at"),
        Index("idx_crawl_results_parent_url", "parent_url"),
    )

# ============================================================================
# TOOLS MODELS
# ============================================================================

class DASTMatchReplaceRule(Base):
    """Match and replace rules for traffic modification"""
    __tablename__ = "dast_match_replace_rules"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    match_pattern = Column(String(1000), nullable=False)
    replace_pattern = Column(String(1000), nullable=False)
    match_type = Column(String(50), default="regex")  # regex, string, wildcard
    apply_to = Column(String(50), default="both")  # request, response, both
    enabled = Column(Boolean, default=True)
    priority = Column(Integer, default=0)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    project = relationship("DASTProject", back_populates="rules")
    
    # Indexes
    __table_args__ = (
        Index("idx_match_replace_rules_project_id", "project_id"),
        Index("idx_match_replace_rules_enabled", "enabled"),
        Index("idx_match_replace_rules_priority", "priority"),
        Index("idx_match_replace_rules_apply_to", "apply_to"),
    )

class DASTIntruderAttack(Base):
    """Intruder tool attacks"""
    __tablename__ = "dast_intruder_attacks"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    name = Column(String(255), nullable=False)
    target_url = Column(String(2000), nullable=False)
    attack_type = Column(String(50), nullable=False)  # sniper, battering_ram, pitchfork, cluster_bomb
    payload_sets = Column(JSONB, nullable=False)
    positions = Column(JSONB, nullable=False)
    status = Column(String(50), default="pending")  # pending, running, completed, failed, paused
    progress = Column(Float, default=0.0)
    total_requests = Column(Integer, default=0)
    completed_requests = Column(Integer, default=0)
    successful_requests = Column(Integer, default=0)
    failed_requests = Column(Integer, default=0)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    project = relationship("DASTProject", back_populates="intruder_attacks")
    results = relationship("DASTIntruderResult", back_populates="attack", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index("idx_intruder_attacks_project_id", "project_id"),
        Index("idx_intruder_attacks_status", "status"),
        Index("idx_intruder_attacks_attack_type", "attack_type"),
        Index("idx_intruder_attacks_created_by", "created_by"),
        CheckConstraint("progress >= 0.0 AND progress <= 100.0", name="chk_intruder_progress"),
    )

class DASTIntruderResult(Base):
    """Results from intruder attacks"""
    __tablename__ = "dast_intruder_results"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    attack_id = Column(UUID(as_uuid=True), ForeignKey("dast_intruder_attacks.id"), nullable=False)
    payload = Column(String(1000), nullable=False)
    status_code = Column(Integer)
    response_size = Column(Integer, default=0)
    response_time = Column(Integer, default=0)  # milliseconds
    response_headers = Column(JSONB)
    response_body = Column(Text)
    content_type = Column(String(100))
    error = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    highlighted = Column(Boolean, default=False)
    notes = Column(Text)
    
    # Relationships
    attack = relationship("DASTIntruderAttack", back_populates="results")
    
    # Indexes
    __table_args__ = (
        Index("idx_intruder_results_attack_id", "attack_id"),
        Index("idx_intruder_results_status_code", "status_code"),
        Index("idx_intruder_results_timestamp", "timestamp"),
        Index("idx_intruder_results_highlighted", "highlighted"),
    )

class DASTRepeaterRequest(Base):
    """Repeater tool requests"""
    __tablename__ = "dast_repeater_requests"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    name = Column(String(255), nullable=False)
    method = Column(String(10), nullable=False)
    url = Column(String(2000), nullable=False)
    headers = Column(JSONB, nullable=False)
    body = Column(Text)
    params = Column(JSONB, default={})
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    project = relationship("DASTProject", back_populates="repeater_requests")
    responses = relationship("DASTRepeaterResponse", back_populates="request", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index("idx_repeater_requests_project_id", "project_id"),
        Index("idx_repeater_requests_method", "method"),
        Index("idx_repeater_requests_created_by", "created_by"),
        Index("idx_repeater_requests_created_at", "created_at"),
    )

class DASTRepeaterResponse(Base):
    """Responses from repeater requests"""
    __tablename__ = "dast_repeater_responses"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id = Column(UUID(as_uuid=True), ForeignKey("dast_repeater_requests.id"), nullable=False)
    status_code = Column(Integer, nullable=False)
    headers = Column(JSONB, nullable=False)
    body = Column(Text)
    content_type = Column(String(100))
    size = Column(Integer, default=0)
    duration = Column(Integer, default=0)  # milliseconds
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    error = Column(Text)
    
    # Relationships
    request = relationship("DASTRepeaterRequest", back_populates="responses")
    
    # Indexes
    __table_args__ = (
        Index("idx_repeater_responses_request_id", "request_id"),
        Index("idx_repeater_responses_status_code", "status_code"),
        Index("idx_repeater_responses_timestamp", "timestamp"),
    )

# ============================================================================
# AUDIT & COMPLIANCE MODELS
# ============================================================================

class DASTAuditLog(Base):
    """Audit logging for compliance requirements"""
    __tablename__ = "dast_audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    action = Column(String(100), nullable=False)  # scan_started, scan_stopped, rule_created, etc.
    resource_type = Column(String(50), nullable=False)  # scan, rule, profile, etc.
    resource_id = Column(UUID(as_uuid=True))
    details = Column(JSONB, default={})
    ip_address = Column(String(45))  # IPv4 or IPv6
    user_agent = Column(String(500))
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    
    # Indexes
    __table_args__ = (
        Index("idx_audit_logs_project_id", "project_id"),
        Index("idx_audit_logs_user_id", "user_id"),
        Index("idx_audit_logs_action", "action"),
        Index("idx_audit_logs_timestamp", "timestamp"),
        Index("idx_audit_logs_resource", "resource_type", "resource_id"),
    )

# ============================================================================
# USER MANAGEMENT & PERMISSIONS
# ============================================================================

class DASTUserPermission(Base):
    """User permissions for DAST projects"""
    __tablename__ = "dast_user_permissions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    role = Column(String(50), nullable=False)  # owner, admin, user, viewer
    permissions = Column(JSONB, default={})
    granted_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True))
    
    # Constraints
    __table_args__ = (
        UniqueConstraint("user_id", "project_id", name="uq_user_project_permission"),
        Index("idx_user_permissions_user_id", "user_id"),
        Index("idx_user_permissions_project_id", "project_id"),
        Index("idx_user_permissions_role", "role"),
        CheckConstraint("role IN ('owner', 'admin', 'user', 'viewer')", name="chk_valid_role"),
    )

# ============================================================================
# CONFIGURATION & SETTINGS MODELS
# ============================================================================

class DASTProjectSettings(Base):
    """Project-specific configuration settings"""
    __tablename__ = "dast_project_settings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False, unique=True)
    proxy_settings = Column(JSONB, default={})
    scanner_settings = Column(JSONB, default={})
    crawler_settings = Column(JSONB, default={})
    notification_settings = Column(JSONB, default={})
    security_settings = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    project = relationship("DASTProject")
    
    # Indexes
    __table_args__ = (
        Index("idx_project_settings_project_id", "project_id"),
    )

# ============================================================================
# NOTIFICATION & ALERTING MODELS
# ============================================================================

class DASTNotification(Base):
    """Notifications and alerts for DAST activities"""
    __tablename__ = "dast_notifications"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("dast_projects.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    type = Column(String(50), nullable=False)  # scan_completed, issue_found, etc.
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), default="info")  # info, warning, error, critical
    read = Column(Boolean, default=False)
    action_url = Column(String(2000))
    notification_metadata = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    read_at = Column(DateTime(timezone=True))
    
    # Indexes
    __table_args__ = (
        Index("idx_notifications_project_id", "project_id"),
        Index("idx_notifications_user_id", "user_id"),
        Index("idx_notifications_type", "type"),
        Index("idx_notifications_severity", "severity"),
        Index("idx_notifications_read", "read"),
        Index("idx_notifications_created_at", "created_at"),
    )
