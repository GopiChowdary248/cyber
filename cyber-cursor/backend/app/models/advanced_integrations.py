from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON, ForeignKey, Float, Enum, UUID, SmallInteger, Numeric, BigInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
import enum
import uuid

Base = declarative_base()

# Enums
class IntegrationType(str, enum.Enum):
    SIEM = "siem"
    SOAR = "soar"
    GITOPS = "gitops"
    DEVSECOPS = "devsecops"
    TICKETING = "ticketing"
    CHATOPS = "chatops"
    MONITORING = "monitoring"
    SECURITY_TOOLS = "security_tools"

class IntegrationStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    CONFIGURING = "configuring"
    TESTING = "testing"

class PipelineStage(str, enum.Enum):
    BUILD = "build"
    TEST = "test"
    SECURITY_SCAN = "security_scan"
    DEPLOY = "deploy"
    MONITOR = "monitor"

class GitProvider(str, enum.Enum):
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"
    AZURE_DEVOPS = "azure_devops"
    GITEA = "gitea"

# SIEM Integration Models
class SIEMIntegration(Base):
    __tablename__ = "siem_integrations"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    siem_type = Column(String(100), nullable=False)  # Splunk, QRadar, ELK, etc.
    description = Column(Text)
    connection_config = Column(JSONB, nullable=False)  # Connection details
    authentication_method = Column(String(100))  # API key, OAuth, etc.
    api_endpoint = Column(String(500))
    api_version = Column(String(50))
    status = Column(Enum(IntegrationStatus), default=IntegrationStatus.CONFIGURING)
    last_sync = Column(DateTime(timezone=True))
    sync_frequency = Column(Integer, default=300)  # seconds
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    data_sources = relationship("SIEMDataSource", back_populates="integration")
    alert_rules = relationship("SIEMAlertRule", back_populates="integration")
    data_exports = relationship("SIEMDataExport", back_populates="integration")

class SIEMDataSource(Base):
    __tablename__ = "siem_data_sources"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    integration_id = Column(PGUUID(as_uuid=True), ForeignKey("siem_integrations.id"), nullable=False)
    source_name = Column(String(255), nullable=False)
    source_type = Column(String(100))  # logs, events, alerts, etc.
    data_format = Column(String(100))  # JSON, CEF, LEEF, etc.
    collection_method = Column(String(100))  # pull, push, syslog, etc.
    parsing_rules = Column(JSONB, default={})  # Data parsing configuration
    enabled = Column(Boolean, default=True)
    last_collection = Column(DateTime(timezone=True))
    collection_stats = Column(JSONB, default={})  # Collection statistics
    
    # Relationships
    integration = relationship("SIEMIntegration", back_populates="data_sources")

class SIEMAlertRule(Base):
    __tablename__ = "siem_alert_rules"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    integration_id = Column(PGUUID(as_uuid=True), ForeignKey("siem_integrations.id"), nullable=False)
    rule_name = Column(String(255), nullable=False)
    rule_description = Column(Text)
    rule_query = Column(Text)  # SIEM query language
    severity = Column(String(50))
    threshold = Column(Integer, default=1)
    time_window = Column(Integer, default=300)  # seconds
    enabled = Column(Boolean, default=True)
    last_triggered = Column(DateTime(timezone=True))
    trigger_count = Column(Integer, default=0)
    
    # Relationships
    integration = relationship("SIEMIntegration", back_populates="alert_rules")

class SIEMDataExport(Base):
    __tablename__ = "siem_data_exports"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    integration_id = Column(PGUUID(as_uuid=True), ForeignKey("siem_integrations.id"), nullable=False)
    export_name = Column(String(255), nullable=False)
    export_type = Column(String(100))  # findings, assets, compliance, etc.
    export_format = Column(String(50))  # JSON, CSV, XML, etc.
    schedule = Column(String(100))  # Cron expression
    last_export = Column(DateTime(timezone=True))
    export_config = Column(JSONB, default={})  # Export configuration
    enabled = Column(Boolean, default=True)
    
    # Relationships
    integration = relationship("SIEMIntegration", back_populates="data_exports")

# SOAR Platform Integration Models
class SOARIntegration(Base):
    __tablename__ = "soar_integrations"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    soar_type = Column(String(100), nullable=False)  # Cortex XSOAR, Phantom, etc.
    description = Column(Text)
    connection_config = Column(JSONB, nullable=False)
    api_endpoint = Column(String(500))
    api_key = Column(String(255))  # Encrypted
    status = Column(Enum(IntegrationStatus), default=IntegrationStatus.CONFIGURING)
    last_sync = Column(DateTime(timezone=True))
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    playbooks = relationship("SOARPlaybook", back_populates="integration")
    incidents = relationship("SOARIncident", back_populates="integration")

class SOARPlaybook(Base):
    __tablename__ = "soar_playbooks"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    integration_id = Column(PGUUID(as_uuid=True), ForeignKey("soar_integrations.id"), nullable=False)
    playbook_name = Column(String(255), nullable=False)
    playbook_id = Column(String(255))  # SOAR platform playbook ID
    description = Column(Text)
    playbook_type = Column(String(100))  # incident_response, threat_hunting, etc.
    automation_level = Column(String(50))  # manual, semi_automated, automated
    estimated_duration = Column(Integer)  # minutes
    enabled = Column(Boolean, default=True)
    last_execution = Column(DateTime(timezone=True))
    execution_count = Column(Integer, default=0)
    
    # Relationships
    integration = relationship("SOARIntegration", back_populates="playbooks")

class SOARIncident(Base):
    __tablename__ = "soar_incidents"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    integration_id = Column(PGUUID(as_uuid=True), ForeignKey("soar_integrations.id"), nullable=False)
    incident_id = Column(String(255), nullable=False)  # SOAR platform incident ID
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(50))
    status = Column(String(50))
    created_at = Column(DateTime(timezone=True))
    updated_at = Column(DateTime(timezone=True))
    assigned_to = Column(String(255))
    tags = Column(JSONB, default=[])
    
    # Relationships
    integration = relationship("SOARIntegration", back_populates="incidents")

# GitOps Integration Models
class GitOpsIntegration(Base):
    __tablename__ = "gitops_integrations"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    git_provider = Column(Enum(GitProvider), nullable=False)
    repository_url = Column(String(500), nullable=False)
    branch = Column(String(100), default="main")
    authentication_method = Column(String(100))  # SSH key, OAuth, etc.
    connection_config = Column(JSONB, nullable=False)
    webhook_url = Column(String(500))
    webhook_secret = Column(String(255))  # Encrypted
    status = Column(Enum(IntegrationStatus), default=IntegrationStatus.CONFIGURING)
    last_sync = Column(DateTime(timezone=True))
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    repositories = relationship("GitRepository", back_populates="integration")
    pull_requests = relationship("GitPullRequest", back_populates="integration")
    security_scans = relationship("GitSecurityScan", back_populates="integration")

class GitRepository(Base):
    __tablename__ = "git_repositories"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    integration_id = Column(PGUUID(as_uuid=True), ForeignKey("gitops_integrations.id"), nullable=False)
    repo_name = Column(String(255), nullable=False)
    repo_id = Column(String(255))  # Git provider repository ID
    description = Column(Text)
    language = Column(String(100))
    framework = Column(String(100))  # React, Angular, Django, etc.
    security_policies = Column(JSONB, default=[])  # Applied security policies
    last_scan = Column(DateTime(timezone=True))
    security_score = Column(Numeric(5, 2), default=0.0)
    
    # Relationships
    integration = relationship("GitOpsIntegration", back_populates="repositories")
    branches = relationship("GitBranch", back_populates="repository")

class GitBranch(Base):
    __tablename__ = "git_branches"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repository_id = Column(PGUUID(as_uuid=True), ForeignKey("git_repositories.id"), nullable=False)
    branch_name = Column(String(255), nullable=False)
    last_commit = Column(String(255))
    last_commit_date = Column(DateTime(timezone=True))
    protection_rules = Column(JSONB, default={})  # Branch protection rules
    security_checks = Column(JSONB, default=[])  # Required security checks
    status = Column(String(50), default="active")
    
    # Relationships
    repository = relationship("GitRepository", back_populates="branches")

class GitPullRequest(Base):
    __tablename__ = "git_pull_requests"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    integration_id = Column(PGUUID(as_uuid=True), ForeignKey("gitops_integrations.id"), nullable=False)
    pr_id = Column(String(255), nullable=False)  # Git provider PR ID
    title = Column(String(500), nullable=False)
    description = Column(Text)
    source_branch = Column(String(255))
    target_branch = Column(String(255))
    status = Column(String(50))  # open, merged, closed
    created_at = Column(DateTime(timezone=True))
    updated_at = Column(DateTime(timezone=True))
    security_scan_status = Column(String(50))  # pending, passed, failed
    security_issues = Column(JSONB, default=[])
    
    # Relationships
    integration = relationship("GitOpsIntegration", back_populates="pull_requests")

class GitSecurityScan(Base):
    __tablename__ = "git_security_scans"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    integration_id = Column(PGUUID(as_uuid=True), ForeignKey("gitops_integrations.id"), nullable=False)
    scan_id = Column(String(255), nullable=False)
    scan_type = Column(String(100))  # SAST, dependency, container, etc.
    target = Column(String(255))  # Branch, PR, commit
    scan_status = Column(String(50))  # running, completed, failed
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    findings = Column(JSONB, default=[])
    security_score = Column(Numeric(5, 2), default=0.0)
    
    # Relationships
    integration = relationship("GitOpsIntegration", back_populates="security_scans")

# DevSecOps Pipeline Integration Models
class DevSecOpsPipeline(Base):
    __tablename__ = "devsecops_pipelines"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    pipeline_type = Column(String(100))  # Jenkins, GitLab CI, GitHub Actions, etc.
    description = Column(Text)
    pipeline_config = Column(JSONB, nullable=False)
    webhook_url = Column(String(500))
    webhook_secret = Column(String(255))  # Encrypted
    status = Column(Enum(IntegrationStatus), default=IntegrationStatus.CONFIGURING)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    stages = relationship("PipelineStage", back_populates="pipeline")
    runs = relationship("PipelineRun", back_populates="pipeline")
    security_gates = relationship("SecurityGate", back_populates="pipeline")

class PipelineStage(Base):
    __tablename__ = "pipeline_stages"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    pipeline_id = Column(PGUUID(as_uuid=True), ForeignKey("devsecops_pipelines.id"), nullable=False)
    stage_name = Column(String(255), nullable=False)
    stage_type = Column(Enum(PipelineStage), nullable=False)
    order = Column(Integer, nullable=False)
    description = Column(Text)
    stage_config = Column(JSONB, default={})
    security_checks = Column(JSONB, default=[])  # Security checks for this stage
    enabled = Column(Boolean, default=True)
    
    # Relationships
    pipeline = relationship("DevSecOpsPipeline", back_populates="stages")

class PipelineRun(Base):
    __tablename__ = "pipeline_runs"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    pipeline_id = Column(PGUUID(as_uuid=True), ForeignKey("devsecops_pipelines.id"), nullable=False)
    run_id = Column(String(255), nullable=False)  # Pipeline run ID
    commit_hash = Column(String(255))
    branch = Column(String(255))
    status = Column(String(50))  # running, success, failed, cancelled
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    duration = Column(Integer)  # seconds
    security_scan_results = Column(JSONB, default={})
    security_score = Column(Numeric(5, 2), default=0.0)
    
    # Relationships
    pipeline = relationship("DevSecOpsPipeline", back_populates="runs")

class SecurityGate(Base):
    __tablename__ = "security_gates"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    pipeline_id = Column(PGUUID(as_uuid=True), ForeignKey("devsecops_pipelines.id"), nullable=False)
    gate_name = Column(String(255), nullable=False)
    gate_type = Column(String(100))  # vulnerability_threshold, security_score, etc.
    description = Column(Text)
    conditions = Column(JSONB, nullable=False)  # Gate conditions
    action = Column(String(100))  # block, warn, allow
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    pipeline = relationship("DevSecOpsPipeline", back_populates="security_gates")

# Infrastructure as Code Analysis
class InfrastructureAsCode(Base):
    __tablename__ = "infrastructure_as_code"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repository_id = Column(PGUUID(as_uuid=True), ForeignKey("git_repositories.id"), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_type = Column(String(100))  # terraform, cloudformation, arm, etc.
    content_hash = Column(String(255))
    last_analyzed = Column(DateTime(timezone=True))
    security_issues = Column(JSONB, default=[])
    compliance_issues = Column(JSONB, default=[])
    security_score = Column(Numeric(5, 2), default=0.0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    repository = relationship("GitRepository")

# Advanced Integration Summary
class AdvancedIntegrationSummary(Base):
    __tablename__ = "advanced_integration_summary"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    summary_date = Column(DateTime(timezone=True), nullable=False)
    
    # SIEM Integration
    active_siem_integrations = Column(Integer, default=0)
    total_data_sources = Column(Integer, default=0)
    active_alert_rules = Column(Integer, default=0)
    
    # SOAR Integration
    active_soar_integrations = Column(Integer, default=0)
    total_playbooks = Column(Integer, default=0)
    active_incidents = Column(Integer, default=0)
    
    # GitOps Integration
    active_git_integrations = Column(Integer, default=0)
    total_repositories = Column(Integer, default=0)
    total_pull_requests = Column(Integer, default=0)
    security_scans_completed = Column(Integer, default=0)
    
    # DevSecOps Pipeline
    active_pipelines = Column(Integer, default=0)
    total_pipeline_runs = Column(Integer, default=0)
    security_gates_active = Column(Integer, default=0)
    
    # Infrastructure as Code
    total_iac_files = Column(Integer, default=0)
    iac_security_issues = Column(Integer, default=0)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    project = relationship("Project")
