from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON, ForeignKey, Float, Enum, UUID, SmallInteger, Numeric, BigInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
import enum
import uuid

Base = declarative_base()

# Enums
class CloudProvider(str, enum.Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    OCI = "oci"
    KUBERNETES = "kubernetes"

class ConnectorStatus(str, enum.Enum):
    PENDING = "pending"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    SYNCING = "syncing"

class FindingStatus(str, enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"

class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class PolicyFramework(str, enum.Enum):
    CIS = "cis"
    NIST = "nist"
    PCI_DSS = "pci_dss"
    ISO27001 = "iso27001"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    CUSTOM = "custom"

class JobStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class JobType(str, enum.Enum):
    SYNC = "sync"
    SCAN = "scan"
    POLICY_EVAL = "policy_evaluation"
    REMEDIATION = "remediation"

# Core CSPM Models
class Organization(Base):
    __tablename__ = "organizations"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    settings = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class Project(Base):
    __tablename__ = "projects"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(PGUUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    settings = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    org = relationship("Organization", back_populates="projects")
    connectors = relationship("Connector", back_populates="project")
    assets = relationship("Asset", back_populates="project")

class Connector(Base):
    __tablename__ = "connectors"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    name = Column(String(255), nullable=False)
    type = Column(Enum(CloudProvider), nullable=False)
    config = Column(JSONB, nullable=False)  # Credentials, regions, etc.
    status = Column(Enum(ConnectorStatus), default=ConnectorStatus.PENDING)
    last_synced = Column(DateTime(timezone=True))
    sync_interval = Column(Integer, default=3600)  # seconds
    permissions_check = Column(JSONB, default={})  # Permission validation results
    error_details = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    project = relationship("Project", back_populates="connectors")
    assets = relationship("Asset", back_populates="connector")
    jobs = relationship("Job", back_populates="connector")

class Asset(Base):
    __tablename__ = "assets"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    connector_id = Column(PGUUID(as_uuid=True), ForeignKey("connectors.id"))
    project_id = Column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    cloud = Column(Enum(CloudProvider))
    resource_id = Column(String(255), nullable=False)  # Cloud native resource ID
    resource_type = Column(String(100), nullable=False)
    name = Column(String(255))
    region = Column(String(100))
    asset_metadata = Column(JSONB, default={})  # Raw provider metadata
    tags = Column(JSONB, default={})
    relationships = Column(JSONB, default={})  # Parent/child relationships
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    risk_score = Column(Numeric(5, 2), default=0.0)
    
    connector = relationship("Connector", back_populates="assets")
    project = relationship("Project", back_populates="assets")
    findings = relationship("Finding", back_populates="asset")

class Policy(Base):
    __tablename__ = "policies"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    framework = Column(Enum(PolicyFramework), default=PolicyFramework.CUSTOM)
    rule = Column(JSONB, nullable=False)  # Expression, Rego, CEL, etc.
    enabled = Column(Boolean, default=True)
    severity = Column(Enum(FindingSeverity), default=FindingSeverity.MEDIUM)
    category = Column(String(100))
    compliance_standards = Column(JSONB, default=[])
    remediation_steps = Column(Text)
    auto_remediable = Column(Boolean, default=False)
    created_by = Column(PGUUID(as_uuid=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    findings = relationship("Finding", back_populates="policy")

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    policy_id = Column(PGUUID(as_uuid=True), ForeignKey("policies.id"), nullable=False)
    severity = Column(Enum(FindingSeverity), nullable=False)
    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    evidence = Column(JSONB, default={})  # Evidence data, risk factors
    risk_score = Column(Numeric(5, 2), default=0.0)
    owner_id = Column(PGUUID(as_uuid=True))
    comments = Column(JSONB, default=[])
    remediation_notes = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True))
    
    asset = relationship("Asset", back_populates="findings")
    policy = relationship("Policy", back_populates="findings")

class Job(Base):
    __tablename__ = "jobs"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    connector_id = Column(PGUUID(as_uuid=True), ForeignKey("connectors.id"))
    project_id = Column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    type = Column(Enum(JobType), nullable=False)
    status = Column(Enum(JobStatus), default=JobStatus.PENDING)
    parameters = Column(JSONB, default={})
    progress = Column(Integer, default=0)  # 0-100
    result = Column(JSONB, default={})
    error_message = Column(Text)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    connector = relationship("Connector", back_populates="jobs")

class Remediation(Base):
    __tablename__ = "remediations"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(PGUUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    steps = Column(JSONB, nullable=False)  # Array of remediation steps
    auto_remediable = Column(Boolean, default=False)
    status = Column(String(50), default="pending")  # pending, in_progress, completed, failed
    executed_by = Column(PGUUID(as_uuid=True))
    executed_at = Column(DateTime(timezone=True))
    result = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Integration(Base):
    __tablename__ = "integrations"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    name = Column(String(255), nullable=False)
    type = Column(String(100), nullable=False)  # slack, pagerduty, servicenow, jira, webhook
    config = Column(JSONB, nullable=False)
    enabled = Column(Boolean, default=True)
    last_test = Column(DateTime(timezone=True))
    test_status = Column(String(50))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class AlertRule(Base):
    __tablename__ = "alert_rules"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    conditions = Column(JSONB, nullable=False)  # Alert conditions
    integrations = Column(JSONB, default=[])  # Array of integration IDs
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class ComplianceFramework(Base):
    __tablename__ = "compliance_frameworks"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    version = Column(String(50))
    description = Column(Text)
    controls = Column(JSONB, nullable=False)  # Framework controls
    policy_mappings = Column(JSONB, default={})  # Policy to control mappings
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class ComplianceReport(Base):
    __tablename__ = "compliance_reports"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    framework_id = Column(PGUUID(as_uuid=True), ForeignKey("compliance_frameworks.id"), nullable=False)
    score = Column(Numeric(5, 2), default=0.0)
    total_controls = Column(Integer, default=0)
    passed_controls = Column(Integer, default=0)
    failed_controls = Column(Integer, default=0)
    report_data = Column(JSONB, default={})
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    
    project = relationship("Project")
    framework = relationship("ComplianceFramework")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(BigInteger, primary_key=True)
    actor_id = Column(PGUUID(as_uuid=True))
    action = Column(String(255), nullable=False)
    object_type = Column(String(100))
    object_id = Column(String(255))
    details = Column(JSONB, default={})
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

# Relationships
Organization.projects = relationship("Project", back_populates="org")
Project.connectors = relationship("Connector", back_populates="project")
Project.assets = relationship("Asset", back_populates="project")
Connector.assets = relationship("Asset", back_populates="connector")
Connector.jobs = relationship("Job", back_populates="connector")
Asset.findings = relationship("Finding", back_populates="asset")
Policy.findings = relationship("Finding", back_populates="policy")

class AssetRelationship(Base):
    __tablename__ = "asset_relationships"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    parent_asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    child_asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    relationship_type = Column(String(100), nullable=False)  # contains, depends_on, etc.
    integration_metadata = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    parent_asset = relationship("Asset", foreign_keys=[parent_asset_id])
    child_asset = relationship("Asset", foreign_keys=[child_asset_id])

class PolicyEvaluationResult(Base):
    __tablename__ = "policy_evaluation_results"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    policy_id = Column(PGUUID(as_uuid=True), ForeignKey("policies.id"), nullable=False)
    evaluation_date = Column(DateTime(timezone=True), server_default=func.now())
    result = Column(Boolean, nullable=False)  # True = passed, False = failed
    evidence = Column(JSONB, default={})  # Raw evaluation data
    execution_time_ms = Column(Integer)  # How long evaluation took
    
    asset = relationship("Asset")
    policy = relationship("Policy")

class ComplianceControl(Base):
    __tablename__ = "compliance_controls"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    framework_id = Column(PGUUID(as_uuid=True), ForeignKey("compliance_frameworks.id"), nullable=False)
    control_id = Column(String(100), nullable=False)  # e.g., "CIS.1.1"
    title = Column(String(500), nullable=False)
    description = Column(Text)
    category = Column(String(100))
    requirements = Column(JSONB, default=[])
    policy_mappings = Column(JSONB, default=[])  # Array of policy IDs
    
    framework = relationship("ComplianceFramework")

class ComplianceMapping(Base):
    __tablename__ = "compliance_mappings"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    control_id = Column(PGUUID(as_uuid=True), ForeignKey("compliance_controls.id"), nullable=False)
    policy_id = Column(PGUUID(as_uuid=True), ForeignKey("policies.id"), nullable=False)
    mapping_type = Column(String(50), default="direct")  # direct, partial, custom
    confidence_score = Column(Numeric(3, 2), default=1.0)  # 0.0-1.0
    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    control = relationship("ComplianceControl")
    policy = relationship("Policy")

class IntegrationWebhook(Base):
    __tablename__ = "integration_webhooks"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    integration_id = Column(PGUUID(as_uuid=True), ForeignKey("integrations.id"), nullable=False)
    webhook_url = Column(String(500), nullable=False)
    secret_key = Column(String(255))  # For signature validation
    events = Column(JSONB, default=[])  # Array of event types to send
    enabled = Column(Boolean, default=True)
    last_delivery = Column(DateTime(timezone=True))
    delivery_count = Column(Integer, default=0)
    failure_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    integration = relationship("Integration")

class ScanTemplate(Base):
    __tablename__ = "scan_templates"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    scan_config = Column(JSONB, nullable=False)  # Scan parameters, included services, etc.
    schedule = Column(String(100))  # Cron expression
    enabled = Column(Boolean, default=True)
    created_by = Column(PGUUID(as_uuid=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    project = relationship("Project")

class RemediationPlaybook(Base):
    __tablename__ = "remediation_playbooks"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    category = Column(String(100))  # aws, azure, gcp, kubernetes
    steps = Column(JSONB, nullable=False)  # Array of remediation steps
    prerequisites = Column(JSONB, default=[])  # Required conditions
    estimated_time = Column(Integer)  # Estimated time in minutes
    risk_level = Column(String(50))  # low, medium, high
    auto_approval = Column(Boolean, default=False)
    created_by = Column(PGUUID(as_uuid=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class RemediationExecution(Base):
    __tablename__ = "remediation_executions"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    playbook_id = Column(PGUUID(as_uuid=True), ForeignKey("remediation_playbooks.id"), nullable=False)
    finding_id = Column(PGUUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    status = Column(String(50), default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    executed_by = Column(PGUUID(as_uuid=True))
    execution_log = Column(JSONB, default=[])
    result = Column(JSONB, default={})
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    playbook = relationship("RemediationPlaybook")
    finding = relationship("Finding")

class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    assessment_date = Column(DateTime(timezone=True), server_default=func.now())
    overall_score = Column(Numeric(5, 2), nullable=False)
    factors = Column(JSONB, default={})  # Risk factors and their scores
    recommendations = Column(JSONB, default=[])  # Risk mitigation recommendations
    assessed_by = Column(PGUUID(as_uuid=True))
    
    asset = relationship("Asset")
