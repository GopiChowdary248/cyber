from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON, ForeignKey, Float, Enum, UUID, SmallInteger, Numeric, BigInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
import enum
import uuid

Base = declarative_base()

# Enums
class ComplianceStatus(str, enum.Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNDER_REVIEW = "under_review"

class CompliancePriority(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class WorkflowStatus(str, enum.Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"

class EvidenceType(str, enum.Enum):
    SCREENSHOT = "screenshot"
    LOG_FILE = "log_file"
    CONFIG_FILE = "config_file"
    API_RESPONSE = "api_response"
    DATABASE_QUERY = "database_query"
    MANUAL_VERIFICATION = "manual_verification"

# Enhanced Compliance Frameworks
class ComplianceFramework(Base):
    __tablename__ = "compliance_frameworks"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    version = Column(String(50), nullable=False)
    description = Column(Text)
    regulatory_body = Column(String(255))  # NIST, ISO, PCI, etc.
    effective_date = Column(DateTime(timezone=True))
    expiry_date = Column(DateTime(timezone=True))
    status = Column(String(50), default="active")  # active, deprecated, draft
    framework_metadata = Column(JSONB, default={})  # Additional framework details
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    controls = relationship("ComplianceControl", back_populates="framework")
    workflows = relationship("ComplianceWorkflow", back_populates="framework")
    regulatory_updates = relationship("RegulatoryUpdate", back_populates="framework")

# Enhanced Compliance Controls
class ComplianceControl(Base):
    __tablename__ = "compliance_controls"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    framework_id = Column(PGUUID(as_uuid=True), ForeignKey("compliance_frameworks.id"), nullable=False)
    control_id = Column(String(100), nullable=False)  # e.g., "CIS.1.1", "NIST.AC.1"
    title = Column(String(500), nullable=False)
    description = Column(Text)
    category = Column(String(100))  # Access Control, Data Protection, etc.
    priority = Column(Enum(CompliancePriority), default=CompliancePriority.MEDIUM)
    implementation_guidance = Column(Text)
    testing_procedures = Column(Text)
    remediation_guidance = Column(Text)
    control_metadata = Column(JSONB, default={})  # Additional control details
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    framework = relationship("ComplianceFramework", back_populates="controls")
    mappings = relationship("ComplianceMapping", back_populates="control")
    assessments = relationship("ComplianceAssessment", back_populates="control")
    evidence_requirements = relationship("EvidenceRequirement", back_populates="control")

# Compliance Workflow Automation
class ComplianceWorkflow(Base):
    __tablename__ = "compliance_workflows"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    framework_id = Column(PGUUID(as_uuid=True), ForeignKey("compliance_frameworks.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    workflow_type = Column(String(100))  # assessment, remediation, monitoring, reporting
    status = Column(Enum(WorkflowStatus), default=WorkflowStatus.DRAFT)
    trigger_conditions = Column(JSONB, default={})  # When workflow should start
    steps = Column(JSONB, nullable=False)  # Workflow steps and sequence
    automation_level = Column(String(50))  # manual, semi-automated, fully-automated
    estimated_duration = Column(Integer)  # Estimated time in hours
    assigned_roles = Column(JSONB, default=[])  # Roles responsible for workflow
    created_by = Column(PGUUID(as_uuid=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    framework = relationship("ComplianceFramework", back_populates="workflows")
    executions = relationship("WorkflowExecution", back_populates="workflow")

class WorkflowExecution(Base):
    __tablename__ = "workflow_executions"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workflow_id = Column(PGUUID(as_uuid=True), ForeignKey("compliance_workflows.id"), nullable=False)
    execution_id = Column(String(255), nullable=False)
    status = Column(String(50), default="running")  # running, completed, failed, paused
    current_step = Column(Integer, default=0)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    executed_by = Column(PGUUID(as_uuid=True))
    execution_log = Column(JSONB, default=[])  # Step-by-step execution log
    results = Column(JSONB, default={})  # Execution results and outputs
    error_details = Column(Text)
    
    # Relationships
    workflow = relationship("ComplianceWorkflow", back_populates="executions")

# Regulatory Updates and Changes
class RegulatoryUpdate(Base):
    __tablename__ = "regulatory_updates"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    framework_id = Column(PGUUID(as_uuid=True), ForeignKey("compliance_frameworks.id"), nullable=False)
    update_type = Column(String(100))  # new_requirement, modification, deprecation
    title = Column(String(500), nullable=False)
    description = Column(Text)
    effective_date = Column(DateTime(timezone=True))
    impact_level = Column(Enum(CompliancePriority), default=CompliancePriority.MEDIUM)
    affected_controls = Column(JSONB, default=[])  # Controls impacted by update
    change_summary = Column(Text)
    implementation_deadline = Column(DateTime(timezone=True))
    source_url = Column(String(500))
    notification_sent = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    framework = relationship("ComplianceFramework", back_populates="regulatory_updates")
    impact_assessments = relationship("RegulatoryImpactAssessment", back_populates="update")

class RegulatoryImpactAssessment(Base):
    __tablename__ = "regulatory_impact_assessments"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    update_id = Column(PGUUID(as_uuid=True), ForeignKey("regulatory_updates.id"), nullable=False)
    project_id = Column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    impact_score = Column(Numeric(5, 2), default=0.0)
    affected_assets = Column(JSONB, default=[])  # Assets impacted by regulatory change
    required_changes = Column(JSONB, default=[])  # Changes needed for compliance
    estimated_effort = Column(Integer)  # Estimated effort in hours
    risk_assessment = Column(JSONB, default={})  # Risk assessment details
    mitigation_plan = Column(Text)
    assessment_date = Column(DateTime(timezone=True), server_default=func.now())
    assessed_by = Column(PGUUID(as_uuid=True))
    
    # Relationships
    update = relationship("RegulatoryUpdate", back_populates="impact_assessments")
    project = relationship("Project")

# Compliance Drift Detection
class ComplianceDrift(Base):
    __tablename__ = "compliance_drift"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    control_id = Column(PGUUID(as_uuid=True), ForeignKey("compliance_controls.id"), nullable=False)
    asset_id = Column(PGUUID(as_uuid=True), ForeignKey("assets.id"))
    drift_type = Column(String(100))  # configuration, access, policy, etc.
    previous_status = Column(Enum(ComplianceStatus))
    current_status = Column(Enum(ComplianceStatus))
    drift_detected_at = Column(DateTime(timezone=True), server_default=func.now())
    drift_reason = Column(Text)
    impact_assessment = Column(JSONB, default={})
    remediation_required = Column(Boolean, default=True)
    remediation_plan = Column(Text)
    status = Column(String(50), default="open")  # open, investigating, remediated
    
    # Relationships
    project = relationship("Project")
    control = relationship("ComplianceControl")
    asset = relationship("Asset")
    evidence = relationship("ComplianceEvidence", back_populates="drift")

# Evidence Collection and Management
class EvidenceRequirement(Base):
    __tablename__ = "evidence_requirements"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    control_id = Column(PGUUID(as_uuid=True), ForeignKey("compliance_controls.id"), nullable=False)
    evidence_type = Column(Enum(EvidenceType), nullable=False)
    description = Column(Text)
    required = Column(Boolean, default=True)
    collection_frequency = Column(String(100))  # continuous, daily, weekly, monthly
    retention_period = Column(Integer)  # Days to retain evidence
    collection_method = Column(String(100))  # automated, manual, api
    validation_rules = Column(JSONB, default={})  # Evidence validation criteria
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    control = relationship("ComplianceControl", back_populates="evidence_requirements")
    evidence = relationship("ComplianceEvidence", back_populates="requirement")

class ComplianceEvidence(Base):
    __tablename__ = "evidence_evidence"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    requirement_id = Column(PGUUID(as_uuid=True), ForeignKey("evidence_requirements.id"), nullable=False)
    drift_id = Column(PGUUID(as_uuid=True), ForeignKey("compliance_drift.id"))
    evidence_type = Column(Enum(EvidenceType), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    content = Column(JSONB, default={})  # Evidence content/data
    file_path = Column(String(500))  # Path to evidence file
    file_hash = Column(String(255))  # File integrity hash
    collected_at = Column(DateTime(timezone=True), server_default=func.now())
    collected_by = Column(PGUUID(as_uuid=True))
    collection_method = Column(String(100))  # How evidence was collected
    validation_status = Column(String(50), default="pending")  # pending, valid, invalid
    validation_notes = Column(Text)
    retention_expiry = Column(DateTime(timezone=True))
    
    # Relationships
    requirement = relationship("EvidenceRequirement", back_populates="evidence")
    drift = relationship("ComplianceDrift", back_populates="evidence")

# Automated Compliance Assessments
class ComplianceAssessment(Base):
    __tablename__ = "compliance_assessments"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    framework_id = Column(PGUUID(as_uuid=True), ForeignKey("compliance_frameworks.id"), nullable=False)
    control_id = Column(PGUUID(as_uuid=True), ForeignKey("compliance_controls.id"), nullable=False)
    assessment_type = Column(String(100))  # automated, manual, hybrid
    assessment_date = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(Enum(ComplianceStatus), nullable=False)
    confidence_score = Column(Numeric(3, 2), default=0.0)  # 0.0-1.0
    assessment_method = Column(String(100))  # How assessment was performed
    findings = Column(JSONB, default=[])  # Assessment findings
    recommendations = Column(JSONB, default=[])  # Recommendations for improvement
    assessed_by = Column(PGUUID(as_uuid=True))
    next_assessment_date = Column(DateTime(timezone=True))
    
    # Relationships
    project = relationship("Project")
    framework = relationship("ComplianceFramework")
    control = relationship("ComplianceControl", back_populates="assessments")

# Compliance Monitoring and Alerting
class ComplianceMonitor(Base):
    __tablename__ = "compliance_monitors"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    control_id = Column(PGUUID(as_uuid=True), ForeignKey("compliance_controls.id"))
    monitoring_frequency = Column(String(100))  # real-time, hourly, daily
    alert_conditions = Column(JSONB, default={})  # When to trigger alerts
    alert_channels = Column(JSONB, default=[])  # How to send alerts
    enabled = Column(Boolean, default=True)
    last_check = Column(DateTime(timezone=True))
    next_check = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    control = relationship("ComplianceControl")
    alerts = relationship("ComplianceAlert", back_populates="monitor")

class ComplianceAlert(Base):
    __tablename__ = "compliance_alerts"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    monitor_id = Column(PGUUID(as_uuid=True), ForeignKey("compliance_monitors.id"), nullable=False)
    alert_type = Column(String(100))  # drift_detected, assessment_failed, deadline_approaching
    severity = Column(Enum(CompliancePriority), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    alert_data = Column(JSONB, default={})  # Alert-specific data
    status = Column(String(50), default="active")  # active, acknowledged, resolved
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    acknowledged_at = Column(DateTime(timezone=True))
    resolved_at = Column(DateTime(timezone=True))
    acknowledged_by = Column(PGUUID(as_uuid=True))
    resolution_notes = Column(Text)
    
    # Relationships
    monitor = relationship("ComplianceMonitor", back_populates="alerts")

# Enhanced Compliance Summary
class EnhancedComplianceSummary(Base):
    __tablename__ = "enhanced_compliance_summary"
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    framework_id = Column(PGUUID(as_uuid=True), ForeignKey("compliance_frameworks.id"), nullable=False)
    summary_date = Column(DateTime(timezone=True), nullable=False)
    
    # Overall Compliance
    overall_score = Column(Numeric(5, 2), default=0.0)
    total_controls = Column(Integer, default=0)
    compliant_controls = Column(Integer, default=0)
    non_compliant_controls = Column(Integer, default=0)
    partially_compliant_controls = Column(Integer, default=0)
    
    # Drift Detection
    total_drift_incidents = Column(Integer, default=0)
    open_drift_incidents = Column(Integer, default=0)
    resolved_drift_incidents = Column(Integer, default=0)
    
    # Evidence Collection
    total_evidence_requirements = Column(Integer, default=0)
    evidence_collected = Column(Integer, default=0)
    evidence_pending = Column(Integer, default=0)
    
    # Workflow Automation
    active_workflows = Column(Integer, default=0)
    completed_workflows = Column(Integer, default=0)
    workflow_success_rate = Column(Numeric(5, 2), default=0.0)
    
    # Regulatory Updates
    pending_regulatory_updates = Column(Integer, default=0)
    high_impact_updates = Column(Integer, default=0)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    project = relationship("Project")
    framework = relationship("ComplianceFramework")
