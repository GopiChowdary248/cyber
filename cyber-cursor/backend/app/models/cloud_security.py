from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON, ForeignKey, Float, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum

Base = declarative_base()

class CloudProvider(str, enum.Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"

class RiskLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ComplianceStandard(str, enum.Enum):
    CIS = "cis"
    NIST = "nist"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    HIPAA = "hipaa"

class AssetType(str, enum.Enum):
    EC2 = "ec2"
    S3 = "s3"
    RDS = "rds"
    LAMBDA = "lambda"
    VPC = "vpc"
    IAM = "iam"
    CLOUDFRONT = "cloudfront"
    ECS = "ecs"
    EKS = "eks"
    VM = "vm"
    BLOB = "blob"
    SQL = "sql"
    APP_SERVICE = "app_service"
    KEY_VAULT = "key_vault"
    COMPUTE_ENGINE = "compute_engine"
    CLOUD_STORAGE = "cloud_storage"
    CLOUD_SQL = "cloud_sql"
    KUBERNETES = "kubernetes"

# CSPM Models
class CloudAccount(Base):
    __tablename__ = "cloud_accounts"
    
    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(String(255), unique=True, index=True)
    name = Column(String(255))
    provider = Column(Enum(CloudProvider))
    region = Column(String(100))
    status = Column(String(50), default="active")
    last_scan = Column(DateTime(timezone=True), server_default=func.now())
    security_score = Column(Float, default=0.0)
    risk_level = Column(Enum(RiskLevel), default=RiskLevel.INFO)
    account_metadata = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class CloudAsset(Base):
    __tablename__ = "cloud_assets"
    
    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey("cloud_accounts.id"))
    asset_id = Column(String(255), index=True)
    name = Column(String(255))
    asset_type = Column(Enum(AssetType))
    region = Column(String(100))
    status = Column(String(50))
    tags = Column(JSON)
    asset_metadata = Column(JSON)
    risk_score = Column(Float, default=0.0)
    last_updated = Column(DateTime(timezone=True), server_default=func.now())
    
    account = relationship("CloudAccount", back_populates="assets")

class Misconfiguration(Base):
    __tablename__ = "misconfigurations"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("cloud_assets.id"))
    rule_id = Column(String(255))
    title = Column(String(500))
    description = Column(Text)
    severity = Column(Enum(RiskLevel))
    category = Column(String(100))
    compliance_standards = Column(JSON)  # Array of compliance standards
    remediation_steps = Column(Text)
    auto_remediable = Column(Boolean, default=False)
    status = Column(String(50), default="open")
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True))
    
    asset = relationship("CloudAsset", back_populates="misconfigurations")

class ComplianceReport(Base):
    __tablename__ = "compliance_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey("cloud_accounts.id"))
    standard = Column(Enum(ComplianceStandard))
    score = Column(Float)
    total_checks = Column(Integer)
    passed_checks = Column(Integer)
    failed_checks = Column(Integer)
    report_data = Column(JSON)
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    
    account = relationship("CloudAccount", back_populates="compliance_reports")

# CASB Models
class SaaSApplication(Base):
    __tablename__ = "saas_applications"
    
    id = Column(Integer, primary_key=True, index=True)
    app_name = Column(String(255))
    app_category = Column(String(100))
    vendor = Column(String(255))
    risk_score = Column(Float, default=0.0)
    status = Column(String(50), default="discovered")  # discovered, sanctioned, blocked
    user_count = Column(Integer, default=0)
    data_classification = Column(JSON)
    security_features = Column(JSON)
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    last_activity = Column(DateTime(timezone=True))

class UserActivity(Base):
    __tablename__ = "user_activities"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(255), index=True)
    app_id = Column(Integer, ForeignKey("saas_applications.id"))
    activity_type = Column(String(100))  # login, upload, download, share, admin_action
    ip_address = Column(String(45))
    location = Column(String(255))
    device_info = Column(JSON)
    risk_score = Column(Float, default=0.0)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    
    app = relationship("SaaSApplication", back_populates="activities")

class DLPIncident(Base):
    __tablename__ = "dlp_incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    app_id = Column(Integer, ForeignKey("saas_applications.id"))
    user_id = Column(String(255))
    incident_type = Column(String(100))  # pii, pci, phi, intellectual_property
    file_name = Column(String(255))
    file_size = Column(Integer)
    action_taken = Column(String(100))  # blocked, quarantined, allowed, alerted
    confidence_score = Column(Float)
    details = Column(JSON)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    
    app = relationship("SaaSApplication", back_populates="dlp_incidents")

# Cloud-Native Security Models
class CloudThreat(Base):
    __tablename__ = "cloud_threats"
    
    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey("cloud_accounts.id"))
    threat_id = Column(String(255))
    threat_type = Column(String(100))  # ddos, malware, unauthorized_access, data_exfiltration
    severity = Column(Enum(RiskLevel))
    source_ip = Column(String(45))
    target_resource = Column(String(255))
    description = Column(Text)
    threat_data = Column(JSON)
    status = Column(String(50), default="active")
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True))
    
    account = relationship("CloudAccount", back_populates="threats")

class IAMRisk(Base):
    __tablename__ = "iam_risks"
    
    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey("cloud_accounts.id"))
    entity_id = Column(String(255))
    entity_type = Column(String(50))  # user, role, group, service_account
    risk_type = Column(String(100))  # over_privileged, unused_permissions, weak_policies
    severity = Column(Enum(RiskLevel))
    permissions = Column(JSON)
    recommendations = Column(JSON)
    status = Column(String(50), default="open")
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    
    account = relationship("CloudAccount", back_populates="iam_risks")

class DDoSProtection(Base):
    __tablename__ = "ddos_protection"
    
    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey("cloud_accounts.id"))
    protection_id = Column(String(255))
    service = Column(String(100))  # aws_shield, azure_ddos, gcp_armor
    status = Column(String(50))
    protected_resources = Column(JSON)
    attack_statistics = Column(JSON)
    last_attack = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    account = relationship("CloudAccount", back_populates="ddos_protection")

# Relationships
CloudAccount.assets = relationship("CloudAsset", back_populates="account")
CloudAccount.compliance_reports = relationship("ComplianceReport", back_populates="account")
CloudAccount.threats = relationship("CloudThreat", back_populates="account")
CloudAccount.iam_risks = relationship("IAMRisk", back_populates="account")
CloudAccount.ddos_protection = relationship("DDoSProtection", back_populates="account")

CloudAsset.misconfigurations = relationship("Misconfiguration", back_populates="asset")

SaaSApplication.activities = relationship("UserActivity", back_populates="app")
SaaSApplication.dlp_incidents = relationship("DLPIncident", back_populates="app") 