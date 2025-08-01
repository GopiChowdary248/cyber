from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON, Float
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from datetime import datetime
from typing import Optional, List
from enum import Enum

from app.core.database import Base

class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"

class ResourceType(str, Enum):
    S3_BUCKET = "s3_bucket"
    EC2_INSTANCE = "ec2_instance"
    IAM_ROLE = "iam_role"
    IAM_USER = "iam_user"
    SECURITY_GROUP = "security_group"
    VPC = "vpc"
    SUBNET = "subnet"
    RDS_INSTANCE = "rds_instance"
    LAMBDA_FUNCTION = "lambda_function"
    CONTAINER_REGISTRY = "container_registry"
    STORAGE_ACCOUNT = "storage_account"
    VIRTUAL_MACHINE = "virtual_machine"
    NETWORK_SECURITY_GROUP = "network_security_group"
    KEY_VAULT = "key_vault"
    BLOB_STORAGE = "blob_storage"
    COMPUTE_INSTANCE = "compute_instance"
    CLOUD_STORAGE = "cloud_storage"
    KUBERNETES_CLUSTER = "kubernetes_cluster"

class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ComplianceFramework(str, Enum):
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    NIST = "nist"

class CloudResource(Base):
    __tablename__ = "cloud_resources"
    
    id = Column(Integer, primary_key=True, index=True)
    resource_id = Column(String(255), nullable=False)  # Cloud provider resource ID
    resource_type = Column(String(50), nullable=False)
    provider = Column(String(20), nullable=False)
    region = Column(String(50), nullable=True)
    name = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    
    # Resource details
    configuration = Column(JSON, nullable=True)  # Current configuration
    tags = Column(JSON, nullable=True)  # Resource tags
    cloud_metadata = Column(JSON, nullable=True)  # Additional metadata
    
    # Security assessment
    security_score = Column(Float, nullable=True)  # 0-100 security score
    last_scan = Column(DateTime, nullable=True)
    next_scan = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    misconfigurations = relationship("CloudMisconfiguration", back_populates="resource")
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, resource_id: int) -> Optional["CloudResource"]:
        """Get cloud resource by ID"""
        result = await db.execute(select(cls).where(cls.id == resource_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_provider(cls, db: AsyncSession, provider: str) -> List["CloudResource"]:
        """Get resources by cloud provider"""
        result = await db.execute(select(cls).where(cls.provider == provider))
        return result.scalars().all()
    
    @classmethod
    async def get_by_type(cls, db: AsyncSession, resource_type: str) -> List["CloudResource"]:
        """Get resources by type"""
        result = await db.execute(select(cls).where(cls.resource_type == resource_type))
        return result.scalars().all()
    
    def __repr__(self):
        return f"<CloudResource(id={self.id}, type='{self.resource_type}', provider='{self.provider}')>"

class CloudMisconfiguration(Base):
    __tablename__ = "cloud_misconfigurations"
    
    id = Column(Integer, primary_key=True, index=True)
    resource_id = Column(Integer, ForeignKey("cloud_resources.id"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), default=SeverityLevel.MEDIUM)
    
    # Misconfiguration details
    rule_id = Column(String(100), nullable=True)  # Security rule identifier
    rule_name = Column(String(255), nullable=True)
    current_value = Column(Text, nullable=True)
    expected_value = Column(Text, nullable=True)
    
    # Compliance
    compliance_frameworks = Column(JSON, nullable=True)  # Array of affected frameworks
    remediation_steps = Column(Text, nullable=True)
    
    # Status
    is_fixed = Column(Boolean, default=False)
    fixed_at = Column(DateTime, nullable=True)
    fixed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Timestamps
    detected_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    resource = relationship("CloudResource", back_populates="misconfigurations")
    fixed_user = relationship("User")
    
    @classmethod
    async def get_by_severity(cls, db: AsyncSession, severity: str) -> List["CloudMisconfiguration"]:
        """Get misconfigurations by severity"""
        result = await db.execute(select(cls).where(cls.severity == severity).order_by(cls.detected_at.desc()))
        return result.scalars().all()
    
    @classmethod
    async def get_unfixed(cls, db: AsyncSession) -> List["CloudMisconfiguration"]:
        """Get unfixed misconfigurations"""
        result = await db.execute(select(cls).where(cls.is_fixed == False).order_by(cls.detected_at.desc()))
        return result.scalars().all()
    
    def __repr__(self):
        return f"<CloudMisconfiguration(id={self.id}, title='{self.title}', severity='{self.severity}')>"

class CloudScan(Base):
    __tablename__ = "cloud_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String(20), nullable=False)
    scan_type = Column(String(50), nullable=False)  # full, incremental, compliance
    status = Column(String(20), default="running")  # running, completed, failed
    
    # Scan results
    resources_scanned = Column(Integer, default=0)
    misconfigurations_found = Column(Integer, default=0)
    security_score = Column(Float, nullable=True)
    
    # Scan details
    scan_config = Column(JSON, nullable=True)  # Scan configuration
    scan_results = Column(JSON, nullable=True)  # Detailed scan results
    
    # Timestamps
    started_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)
    
    # Relationships
    initiated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    def __repr__(self):
        return f"<CloudScan(id={self.id}, provider='{self.provider}', status='{self.status}')>"

class ComplianceReport(Base):
    __tablename__ = "compliance_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    framework = Column(String(50), nullable=False)
    provider = Column(String(20), nullable=False)
    
    # Report details
    overall_score = Column(Float, nullable=True)  # 0-100 compliance score
    total_controls = Column(Integer, default=0)
    passed_controls = Column(Integer, default=0)
    failed_controls = Column(Integer, default=0)
    
    # Report data
    report_data = Column(JSON, nullable=True)  # Detailed compliance data
    recommendations = Column(Text, nullable=True)
    
    # Timestamps
    generated_at = Column(DateTime, default=func.now())
    valid_until = Column(DateTime, nullable=True)
    
    # Relationships
    generated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    def __repr__(self):
        return f"<ComplianceReport(id={self.id}, framework='{self.framework}', score={self.overall_score})>" 