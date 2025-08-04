from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum

# Enums
class KeyType(str, Enum):
    AES = "AES"
    RSA = "RSA"
    ECC = "ECC"

class PolicyType(str, Enum):
    EMAIL = "email"
    FILE = "file"
    DATABASE = "database"
    CLOUD = "cloud"

class EnforcementLevel(str, Enum):
    MONITOR = "monitor"
    BLOCK = "block"
    QUARANTINE = "quarantine"

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

class DatabaseType(str, Enum):
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    ORACLE = "oracle"
    SQLSERVER = "sqlserver"

class AccessType(str, Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"

class RequestStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"

class ComplianceFramework(str, Enum):
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    SOX = "sox"
    ISO27001 = "iso27001"

# Encryption Schemas
class EncryptionKeyCreate(BaseModel):
    key_name: str = Field(..., min_length=1, max_length=255)
    key_type: KeyType
    key_size: int = Field(..., ge=128, le=4096)
    expires_at: Optional[datetime] = None
    key_metadata: Optional[Dict[str, Any]] = None

class EncryptionKeyUpdate(BaseModel):
    key_name: Optional[str] = Field(None, min_length=1, max_length=255)
    expires_at: Optional[datetime] = None
    key_metadata: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None

class EncryptionKeyResponse(BaseModel):
    key_id: int
    key_name: str
    key_type: str
    key_size: int
    created_at: datetime
    expires_at: Optional[datetime]
    is_active: bool
    key_metadata: Optional[Dict[str, Any]]

    class Config:
        from_attributes = True

class EncryptedAssetCreate(BaseModel):
    asset_type: str = Field(..., min_length=1, max_length=50)
    asset_path: str = Field(..., min_length=1, max_length=500)
    key_id: int
    metadata: Optional[Dict[str, Any]] = None

class EncryptedAssetResponse(BaseModel):
    asset_id: int
    asset_type: str
    asset_path: str
    key_id: int
    encryption_status: str
    last_encrypted: datetime
    metadata: Optional[Dict[str, Any]]

    class Config:
        from_attributes = True

class DatabaseEncryptionCreate(BaseModel):
    database_name: str = Field(..., min_length=1, max_length=255)
    table_name: str = Field(..., min_length=1, max_length=255)
    column_name: str = Field(..., min_length=1, max_length=255)
    key_id: int
    encryption_type: str = Field(..., min_length=1, max_length=50)

class DatabaseEncryptionResponse(BaseModel):
    encryption_id: int
    database_name: str
    table_name: str
    column_name: str
    key_id: int
    encryption_type: str
    created_at: datetime
    is_active: bool

    class Config:
        from_attributes = True

# DLP Schemas
class DLPPolicyCreate(BaseModel):
    policy_name: str = Field(..., min_length=1, max_length=255)
    policy_type: PolicyType
    policy_rules: Dict[str, Any]
    enforcement_level: EnforcementLevel = EnforcementLevel.MONITOR

class DLPPolicyUpdate(BaseModel):
    policy_name: Optional[str] = Field(None, min_length=1, max_length=255)
    policy_rules: Optional[Dict[str, Any]] = None
    enforcement_level: Optional[EnforcementLevel] = None
    is_active: Optional[bool] = None

class DLPPolicyResponse(BaseModel):
    policy_id: int
    policy_name: str
    policy_type: str
    policy_rules: Dict[str, Any]
    enforcement_level: str
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class DLPIncidentCreate(BaseModel):
    policy_id: int
    user_id: Optional[int] = None
    file_path: Optional[str] = None
    content_type: Optional[str] = None
    violation_type: str = Field(..., min_length=1, max_length=100)
    severity: Severity = Severity.MEDIUM

class DLPIncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    resolution_notes: Optional[str] = None
    resolved_at: Optional[datetime] = None

class DLPIncidentResponse(BaseModel):
    incident_id: int
    policy_id: int
    user_id: Optional[int]
    file_path: Optional[str]
    content_type: Optional[str]
    violation_type: str
    severity: str
    status: str
    created_at: datetime
    resolved_at: Optional[datetime]
    resolution_notes: Optional[str]

    class Config:
        from_attributes = True

class DataDiscoveryCreate(BaseModel):
    scan_type: str = Field(..., min_length=1, max_length=50)
    target_path: str = Field(..., min_length=1, max_length=500)
    discovered_data: Dict[str, Any]
    classification: str = Field(..., min_length=1, max_length=50)

class DataDiscoveryResponse(BaseModel):
    discovery_id: int
    scan_type: str
    target_path: str
    discovered_data: Dict[str, Any]
    classification: str
    scan_date: datetime
    is_processed: bool

    class Config:
        from_attributes = True

# Database Security Schemas
class DatabaseConnectionCreate(BaseModel):
    db_name: str = Field(..., min_length=1, max_length=255)
    db_type: DatabaseType
    host: str = Field(..., min_length=1, max_length=255)
    port: Optional[int] = Field(None, ge=1, le=65535)
    connection_string: Optional[str] = None
    is_monitored: bool = True

class DatabaseConnectionUpdate(BaseModel):
    db_name: Optional[str] = Field(None, min_length=1, max_length=255)
    host: Optional[str] = Field(None, min_length=1, max_length=255)
    port: Optional[int] = Field(None, ge=1, le=65535)
    connection_string: Optional[str] = None
    is_monitored: Optional[bool] = None

class DatabaseConnectionResponse(BaseModel):
    connection_id: int
    db_name: str
    db_type: str
    host: str
    port: Optional[int]
    is_monitored: bool
    created_at: datetime

    class Config:
        from_attributes = True

class DatabaseAuditLogCreate(BaseModel):
    connection_id: int
    user_id: Optional[str] = None
    query_text: Optional[str] = None
    query_type: Optional[str] = None
    execution_time: Optional[int] = None
    rows_affected: Optional[int] = None
    ip_address: Optional[str] = None
    is_anomalous: bool = False

class DatabaseAuditLogResponse(BaseModel):
    log_id: int
    connection_id: int
    user_id: Optional[str]
    query_text: Optional[str]
    query_type: Optional[str]
    execution_time: Optional[int]
    rows_affected: Optional[int]
    ip_address: Optional[str]
    timestamp: datetime
    is_anomalous: bool

    class Config:
        from_attributes = True

class DatabaseAccessRequestCreate(BaseModel):
    user_id: int
    connection_id: int
    access_type: AccessType
    reason: str = Field(..., min_length=1)
    requested_duration: int = Field(..., ge=1, le=1440)  # 1 minute to 24 hours

class DatabaseAccessRequestUpdate(BaseModel):
    status: Optional[RequestStatus] = None
    approved_by: Optional[int] = None
    approved_at: Optional[datetime] = None

class DatabaseAccessRequestResponse(BaseModel):
    request_id: int
    user_id: int
    connection_id: int
    access_type: str
    reason: str
    requested_duration: int
    status: str
    approved_by: Optional[int]
    approved_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True

class DatabaseVulnerabilityCreate(BaseModel):
    connection_id: int
    vulnerability_type: str = Field(..., min_length=1, max_length=100)
    severity: Severity
    description: str = Field(..., min_length=1)
    remediation_steps: Optional[str] = None

class DatabaseVulnerabilityResponse(BaseModel):
    vulnerability_id: int
    connection_id: int
    vulnerability_type: str
    severity: str
    description: str
    remediation_steps: Optional[str]
    discovered_at: datetime
    resolved_at: Optional[datetime]
    is_resolved: bool

    class Config:
        from_attributes = True

# Data Protection Schemas
class DataMaskingCreate(BaseModel):
    connection_id: int
    table_name: str = Field(..., min_length=1, max_length=255)
    column_name: str = Field(..., min_length=1, max_length=255)
    masking_type: str = Field(..., min_length=1, max_length=50)
    masking_rules: Optional[Dict[str, Any]] = None

class DataMaskingResponse(BaseModel):
    masking_id: int
    connection_id: int
    table_name: str
    column_name: str
    masking_type: str
    masking_rules: Optional[Dict[str, Any]]
    created_at: datetime
    is_active: bool

    class Config:
        from_attributes = True

class DataTokenizationCreate(BaseModel):
    connection_id: int
    table_name: str = Field(..., min_length=1, max_length=255)
    column_name: str = Field(..., min_length=1, max_length=255)
    token_type: str = Field(..., min_length=1, max_length=50)
    token_format: Optional[str] = None

class DataTokenizationResponse(BaseModel):
    tokenization_id: int
    connection_id: int
    table_name: str
    column_name: str
    token_type: str
    token_format: Optional[str]
    created_at: datetime
    is_active: bool

    class Config:
        from_attributes = True

# Compliance Schemas
class SecurityComplianceCreate(BaseModel):
    framework: ComplianceFramework
    requirement: str = Field(..., min_length=1, max_length=255)
    status: str = Field(..., min_length=1, max_length=50)
    evidence: Optional[str] = None
    next_assessment: Optional[datetime] = None

class SecurityComplianceResponse(BaseModel):
    compliance_id: int
    framework: str
    requirement: str
    status: str
    evidence: Optional[str]
    last_assessed: datetime
    next_assessment: Optional[datetime]

    class Config:
        from_attributes = True

class SecurityReportCreate(BaseModel):
    report_type: str = Field(..., min_length=1, max_length=50)
    report_data: Dict[str, Any]
    generated_by: Optional[int] = None
    report_path: Optional[str] = None

class SecurityReportResponse(BaseModel):
    report_id: int
    report_type: str
    report_data: Dict[str, Any]
    generated_at: datetime
    generated_by: Optional[int]
    report_path: Optional[str]

    class Config:
        from_attributes = True

# Dashboard and Statistics Schemas
class DataSecurityStats(BaseModel):
    total_encrypted_assets: int
    active_dlp_incidents: int
    monitored_databases: int
    security_score: float
    compliance_status: Dict[str, str]
    recent_vulnerabilities: int
    pending_access_requests: int

class EncryptionStats(BaseModel):
    total_keys: int
    active_keys: int
    encrypted_files: int
    encrypted_databases: int
    key_rotation_due: int

class DLPStats(BaseModel):
    total_policies: int
    active_policies: int
    open_incidents: int
    resolved_incidents: int
    false_positives: int

class DatabaseSecurityStats(BaseModel):
    monitored_connections: int
    total_audit_logs: int
    anomalous_activities: int
    open_vulnerabilities: int
    pending_requests: int

# List Response Schemas
class EncryptionKeyListResponse(BaseModel):
    keys: List[EncryptionKeyResponse]
    total: int
    page: int
    size: int

class DLPPolicyListResponse(BaseModel):
    policies: List[DLPPolicyResponse]
    total: int
    page: int
    size: int

class DLPIncidentListResponse(BaseModel):
    incidents: List[DLPIncidentResponse]
    total: int
    page: int
    size: int

class DatabaseConnectionListResponse(BaseModel):
    connections: List[DatabaseConnectionResponse]
    total: int
    page: int
    size: int

class DatabaseAuditLogListResponse(BaseModel):
    logs: List[DatabaseAuditLogResponse]
    total: int
    page: int
    size: int

class DatabaseAccessRequestListResponse(BaseModel):
    requests: List[DatabaseAccessRequestResponse]
    total: int
    page: int
    size: int

# Health Check Schema
class DataSecurityHealthCheck(BaseModel):
    status: str
    encryption_service: str
    dlp_service: str
    database_security_service: str
    database_connection: str
    last_check: datetime 