from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

# Enums
class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"

class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ComplianceStandard(str, Enum):
    CIS = "cis"
    NIST = "nist"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    HIPAA = "hipaa"

class AssetType(str, Enum):
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

# CSPM Schemas
class CloudAccountCreate(BaseModel):
    account_id: str = Field(..., description="Cloud account identifier")
    name: str = Field(..., description="Account name")
    provider: CloudProvider = Field(..., description="Cloud provider")
    region: str = Field(..., description="Primary region")
    account_metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

class CloudAccountResponse(BaseModel):
    id: int
    account_id: str
    name: str
    provider: CloudProvider
    region: str
    status: str
    last_scan: Optional[datetime]
    security_score: float
    risk_level: RiskLevel
    account_metadata: Optional[Dict[str, Any]]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class CloudAssetCreate(BaseModel):
    asset_id: str = Field(..., description="Asset identifier")
    name: str = Field(..., description="Asset name")
    asset_type: AssetType = Field(..., description="Type of asset")
    region: str = Field(..., description="Asset region")
    tags: Optional[Dict[str, str]] = Field(None, description="Asset tags")
    asset_metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

class CloudAssetResponse(BaseModel):
    id: int
    account_id: int
    asset_id: str
    name: str
    asset_type: AssetType
    region: str
    status: str
    tags: Optional[Dict[str, str]]
    asset_metadata: Optional[Dict[str, Any]]
    risk_score: float
    last_updated: datetime

    class Config:
        from_attributes = True

class MisconfigurationCreate(BaseModel):
    rule_id: str = Field(..., description="Security rule identifier")
    title: str = Field(..., description="Misconfiguration title")
    description: str = Field(..., description="Detailed description")
    severity: RiskLevel = Field(..., description="Risk severity")

class ComprehensiveScanRequest(BaseModel):
    account_id: str = Field(..., description="Cloud account identifier")
    provider: CloudProvider = Field(..., description="Cloud provider")
    scan_type: str = Field("comprehensive", description="Type of scan to perform")
    include_cspm: bool = Field(True, description="Include CSPM checks")
    include_casb: bool = Field(True, description="Include CASB checks")
    include_cloud_native: bool = Field(True, description="Include cloud-native security checks")

class CSPMScanRequest(BaseModel):
    account_id: str = Field(..., description="Cloud account identifier")
    provider: CloudProvider = Field(..., description="Cloud provider")
    scan_type: str = Field("cspm", description="Type of scan to perform")
    include_asset_discovery: bool = Field(True, description="Include asset discovery")
    include_compliance_checks: bool = Field(True, description="Include compliance checks")

class CSPMRemediationRequest(BaseModel):
    finding_id: str = Field(..., description="Security finding identifier")
    remediation_type: str = Field(..., description="Type of remediation to apply")
    auto_remediate: bool = Field(False, description="Whether to apply remediation automatically")
    approval_required: bool = Field(True, description="Whether approval is required")

class CASBDiscoveryRequest(BaseModel):
    account_id: str = Field(..., description="Cloud account identifier")
    provider: CloudProvider = Field(..., description="Cloud provider")
    discovery_type: str = Field("full", description="Type of discovery to perform")
    include_saas_apps: bool = Field(True, description="Include SaaS application discovery")
    include_user_activities: bool = Field(True, description="Include user activity analysis")

class DLPScanRequest(BaseModel):
    account_id: str = Field(..., description="Cloud account identifier")
    provider: CloudProvider = Field(..., description="Cloud provider")
    scan_type: str = Field("dlp", description="Type of DLP scan to perform")
    include_data_discovery: bool = Field(True, description="Include data discovery")
    include_classification: bool = Field(True, description="Include data classification")
    category: str = Field(..., description="Misconfiguration category")
    compliance_standards: List[ComplianceStandard] = Field(..., description="Affected compliance standards")
    remediation_steps: str = Field(..., description="Remediation instructions")
    auto_remediable: bool = Field(False, description="Whether auto-remediation is possible")

class MisconfigurationResponse(BaseModel):
    id: int
    asset_id: int
    rule_id: str
    title: str
    description: str
    severity: RiskLevel
    category: str
    compliance_standards: List[ComplianceStandard]
    remediation_steps: str
    auto_remediable: bool
    status: str
    detected_at: datetime
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True

class ComplianceReportCreate(BaseModel):
    standard: ComplianceStandard = Field(..., description="Compliance standard")
    score: float = Field(..., ge=0, le=100, description="Compliance score (0-100)")
    total_checks: int = Field(..., ge=0, description="Total compliance checks")
    passed_checks: int = Field(..., ge=0, description="Passed compliance checks")
    failed_checks: int = Field(..., ge=0, description="Failed compliance checks")
    report_data: Dict[str, Any] = Field(..., description="Detailed compliance data")

class ComplianceReportResponse(BaseModel):
    id: int
    account_id: int
    standard: ComplianceStandard
    score: float
    total_checks: int
    passed_checks: int
    failed_checks: int
    report_data: Dict[str, Any]
    generated_at: datetime

    class Config:
        from_attributes = True

# CASB Schemas
class SaaSApplicationCreate(BaseModel):
    app_name: str = Field(..., description="Application name")
    app_category: str = Field(..., description="Application category")
    vendor: str = Field(..., description="Vendor name")
    risk_score: float = Field(0.0, ge=0, le=100, description="Risk score (0-100)")
    status: str = Field("discovered", description="Application status")
    user_count: int = Field(0, ge=0, description="Number of users")
    data_classification: Optional[Dict[str, Any]] = Field(None, description="Data classification")
    security_features: Optional[Dict[str, Any]] = Field(None, description="Security features")

class SaaSApplicationResponse(BaseModel):
    id: int
    app_name: str
    app_category: str
    vendor: str
    risk_score: float
    status: str
    user_count: int
    data_classification: Optional[Dict[str, Any]]
    security_features: Optional[Dict[str, Any]]
    discovered_at: datetime
    last_activity: Optional[datetime]

    class Config:
        from_attributes = True

class UserActivityCreate(BaseModel):
    user_id: str = Field(..., description="User identifier")
    activity_type: str = Field(..., description="Type of activity")
    ip_address: str = Field(..., description="IP address")
    location: Optional[str] = Field(None, description="Geographic location")
    device_info: Optional[Dict[str, Any]] = Field(None, description="Device information")
    risk_score: float = Field(0.0, ge=0, le=100, description="Activity risk score")

class UserActivityResponse(BaseModel):
    id: int
    user_id: str
    app_id: int
    activity_type: str
    ip_address: str
    location: Optional[str]
    device_info: Optional[Dict[str, Any]]
    risk_score: float
    timestamp: datetime

    class Config:
        from_attributes = True

class DLPIncidentCreate(BaseModel):
    user_id: str = Field(..., description="User identifier")
    incident_type: str = Field(..., description="Type of DLP incident")
    file_name: str = Field(..., description="File name")
    file_size: int = Field(..., ge=0, description="File size in bytes")
    action_taken: str = Field(..., description="Action taken")
    confidence_score: float = Field(..., ge=0, le=100, description="Detection confidence")
    details: Dict[str, Any] = Field(..., description="Incident details")

class DLPIncidentResponse(BaseModel):
    id: int
    app_id: int
    user_id: str
    incident_type: str
    file_name: str
    file_size: int
    action_taken: str
    confidence_score: float
    details: Dict[str, Any]
    timestamp: datetime

    class Config:
        from_attributes = True

# Cloud-Native Security Schemas
class CloudThreatCreate(BaseModel):
    threat_id: str = Field(..., description="Threat identifier")
    threat_type: str = Field(..., description="Type of threat")
    severity: RiskLevel = Field(..., description="Threat severity")
    source_ip: str = Field(..., description="Source IP address")
    target_resource: str = Field(..., description="Target resource")
    description: str = Field(..., description="Threat description")
    threat_data: Dict[str, Any] = Field(..., description="Threat details")

class CloudThreatResponse(BaseModel):
    id: int
    account_id: int
    threat_id: str
    threat_type: str
    severity: RiskLevel
    source_ip: str
    target_resource: str
    description: str
    threat_data: Dict[str, Any]
    status: str
    detected_at: datetime
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True

class IAMRiskCreate(BaseModel):
    entity_id: str = Field(..., description="Entity identifier")
    entity_type: str = Field(..., description="Type of entity")
    risk_type: str = Field(..., description="Type of IAM risk")
    severity: RiskLevel = Field(..., description="Risk severity")
    permissions: Dict[str, Any] = Field(..., description="Entity permissions")
    recommendations: Dict[str, Any] = Field(..., description="Risk mitigation recommendations")

class IAMRiskResponse(BaseModel):
    id: int
    account_id: int
    entity_id: str
    entity_type: str
    risk_type: str
    severity: RiskLevel
    permissions: Dict[str, Any]
    recommendations: Dict[str, Any]
    status: str
    detected_at: datetime

    class Config:
        from_attributes = True

class DDoSProtectionCreate(BaseModel):
    protection_id: str = Field(..., description="Protection identifier")
    service: str = Field(..., description="DDoS protection service")
    status: str = Field(..., description="Protection status")
    protected_resources: List[str] = Field(..., description="Protected resources")
    attack_statistics: Dict[str, Any] = Field(..., description="Attack statistics")

class DDoSProtectionResponse(BaseModel):
    id: int
    account_id: int
    protection_id: str
    service: str
    status: str
    protected_resources: List[str]
    attack_statistics: Dict[str, Any]
    last_attack: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True

# Dashboard and Analytics Schemas
class CloudSecurityOverview(BaseModel):
    total_accounts: int
    total_assets: int
    total_misconfigurations: int
    total_threats: int
    total_saas_apps: int
    overall_security_score: float
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    # Enhanced Cloud Security fields
    total_containers: int = 0
    container_vulnerabilities: int = 0
    container_security_score: float = 0.0
    total_functions: int = 0
    function_vulnerabilities: int = 0
    function_security_score: float = 0.0
    total_clusters: int = 0
    total_pods: int = 0
    kubernetes_security_score: float = 0.0

class CloudSecurityMetrics(BaseModel):
    provider_distribution: Dict[str, int]
    asset_type_distribution: Dict[str, int]
    misconfiguration_trends: Dict[str, int]
    threat_trends: Dict[str, int]
    compliance_scores: Dict[str, float]
    risk_distribution: Dict[str, int]

# Scan and Remediation Schemas
class CloudScanRequest(BaseModel):
    account_id: int = Field(..., description="Account to scan")
    scan_type: str = Field(..., description="Type of scan")
    include_assets: bool = Field(True, description="Include asset discovery")
    include_misconfigurations: bool = Field(True, description="Include misconfiguration detection")
    include_compliance: bool = Field(True, description="Include compliance checks")

class RemediationRequest(BaseModel):
    misconfiguration_id: int = Field(..., description="Misconfiguration to remediate")
    auto_remediate: bool = Field(False, description="Use automated remediation")
    custom_steps: Optional[str] = Field(None, description="Custom remediation steps")

class RemediationResponse(BaseModel):
    success: bool
    message: str
    remediation_id: Optional[str] = None
    estimated_time: Optional[int] = None  # in minutes 