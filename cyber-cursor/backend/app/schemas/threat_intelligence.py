from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

# Enums
class ThreatFeedType(str, Enum):
    MISP = "misp"
    RECORDED_FUTURE = "recorded_future"
    ANOMALI = "anomali"
    IBM_XFORCE = "ibm_xforce"
    VIRUSTOTAL = "virustotal"
    CUSTOM = "custom"

class IoCType(str, Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CVE = "cve"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"

class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class FeedStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    UPDATING = "updating"

# Base Models
class ThreatFeedBase(BaseModel):
    name: str = Field(..., description="Name of the threat feed")
    feed_type: ThreatFeedType = Field(..., description="Type of threat feed")
    url: str = Field(..., description="URL or endpoint for the feed")
    api_key: Optional[str] = Field(None, description="API key for the feed (encrypted)")
    update_frequency: int = Field(3600, description="Update frequency in seconds")
    description: Optional[str] = Field(None, description="Description of the feed")
    is_enabled: bool = Field(True, description="Whether the feed is enabled")

class IoCBase(BaseModel):
    value: str = Field(..., description="The IoC value")
    ioc_type: IoCType = Field(..., description="Type of IoC")
    threat_level: ThreatLevel = Field(ThreatLevel.MEDIUM, description="Threat level")
    confidence_score: float = Field(0.0, ge=0.0, le=1.0, description="Confidence score (0-1)")
    tags: List[str] = Field(default_factory=list, description="Tags for the IoC")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

class ThreatAlertBase(BaseModel):
    title: str = Field(..., description="Alert title")
    description: Optional[str] = Field(None, description="Alert description")
    threat_level: ThreatLevel = Field(..., description="Threat level")
    source: str = Field(..., description="Source of the alert")

class IntegrationConfigBase(BaseModel):
    name: str = Field(..., description="Integration name")
    integration_type: str = Field(..., description="Type of integration (siem, soar, firewall, edr)")
    endpoint_url: str = Field(..., description="Integration endpoint URL")
    api_key: Optional[str] = Field(None, description="API key (encrypted)")
    credentials: Dict[str, Any] = Field(default_factory=dict, description="Additional credentials")
    is_enabled: bool = Field(True, description="Whether integration is enabled")
    auto_block: bool = Field(False, description="Enable automatic blocking")
    block_threshold: ThreatLevel = Field(ThreatLevel.HIGH, description="Threshold for auto-blocking")

# Create Models
class ThreatFeedCreate(ThreatFeedBase):
    pass

class IoCCreate(IoCBase):
    feed_id: int = Field(..., description="ID of the associated threat feed")

class ThreatAlertCreate(ThreatAlertBase):
    ioc_id: int = Field(..., description="ID of the associated IoC")

class IntegrationConfigCreate(IntegrationConfigBase):
    pass

# Update Models
class ThreatFeedUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    api_key: Optional[str] = None
    update_frequency: Optional[int] = None
    description: Optional[str] = None
    is_enabled: Optional[bool] = None

class IoCUpdate(BaseModel):
    threat_level: Optional[ThreatLevel] = None
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None

class ThreatAlertUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    threat_level: Optional[ThreatLevel] = None
    is_resolved: Optional[bool] = None
    resolved_by: Optional[str] = None

class IntegrationConfigUpdate(BaseModel):
    name: Optional[str] = None
    endpoint_url: Optional[str] = None
    api_key: Optional[str] = None
    credentials: Optional[Dict[str, Any]] = None
    is_enabled: Optional[bool] = None
    auto_block: Optional[bool] = None
    block_threshold: Optional[ThreatLevel] = None

# Response Models
class ThreatFeedResponse(ThreatFeedBase):
    id: int
    status: FeedStatus
    last_update: Optional[datetime]
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class IoCResponse(IoCBase):
    id: int
    first_seen: datetime
    last_seen: datetime
    feed_id: int
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class ThreatAlertResponse(ThreatAlertBase):
    id: int
    ioc_id: int
    is_resolved: bool
    resolved_at: Optional[datetime]
    resolved_by: Optional[str]
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class IntegrationConfigResponse(IntegrationConfigBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class FeedLogResponse(BaseModel):
    id: int
    feed_id: int
    status: str
    message: Optional[str]
    iocs_added: int
    iocs_updated: int
    iocs_removed: int
    execution_time: Optional[float]
    created_at: datetime
    
    class Config:
        from_attributes = True

class IoCCorrelationResponse(BaseModel):
    id: int
    ioc_id: int
    correlated_ioc_id: int
    correlation_type: str
    confidence_score: float
    created_at: datetime
    
    class Config:
        from_attributes = True

class ThreatReportResponse(BaseModel):
    id: int
    title: str
    report_type: str
    content: Dict[str, Any]
    generated_by: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True

class ReportExportResponse(BaseModel):
    id: int
    report_id: int
    export_format: str
    file_path: Optional[str]
    exported_by: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True

# Dashboard and Statistics Models
class ThreatIntelligenceStats(BaseModel):
    total_iocs: int
    new_iocs_today: int
    active_feeds: int
    alerts_generated_today: int
    threats_blocked_today: int
    avg_confidence_score: float
    threat_level_distribution: Dict[str, int]
    top_ioc_types: List[Dict[str, Any]]
    recent_alerts: List[ThreatAlertResponse]
    feed_status_summary: Dict[str, int]

class IoCSearchRequest(BaseModel):
    query: str = Field(..., description="Search query")
    ioc_type: Optional[IoCType] = None
    threat_level: Optional[ThreatLevel] = None
    feed_id: Optional[int] = None
    tags: Optional[List[str]] = None
    limit: int = Field(50, le=1000, description="Maximum number of results")
    offset: int = Field(0, ge=0, description="Offset for pagination")

class IoCSearchResponse(BaseModel):
    iocs: List[IoCResponse]
    total: int
    limit: int
    offset: int

class ThreatFeedUpdateRequest(BaseModel):
    feed_id: int = Field(..., description="ID of the feed to update")

class IoCExportRequest(BaseModel):
    ioc_ids: List[int] = Field(..., description="List of IoC IDs to export")
    format: str = Field("stix", description="Export format (stix, csv, json)")
    include_metadata: bool = Field(True, description="Include metadata in export")

class IoCExportResponse(BaseModel):
    export_id: str
    format: str
    download_url: Optional[str]
    expires_at: datetime

class ThreatReportGenerateRequest(BaseModel):
    report_type: str = Field(..., description="Type of report (daily, weekly, monthly)")
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    include_iocs: bool = Field(True, description="Include IoC data")
    include_alerts: bool = Field(True, description="Include alert data")
    include_feeds: bool = Field(True, description="Include feed status")

class ThreatReportGenerateResponse(BaseModel):
    report_id: int
    status: str
    estimated_completion: Optional[datetime]

# List Response Models
class ThreatFeedListResponse(BaseModel):
    feeds: List[ThreatFeedResponse]
    total: int
    limit: int
    offset: int

class IoCListResponse(BaseModel):
    iocs: List[IoCResponse]
    total: int
    limit: int
    offset: int

class ThreatAlertListResponse(BaseModel):
    alerts: List[ThreatAlertResponse]
    total: int
    limit: int
    offset: int

class IntegrationConfigListResponse(BaseModel):
    integrations: List[IntegrationConfigResponse]
    total: int
    limit: int
    offset: int

class FeedLogListResponse(BaseModel):
    logs: List[FeedLogResponse]
    total: int
    limit: int
    offset: int

class ThreatReportListResponse(BaseModel):
    reports: List[ThreatReportResponse]
    total: int
    limit: int
    offset: int

# Health Check Models
class ThreatIntelligenceHealth(BaseModel):
    status: str
    active_feeds: int
    total_iocs: int
    last_feed_update: Optional[datetime]
    database_connection: str
    external_apis: Dict[str, str]
    last_check: datetime 