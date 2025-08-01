from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum

class IntegrationType(str, Enum):
    SIEM = "siem"
    EMAIL = "email"
    CLOUD = "cloud"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"

class SIEMProvider(str, Enum):
    SPLUNK = "splunk"
    QRADAR = "qradar"
    ELK = "elk"
    SENTINEL = "sentinel"
    CROWDSTRIKE = "crowdstrike"

class EmailProvider(str, Enum):
    OFFICE365 = "office365"
    GMAIL = "gmail"
    EXCHANGE = "exchange"
    SMTP = "smtp"

class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"

class IntegrationCreate(BaseModel):
    """Request model for creating an integration"""
    name: str = Field(..., min_length=1, max_length=100, description="Integration name")
    type: IntegrationType = Field(..., description="Integration type")
    provider: str = Field(..., description="Integration provider")
    config: Dict[str, Any] = Field(..., description="Integration configuration")
    enabled: bool = Field(default=True, description="Whether integration is enabled")

class IntegrationUpdate(BaseModel):
    """Request model for updating an integration"""
    name: Optional[str] = Field(None, min_length=1, max_length=100, description="Integration name")
    config: Optional[Dict[str, Any]] = Field(None, description="Integration configuration")
    enabled: Optional[bool] = Field(None, description="Whether integration is enabled")

class IntegrationResponse(BaseModel):
    """Response model for integration data"""
    id: str
    name: str
    type: str
    provider: str
    enabled: bool
    status: str
    last_sync: Optional[datetime] = None

class IntegrationTestResponse(BaseModel):
    """Response model for integration test results"""
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class SyncResponse(BaseModel):
    """Response model for sync operations"""
    success: bool
    message: str
    integration_id: str

class IntegrationStatusResponse(BaseModel):
    """Response model for integration status overview"""
    total_integrations: int
    enabled_integrations: int
    active_integrations: int
    type_statistics: Dict[str, Dict[str, int]]
    recent_syncs: List[Dict[str, Any]]

class NotificationRequest(BaseModel):
    """Request model for sending notifications"""
    message: str = Field(..., min_length=1, description="Notification message")
    channel: Optional[str] = Field("#security", description="Slack channel or Teams webhook")
    priority: Optional[str] = Field("normal", description="Notification priority")

class WebhookPayload(BaseModel):
    """Model for webhook payloads"""
    event_type: str = Field(..., description="Type of event")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Event timestamp")
    data: Dict[str, Any] = Field(..., description="Event data")
    source: str = Field(..., description="Event source")

class IntegrationConfig(BaseModel):
    """Model for integration configuration"""
    url: Optional[str] = Field(None, description="Integration URL")
    username: Optional[str] = Field(None, description="Username for authentication")
    password: Optional[str] = Field(None, description="Password for authentication")
    token: Optional[str] = Field(None, description="API token")
    api_key: Optional[str] = Field(None, description="API key")
    secret_key: Optional[str] = Field(None, description="Secret key")
    region: Optional[str] = Field(None, description="Cloud region")
    tenant_id: Optional[str] = Field(None, description="Tenant ID")
    client_id: Optional[str] = Field(None, description="Client ID")
    client_secret: Optional[str] = Field(None, description="Client secret")
    mailbox: Optional[str] = Field(None, description="Email mailbox")
    index: Optional[str] = Field(None, description="SIEM index")
    services: Optional[List[str]] = Field(None, description="Cloud services")

class SIEMConfig(IntegrationConfig):
    """Configuration for SIEM integrations"""
    index: str = Field(..., description="SIEM index for events")
    sourcetype: Optional[str] = Field(None, description="SIEM sourcetype")
    host: Optional[str] = Field(None, description="SIEM host")

class EmailConfig(IntegrationConfig):
    """Configuration for email integrations"""
    mailbox: str = Field(..., description="Email mailbox")
    folder: Optional[str] = Field("Inbox", description="Email folder")
    filter_query: Optional[str] = Field(None, description="Email filter query")

class CloudConfig(IntegrationConfig):
    """Configuration for cloud integrations"""
    region: str = Field(..., description="Cloud region")
    services: List[str] = Field(..., description="Cloud services to monitor")
    subscription_id: Optional[str] = Field(None, description="Azure subscription ID")
    project_id: Optional[str] = Field(None, description="GCP project ID")

class IntegrationEvent(BaseModel):
    """Model for integration events"""
    id: str
    integration_id: str
    event_type: str
    timestamp: datetime
    data: Dict[str, Any]
    status: str = "pending"
    processed: bool = False
    error_message: Optional[str] = None

class IntegrationMetrics(BaseModel):
    """Model for integration metrics"""
    integration_id: str
    total_events: int
    successful_events: int
    failed_events: int
    last_event_time: Optional[datetime] = None
    average_processing_time: Optional[float] = None
    uptime_percentage: float

class ProviderCapability(BaseModel):
    """Model for provider capabilities"""
    name: str
    description: str
    capabilities: List[str]
    authentication_methods: List[str]
    required_config: List[str]
    optional_config: List[str]

class IntegrationTemplate(BaseModel):
    """Model for integration templates"""
    provider: str
    type: IntegrationType
    name: str
    description: str
    config_template: Dict[str, Any]
    capabilities: List[str]
    documentation_url: Optional[str] = None 