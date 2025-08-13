from pydantic import BaseModel, EmailStr, Field, validator, model_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

# Enums
class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    USER = "user"
    PRIVILEGED = "privileged"

class SystemType(str, Enum):
    SERVER = "server"
    DATABASE = "database"
    NETWORK_DEVICE = "network_device"
    CLOUD = "cloud"

class AccountType(str, Enum):
    ADMIN = "admin"
    ROOT = "root"
    SERVICE_ACCOUNT = "service_account"

class AccessType(str, Enum):
    JIT = "jit"
    EMERGENCY = "emergency"
    SCHEDULED = "scheduled"

class AccessStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    ACTIVE = "active"
    EXPIRED = "expired"

class EventType(str, Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    PRIVILEGED_ACCESS = "privileged_access"
    SESSION = "session"

class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class MFAType(str, Enum):
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    PUSH = "push"

class SSOProviderType(str, Enum):
    AZURE_AD = "azure_ad"
    OKTA = "okta"
    GOOGLE = "google"
    SAML = "saml"
    OIDC = "oidc"

# Base Models
class BaseSchema(BaseModel):
    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

# User Schemas
class UserBase(BaseSchema):
    username: str = Field(..., min_length=3, max_length=100)
    email: EmailStr
    full_name: Optional[str] = Field(None, max_length=255)
    department: Optional[str] = Field(None, max_length=100)
    phone: Optional[str] = Field(None, max_length=20)
    role: UserRole = UserRole.USER

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    sso_provider: Optional[str] = None
    sso_external_id: Optional[str] = None

class UserUpdate(BaseSchema):
    username: Optional[str] = Field(None, min_length=3, max_length=100)
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(None, max_length=255)
    department: Optional[str] = Field(None, max_length=100)
    phone: Optional[str] = Field(None, max_length=20)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None

class UserResponse(UserBase):
    id: int
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    sso_provider: Optional[str] = None
    last_login: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

class UserListResponse(BaseSchema):
    users: List[UserResponse]
    total: int
    page: int
    size: int

# Session Schemas
class SessionBase(BaseSchema):
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_info: Optional[Dict[str, Any]] = None
    location_info: Optional[Dict[str, Any]] = None

class SessionCreate(SessionBase):
    user_id: int
    token: str
    refresh_token: Optional[str] = None
    expires_at: datetime
    sso_provider: Optional[str] = None
    sso_session_id: Optional[str] = None

class SessionResponse(SessionBase):
    id: int
    user_id: int
    is_active: bool
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    sso_provider: Optional[str] = None
    mfa_verified: bool
    mfa_method_used: Optional[str] = None

class SessionListResponse(BaseSchema):
    sessions: List[SessionResponse]
    total: int

# Privileged Account Schemas
class PrivilegedAccountBase(BaseSchema):
    system_name: str = Field(..., max_length=255)
    system_type: SystemType
    username: str = Field(..., max_length=100)
    account_type: AccountType = AccountType.ADMIN
    hostname: Optional[str] = Field(None, max_length=255)
    ip_address: Optional[str] = None
    port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: str = Field(default="ssh", max_length=20)
    requires_approval: bool = True
    max_session_duration: int = Field(default=60, ge=1, le=1440)  # minutes
    allowed_ips: Optional[List[str]] = None
    rotation_interval: int = Field(default=90, ge=1, le=365)  # days

class PrivilegedAccountCreate(PrivilegedAccountBase):
    password: str = Field(..., min_length=1)
    private_key: Optional[str] = None

class PrivilegedAccountUpdate(BaseSchema):
    system_name: Optional[str] = Field(None, max_length=255)
    system_type: Optional[SystemType] = None
    username: Optional[str] = Field(None, max_length=100)
    account_type: Optional[AccountType] = None
    hostname: Optional[str] = Field(None, max_length=255)
    ip_address: Optional[str] = None
    port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[str] = Field(None, max_length=20)
    requires_approval: Optional[bool] = None
    max_session_duration: Optional[int] = Field(None, ge=1, le=1440)
    allowed_ips: Optional[List[str]] = None
    rotation_interval: Optional[int] = Field(None, ge=1, le=365)
    is_active: Optional[bool] = None

class PrivilegedAccountResponse(PrivilegedAccountBase):
    id: int
    is_active: bool
    last_rotation: Optional[datetime] = None
    next_rotation: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

class PrivilegedAccountListResponse(BaseSchema):
    accounts: List[PrivilegedAccountResponse]
    total: int
    page: int
    size: int

# Privileged Access Schemas
class PrivilegedAccessBase(BaseSchema):
    account_id: int
    access_type: AccessType = AccessType.JIT
    reason: str = Field(..., min_length=1, max_length=1000)
    expires_at: datetime

class PrivilegedAccessCreate(PrivilegedAccessBase):
    pass

class PrivilegedAccessUpdate(BaseSchema):
    status: AccessStatus
    approved_by: Optional[int] = None
    actual_expires_at: Optional[datetime] = None

class PrivilegedAccessResponse(PrivilegedAccessBase):
    id: int
    user_id: int
    status: AccessStatus
    requested_at: datetime
    approved_at: Optional[datetime] = None
    approved_by: Optional[int] = None
    actual_expires_at: Optional[datetime] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    mfa_verified: bool
    mfa_method_used: Optional[str] = None

class PrivilegedAccessListResponse(BaseSchema):
    access_requests: List[PrivilegedAccessResponse]
    total: int
    page: int
    size: int

# Audit Log Schemas
class AuditLogBase(BaseSchema):
    action: str = Field(..., max_length=255)
    target: Optional[str] = Field(None, max_length=255)
    target_type: Optional[str] = Field(None, max_length=50)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    event_type: EventType
    severity: Severity = Severity.INFO
    details: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None
    compliance_framework: Optional[str] = Field(None, max_length=50)
    risk_score: Optional[float] = Field(None, ge=0.0, le=10.0)

class AuditLogCreate(AuditLogBase):
    user_id: Optional[int] = None
    privileged_account_id: Optional[int] = None

class AuditLogResponse(AuditLogBase):
    id: int
    user_id: Optional[int] = None
    privileged_account_id: Optional[int] = None
    timestamp: datetime

class AuditLogListResponse(BaseSchema):
    logs: List[AuditLogResponse]
    total: int
    page: int
    size: int

# SSO Provider Schemas
class SSOProviderBase(BaseSchema):
    name: str = Field(..., max_length=100)
    provider_type: SSOProviderType
    client_id: str = Field(..., max_length=255)
    redirect_uri: str = Field(..., max_length=500)
    authorization_url: Optional[str] = Field(None, max_length=500)
    token_url: Optional[str] = Field(None, max_length=500)
    userinfo_url: Optional[str] = Field(None, max_length=500)
    saml_entity_id: Optional[str] = Field(None, max_length=255)
    saml_sso_url: Optional[str] = Field(None, max_length=500)
    saml_x509_cert: Optional[str] = None
    auto_provision: bool = True
    default_role: UserRole = UserRole.USER
    allowed_domains: Optional[List[str]] = None

class SSOProviderCreate(SSOProviderBase):
    client_secret: str = Field(..., min_length=1)

class SSOProviderUpdate(BaseSchema):
    name: Optional[str] = Field(None, max_length=100)
    provider_type: Optional[SSOProviderType] = None
    client_id: Optional[str] = Field(None, max_length=255)
    client_secret: Optional[str] = None
    redirect_uri: Optional[str] = Field(None, max_length=500)
    authorization_url: Optional[str] = Field(None, max_length=500)
    token_url: Optional[str] = Field(None, max_length=500)
    userinfo_url: Optional[str] = Field(None, max_length=500)
    saml_entity_id: Optional[str] = Field(None, max_length=255)
    saml_sso_url: Optional[str] = Field(None, max_length=500)
    saml_x509_cert: Optional[str] = None
    auto_provision: Optional[bool] = None
    default_role: Optional[UserRole] = None
    allowed_domains: Optional[List[str]] = None
    is_active: Optional[bool] = None

class SSOProviderResponse(SSOProviderBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

class SSOProviderListResponse(BaseSchema):
    providers: List[SSOProviderResponse]
    total: int

# MFA Schemas
class MFASetupBase(BaseSchema):
    mfa_type: MFAType
    phone_number: Optional[str] = Field(None, max_length=20)
    email_address: Optional[EmailStr] = None
    device_name: Optional[str] = Field(None, max_length=100)

class MFASetupCreate(MFASetupBase):
    user_id: int

class MFASetupResponse(MFASetupBase):
    id: int
    user_id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

class MFASetupListResponse(BaseSchema):
    setups: List[MFASetupResponse]
    total: int

# Authentication Schemas
class LoginRequest(BaseSchema):
    username: Optional[str] = None
    email: Optional[str] = None
    password: str
    mfa_token: Optional[str] = None
    device_info: Optional[Dict[str, Any]] = None
    
    @model_validator(mode='after')
    def validate_username_or_email_required(self):
        if not self.username and not self.email:
            raise ValueError('Either username or email must be provided')
        return self

class SSOLoginRequest(BaseSchema):
    provider: str
    code: str
    state: Optional[str] = None
    device_info: Optional[Dict[str, Any]] = None

class TokenResponse(BaseSchema):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int
    user_id: int
    email: str
    role: str
    mfa_required: bool = False

class RefreshTokenRequest(BaseSchema):
    refresh_token: str

class LogoutRequest(BaseSchema):
    session_id: Optional[str] = None

# MFA Verification Schemas
class MFAVerifyRequest(BaseSchema):
    token: str = Field(..., min_length=6, max_length=6)
    backup_code: Optional[str] = None

class MFAVerifyResponse(BaseSchema):
    success: bool
    message: str
    backup_codes_remaining: Optional[int] = None

class MFASetupInitResponse(BaseSchema):
    success: bool
    qr_code: Optional[str] = None
    secret: Optional[str] = None
    backup_codes: List[str]
    setup_uri: Optional[str] = None
    message: str

# Dashboard and Analytics Schemas
class IAMDashboardStats(BaseSchema):
    total_users: int
    active_users: int
    privileged_accounts: int
    active_sessions: int
    pending_approvals: int
    recent_audit_events: int
    mfa_enabled_users: int
    sso_enabled_users: int

class IAMAnalytics(BaseSchema):
    login_attempts_24h: int
    failed_logins_24h: int
    privileged_access_24h: int
    mfa_challenges_24h: int
    active_sessions_by_role: Dict[str, int]
    top_privileged_systems: List[Dict[str, Any]]
    recent_security_events: List[Dict[str, Any]]

# Compliance Schemas
class ComplianceReport(BaseSchema):
    framework: str
    report_date: datetime
    total_checks: int
    passed_checks: int
    failed_checks: int
    compliance_score: float
    details: List[Dict[str, Any]]

class ComplianceReportList(BaseSchema):
    reports: List[ComplianceReport]
    total: int

# Search and Filter Schemas
class UserSearchParams(BaseSchema):
    username: Optional[str] = None
    email: Optional[str] = None
    role: Optional[UserRole] = None
    department: Optional[str] = None
    is_active: Optional[bool] = None
    sso_provider: Optional[str] = None
    mfa_enabled: Optional[bool] = None

class AuditLogSearchParams(BaseSchema):
    user_id: Optional[int] = None
    action: Optional[str] = None
    event_type: Optional[EventType] = None
    severity: Optional[Severity] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    ip_address: Optional[str] = None

class PrivilegedAccountSearchParams(BaseSchema):
    system_name: Optional[str] = None
    system_type: Optional[SystemType] = None
    account_type: Optional[AccountType] = None
    is_active: Optional[bool] = None
    requires_approval: Optional[bool] = None

# Bulk Operations
class BulkUserCreate(BaseSchema):
    users: List[UserCreate]

class BulkUserUpdate(BaseSchema):
    user_ids: List[int]
    updates: UserUpdate

class BulkPrivilegedAccountCreate(BaseSchema):
    accounts: List[PrivilegedAccountCreate]

# Notification Schemas
class NotificationRequest(BaseSchema):
    user_id: int
    notification_type: str
    title: str
    message: str
    data: Optional[Dict[str, Any]] = None

class NotificationResponse(BaseSchema):
    id: int
    user_id: int
    notification_type: str
    title: str
    message: str
    data: Optional[Dict[str, Any]] = None
    is_read: bool
    created_at: datetime

# Health Check Schemas
class IAMHealthCheck(BaseSchema):
    database: bool
    redis: bool
    encryption_service: bool
    sso_providers: Dict[str, bool]
    mfa_service: bool
    audit_service: bool
    overall_status: str

# Error Response Schemas
class ErrorResponse(BaseSchema):
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.now)

class ValidationErrorResponse(BaseSchema):
    error: str = "validation_error"
    message: str
    field_errors: Dict[str, List[str]]
    timestamp: datetime = Field(default_factory=datetime.now) 