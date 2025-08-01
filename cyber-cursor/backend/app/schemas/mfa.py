from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class MFASetupRequest(BaseModel):
    """Request model for MFA setup"""
    pass

class MFASetupResponse(BaseModel):
    """Response model for MFA setup"""
    success: bool
    qr_code: str
    backup_codes: List[str]
    secret: str
    setup_uri: str
    message: str

class MFAVerificationRequest(BaseModel):
    """Request model for MFA verification"""
    token: str = Field(..., min_length=6, max_length=9, description="6-digit TOTP token or backup code")

class MFAResponse(BaseModel):
    """Response model for MFA operations"""
    success: bool
    message: str

class BackupCodesResponse(BaseModel):
    """Response model for backup codes operations"""
    success: bool
    backup_codes: List[str]
    message: str

class MFAStatusResponse(BaseModel):
    """Response model for MFA status"""
    success: bool
    mfa_status: dict

class RecoveryTokenRequest(BaseModel):
    """Request model for recovery token generation"""
    email: str = Field(..., description="User email address")

class RecoveryTokenResponse(BaseModel):
    """Response model for recovery token"""
    success: bool
    recovery_token: str
    expires_in: str
    message: str

class RecoveryTokenValidationRequest(BaseModel):
    """Request model for recovery token validation"""
    recovery_token: str = Field(..., description="Recovery token")

class RecoveryTokenValidationResponse(BaseModel):
    """Response model for recovery token validation"""
    success: bool
    user_id: int
    message: str

class MFAStatus(BaseModel):
    """MFA status information"""
    enabled: bool
    setup_pending: bool = False
    backup_codes_remaining: int = 0
    enabled_at: Optional[datetime] = None
    last_used: Optional[datetime] = None

class MFAConfiguration(BaseModel):
    """MFA configuration settings"""
    totp_window: int = Field(default=1, description="TOTP verification window")
    backup_codes_count: int = Field(default=10, description="Number of backup codes to generate")
    backup_code_length: int = Field(default=8, description="Length of backup codes")
    recovery_token_expiry_hours: int = Field(default=24, description="Recovery token expiry in hours")

class MFAUsageStats(BaseModel):
    """MFA usage statistics"""
    total_logins: int
    mfa_logins: int
    backup_code_usage: int
    failed_attempts: int
    last_used: Optional[datetime] = None 