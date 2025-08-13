from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class UserProfile(BaseModel):
    id: int
    email: str
    username: str
    full_name: Optional[str] = None
    role: str
    department: Optional[str] = None
    phone: Optional[str] = None
    avatar_url: Optional[str] = None
    is_active: bool
    is_verified: bool
    last_login: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    two_factor_enabled: bool = False

    class Config:
        from_attributes = True

class UserProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    department: Optional[str] = None
    phone: Optional[str] = None
    avatar_url: Optional[str] = None
    preferences: Optional[Dict[str, Any]] = None

class UserPreferences(BaseModel):
    theme: str = "light"
    language: str = "en"
    timezone: str = "UTC"
    notifications: Dict[str, bool] = {
        "email": True,
        "slack": False,
        "dashboard": True
    }
    dashboard_layout: Dict[str, Any] = {
        "widgets": [],
        "columns": 3
    }

class UserActivity(BaseModel):
    id: int
    user_id: int
    action: str
    resource: str
    ip_address: str
    user_agent: str
    timestamp: datetime
    details: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True

class UserSession(BaseModel):
    id: int
    user_id: int
    session_id: str
    ip_address: str
    user_agent: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    is_active: bool

    class Config:
        from_attributes = True

class UserDashboardResponse(BaseModel):
    user_profile: UserProfile
    recent_activities: List[UserActivity]
    active_sessions: List[UserSession]
    preferences: UserPreferences
    security_status: Dict[str, Any]
    last_updated: datetime

# Additional schemas needed by user endpoints
class UserIncidentResponse(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    status: str
    reported_by: int
    assigned_to: Optional[int] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class UserTrainingResponse(BaseModel):
    id: int
    title: str
    description: str
    module_type: str
    completed: bool
    score: Optional[int] = None
    completed_at: Optional[datetime] = None
    next_training: Optional[datetime] = None

    class Config:
        from_attributes = True

class UserProfileResponse(BaseModel):
    id: int
    email: str
    username: str
    full_name: Optional[str] = None
    role: str
    department: Optional[str] = None
    phone: Optional[str] = None
    avatar_url: Optional[str] = None
    is_active: bool
    is_verified: bool
    last_login: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    two_factor_enabled: bool = False

    class Config:
        from_attributes = True

class SecurityTipsResponse(BaseModel):
    id: int
    title: str
    description: str
    category: str
    priority: str
    created_at: datetime
    is_read: bool = False
