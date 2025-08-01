from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: int
    email: str
    role: str

class TokenData(BaseModel):
    email: Optional[str] = None

class UserBase(BaseModel):
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    role: str = "viewer"
    department: Optional[str] = None
    phone: Optional[str] = None

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    confirm_password: str

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    department: Optional[str] = None
    phone: Optional[str] = None
    avatar_url: Optional[str] = None
    preferences: Optional[dict] = None

class UserInDB(UserBase):
    id: int
    is_active: bool
    is_verified: bool
    last_login: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    two_factor_enabled: bool = False
    
    class Config:
        from_attributes = True

class User(UserInDB):
    pass

class UserLogin(BaseModel):
    email: EmailStr
    password: str
    remember_me: bool = False

class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str

class PasswordReset(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str

class TwoFactorSetup(BaseModel):
    enable: bool

class TwoFactorVerify(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)

class UserPreferences(BaseModel):
    theme: str = "light"
    language: str = "en"
    timezone: str = "UTC"
    notifications: dict = {
        "email": True,
        "slack": False,
        "dashboard": True
    }
    dashboard_layout: dict = {
        "widgets": [],
        "columns": 3
    } 