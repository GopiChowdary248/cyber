from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, JSON, Float
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from datetime import datetime
from typing import Optional, List
import json

from app.core.database import Base

class IAMUser(Base):
    """Enhanced User model for IAM with SSO/MFA support"""
    __tablename__ = "iam_users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=True)  # Nullable for SSO-only users
    mfa_enabled = Column(Boolean, default=False)
    role = Column(String(50), default="user")  # admin, analyst, user, privileged
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # SSO Information
    sso_provider = Column(String(50), nullable=True)  # azure_ad, okta, google, saml
    sso_external_id = Column(String(255), nullable=True)
    sso_attributes = Column(JSON, nullable=True)  # Store SSO provider attributes
    
    # MFA Information
    mfa_secret = Column(String(255), nullable=True)
    mfa_backup_codes = Column(JSON, nullable=True)
    mfa_method = Column(String(20), default="totp")  # totp, sms, email, push
    
    # Profile Information
    full_name = Column(String(255), nullable=True)
    department = Column(String(100), nullable=True)
    phone = Column(String(20), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    
    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    privileged_access = relationship("PrivilegedAccess", back_populates="user", foreign_keys="[PrivilegedAccess.user_id]", cascade="all, delete-orphan")
    
    @classmethod
    async def get_by_email(cls, db: AsyncSession, email: str) -> Optional["IAMUser"]:
        """Get user by email"""
        result = await db.execute(select(cls).where(cls.email == email))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_username(cls, db: AsyncSession, username: str) -> Optional["IAMUser"]:
        """Get user by username"""
        result = await db.execute(select(cls).where(cls.username == username))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_sso_id(cls, db: AsyncSession, sso_provider: str, sso_external_id: str) -> Optional["IAMUser"]:
        """Get user by SSO provider and external ID"""
        result = await db.execute(
            select(cls).where(
                cls.sso_provider == sso_provider,
                cls.sso_external_id == sso_external_id
            )
        )
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_id(cls, db: AsyncSession, user_id: int) -> Optional["IAMUser"]:
        """Get user by ID"""
        result = await db.execute(select(cls).where(cls.id == user_id))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_all(cls, db: AsyncSession, skip: int = 0, limit: int = 100) -> List["IAMUser"]:
        """Get all users with pagination"""
        result = await db.execute(select(cls).offset(skip).limit(limit))
        return result.scalars().all()
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}', role='{self.role}')>"


class Session(Base):
    """User session management for SSO and security"""
    __tablename__ = "iam_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("iam_users.id"), nullable=False)
    token = Column(String(500), unique=True, nullable=False, index=True)
    refresh_token = Column(String(500), unique=True, nullable=True)
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(Text, nullable=True)
    device_info = Column(JSON, nullable=True)  # Store device fingerprint
    location_info = Column(JSON, nullable=True)  # Store location data
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=func.now())
    
    # SSO Information
    sso_provider = Column(String(50), nullable=True)
    sso_session_id = Column(String(255), nullable=True)
    
    # MFA Information
    mfa_verified = Column(Boolean, default=False)
    mfa_method_used = Column(String(20), nullable=True)
    
    # Relationships
    user = relationship("IAMUser", back_populates="sessions")
    
    @classmethod
    async def get_by_token(cls, db: AsyncSession, token: str) -> Optional["Session"]:
        """Get session by token"""
        result = await db.execute(select(cls).where(cls.token == token))
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_active_sessions(cls, db: AsyncSession, user_id: int) -> List["Session"]:
        """Get all active sessions for a user"""
        result = await db.execute(
            select(cls).where(
                cls.user_id == user_id,
                cls.is_active == True,
                cls.expires_at > datetime.utcnow()
            )
        )
        return result.scalars().all()
    
    def __repr__(self):
        return f"<Session(id={self.id}, user_id={self.user_id}, expires_at='{self.expires_at}')>"


class PrivilegedAccount(Base):
    """Privileged account management for PAM"""
    __tablename__ = "iam_privileged_accounts"
    
    id = Column(Integer, primary_key=True, index=True)
    system_name = Column(String(255), nullable=False)
    system_type = Column(String(50), nullable=False)  # server, database, network_device, cloud
    username = Column(String(100), nullable=False)
    encrypted_password = Column(Text, nullable=False)  # AES-256 encrypted
    encrypted_private_key = Column(Text, nullable=True)  # For SSH keys
    account_type = Column(String(50), default="admin")  # admin, root, service_account
    is_active = Column(Boolean, default=True)
    last_rotation = Column(DateTime, nullable=True)
    next_rotation = Column(DateTime, nullable=True)
    rotation_interval = Column(Integer, default=90)  # days
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # System Information
    hostname = Column(String(255), nullable=True)
    ip_address = Column(String(50), nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(20), default="ssh")  # ssh, rdp, http, https
    
    # Security Settings
    requires_approval = Column(Boolean, default=True)
    max_session_duration = Column(Integer, default=60)  # minutes
    allowed_ips = Column(JSON, nullable=True)  # List of allowed IP addresses
    
    # Relationships
    privileged_access = relationship("PrivilegedAccess", back_populates="account", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="privileged_account", cascade="all, delete-orphan")
    
    @classmethod
    async def get_all(cls, db: AsyncSession, skip: int = 0, limit: int = 100) -> List["PrivilegedAccount"]:
        """Get all privileged accounts"""
        result = await db.execute(select(cls).offset(skip).limit(limit))
        return result.scalars().all()
    
    @classmethod
    async def get_by_system(cls, db: AsyncSession, system_name: str) -> List["PrivilegedAccount"]:
        """Get privileged accounts by system name"""
        result = await db.execute(select(cls).where(cls.system_name == system_name))
        return result.scalars().all()
    
    def __repr__(self):
        return f"<PrivilegedAccount(id={self.id}, system='{self.system_name}', username='{self.username}')>"


class PrivilegedAccess(Base):
    """Just-in-Time access management for PAM"""
    __tablename__ = "iam_privileged_access"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("iam_users.id"), nullable=False)
    account_id = Column(Integer, ForeignKey("iam_privileged_accounts.id"), nullable=False)
    access_type = Column(String(50), default="jit")  # jit, emergency, scheduled
    status = Column(String(20), default="pending")  # pending, approved, denied, active, expired
    requested_at = Column(DateTime, default=func.now())
    approved_at = Column(DateTime, nullable=True)
    approved_by = Column(Integer, ForeignKey("iam_users.id"), nullable=True)
    expires_at = Column(DateTime, nullable=False)
    actual_expires_at = Column(DateTime, nullable=True)
    
    # Access Details
    reason = Column(Text, nullable=False)
    session_id = Column(String(255), nullable=True)
    ip_address = Column(String(50), nullable=True)
    
    # MFA Verification
    mfa_verified = Column(Boolean, default=False)
    mfa_method_used = Column(String(20), nullable=True)
    
    # Relationships
    user = relationship("IAMUser", back_populates="privileged_access", foreign_keys=[user_id])
    approver = relationship("IAMUser", foreign_keys=[approved_by], overlaps="user")
    account = relationship("PrivilegedAccount", back_populates="privileged_access")
    
    @classmethod
    async def get_active_access(cls, db: AsyncSession, user_id: int) -> List["PrivilegedAccess"]:
        """Get active privileged access for a user"""
        result = await db.execute(
            select(cls).where(
                cls.user_id == user_id,
                cls.status == "active",
                cls.expires_at > datetime.utcnow()
            )
        )
        return result.scalars().all()
    
    @classmethod
    async def get_pending_approvals(cls, db: AsyncSession, approver_id: int) -> List["PrivilegedAccess"]:
        """Get pending approvals for an approver"""
        result = await db.execute(
            select(cls).where(
                cls.status == "pending",
                cls.approved_by == approver_id
            )
        )
        return result.scalars().all()
    
    def __repr__(self):
        return f"<PrivilegedAccess(id={self.id}, user_id={self.user_id}, account_id={self.account_id}, status='{self.status}')>"


class AuditLog(Base):
    """Comprehensive audit logging for compliance"""
    __tablename__ = "iam_audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("iam_users.id"), nullable=True)
    privileged_account_id = Column(Integer, ForeignKey("iam_privileged_accounts.id"), nullable=True)
    action = Column(String(255), nullable=False)
    target = Column(String(255), nullable=True)
    target_type = Column(String(50), nullable=True)  # user, account, session, system
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=func.now())
    
    # Event Details
    event_type = Column(String(50), nullable=False)  # authentication, authorization, privileged_access, session
    severity = Column(String(20), default="info")  # info, warning, error, critical
    details = Column(JSON, nullable=True)  # Additional event details
    session_id = Column(String(255), nullable=True)
    
    # Compliance Information
    compliance_framework = Column(String(50), nullable=True)  # pci_dss, sox, hipaa, iso27001
    risk_score = Column(Float, nullable=True)
    
    # Relationships
    user = relationship("IAMUser", back_populates="audit_logs")
    privileged_account = relationship("PrivilegedAccount", back_populates="audit_logs")
    
    @classmethod
    async def get_user_logs(cls, db: AsyncSession, user_id: int, skip: int = 0, limit: int = 100) -> List["AuditLog"]:
        """Get audit logs for a specific user"""
        result = await db.execute(
            select(cls).where(cls.user_id == user_id).order_by(cls.timestamp.desc()).offset(skip).limit(limit)
        )
        return result.scalars().all()
    
    @classmethod
    async def get_recent_logs(cls, db: AsyncSession, hours: int = 24) -> List["AuditLog"]:
        """Get recent audit logs"""
        from datetime import timedelta
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        result = await db.execute(
            select(cls).where(cls.timestamp >= cutoff_time).order_by(cls.timestamp.desc())
        )
        return result.scalars().all()
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, user_id={self.user_id}, action='{self.action}', timestamp='{self.timestamp}')>"


class SSOProvider(Base):
    """SSO provider configuration"""
    __tablename__ = "iam_sso_providers"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    provider_type = Column(String(50), nullable=False)  # azure_ad, okta, google, saml, oidc
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Configuration
    client_id = Column(String(255), nullable=False)
    client_secret = Column(Text, nullable=False)  # Encrypted
    redirect_uri = Column(String(500), nullable=False)
    authorization_url = Column(String(500), nullable=True)
    token_url = Column(String(500), nullable=True)
    userinfo_url = Column(String(500), nullable=True)
    
    # SAML Configuration
    saml_entity_id = Column(String(255), nullable=True)
    saml_sso_url = Column(String(500), nullable=True)
    saml_x509_cert = Column(Text, nullable=True)
    
    # Settings
    auto_provision = Column(Boolean, default=True)
    default_role = Column(String(50), default="user")
    allowed_domains = Column(JSON, nullable=True)  # List of allowed email domains
    
    def __repr__(self):
        return f"<SSOProvider(id={self.id}, name='{self.name}', type='{self.provider_type}')>"


class MFASetup(Base):
    """MFA setup and configuration"""
    __tablename__ = "iam_mfa_setups"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("iam_users.id"), nullable=False)
    mfa_type = Column(String(20), nullable=False)  # totp, sms, email, push
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # TOTP Configuration
    secret_key = Column(String(255), nullable=True)  # Encrypted
    backup_codes = Column(JSON, nullable=True)  # List of backup codes
    
    # SMS/Email Configuration
    phone_number = Column(String(20), nullable=True)
    email_address = Column(String(255), nullable=True)
    
    # Push Configuration
    device_token = Column(String(500), nullable=True)
    device_name = Column(String(100), nullable=True)
    
    def __repr__(self):
        return f"<MFASetup(id={self.id}, user_id={self.user_id}, type='{self.mfa_type}')>" 