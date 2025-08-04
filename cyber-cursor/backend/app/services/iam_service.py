import asyncio
import secrets
import string
import hashlib
import hmac
import base64
import json
import qrcode
import io
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_, or_, func
import structlog
import bcrypt
import pyotp
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.models.iam import IAMUser, Session, PrivilegedAccount, PrivilegedAccess, AuditLog, SSOProvider, MFASetup
from app.schemas.iam import (
    UserCreate, UserUpdate, PrivilegedAccountCreate, PrivilegedAccessCreate,
    AuditLogCreate, SSOProviderCreate, MFASetupCreate
)
from app.core.config import settings

logger = structlog.get_logger()

class EncryptionService:
    """Service for encrypting sensitive data"""
    
    def __init__(self):
        self.key = settings.security.SECRET_KEY.encode()
        self.cipher_suite = Fernet(base64.urlsafe_b64encode(
            PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'cybershield_salt',
                iterations=100000,
            ).derive(self.key)
        ))
    
    def encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        return self.cipher_suite.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()

class MFAService:
    """Service for Multi-Factor Authentication"""
    
    def __init__(self):
        self.encryption_service = EncryptionService()
    
    def generate_totp_secret(self) -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate backup codes for MFA"""
        codes = []
        for _ in range(count):
            code = ''.join(secrets.choice(string.digits) for _ in range(8))
            codes.append(f"{code[:4]}-{code[4:]}")
        return codes
    
    def generate_qr_code(self, secret: str, username: str, issuer: str = "CyberShield") -> str:
        """Generate QR code for TOTP setup"""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name=issuer
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    def verify_totp(self, secret: str, token: str) -> bool:
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token)
    
    def verify_backup_code(self, backup_codes: List[str], code: str) -> Tuple[bool, List[str]]:
        """Verify backup code and return remaining codes"""
        if code in backup_codes:
            remaining_codes = [c for c in backup_codes if c != code]
            return True, remaining_codes
        return False, backup_codes

class SSOService:
    """Service for Single Sign-On integration"""
    
    def __init__(self):
        self.encryption_service = EncryptionService()
    
    async def get_sso_provider(self, db: AsyncSession, provider_name: str) -> Optional[SSOProvider]:
        """Get SSO provider configuration"""
        result = await db.execute(
            select(SSOProvider).where(
                and_(
                    SSOProvider.name == provider_name,
                    SSOProvider.is_active == True
                )
            )
        )
        return result.scalar_one_or_none()
    
    async def create_sso_user(self, db: AsyncSession, sso_data: Dict[str, Any]) -> IAMUser:
        """Create or update user from SSO data"""
        # Check if user already exists
        user = await IAMUser.get_by_sso_id(
            db, 
            sso_data["provider"], 
            sso_data["external_id"]
        )
        
        if user:
            # Update existing user
            user.sso_attributes = sso_data.get("attributes", {})
            user.last_login = datetime.utcnow()
            await db.commit()
            await db.refresh(user)
            return user
        
        # Create new user
        user_data = {
            "username": sso_data["username"],
            "email": sso_data["email"],
            "full_name": sso_data.get("full_name"),
            "sso_provider": sso_data["provider"],
            "sso_external_id": sso_data["external_id"],
            "sso_attributes": sso_data.get("attributes", {}),
            "role": sso_data.get("role", "user"),
            "is_verified": True,
            "is_active": True
        }
        
        user = IAMUser(**user_data)
        db.add(user)
        await db.commit()
        await db.refresh(user)
        
        return user
    
    def validate_sso_token(self, provider: SSOProvider, token: str) -> Dict[str, Any]:
        """Validate SSO token and extract user information"""
        # This is a simplified implementation
        # In production, you would integrate with actual SSO providers
        try:
            # For demo purposes, we'll simulate token validation
            if provider.provider_type == "azure_ad":
                return self._validate_azure_ad_token(token)
            elif provider.provider_type == "okta":
                return self._validate_okta_token(token)
            elif provider.provider_type == "google":
                return self._validate_google_token(token)
            else:
                raise ValueError(f"Unsupported SSO provider: {provider.provider_type}")
        except Exception as e:
            logger.error("SSO token validation failed", error=str(e))
            raise
    
    def _validate_azure_ad_token(self, token: str) -> Dict[str, Any]:
        """Validate Azure AD token (simplified)"""
        # In production, use Microsoft Graph API or Azure AD libraries
        return {
            "external_id": "azure_user_123",
            "username": "azure_user",
            "email": "user@company.com",
            "full_name": "Azure User",
            "attributes": {"groups": ["Users"]}
        }
    
    def _validate_okta_token(self, token: str) -> Dict[str, Any]:
        """Validate Okta token (simplified)"""
        return {
            "external_id": "okta_user_456",
            "username": "okta_user",
            "email": "user@company.com",
            "full_name": "Okta User",
            "attributes": {"groups": ["Users"]}
        }
    
    def _validate_google_token(self, token: str) -> Dict[str, Any]:
        """Validate Google token (simplified)"""
        return {
            "external_id": "google_user_789",
            "username": "google_user",
            "email": "user@gmail.com",
            "full_name": "Google User",
            "attributes": {"groups": ["Users"]}
        }

class SessionService:
    """Service for session management"""
    
    def __init__(self):
        self.encryption_service = EncryptionService()
    
    def create_session_token(self, user_id: int, expires_in: int = 3600) -> str:
        """Create JWT session token"""
        payload = {
            "user_id": user_id,
            "exp": datetime.utcnow() + timedelta(seconds=expires_in),
            "iat": datetime.utcnow(),
            "type": "session"
        }
        return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    
    def create_refresh_token(self, user_id: int) -> str:
        """Create refresh token"""
        payload = {
            "user_id": user_id,
            "exp": datetime.utcnow() + timedelta(days=30),
            "iat": datetime.utcnow(),
            "type": "refresh"
        }
        return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None
    
    async def create_session(
        self, 
        db: AsyncSession, 
        user_id: int, 
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_info: Optional[Dict[str, Any]] = None,
        sso_provider: Optional[str] = None
    ) -> Session:
        """Create a new user session"""
        access_token = self.create_session_token(user_id)
        refresh_token = self.create_refresh_token(user_id)
        
        session = Session(
            user_id=user_id,
            token=access_token,
            refresh_token=refresh_token,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            sso_provider=sso_provider
        )
        
        db.add(session)
        await db.commit()
        await db.refresh(session)
        
        return session
    
    async def get_session(self, db: AsyncSession, token: str) -> Optional[Session]:
        """Get session by token"""
        return await Session.get_by_token(db, token)
    
    async def invalidate_session(self, db: AsyncSession, session_id: int) -> bool:
        """Invalidate a session"""
        result = await db.execute(select(Session).where(Session.id == session_id))
        session = result.scalar_one_or_none()
        
        if session:
            session.is_active = False
            await db.commit()
            return True
        return False
    
    async def invalidate_user_sessions(self, db: AsyncSession, user_id: int) -> int:
        """Invalidate all sessions for a user"""
        result = await db.execute(
            select(Session).where(
                and_(
                    Session.user_id == user_id,
                    Session.is_active == True
                )
            )
        )
        sessions = result.scalars().all()
        
        for session in sessions:
            session.is_active = False
        
        await db.commit()
        return len(sessions)

class PrivilegedAccessService:
    """Service for Privileged Access Management"""
    
    def __init__(self):
        self.encryption_service = EncryptionService()
    
    def encrypt_credentials(self, password: str, private_key: Optional[str] = None) -> Tuple[str, Optional[str]]:
        """Encrypt privileged account credentials"""
        encrypted_password = self.encryption_service.encrypt(password)
        encrypted_private_key = None
        
        if private_key:
            encrypted_private_key = self.encryption_service.encrypt(private_key)
        
        return encrypted_password, encrypted_private_key
    
    def decrypt_credentials(self, encrypted_password: str, encrypted_private_key: Optional[str] = None) -> Tuple[str, Optional[str]]:
        """Decrypt privileged account credentials"""
        password = self.encryption_service.decrypt(encrypted_password)
        private_key = None
        
        if encrypted_private_key:
            private_key = self.encryption_service.decrypt(encrypted_private_key)
        
        return password, private_key
    
    async def create_privileged_account(
        self, 
        db: AsyncSession, 
        account_data: PrivilegedAccountCreate
    ) -> PrivilegedAccount:
        """Create a new privileged account"""
        encrypted_password, encrypted_private_key = self.encrypt_credentials(
            account_data.password, 
            account_data.private_key
        )
        
        account = PrivilegedAccount(
            system_name=account_data.system_name,
            system_type=account_data.system_type,
            username=account_data.username,
            encrypted_password=encrypted_password,
            encrypted_private_key=encrypted_private_key,
            account_type=account_data.account_type,
            hostname=account_data.hostname,
            ip_address=account_data.ip_address,
            port=account_data.port,
            protocol=account_data.protocol,
            requires_approval=account_data.requires_approval,
            max_session_duration=account_data.max_session_duration,
            allowed_ips=account_data.allowed_ips,
            rotation_interval=account_data.rotation_interval,
            next_rotation=datetime.utcnow() + timedelta(days=account_data.rotation_interval)
        )
        
        db.add(account)
        await db.commit()
        await db.refresh(account)
        
        return account
    
    async def request_privileged_access(
        self, 
        db: AsyncSession, 
        user_id: int, 
        access_data: PrivilegedAccessCreate
    ) -> PrivilegedAccess:
        """Request privileged access"""
        # Check if user already has active access
        active_access = await PrivilegedAccess.get_active_access(db, user_id)
        for access in active_access:
            if access.account_id == access_data.account_id:
                raise ValueError("User already has active access to this account")
        
        access = PrivilegedAccess(
            user_id=user_id,
            account_id=access_data.account_id,
            access_type=access_data.access_type,
            reason=access_data.reason,
            expires_at=access_data.expires_at
        )
        
        db.add(access)
        await db.commit()
        await db.refresh(access)
        
        return access
    
    async def approve_privileged_access(
        self, 
        db: AsyncSession, 
        access_id: int, 
        approver_id: int
    ) -> PrivilegedAccess:
        """Approve privileged access request"""
        result = await db.execute(select(PrivilegedAccess).where(PrivilegedAccess.id == access_id))
        access = result.scalar_one_or_none()
        
        if not access:
            raise ValueError("Access request not found")
        
        if access.status != "pending":
            raise ValueError("Access request is not pending")
        
        access.status = "approved"
        access.approved_by = approver_id
        access.approved_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(access)
        
        return access
    
    async def activate_privileged_access(
        self, 
        db: AsyncSession, 
        access_id: int, 
        session_id: str,
        ip_address: Optional[str] = None
    ) -> PrivilegedAccess:
        """Activate approved privileged access"""
        result = await db.execute(select(PrivilegedAccess).where(PrivilegedAccess.id == access_id))
        access = result.scalar_one_or_none()
        
        if not access:
            raise ValueError("Access request not found")
        
        if access.status != "approved":
            raise ValueError("Access request is not approved")
        
        if access.expires_at < datetime.utcnow():
            access.status = "expired"
            await db.commit()
            raise ValueError("Access request has expired")
        
        access.status = "active"
        access.session_id = session_id
        access.ip_address = ip_address
        access.actual_expires_at = datetime.utcnow() + timedelta(minutes=60)  # Default 1 hour
        
        await db.commit()
        await db.refresh(access)
        
        return access
    
    async def get_privileged_credentials(
        self, 
        db: AsyncSession, 
        account_id: int
    ) -> Tuple[str, Optional[str]]:
        """Get decrypted privileged account credentials"""
        result = await db.execute(
            select(PrivilegedAccount).where(PrivilegedAccount.id == account_id)
        )
        account = result.scalar_one_or_none()
        
        if not account:
            raise ValueError("Privileged account not found")
        
        return self.decrypt_credentials(
            account.encrypted_password, 
            account.encrypted_private_key
        )

class AuditService:
    """Service for audit logging"""
    
    async def log_event(
        self, 
        db: AsyncSession, 
        event_data: AuditLogCreate
    ) -> AuditLog:
        """Log an audit event"""
        log = AuditLog(**event_data.dict())
        db.add(log)
        await db.commit()
        await db.refresh(log)
        
        # Log to structured logger for real-time monitoring
        logger.info(
            "Audit event logged",
            event_type=event_data.event_type,
            action=event_data.action,
            user_id=event_data.user_id,
            severity=event_data.severity,
            ip_address=event_data.ip_address
        )
        
        return log
    
    async def get_user_audit_logs(
        self, 
        db: AsyncSession, 
        user_id: int, 
        skip: int = 0, 
        limit: int = 100
    ) -> List[AuditLog]:
        """Get audit logs for a specific user"""
        return await AuditLog.get_user_logs(db, user_id, skip, limit)
    
    async def get_recent_audit_logs(
        self, 
        db: AsyncSession, 
        hours: int = 24
    ) -> List[AuditLog]:
        """Get recent audit logs"""
        return await AuditLog.get_recent_logs(db, hours)
    
    async def get_privileged_access_logs(
        self, 
        db: AsyncSession, 
        account_id: Optional[int] = None,
        skip: int = 0, 
        limit: int = 100
    ) -> List[AuditLog]:
        """Get privileged access audit logs"""
        query = select(AuditLog).where(
            AuditLog.event_type == "privileged_access"
        )
        
        if account_id:
            query = query.where(AuditLog.privileged_account_id == account_id)
        
        query = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit)
        result = await db.execute(query)
        return result.scalars().all()
    
    async def get_filtered_logs(
        self,
        db: AsyncSession,
        skip: int = 0,
        limit: int = 100,
        user_id: Optional[int] = None,
        action: Optional[str] = None,
        target_type: Optional[str] = None,
        risk_level: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[AuditLog]:
        """Get filtered audit logs"""
        query = select(AuditLog)
        
        # Apply filters
        if user_id:
            query = query.where(AuditLog.user_id == user_id)
        
        if action:
            query = query.where(AuditLog.action == action)
        
        if target_type:
            query = query.where(AuditLog.target_type == target_type)
        
        if risk_level:
            query = query.where(AuditLog.severity == risk_level)
        
        if start_date:
            query = query.where(AuditLog.timestamp >= start_date)
        
        if end_date:
            query = query.where(AuditLog.timestamp <= end_date)
        
        # Order by timestamp descending and apply pagination
        query = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit)
        result = await db.execute(query)
        return result.scalars().all()

class IAMService:
    """Main IAM service that orchestrates all IAM functionality"""
    
    def __init__(self):
        self.mfa_service = MFAService()
        self.sso_service = SSOService()
        self.session_service = SessionService()
        self.privileged_access_service = PrivilegedAccessService()
        self.audit_service = AuditService()
        self.encryption_service = EncryptionService()
    
    async def authenticate_user(
        self, 
        db: AsyncSession, 
        username: str, 
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_info: Optional[Dict[str, Any]] = None
    ) -> Tuple[Optional[IAMUser], Optional[str]]:
        """Authenticate user with username/password"""
        # Find user by username or email
        user = await IAMUser.get_by_username(db, username)
        if not user:
            user = await IAMUser.get_by_email(db, username)
        
        if not user or not user.is_active:
            await self.audit_service.log_event(db, AuditLogCreate(
                action="login_failed",
                target=username,
                target_type="user",
                event_type="authentication",
                severity="warning",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "invalid_credentials"}
            ))
            return None, "Invalid credentials"
        
        # Check password
        if user.password_hash and not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            await self.audit_service.log_event(db, AuditLogCreate(
                action="login_failed",
                target=username,
                target_type="user",
                event_type="authentication",
                severity="warning",
                ip_address=ip_address,
                user_agent=user_agent,
                user_id=user.id,
                details={"reason": "invalid_password"}
            ))
            return None, "Invalid credentials"
        
        # Check if MFA is required
        if user.mfa_enabled:
            await self.audit_service.log_event(db, AuditLogCreate(
                action="login_success_mfa_required",
                target=username,
                target_type="user",
                event_type="authentication",
                severity="info",
                ip_address=ip_address,
                user_agent=user_agent,
                user_id=user.id
            ))
            return user, "mfa_required"
        
        # Update last login
        user.last_login = datetime.utcnow()
        await db.commit()
        
        await self.audit_service.log_event(db, AuditLogCreate(
            action="login_success",
            target=username,
            target_type="user",
            event_type="authentication",
            severity="info",
            ip_address=ip_address,
            user_agent=user_agent,
            user_id=user.id
        ))
        
        return user, "success"
    
    async def authenticate_sso(
        self, 
        db: AsyncSession, 
        provider_name: str, 
        code: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_info: Optional[Dict[str, Any]] = None
    ) -> Tuple[Optional[IAMUser], Optional[str]]:
        """Authenticate user via SSO"""
        # Get SSO provider configuration
        provider = await self.sso_service.get_sso_provider(db, provider_name)
        if not provider:
            return None, "SSO provider not configured"
        
        try:
            # Validate SSO token
            sso_data = self.sso_service.validate_sso_token(provider, code)
            sso_data["provider"] = provider_name
            
            # Create or update user
            user = await self.sso_service.create_sso_user(db, sso_data)
            
            # Check if MFA is required
            if user.mfa_enabled:
                await self.audit_service.log_event(db, AuditLogCreate(
                    action="sso_login_success_mfa_required",
                    target=user.username,
                    target_type="user",
                    event_type="authentication",
                    severity="info",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    user_id=user.id,
                    details={"sso_provider": provider_name}
                ))
                return user, "mfa_required"
            
            await self.audit_service.log_event(db, AuditLogCreate(
                action="sso_login_success",
                target=user.username,
                target_type="user",
                event_type="authentication",
                severity="info",
                ip_address=ip_address,
                user_agent=user_agent,
                user_id=user.id,
                details={"sso_provider": provider_name}
            ))
            
            return user, "success"
            
        except Exception as e:
            logger.error("SSO authentication failed", error=str(e))
            await self.audit_service.log_event(db, AuditLogCreate(
                action="sso_login_failed",
                target=provider_name,
                target_type="sso_provider",
                event_type="authentication",
                severity="error",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"error": str(e)}
            ))
            return None, "SSO authentication failed"
    
    async def verify_mfa(
        self, 
        db: AsyncSession, 
        user_id: int, 
        token: str,
        ip_address: Optional[str] = None
    ) -> bool:
        """Verify MFA token for user"""
        user = await User.get_by_id(db, user_id)
        if not user or not user.mfa_enabled:
            return False
        
        # Check if it's a backup code
        if user.mfa_backup_codes and token in user.mfa_backup_codes:
            # Remove used backup code
            remaining_codes = [c for c in user.mfa_backup_codes if c != token]
            user.mfa_backup_codes = remaining_codes
            await db.commit()
            
            await self.audit_service.log_event(db, AuditLogCreate(
                action="mfa_backup_code_used",
                target=user.username,
                target_type="user",
                event_type="authentication",
                severity="info",
                ip_address=ip_address,
                user_id=user.id
            ))
            return True
        
        # Verify TOTP token
        if user.mfa_secret and self.mfa_service.verify_totp(user.mfa_secret, token):
            await self.audit_service.log_event(db, AuditLogCreate(
                action="mfa_verification_success",
                target=user.username,
                target_type="user",
                event_type="authentication",
                severity="info",
                ip_address=ip_address,
                user_id=user.id
            ))
            return True
        
        await self.audit_service.log_event(db, AuditLogCreate(
            action="mfa_verification_failed",
            target=user.username,
            target_type="user",
            event_type="authentication",
            severity="warning",
            ip_address=ip_address,
            user_id=user.id
        ))
        return False
    
    async def setup_mfa(
        self, 
        db: AsyncSession, 
        user_id: int, 
        mfa_type: str = "totp"
    ) -> Dict[str, Any]:
        """Setup MFA for user"""
        user = await User.get_by_id(db, user_id)
        if not user:
            raise ValueError("User not found")
        
        if user.mfa_enabled:
            raise ValueError("MFA is already enabled")
        
        if mfa_type == "totp":
            secret = self.mfa_service.generate_totp_secret()
            backup_codes = self.mfa_service.generate_backup_codes()
            qr_code = self.mfa_service.generate_qr_code(secret, user.username)
            
            # Store encrypted secret and backup codes
            user.mfa_secret = self.encryption_service.encrypt(secret)
            user.mfa_backup_codes = backup_codes
            user.mfa_method = "totp"
            
            await db.commit()
            
            await self.audit_service.log_event(db, AuditLogCreate(
                action="mfa_setup_initiated",
                target=user.username,
                target_type="user",
                event_type="authentication",
                severity="info",
                user_id=user.id
            ))
            
            return {
                "qr_code": qr_code,
                "secret": secret,
                "backup_codes": backup_codes,
                "setup_uri": f"otpauth://totp/{user.username}?secret={secret}&issuer=CyberShield"
            }
        else:
            raise ValueError(f"Unsupported MFA type: {mfa_type}")
    
    async def complete_mfa_setup(
        self, 
        db: AsyncSession, 
        user_id: int, 
        token: str
    ) -> bool:
        """Complete MFA setup by verifying first token"""
        user = await User.get_by_id(db, user_id)
        if not user or not user.mfa_secret:
            return False
        
        secret = self.encryption_service.decrypt(user.mfa_secret)
        if self.mfa_service.verify_totp(secret, token):
            user.mfa_enabled = True
            await db.commit()
            
            await self.audit_service.log_event(db, AuditLogCreate(
                action="mfa_setup_completed",
                target=user.username,
                target_type="user",
                event_type="authentication",
                severity="info",
                user_id=user.id
            ))
            return True
        
        return False
    
    async def get_dashboard_stats(self, db: AsyncSession) -> Dict[str, Any]:
        """Get IAM dashboard statistics"""
        # Get user counts
        total_users = await db.execute(select(func.count(User.id)))
        active_users = await db.execute(select(func.count(User.id)).where(User.is_active == True))
        mfa_enabled_users = await db.execute(select(func.count(User.id)).where(User.mfa_enabled == True))
        sso_enabled_users = await db.execute(select(func.count(User.id)).where(User.sso_provider.isnot(None)))
        
        # Get privileged account counts
        privileged_accounts = await db.execute(select(func.count(PrivilegedAccount.id)))
        
        # Get session counts
        active_sessions = await db.execute(
            select(func.count(Session.id)).where(
                and_(Session.is_active == True, Session.expires_at > datetime.utcnow())
            )
        )
        
        # Get pending approvals
        pending_approvals = await db.execute(
            select(func.count(PrivilegedAccess.id)).where(PrivilegedAccess.status == "pending")
        )
        
        # Get recent audit events
        recent_audit_events = await db.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
            )
        )
        
        return {
            "total_users": total_users.scalar(),
            "active_users": active_users.scalar(),
            "privileged_accounts": privileged_accounts.scalar(),
            "active_sessions": active_sessions.scalar(),
            "pending_approvals": pending_approvals.scalar(),
            "recent_audit_events": recent_audit_events.scalar(),
            "mfa_enabled_users": mfa_enabled_users.scalar(),
            "sso_enabled_users": sso_enabled_users.scalar()
        }

# Global IAM service instance
iam_service = IAMService() 