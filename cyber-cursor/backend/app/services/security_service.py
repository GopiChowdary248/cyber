import asyncio
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc, text
from sqlalchemy.orm import joinedload
import json
import hashlib
import secrets
import pyotp
import qrcode
from io import BytesIO
import base64
from enum import Enum

from app.models.user import User
from app.services.notification_service import notification_service

logger = structlog.get_logger()

class MFAMethod(Enum):
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    BIOMETRIC = "biometric"
    HARDWARE_TOKEN = "hardware_token"
    BACKUP_CODES = "backup_codes"

class SecurityEventType(Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_VERIFICATION = "mfa_verification"
    MFA_VERIFICATION_FAILED = "mfa_verification_failed"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    ACCESS_DENIED = "access_denied"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_ACCESS = "data_access"
    CONFIGURATION_CHANGE = "configuration_change"

class SecurityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityService:
    def __init__(self):
        self.failed_login_attempts: Dict[int, List[datetime]] = {}
        self.account_lockouts: Dict[int, datetime] = {}
        self.suspicious_activities: Dict[int, List[Dict[str, Any]]] = {}
        self.security_events: List[Dict[str, Any]] = []
        self.mfa_secrets: Dict[int, str] = {}
        self.backup_codes: Dict[int, List[str]] = {}
        self.session_tokens: Dict[str, Dict[str, Any]] = {}
        
        # Security configuration
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 30
        self.session_timeout_minutes = 60
        self.mfa_required = True
        self.password_policy = {
            "min_length": 12,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_special": True,
            "max_age_days": 90
        }
    
    async def start_security_service(self):
        """Start the security service"""
        logger.info("Starting security service")
        asyncio.create_task(self._cleanup_expired_sessions())
        asyncio.create_task(self._monitor_suspicious_activities())
    
    # Advanced MFA Implementation
    async def setup_mfa(self, user_id: int, method: MFAMethod) -> Dict[str, Any]:
        """Setup MFA for a user"""
        try:
            if method == MFAMethod.TOTP:
                return await self._setup_totp_mfa(user_id)
            elif method == MFAMethod.SMS:
                return await self._setup_sms_mfa(user_id)
            elif method == MFAMethod.EMAIL:
                return await self._setup_email_mfa(user_id)
            elif method == MFAMethod.BACKUP_CODES:
                return await self._setup_backup_codes(user_id)
            else:
                raise ValueError(f"Unsupported MFA method: {method}")
                
        except Exception as e:
            logger.error("Failed to setup MFA", error=str(e))
            raise
    
    async def _setup_totp_mfa(self, user_id: int) -> Dict[str, Any]:
        """Setup TOTP-based MFA"""
        try:
            # Generate secret key
            secret = pyotp.random_base32()
            self.mfa_secrets[user_id] = secret
            
            # Generate TOTP object
            totp = pyotp.TOTP(secret)
            
            # Generate QR code
            provisioning_uri = totp.provisioning_uri(
                name=f"user_{user_id}",
                issuer_name="CyberShield"
            )
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            # Generate backup codes
            backup_codes = await self._generate_backup_codes(user_id)
            
            # Log security event
            await self._log_security_event(
                SecurityEventType.MFA_ENABLED,
                user_id,
                {"method": "totp", "secret_created": True}
            )
            
            return {
                "method": "totp",
                "secret": secret,
                "qr_code": f"data:image/png;base64,{qr_code_base64}",
                "provisioning_uri": provisioning_uri,
                "backup_codes": backup_codes,
                "setup_complete": False
            }
            
        except Exception as e:
            logger.error("Failed to setup TOTP MFA", error=str(e))
            raise
    
    async def _setup_sms_mfa(self, user_id: int) -> Dict[str, Any]:
        """Setup SMS-based MFA"""
        try:
            # Generate verification code
            verification_code = secrets.token_hex(3).upper()[:6]
            
            # Store verification code (in real implementation, this would be temporary)
            self.mfa_secrets[user_id] = verification_code
            
            # Send SMS (placeholder)
            # await self._send_sms_verification(user_id, verification_code)
            
            # Log security event
            await self._log_security_event(
                SecurityEventType.MFA_ENABLED,
                user_id,
                {"method": "sms", "verification_sent": True}
            )
            
            return {
                "method": "sms",
                "verification_code": verification_code,
                "setup_complete": False
            }
            
        except Exception as e:
            logger.error("Failed to setup SMS MFA", error=str(e))
            raise
    
    async def _setup_email_mfa(self, user_id: int) -> Dict[str, Any]:
        """Setup email-based MFA"""
        try:
            # Generate verification code
            verification_code = secrets.token_hex(3).upper()[:6]
            
            # Store verification code
            self.mfa_secrets[user_id] = verification_code
            
            # Send email verification (placeholder)
            # await self._send_email_verification(user_id, verification_code)
            
            # Log security event
            await self._log_security_event(
                SecurityEventType.MFA_ENABLED,
                user_id,
                {"method": "email", "verification_sent": True}
            )
            
            return {
                "method": "email",
                "verification_code": verification_code,
                "setup_complete": False
            }
            
        except Exception as e:
            logger.error("Failed to setup email MFA", error=str(e))
            raise
    
    async def _generate_backup_codes(self, user_id: int) -> List[str]:
        """Generate backup codes for MFA"""
        try:
            codes = []
            for _ in range(10):
                code = secrets.token_hex(4).upper()[:8]
                codes.append(code)
            
            self.backup_codes[user_id] = codes
            
            return codes
            
        except Exception as e:
            logger.error("Failed to generate backup codes", error=str(e))
            return []
    
    async def verify_mfa(self, user_id: int, method: MFAMethod, code: str) -> bool:
        """Verify MFA code"""
        try:
            if method == MFAMethod.TOTP:
                return await self._verify_totp_mfa(user_id, code)
            elif method == MFAMethod.SMS:
                return await self._verify_sms_mfa(user_id, code)
            elif method == MFAMethod.EMAIL:
                return await self._verify_email_mfa(user_id, code)
            elif method == MFAMethod.BACKUP_CODES:
                return await self._verify_backup_code(user_id, code)
            else:
                return False
                
        except Exception as e:
            logger.error("Failed to verify MFA", error=str(e))
            return False
    
    async def _verify_totp_mfa(self, user_id: int, code: str) -> bool:
        """Verify TOTP MFA code"""
        try:
            if user_id not in self.mfa_secrets:
                return False
            
            secret = self.mfa_secrets[user_id]
            totp = pyotp.TOTP(secret)
            
            is_valid = totp.verify(code)
            
            # Log verification attempt
            event_type = SecurityEventType.MFA_VERIFICATION if is_valid else SecurityEventType.MFA_VERIFICATION_FAILED
            await self._log_security_event(event_type, user_id, {"method": "totp", "code_provided": bool(code)})
            
            return is_valid
            
        except Exception as e:
            logger.error("Failed to verify TOTP MFA", error=str(e))
            return False
    
    async def _verify_sms_mfa(self, user_id: int, code: str) -> bool:
        """Verify SMS MFA code"""
        try:
            if user_id not in self.mfa_secrets:
                return False
            
            stored_code = self.mfa_secrets[user_id]
            is_valid = code == stored_code
            
            # Log verification attempt
            event_type = SecurityEventType.MFA_VERIFICATION if is_valid else SecurityEventType.MFA_VERIFICATION_FAILED
            await self._log_security_event(event_type, user_id, {"method": "sms", "code_provided": bool(code)})
            
            return is_valid
            
        except Exception as e:
            logger.error("Failed to verify SMS MFA", error=str(e))
            return False
    
    async def _verify_email_mfa(self, user_id: int, code: str) -> bool:
        """Verify email MFA code"""
        try:
            if user_id not in self.mfa_secrets:
                return False
            
            stored_code = self.mfa_secrets[user_id]
            is_valid = code == stored_code
            
            # Log verification attempt
            event_type = SecurityEventType.MFA_VERIFICATION if is_valid else SecurityEventType.MFA_VERIFICATION_FAILED
            await self._log_security_event(event_type, user_id, {"method": "email", "code_provided": bool(code)})
            
            return is_valid
            
        except Exception as e:
            logger.error("Failed to verify email MFA", error=str(e))
            return False
    
    async def _verify_backup_code(self, user_id: int, code: str) -> bool:
        """Verify backup code"""
        try:
            if user_id not in self.backup_codes:
                return False
            
            codes = self.backup_codes[user_id]
            is_valid = code in codes
            
            if is_valid:
                # Remove used backup code
                codes.remove(code)
                self.backup_codes[user_id] = codes
            
            # Log verification attempt
            event_type = SecurityEventType.MFA_VERIFICATION if is_valid else SecurityEventType.MFA_VERIFICATION_FAILED
            await self._log_security_event(event_type, user_id, {"method": "backup_code", "code_provided": bool(code)})
            
            return is_valid
            
        except Exception as e:
            logger.error("Failed to verify backup code", error=str(e))
            return False
    
    async def disable_mfa(self, user_id: int) -> bool:
        """Disable MFA for a user"""
        try:
            if user_id in self.mfa_secrets:
                del self.mfa_secrets[user_id]
            
            if user_id in self.backup_codes:
                del self.backup_codes[user_id]
            
            # Log security event
            await self._log_security_event(
                SecurityEventType.MFA_DISABLED,
                user_id,
                {"mfa_disabled": True}
            )
            
            return True
            
        except Exception as e:
            logger.error("Failed to disable MFA", error=str(e))
            return False
    
    # Enhanced Login Security
    async def authenticate_user(self, user_id: int, password: str, ip_address: str, user_agent: str) -> Dict[str, Any]:
        """Authenticate user with enhanced security checks"""
        try:
            # Check if account is locked
            if await self._is_account_locked(user_id):
                await self._log_security_event(
                    SecurityEventType.ACCESS_DENIED,
                    user_id,
                    {"reason": "account_locked", "ip_address": ip_address}
                )
                return {"success": False, "error": "Account is locked"}
            
            # Check for suspicious activity
            if await self._detect_suspicious_activity(user_id, ip_address):
                await self._log_security_event(
                    SecurityEventType.SUSPICIOUS_ACTIVITY,
                    user_id,
                    {"ip_address": ip_address, "user_agent": user_agent}
                )
                await self._lock_account(user_id)
                return {"success": False, "error": "Suspicious activity detected"}
            
            # Verify password (placeholder - would integrate with actual auth system)
            password_valid = await self._verify_password(user_id, password)
            
            if password_valid:
                # Reset failed attempts
                if user_id in self.failed_login_attempts:
                    del self.failed_login_attempts[user_id]
                
                # Generate session token
                session_token = await self._generate_session_token(user_id, ip_address, user_agent)
                
                # Log successful login
                await self._log_security_event(
                    SecurityEventType.LOGIN_SUCCESS,
                    user_id,
                    {"ip_address": ip_address, "user_agent": user_agent, "session_token": session_token}
                )
                
                return {
                    "success": True,
                    "session_token": session_token,
                    "mfa_required": self.mfa_required and user_id in self.mfa_secrets
                }
            else:
                # Increment failed attempts
                await self._record_failed_login(user_id, ip_address)
                
                # Log failed login
                await self._log_security_event(
                    SecurityEventType.LOGIN_FAILED,
                    user_id,
                    {"ip_address": ip_address, "user_agent": user_agent}
                )
                
                return {"success": False, "error": "Invalid credentials"}
                
        except Exception as e:
            logger.error("Authentication failed", error=str(e))
            return {"success": False, "error": "Authentication error"}
    
    async def _is_account_locked(self, user_id: int) -> bool:
        """Check if account is locked"""
        if user_id in self.account_lockouts:
            lockout_time = self.account_lockouts[user_id]
            if datetime.utcnow() < lockout_time:
                return True
            else:
                # Lockout expired
                del self.account_lockouts[user_id]
        return False
    
    async def _detect_suspicious_activity(self, user_id: int, ip_address: str) -> bool:
        """Detect suspicious login activity"""
        try:
            # Check for multiple failed attempts from different IPs
            if user_id in self.failed_login_attempts:
                attempts = self.failed_login_attempts[user_id]
                recent_attempts = [a for a in attempts if datetime.utcnow() - a < timedelta(minutes=30)]
                
                if len(recent_attempts) >= 3:
                    return True
            
            # Check for login from unusual location (placeholder)
            # In a real implementation, this would check against known user locations
            
            # Check for rapid login attempts
            if user_id in self.suspicious_activities:
                activities = self.suspicious_activities[user_id]
                recent_activities = [a for a in activities if datetime.utcnow() - a["timestamp"] < timedelta(minutes=5)]
                
                if len(recent_activities) >= 5:
                    return True
            
            return False
            
        except Exception as e:
            logger.error("Failed to detect suspicious activity", error=str(e))
            return False
    
    async def _lock_account(self, user_id: int):
        """Lock user account"""
        try:
            lockout_time = datetime.utcnow() + timedelta(minutes=self.lockout_duration_minutes)
            self.account_lockouts[user_id] = lockout_time
            
            # Log account lock
            await self._log_security_event(
                SecurityEventType.ACCOUNT_LOCKED,
                user_id,
                {"lockout_duration_minutes": self.lockout_duration_minutes}
            )
            
            # Notify user
            await notification_service.send_personal_message({
                "recipient_id": user_id,
                "type": "in_app",
                "notification_type": "security_alert",
                "priority": "high",
                "message": "Your account has been locked due to suspicious activity"
            })
            
        except Exception as e:
            logger.error("Failed to lock account", error=str(e))
    
    async def _record_failed_login(self, user_id: int, ip_address: str):
        """Record failed login attempt"""
        try:
            if user_id not in self.failed_login_attempts:
                self.failed_login_attempts[user_id] = []
            
            self.failed_login_attempts[user_id].append(datetime.utcnow())
            
            # Clean old attempts
            cutoff_time = datetime.utcnow() - timedelta(hours=1)
            self.failed_login_attempts[user_id] = [
                a for a in self.failed_login_attempts[user_id] if a > cutoff_time
            ]
            
            # Check if account should be locked
            if len(self.failed_login_attempts[user_id]) >= self.max_failed_attempts:
                await self._lock_account(user_id)
                
        except Exception as e:
            logger.error("Failed to record failed login", error=str(e))
    
    async def _verify_password(self, user_id: int, password: str) -> bool:
        """Verify user password"""
        # Placeholder - would integrate with actual password verification
        return password == "password123"  # Mock verification
    
    async def _generate_session_token(self, user_id: int, ip_address: str, user_agent: str) -> str:
        """Generate session token"""
        try:
            token = secrets.token_urlsafe(32)
            
            self.session_tokens[token] = {
                "user_id": user_id,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "created_at": datetime.utcnow(),
                "last_activity": datetime.utcnow()
            }
            
            return token
            
        except Exception as e:
            logger.error("Failed to generate session token", error=str(e))
            raise
    
    # Audit Logging
    async def _log_security_event(self, event_type: SecurityEventType, user_id: int, details: Dict[str, Any]):
        """Log security event"""
        try:
            event = {
                "id": f"event_{datetime.utcnow().timestamp()}",
                "event_type": event_type.value,
                "user_id": user_id,
                "timestamp": datetime.utcnow().isoformat(),
                "details": details,
                "security_level": self._get_security_level(event_type)
            }
            
            self.security_events.append(event)
            
            # Keep only last 10000 events
            if len(self.security_events) > 10000:
                self.security_events = self.security_events[-10000:]
            
            # Log to structured logger
            logger.info("Security event logged",
                       event_type=event_type.value,
                       user_id=user_id,
                       details=details)
            
            # Send alerts for critical events
            if event_type in [SecurityEventType.SUSPICIOUS_ACTIVITY, SecurityEventType.PRIVILEGE_ESCALATION]:
                await self._send_security_alert(event)
                
        except Exception as e:
            logger.error("Failed to log security event", error=str(e))
    
    def _get_security_level(self, event_type: SecurityEventType) -> SecurityLevel:
        """Get security level for event type"""
        critical_events = [
            SecurityEventType.SUSPICIOUS_ACTIVITY,
            SecurityEventType.PRIVILEGE_ESCALATION,
            SecurityEventType.ACCOUNT_LOCKED
        ]
        
        high_events = [
            SecurityEventType.LOGIN_FAILED,
            SecurityEventType.MFA_VERIFICATION_FAILED,
            SecurityEventType.ACCESS_DENIED
        ]
        
        if event_type in critical_events:
            return SecurityLevel.CRITICAL
        elif event_type in high_events:
            return SecurityLevel.HIGH
        else:
            return SecurityLevel.MEDIUM
    
    async def _send_security_alert(self, event: Dict[str, Any]):
        """Send security alert for critical events"""
        try:
            # Notify security team
            await notification_service.send_personal_message({
                "recipient_id": 1,  # Security team user ID
                "type": "in_app",
                "notification_type": "security_alert",
                "priority": "critical",
                "message": f"Critical security event: {event['event_type']}",
                "metadata": event
            })
            
        except Exception as e:
            logger.error("Failed to send security alert", error=str(e))
    
    # Session Management
    async def validate_session(self, session_token: str, ip_address: str) -> Optional[int]:
        """Validate session token"""
        try:
            if session_token not in self.session_tokens:
                return None
            
            session = self.session_tokens[session_token]
            
            # Check if session is expired
            if datetime.utcnow() - session["created_at"] > timedelta(minutes=self.session_timeout_minutes):
                del self.session_tokens[session_token]
                return None
            
            # Check IP address (optional security measure)
            if session["ip_address"] != ip_address:
                # Log potential session hijacking
                await self._log_security_event(
                    SecurityEventType.SUSPICIOUS_ACTIVITY,
                    session["user_id"],
                    {"reason": "ip_mismatch", "expected_ip": session["ip_address"], "actual_ip": ip_address}
                )
            
            # Update last activity
            session["last_activity"] = datetime.utcnow()
            
            return session["user_id"]
            
        except Exception as e:
            logger.error("Failed to validate session", error=str(e))
            return None
    
    async def logout_user(self, session_token: str, user_id: int):
        """Logout user and invalidate session"""
        try:
            if session_token in self.session_tokens:
                del self.session_tokens[session_token]
            
            # Log logout event
            await self._log_security_event(
                SecurityEventType.LOGOUT,
                user_id,
                {"session_token": session_token}
            )
            
        except Exception as e:
            logger.error("Failed to logout user", error=str(e))
    
    # Security Monitoring
    async def _cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        while True:
            try:
                current_time = datetime.utcnow()
                expired_tokens = []
                
                for token, session in self.session_tokens.items():
                    if current_time - session["created_at"] > timedelta(minutes=self.session_timeout_minutes):
                        expired_tokens.append(token)
                
                for token in expired_tokens:
                    del self.session_tokens[token]
                
                if expired_tokens:
                    logger.info(f"Cleaned up {len(expired_tokens)} expired sessions")
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                logger.error("Error in session cleanup", error=str(e))
                await asyncio.sleep(300)
    
    async def _monitor_suspicious_activities(self):
        """Monitor for suspicious activities"""
        while True:
            try:
                # Analyze recent security events for patterns
                recent_events = [
                    e for e in self.security_events 
                    if datetime.utcnow() - datetime.fromisoformat(e["timestamp"]) < timedelta(hours=1)
                ]
                
                # Check for rapid failed login attempts
                failed_logins = [e for e in recent_events if e["event_type"] == SecurityEventType.LOGIN_FAILED.value]
                
                for event in failed_logins:
                    user_id = event["user_id"]
                    if user_id not in self.suspicious_activities:
                        self.suspicious_activities[user_id] = []
                    
                    self.suspicious_activities[user_id].append({
                        "timestamp": datetime.fromisoformat(event["timestamp"]),
                        "event_type": event["event_type"],
                        "details": event["details"]
                    })
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error("Error in suspicious activity monitoring", error=str(e))
                await asyncio.sleep(60)
    
    # Security Reports
    async def get_security_report(self, user_id: Optional[int] = None, time_range: str = "24h") -> Dict[str, Any]:
        """Generate security report"""
        try:
            # Calculate time range
            if time_range == "24h":
                start_time = datetime.utcnow() - timedelta(hours=24)
            elif time_range == "7d":
                start_time = datetime.utcnow() - timedelta(days=7)
            elif time_range == "30d":
                start_time = datetime.utcnow() - timedelta(days=30)
            else:
                start_time = datetime.utcnow() - timedelta(hours=24)
            
            # Filter events by time range
            filtered_events = [
                e for e in self.security_events
                if datetime.fromisoformat(e["timestamp"]) >= start_time
            ]
            
            # Filter by user if specified
            if user_id:
                filtered_events = [e for e in filtered_events if e["user_id"] == user_id]
            
            # Generate statistics
            event_counts = {}
            for event in filtered_events:
                event_type = event["event_type"]
                event_counts[event_type] = event_counts.get(event_type, 0) + 1
            
            # Security level distribution
            security_levels = {}
            for event in filtered_events:
                level = event["security_level"]
                security_levels[level] = security_levels.get(level, 0) + 1
            
            return {
                "time_range": time_range,
                "total_events": len(filtered_events),
                "event_counts": event_counts,
                "security_levels": security_levels,
                "recent_events": filtered_events[-10:],  # Last 10 events
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error("Failed to generate security report", error=str(e))
            return {}

# Global instance
security_service = SecurityService() 