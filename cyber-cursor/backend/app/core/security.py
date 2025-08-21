"""
Security enhancements for CSPM module
"""

import time
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from functools import wraps
from fastapi import HTTPException, Request, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert
import hashlib
import hmac
import secrets
from app.core.database import get_db
from app.models.user import User
from app.models.cspm_models import AuditLog
import asyncio
from collections import defaultdict, deque
import threading
import jwt

# JWT Configuration
SECRET_KEY = "your-secret-key-here"  # In production, use environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Security scheme
security = HTTPBearer()

logger = logging.getLogger(__name__)

# ============================================================================
# Rate Limiting
# ============================================================================

class RateLimiter:
    """
    In-memory rate limiter for API endpoints
    """
    
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.requests = defaultdict(deque)
        self.lock = threading.Lock()
    
    def is_allowed(self, identifier: str) -> bool:
        """
        Check if request is allowed based on rate limit
        """
        now = time.time()
        cutoff = now - 60  # 1 minute window
        
        with self.lock:
            # Clean old requests
            if identifier in self.requests:
                while self.requests[identifier] and self.requests[identifier][0] < cutoff:
                    self.requests[identifier].popleft()
            
            # Check if under limit
            if len(self.requests[identifier]) >= self.requests_per_minute:
                return False
            
            # Add current request
            self.requests[identifier].append(now)
            return True
    
    def get_remaining_requests(self, identifier: str) -> int:
        """
        Get remaining requests for identifier
        """
        now = time.time()
        cutoff = now - 60
        
        with self.lock:
            if identifier in self.requests:
                # Clean old requests
                while self.requests[identifier] and self.requests[identifier][0] < cutoff:
                    self.requests[identifier].popleft()
                
                return max(0, self.requests_per_minute - len(self.requests[identifier]))
        
        return self.requests_per_minute

# Global rate limiters for different endpoints
cspm_rate_limiter = RateLimiter(requests_per_minute=100)  # 100 requests per minute
auth_rate_limiter = RateLimiter(requests_per_minute=10)    # 10 auth attempts per minute
scan_rate_limiter = RateLimiter(requests_per_minute=20)    # 20 scan requests per minute

def rate_limit(limiter: RateLimiter, identifier_func: Optional[Callable] = None):
    """
    Decorator for rate limiting endpoints
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get identifier (default to IP address)
            if identifier_func:
                identifier = identifier_func(*args, **kwargs)
            else:
                # Default to request IP
                request = next((arg for arg in args if isinstance(arg, Request)), None)
                if request:
                    identifier = request.client.host
                else:
                    identifier = "unknown"
            
            # Check rate limit
            if not limiter.is_allowed(identifier):
                remaining_time = 60 - (time.time() % 60)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "Rate limit exceeded",
                        "retry_after": int(remaining_time),
                        "limit": limiter.requests_per_minute,
                        "window": "1 minute"
                    }
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator

# ============================================================================
# Audit Logging
# ============================================================================

class AuditLogger:
    """
    Comprehensive audit logging for CSPM operations
    """
    
    def __init__(self):
        self.logger = logging.getLogger('audit')
        self.logger.setLevel(logging.INFO)
    
    async def log_action(
        self,
        db: AsyncSession,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Dict[str, Any],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True
    ):
        """
        Log an audit event to database and file
        """
        try:
            # Create audit log entry
            audit_entry = AuditLog(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details,
                ip_address=ip_address,
                user_agent=user_agent,
                success=success,
                timestamp=datetime.utcnow()
            )
            
            db.add(audit_entry)
            await db.commit()
            
            # Also log to file for redundancy
            log_message = {
                'timestamp': datetime.utcnow().isoformat(),
                'user_id': user_id,
                'action': action,
                'resource_type': resource_type,
                'resource_id': resource_id,
                'details': details,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'success': success
            }
            
            self.logger.info(f"AUDIT: {json.dumps(log_message)}")
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            # Don't fail the main operation if audit logging fails
    
    async def log_security_event(
        self,
        db: AsyncSession,
        event_type: str,
        severity: str,
        description: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Log security-specific events
        """
        await self.log_action(
            db=db,
            user_id=user_id or "system",
            action=f"security.{event_type}",
            resource_type="security_event",
            resource_id=secrets.token_urlsafe(16),
            details={
                'event_type': event_type,
                'severity': severity,
                'description': description,
                'details': details or {}
            },
            ip_address=ip_address,
            success=True
        )

# Global audit logger instance
audit_logger = AuditLogger()

def audit_log(
    action: str,
    resource_type: str,
    resource_id_func: Optional[Callable] = None,
    details_func: Optional[Callable] = None
):
    """
    Decorator for automatic audit logging
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get database session and user from function arguments
            db = next((arg for arg in args if isinstance(arg, AsyncSession)), None)
            user = next((arg for arg in args if hasattr(arg, 'id') and hasattr(arg, 'email')), None)
            
            if not db or not user:
                return await func(*args, **kwargs)
            
            # Get resource ID and details
            resource_id = resource_id_func(*args, **kwargs) if resource_id_func else "unknown"
            details = details_func(*args, **kwargs) if details_func else {}
            
            try:
                # Execute the function
                result = await func(*args, **kwargs)
                
                # Log successful action
                await audit_logger.log_action(
                    db=db,
                    user_id=str(user.id),
                    action=action,
                    resource_type=resource_type,
                    resource_id=str(resource_id),
                    details=details,
                    success=True
                )
                
                return result
                
            except Exception as e:
                # Log failed action
                await audit_logger.log_action(
                    db=db,
                    user_id=str(user.id),
                    action=action,
                    resource_type=resource_type,
                    resource_id=str(resource_id),
                    details={**details, 'error': str(e)},
                    success=False
                )
                raise
        
        return wrapper
    return decorator

# ============================================================================
# RBAC (Role-Based Access Control)
# ============================================================================

class RBACManager:
    """
    Role-based access control manager
    """
    
    def __init__(self):
        # Define roles and their permissions
        self.roles = {
            'admin': {
                'permissions': [
                    'cspm.*',           # All CSPM operations
                    'assets.*',          # All asset operations
                    'policies.*',        # All policy operations
                    'compliance.*',      # All compliance operations
                    'remediation.*',     # All remediation operations
                    'users.*',           # All user operations
                    'audit.*'            # All audit operations
                ]
            },
            'security_analyst': {
                'permissions': [
                    'cspm.read',         # Read CSPM data
                    'assets.read',       # Read asset data
                    'assets.update',     # Update asset data
                    'policies.read',     # Read policies
                    'policies.evaluate', # Evaluate policies
                    'findings.*',        # All finding operations
                    'compliance.read',   # Read compliance data
                    'remediation.read',  # Read remediation data
                    'remediation.execute' # Execute remediation
                ]
            },
            'compliance_auditor': {
                'permissions': [
                    'cspm.read',         # Read CSPM data
                    'assets.read',       # Read asset data
                    'policies.read',     # Read policies
                    'compliance.*',      # All compliance operations
                    'audit.read'         # Read audit logs
                ]
            },
            'remediation_engineer': {
                'permissions': [
                    'assets.read',       # Read asset data
                    'findings.read',     # Read findings
                    'remediation.*',     # All remediation operations
                    'policies.read'      # Read policies
                ]
            },
            'viewer': {
                'permissions': [
                    'cspm.read',         # Read CSPM data
                    'assets.read',       # Read asset data
                    'findings.read',     # Read findings
                    'compliance.read'    # Read compliance data
                ]
            }
        }
    
    def has_permission(self, user_role: str, permission: str) -> bool:
        """
        Check if user has specific permission
        """
        if user_role not in self.roles:
            return False
        
        user_permissions = self.roles[user_role]['permissions']
        
        # Check exact permission or wildcard
        if permission in user_permissions:
            return True
        
        # Check wildcard permissions (e.g., 'cspm.*' covers 'cspm.read')
        for user_perm in user_permissions:
            if user_perm.endswith('.*'):
                base_perm = user_perm[:-2]
                if permission.startswith(base_perm + '.'):
                    return True
        
        return False
    
    def get_user_permissions(self, user_role: str) -> List[str]:
        """
        Get all permissions for a user role
        """
        if user_role not in self.roles:
            return []
        
        return self.roles[user_role]['permissions']

# Global RBAC manager instance
rbac_manager = RBACManager()

def require_permission(permission: str):
    """
    Decorator to require specific permission
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get user from function arguments
            user = next((arg for arg in args if hasattr(arg, 'id') and hasattr(arg, 'role')), None)
            
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not authenticated"
                )
            
            # Check permission
            if not rbac_manager.has_permission(user.role, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required: {permission}"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator

# ============================================================================
# Security Headers and Middleware
# ============================================================================

class SecurityHeaders:
    """
    Security headers configuration
    """
    
    @staticmethod
    def get_headers() -> Dict[str, str]:
        """
        Get security headers for responses
        """
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }

# ============================================================================
# Input Validation and Sanitization
# ============================================================================

class InputValidator:
    """
    Input validation and sanitization utilities
    """
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """
        Sanitize string input
        """
        if not isinstance(value, str):
            raise ValueError("Value must be a string")
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in value if ord(char) >= 32)
        
        # Limit length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized.strip()
    
    @staticmethod
    def validate_json_schema(data: Dict[str, Any], required_fields: List[str]) -> bool:
        """
        Validate JSON schema requirements
        """
        for field in required_fields:
            if field not in data:
                return False
        
        return True
    
    @staticmethod
    def sanitize_json_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize JSON data recursively
        """
        if not isinstance(data, dict):
            return data
        
        sanitized = {}
        for key, value in data.items():
            # Sanitize key
            clean_key = InputValidator.sanitize_string(str(key), 100)
            
            # Sanitize value
            if isinstance(value, str):
                clean_value = InputValidator.sanitize_string(value)
            elif isinstance(value, dict):
                clean_value = InputValidator.sanitize_json_data(value)
            elif isinstance(value, list):
                clean_value = [InputValidator.sanitize_json_data(item) if isinstance(item, dict) else item for item in value]
            else:
                clean_value = value
            
            sanitized[clean_key] = clean_value
        
        return sanitized

# ============================================================================
# Security Utilities
# ============================================================================

def generate_secure_token(length: int = 32) -> str:
    """
    Generate a secure random token
    """
    return secrets.token_urlsafe(length)

def hash_secret(secret: str, salt: Optional[str] = None) -> str:
    """
    Hash a secret with salt
    """
    if salt is None:
        salt = secrets.token_hex(16)
    
    hash_obj = hashlib.pbkdf2_hmac('sha256', secret.encode(), salt.encode(), 100000)
    return f"{salt}${hash_obj.hex()}"

def verify_secret(secret: str, hashed: str) -> bool:
    """
    Verify a secret against its hash
    """
    try:
        salt, hash_value = hashed.split('$', 1)
        expected_hash = hashlib.pbkdf2_hmac('sha256', secret.encode(), salt.encode(), 100000)
        return hmac.compare_digest(expected_hash.hex(), hash_value)
    except Exception:
        return False

def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format
    """
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                return False
        
        return True
    except Exception:
        return False 

# ============================================================================
# JWT Token Management
# ============================================================================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Create JWT access token
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> dict:
    """
    Verify JWT token and return payload
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Get current authenticated user from JWT token
    """
    try:
        token = credentials.credentials
        payload = verify_token(token)
        user_id: int = payload.get("sub")
        
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        
        # Get user from database
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user"
            )
        
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        ) 

def require_analyst(current_user: dict = Depends(get_current_user)):
    """Require analyst role"""
    if not current_user or current_user.get("role") not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Analyst access required")
    return current_user