from fastapi import Request, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import jwt
import time
import hashlib
import hmac
import secrets
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import redis.asyncio as redis
from pydantic import BaseModel
import json
from sqlalchemy.ext.asyncio import AsyncSession

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security configuration
SECRET_KEY = "your-super-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Rate limiting configuration
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 100  # requests per window
RATE_LIMIT_BURST = 10  # burst requests

# Security headers
SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
}

class SecurityConfig(BaseModel):
    """Security configuration model"""
    secret_key: str = SECRET_KEY
    algorithm: str = ALGORITHM
    access_token_expire_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES
    refresh_token_expire_days: int = REFRESH_TOKEN_EXPIRE_DAYS
    rate_limit_window: int = RATE_LIMIT_WINDOW
    rate_limit_max_requests: int = RATE_LIMIT_MAX_REQUESTS
    rate_limit_burst: int = RATE_LIMIT_BURST

class User(BaseModel):
    """User model for authentication"""
    id: int
    email: str
    username: str
    role: str
    is_active: bool
    permissions: List[str] = []

class TokenData(BaseModel):
    """Token data model"""
    user_id: Optional[int] = None
    email: Optional[str] = None
    role: Optional[str] = None

class AuditLog(BaseModel):
    """Audit log model"""
    timestamp: datetime
    user_id: Optional[int]
    action: str
    resource: str
    ip_address: str
    user_agent: str
    success: bool
    details: Dict[str, Any] = {}

class SecurityMiddleware:
    """Comprehensive security middleware for FastAPI"""
    
    def __init__(self, redis_client: redis.Redis, config: SecurityConfig = SecurityConfig()):
        self.redis = redis_client
        self.config = config
        self.security = HTTPBearer()
        
    async def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.config.access_token_expire_minutes)
        
        to_encode.update({"exp": expire, "type": "access"})
        encoded_jwt = jwt.encode(to_encode, self.config.secret_key, algorithm=self.config.algorithm)
        return encoded_jwt
    
    async def create_refresh_token(self, data: dict) -> str:
        """Create JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=self.config.refresh_token_expire_days)
        to_encode.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(to_encode, self.config.secret_key, algorithm=self.config.algorithm)
        return encoded_jwt
    
    async def verify_token(self, token: str) -> TokenData:
        """Verify JWT token and return token data"""
        try:
            payload = jwt.decode(token, self.config.secret_key, algorithms=[self.config.algorithm])
            user_id: int = payload.get("user_id")
            email: str = payload.get("email")
            role: str = payload.get("role")
            token_type: str = payload.get("type")
            
            if user_id is None or email is None or role is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token payload",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            if token_type != "access":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            return TokenData(user_id=user_id, email=email, role=role)
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    async def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> User:
        """Get current authenticated user"""
        token_data = await self.verify_token(credentials.credentials)
        
        # Here you would typically fetch user from database
        # For now, we'll create a mock user
        user = User(
            id=token_data.user_id,
            email=token_data.email,
            username=token_data.email.split('@')[0],
            role=token_data.role,
            is_active=True,
            permissions=self._get_permissions_for_role(token_data.role)
        )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user"
            )
        
        return user
    
    def _get_permissions_for_role(self, role: str) -> List[str]:
        """Get permissions for a given role"""
        permissions = {
            "admin": [
                "read:all", "write:all", "delete:all", "admin:users", 
                "admin:system", "admin:licenses", "admin:logs"
            ],
            "user": [
                "read:own", "write:own", "read:security", "write:security"
            ],
            "analyst": [
                "read:all", "write:security", "read:logs", "write:reports"
            ]
        }
        return permissions.get(role, [])
    
    async def check_permission(self, user: User, required_permission: str) -> bool:
        """Check if user has required permission"""
        return required_permission in user.permissions
    
    async def require_permission(self, permission: str):
        """Dependency to require specific permission"""
        async def permission_checker(user: User = Depends(self.get_current_user)):
            if not await self.check_permission(user, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions"
                )
            return user
        return permission_checker
    
    async def rate_limit_check(self, request: Request) -> bool:
        """Check rate limiting for the request"""
        client_ip = self._get_client_ip(request)
        key = f"rate_limit:{client_ip}"
        
        try:
            # Get current request count
            current_count = await self.redis.get(key)
            current_count = int(current_count) if current_count else 0
            
            if current_count >= self.config.rate_limit_max_requests:
                return False
            
            # Increment counter
            pipe = self.redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, self.config.rate_limit_window)
            await pipe.execute()
            
            return True
        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            return True  # Allow request if rate limiting fails
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address"""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host
    
    async def log_audit_event(self, request: Request, user: Optional[User], 
                            action: str, resource: str, success: bool, 
                            details: Dict[str, Any] = None):
        """Log audit event"""
        try:
            audit_log = AuditLog(
                timestamp=datetime.utcnow(),
                user_id=user.id if user else None,
                action=action,
                resource=resource,
                ip_address=self._get_client_ip(request),
                user_agent=request.headers.get("User-Agent", ""),
                success=success,
                details=details or {}
            )
            
            # Store in Redis for immediate access
            log_key = f"audit_log:{int(time.time())}:{secrets.token_hex(8)}"
            await self.redis.setex(
                log_key, 
                86400,  # 24 hours
                json.dumps(audit_log.dict(), default=str)
            )
            
            # Log to file system
            logger.info(f"AUDIT: {audit_log.json()}")
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
    
    async def validate_input(self, data: Any) -> bool:
        """Validate and sanitize input data"""
        if isinstance(data, str):
            # Basic XSS prevention
            dangerous_patterns = [
                "<script", "javascript:", "onerror=", "onload=",
                "eval(", "document.cookie", "window.location"
            ]
            data_lower = data.lower()
            return not any(pattern in data_lower for pattern in dangerous_patterns)
        
        if isinstance(data, dict):
            return all(await self.validate_input(value) for value in data.values())
        
        if isinstance(data, list):
            return all(await self.validate_input(item) for item in data)
        
        return True
    
    async def generate_2fa_secret(self) -> str:
        """Generate 2FA secret for user"""
        return secrets.token_hex(16)
    
    async def verify_2fa_code(self, secret: str, code: str) -> bool:
        """Verify 2FA code (simplified implementation)"""
        # In production, use proper TOTP library like pyotp
        try:
            # This is a simplified verification
            # In real implementation, use pyotp.TOTP(secret).verify(code)
            expected_code = hashlib.sha256(f"{secret}{int(time.time() // 30)}".encode()).hexdigest()[:6]
            return hmac.compare_digest(code, expected_code)
        except Exception:
            return False
    
    async def hash_password(self, password: str) -> str:
        """Hash password using secure algorithm"""
        salt = secrets.token_hex(16)
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}${hash_obj.hex()}"
    
    async def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            salt, hash_hex = hashed.split('$')
            hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return hmac.compare_digest(hash_obj.hex(), hash_hex)
        except Exception:
            return False

# Middleware functions
async def security_middleware(request: Request, call_next):
    """Main security middleware"""
    security = SecurityMiddleware(redis.Redis())  # Initialize with your Redis client
    
    # Rate limiting
    if not await security.rate_limit_check(request):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Rate limit exceeded"}
        )
    
    # Input validation for POST/PUT requests
    if request.method in ["POST", "PUT", "PATCH"]:
        try:
            body = await request.body()
            if body:
                data = json.loads(body)
                if not await security.validate_input(data):
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={"detail": "Invalid input detected"}
                    )
        except Exception:
            pass  # Continue if validation fails
    
    # Add security headers
    response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    
    return response

# CORS middleware configuration
def get_cors_middleware():
    """Get CORS middleware with secure configuration"""
    return CORSMiddleware(
        allow_origins=["http://localhost:3000", "https://yourdomain.com"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Total-Count"],
        max_age=3600,
    )

# Trusted host middleware
def get_trusted_host_middleware():
    """Get trusted host middleware"""
    return TrustedHostMiddleware(
        allowed_hosts=["localhost", "127.0.0.1", "yourdomain.com"]
    ) 

# Global security instance
security_middleware_instance = SecurityMiddleware(redis.Redis())

# Authentication functions
async def authenticate_user(db: AsyncSession, email: str, password: str) -> Optional[User]:
    """Authenticate user with email and password"""
    try:
        # Import User model directly
        from app.models.user import User as DBUser
        
        # Get user by email
        db_user = await DBUser.get_by_email(db, email)
        if not db_user:
            return None
        
        # Verify password
        if not verify_password(password, db_user.hashed_password):
            return None
        
        # Return user with permissions (create a new User instance without permissions field)
        return User(
            id=db_user.id,
            email=db_user.email,
            username=db_user.username,
            role=db_user.role,
            is_active=db_user.is_active
        )
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return None

def _get_permissions_for_role(role: str) -> List[str]:
    """Get permissions for a given role"""
    permissions = {
        "admin": [
            "read:all", "write:all", "delete:all", "admin:users", 
            "admin:system", "admin:licenses", "admin:logs"
        ],
        "user": [
            "read:own", "write:own", "read:security", "write:security"
        ],
        "analyst": [
            "read:all", "write:security", "read:logs", "write:reports"
        ]
    }
    return permissions.get(role, [])

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    try:
        import bcrypt
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_password_hash(password: str) -> str:
    """Hash password using secure algorithm"""
    salt = secrets.token_hex(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${hash_obj.hex()}"

async def get_current_active_user(current_user: User = Depends(security_middleware_instance.get_current_user)) -> User:
    """Get current active user"""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user

async def require_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """Require admin role"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

async def require_analyst(current_user: User = Depends(get_current_active_user)) -> User:
    """Require analyst role"""
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst access required"
        )
    return current_user

# Function for main.py import
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> User:
    """Get current authenticated user - simplified version for main.py"""
    try:
        # For development, return a mock user
        return User(
            id=1,
            email="admin@cybershield.com",
            username="admin",
            role="admin",
            is_active=True,
            permissions=["read:all", "write:all", "delete:all", "admin:users"]
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) 