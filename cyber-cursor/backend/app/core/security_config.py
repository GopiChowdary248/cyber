"""
Security Configuration for CyberShield
Comprehensive security settings for production deployment
"""

import os
from typing import List, Dict, Any
from pydantic_settings import BaseSettings
from pydantic import validator

class SecurityConfig(BaseSettings):
    """Security configuration model"""
    
    # Application Security
    SECRET_KEY: str = "your-super-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # CORS Configuration
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000"]
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1"]
    ALLOWED_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    ALLOWED_HEADERS: List[str] = ["*"]
    EXPOSE_HEADERS: List[str] = ["X-Total-Count", "X-Request-ID"]
    MAX_AGE: int = 3600
    
    # Rate Limiting
    RATE_LIMIT_WINDOW: int = 60  # seconds
    RATE_LIMIT_MAX_REQUESTS: int = 100  # requests per window
    RATE_LIMIT_BURST: int = 10  # burst requests
    
    # Security Headers
    SECURITY_HEADERS_ENABLED: bool = True
    CSP_ENABLED: bool = True
    HSTS_ENABLED: bool = True
    
    # Content Security Policy
    CSP_DEFAULT_SRC: List[str] = ["'self'"]
    CSP_SCRIPT_SRC: List[str] = ["'self'", "'unsafe-inline'"]
    CSP_STYLE_SRC: List[str] = ["'self'", "'unsafe-inline'"]
    CSP_IMG_SRC: List[str] = ["'self'", "data:", "https:"]
    CSP_FONT_SRC: List[str] = ["'self'", "https:"]
    CSP_CONNECT_SRC: List[str] = ["'self'"]
    CSP_FRAME_SRC: List[str] = ["'none'"]
    CSP_OBJECT_SRC: List[str] = ["'none'"]
    CSP_BASE_URI: List[str] = ["'self'"]
    CSP_FORM_ACTION: List[str] = ["'self'"]
    
    # HTTP Strict Transport Security
    HSTS_MAX_AGE: int = 31536000  # 1 year
    HSTS_INCLUDE_SUBDOMAINS: bool = True
    HSTS_PRELOAD: bool = True
    
    # Trusted Hosts
    TRUSTED_HOSTS_ENABLED: bool = True
    
    # Input Validation
    INPUT_VALIDATION_ENABLED: bool = True
    MAX_REQUEST_SIZE: int = 10 * 1024 * 1024  # 10MB
    
    # Session Security
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    SESSION_COOKIE_MAX_AGE: int = 3600  # 1 hour
    
    # Password Policy
    MIN_PASSWORD_LENGTH: int = 12
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGITS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    
    # Account Lockout
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION: int = 900  # 15 minutes
    
    # Audit Logging
    AUDIT_LOGGING_ENABLED: bool = True
    AUDIT_LOG_RETENTION_DAYS: int = 365
    
    # API Security
    API_RATE_LIMIT_ENABLED: bool = True
    API_KEY_REQUIRED: bool = False
    API_VERSIONING_ENABLED: bool = True
    
    # Database Security
    DB_SSL_REQUIRED: bool = True
    DB_CONNECTION_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 30
    
    # Redis Security
    REDIS_SSL_REQUIRED: bool = True
    REDIS_PASSWORD_REQUIRED: bool = True
    
    # Logging Security
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    LOG_SENSITIVE_DATA: bool = False
    
    # Monitoring and Health Checks
    HEALTH_CHECK_ENABLED: bool = True
    METRICS_ENABLED: bool = True
    PROFILING_ENABLED: bool = False
    
    @validator('ALLOWED_ORIGINS', 'ALLOWED_HOSTS', pre=True)
    def parse_list(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(',')]
        return v
    
    @property
    def security_headers(self) -> Dict[str, str]:
        """Get security headers configuration"""
        headers = {}
        
        if self.SECURITY_HEADERS_ENABLED:
            # Basic Security Headers
            headers.update({
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
                "X-Request-ID": "{{request_id}}"
            })
            
            # Content Security Policy
            if self.CSP_ENABLED:
                csp_parts = []
                csp_parts.append(f"default-src {' '.join(self.CSP_DEFAULT_SRC)}")
                csp_parts.append(f"script-src {' '.join(self.CSP_SCRIPT_SRC)}")
                csp_parts.append(f"style-src {' '.join(self.CSP_STYLE_SRC)}")
                csp_parts.append(f"img-src {' '.join(self.CSP_IMG_SRC)}")
                csp_parts.append(f"font-src {' '.join(self.CSP_FONT_SRC)}")
                csp_parts.append(f"connect-src {' '.join(self.CSP_CONNECT_SRC)}")
                csp_parts.append(f"frame-src {' '.join(self.CSP_FRAME_SRC)}")
                csp_parts.append(f"object-src {' '.join(self.CSP_OBJECT_SRC)}")
                csp_parts.append(f"base-uri {' '.join(self.CSP_BASE_URI)}")
                csp_parts.append(f"form-action {' '.join(self.CSP_FORM_ACTION)}")
                
                headers["Content-Security-Policy"] = "; ".join(csp_parts)
            
            # HTTP Strict Transport Security
            if self.HSTS_ENABLED:
                hsts_parts = [f"max-age={self.HSTS_MAX_AGE}"]
                if self.HSTS_INCLUDE_SUBDOMAINS:
                    hsts_parts.append("includeSubDomains")
                if self.HSTS_PRELOAD:
                    hsts_parts.append("preload")
                
                headers["Strict-Transport-Security"] = "; ".join(hsts_parts)
        
        return headers
    
    @property
    def cors_config(self) -> Dict[str, Any]:
        """Get CORS configuration"""
        return {
            "allow_origins": self.ALLOWED_ORIGINS,
            "allow_credentials": True,
            "allow_methods": self.ALLOWED_METHODS,
            "allow_headers": self.ALLOWED_HEADERS,
            "expose_headers": self.EXPOSE_HEADERS,
            "max_age": self.MAX_AGE
        }
    
    @property
    def trusted_hosts_config(self) -> Dict[str, Any]:
        """Get trusted hosts configuration"""
        return {
            "allowed_hosts": self.ALLOWED_HOSTS
        }

# Global security configuration instance
security_config = SecurityConfig()

# Export configuration for easy access
__all__ = ["SecurityConfig", "security_config"]
