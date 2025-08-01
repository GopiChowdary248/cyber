from pydantic_settings import BaseSettings
from pydantic import validator
from typing import List, Optional
import os

class SecuritySettings(BaseSettings):
    """Security configuration settings"""
    
    # JWT Settings
    SECRET_KEY: str = "your-super-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Rate Limiting
    RATE_LIMIT_WINDOW: int = 60
    RATE_LIMIT_MAX_REQUESTS: int = 100
    RATE_LIMIT_BURST: int = 10
    
    # Password Policy
    MIN_PASSWORD_LENGTH: int = 12
    REQUIRE_UPPERCASE: bool = True
    REQUIRE_LOWERCASE: bool = True
    REQUIRE_NUMBERS: bool = True
    REQUIRE_SPECIAL_CHARS: bool = True
    PASSWORD_HISTORY_COUNT: int = 5
    
    # Session Management
    SESSION_TIMEOUT_MINUTES: int = 30
    MAX_CONCURRENT_SESSIONS: int = 3
    SESSION_INACTIVITY_TIMEOUT: int = 15
    
    # 2FA Settings
    REQUIRE_2FA: bool = True
    TOTP_ISSUER: str = "CyberShield"
    BACKUP_CODES_COUNT: int = 10
    
    # API Security
    API_KEY_HEADER: str = "X-API-Key"
    API_KEY_LENGTH: int = 32
    
    # CORS Settings
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "https://yourdomain.com"]
    ALLOWED_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    ALLOWED_HEADERS: List[str] = ["*"]
    
    # Trusted Hosts
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1", "yourdomain.com"]
    
    # Security Headers
    ENABLE_HSTS: bool = True
    HSTS_MAX_AGE: int = 31536000
    ENABLE_CSP: bool = True
    CSP_POLICY: str = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    
    # Audit Logging
    AUDIT_LOG_ENABLED: bool = True
    AUDIT_LOG_RETENTION_DAYS: int = 90
    AUDIT_LOG_LEVEL: str = "INFO"
    
    # Encryption
    ENCRYPTION_KEY: str = "your-encryption-key-change-in-production"
    ENCRYPTION_ALGORITHM: str = "AES-256-GCM"
    
    # Database Security
    DB_CONNECTION_POOL_SIZE: int = 10
    DB_CONNECTION_TIMEOUT: int = 30
    DB_SSL_MODE: str = "require"
    
    # Redis Security
    REDIS_SSL: bool = True
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0
    
    # File Upload Security
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    ALLOWED_FILE_TYPES: List[str] = [".pdf", ".txt", ".csv", ".json", ".xml"]
    UPLOAD_PATH: str = "./uploads"
    SCAN_UPLOADS: bool = True
    
    # Network Security
    ENABLE_IP_WHITELIST: bool = False
    IP_WHITELIST: List[str] = []
    ENABLE_GEO_BLOCKING: bool = False
    BLOCKED_COUNTRIES: List[str] = []
    
    # Monitoring
    ENABLE_SECURITY_MONITORING: bool = True
    ALERT_ON_FAILED_LOGIN: bool = True
    ALERT_ON_SUSPICIOUS_ACTIVITY: bool = True
    ALERT_EMAIL: Optional[str] = None
    
    @validator('SECRET_KEY')
    def validate_secret_key(cls, v):
        if len(v) < 32:
            raise ValueError('SECRET_KEY must be at least 32 characters long')
        return v
    
    @validator('ENCRYPTION_KEY')
    def validate_encryption_key(cls, v):
        if len(v) < 32:
            raise ValueError('ENCRYPTION_KEY must be at least 32 characters long')
        return v
    
    @validator('ALLOWED_ORIGINS')
    def validate_allowed_origins(cls, v):
        if not v:
            raise ValueError('At least one allowed origin must be specified')
        return v

class DatabaseSettings(BaseSettings):
    """Database configuration settings"""
    
    # Use PostgreSQL in production, SQLite in development
    DATABASE_URL: str = "postgresql+asyncpg://cybershield_user:cybershield_password@postgres:5432/cybershield"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 3600
    
    # SSL Configuration
    DB_SSL_MODE: str = "require"
    DB_SSL_CERT: Optional[str] = None
    DB_SSL_KEY: Optional[str] = None
    DB_SSL_CA: Optional[str] = None
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Override with SQLite for local development if PostgreSQL is not available
        if os.getenv("USE_SQLITE", "false").lower() == "true":
            self.DATABASE_URL = "sqlite+aiosqlite:///./cybershield.db"

class RedisSettings(BaseSettings):
    """Redis configuration settings"""
    
    REDIS_URL: str = "redis://:redis_password@redis:6379/0"
    REDIS_PASSWORD: Optional[str] = "redis_password"
    REDIS_DB: int = 0
    REDIS_SSL: bool = False
    REDIS_MAX_CONNECTIONS: int = 20

class APISettings(BaseSettings):
    """API configuration settings"""
    
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "CyberShield API"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Comprehensive cybersecurity platform API"
    
    # Server Settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = True
    
    # Pagination
    DEFAULT_PAGE_SIZE: int = 20
    MAX_PAGE_SIZE: int = 100
    
    # Response Caching
    ENABLE_CACHING: bool = True
    CACHE_TTL: int = 300  # 5 minutes

class LoggingSettings(BaseSettings):
    """Logging configuration settings"""
    
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_FILE: Optional[str] = None
    LOG_MAX_SIZE: int = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT: int = 5
    
    # Security Logging
    SECURITY_LOG_LEVEL: str = "WARNING"
    SECURITY_LOG_FILE: Optional[str] = None

# Create settings instances
security_settings = SecuritySettings()
database_settings = DatabaseSettings()
redis_settings = RedisSettings()
api_settings = APISettings()
logging_settings = LoggingSettings()

# Combined settings for easy access
class Settings:
    """Combined settings class"""
    
    def __init__(self):
        self.security = security_settings
        self.database = database_settings
        self.redis = redis_settings
        self.api = api_settings
        self.logging = logging_settings
    
    @property
    def is_production(self) -> bool:
        """Check if running in production"""
        return os.getenv("ENVIRONMENT", "development").lower() == "production"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development"""
        return os.getenv("ENVIRONMENT", "development").lower() == "development"
    
    @property
    def is_testing(self) -> bool:
        """Check if running in testing"""
        return os.getenv("ENVIRONMENT", "development").lower() == "testing"

# Global settings instance
settings = Settings()

# Ensure upload directory exists
os.makedirs(settings.security.UPLOAD_PATH, exist_ok=True) 