"""
Configuration settings for Cyber Cursor Security Platform
"""

import os
from typing import List, Optional
from pydantic import validator
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Cyber Cursor Security Platform"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 1
    
    # Logging
    LOG_LEVEL: str = "info"
    LOG_FORMAT: str = "json"
    
    # Security
    SECRET_KEY: str = "your-secret-key-here-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # CORS
    ALLOWED_HOSTS: List[str] = ["*"]
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",  # React dev server
        "http://localhost:3001",  # Alternative React port
        "http://127.0.0.1:3000", # Alternative localhost
        "http://127.0.0.1:3001", # Alternative localhost port
        "*"  # Allow all origins in development
    ]
    ALLOWED_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]
    ALLOWED_HEADERS: List[str] = [
        "Accept", "Accept-Language", "Content-Language", "Content-Type",
        "Authorization", "X-Requested-With", "Origin", "Cache-Control",
        "X-CSRF-Token", "X-API-Key"
    ]
    
    # Database
    DATABASE_URL: str = "postgresql://postgres:password@localhost:5432/cyber_cursor"
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    DATABASE_POOL_TIMEOUT: int = 30
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0
    
    # WebSocket
    WEBSOCKET_PING_INTERVAL: int = 25
    WEBSOCKET_PING_TIMEOUT: int = 10
    WEBSOCKET_CLOSE_TIMEOUT: int = 10
    
    # File Upload
    MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB
    UPLOAD_DIR: str = "uploads"
    ALLOWED_FILE_TYPES: List[str] = [
        "txt", "pdf", "doc", "docx", "xls", "xlsx", "csv", "json", "xml", "yaml", "yml",
        "py", "js", "ts", "java", "cpp", "c", "cs", "php", "rb", "go", "rs", "swift",
        "html", "css", "scss", "sass", "less", "vue", "jsx", "tsx"
    ]
    
    # Email
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_TLS: bool = True
    SMTP_SSL: bool = False
    
    # External APIs
    OPENAI_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    CENSYS_API_ID: Optional[str] = None
    CENSYS_API_SECRET: Optional[str] = None
    
    # Cloud Providers
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    AWS_REGION: str = "us-east-1"
    AWS_S3_BUCKET: Optional[str] = None
    
    AZURE_TENANT_ID: Optional[str] = None
    AZURE_CLIENT_ID: Optional[str] = None
    AZURE_CLIENT_SECRET: Optional[str] = None
    AZURE_SUBSCRIPTION_ID: Optional[str] = None
    
    GCP_PROJECT_ID: Optional[str] = None
    GCP_SERVICE_ACCOUNT_KEY: Optional[str] = None
    
    # Monitoring
    ENABLE_METRICS: bool = True
    METRICS_PORT: int = 9090
    ENABLE_HEALTH_CHECKS: bool = True
    HEALTH_CHECK_INTERVAL: int = 30
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds
    
    # Session Management
    SESSION_TIMEOUT: int = 3600  # 1 hour
    MAX_SESSIONS_PER_USER: int = 5
    
    # Backup
    BACKUP_ENABLED: bool = False
    BACKUP_INTERVAL: int = 24  # hours
    BACKUP_RETENTION_DAYS: int = 30
    
    # Integration
    SLACK_WEBHOOK_URL: Optional[str] = None
    TEAMS_WEBHOOK_URL: Optional[str] = None
    JIRA_URL: Optional[str] = None
    JIRA_USERNAME: Optional[str] = None
    JIRA_API_TOKEN: Optional[str] = None
    
    # AI/ML
    AI_MODEL_PATH: str = "models/"
    AI_ENABLE_GPU: bool = False
    AI_BATCH_SIZE: int = 32
    AI_MAX_SEQUENCE_LENGTH: int = 512
    
    # Compliance
    COMPLIANCE_FRAMEWORKS: List[str] = [
        "ISO27001", "SOC2", "PCI-DSS", "GDPR", "HIPAA", "NIST", "OWASP"
    ]
    
    # Threat Intelligence
    THREAT_INTEL_SOURCES: List[str] = [
        "virustotal", "abuseipdb", "shodan", "censys", "alienvault", "misp"
    ]
    THREAT_INTEL_UPDATE_INTERVAL: int = 3600  # 1 hour
    
    # Incident Management
    INCIDENT_SEVERITY_LEVELS: List[str] = [
        "Critical", "High", "Medium", "Low", "Info"
    ]
    INCIDENT_STATUSES: List[str] = [
        "New", "Assigned", "In Progress", "Resolved", "Closed"
    ]
    
    # Reporting
    REPORT_FORMATS: List[str] = ["pdf", "html", "json", "csv", "xml"]
    REPORT_TEMPLATES_DIR: str = "templates/reports/"
    
    # Development
    ENABLE_SWAGGER: bool = True
    ENABLE_REDOC: bool = True
    ENABLE_OPENAPI: bool = True
    
    @validator("DATABASE_URL", pre=True)
    def assemble_db_url(cls, v: Optional[str], values: dict) -> str:
        if isinstance(v, str):
            return v
        
        # Build from components if not provided
        user = values.get("DB_USER", "postgres")
        password = values.get("DB_PASSWORD", "password")
        host = values.get("DB_HOST", "localhost")
        port = values.get("DB_PORT", "5432")
        name = values.get("DB_NAME", "cyber_cursor")
        
        return f"postgresql://{user}:{password}@{host}:{port}/{name}"
    
    @validator("ALLOWED_HOSTS", pre=True)
    def assemble_allowed_hosts(cls, v: str) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, tuple)):
            return v
        raise ValueError(v)
    
    @validator("ALLOWED_ORIGINS", pre=True)
    def assemble_allowed_origins(cls, v: str) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, tuple)):
            return v
        raise ValueError(v)
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "allow"

# Create settings instance
settings = Settings()

# Environment-specific overrides
if settings.ENVIRONMENT == "production":
    settings.DEBUG = False
    settings.LOG_LEVEL = "warning"
    settings.ENABLE_SWAGGER = False
    settings.ENABLE_REDOC = False
elif settings.ENVIRONMENT == "testing":
    settings.DEBUG = True
    settings.LOG_LEVEL = "debug"
    settings.DATABASE_URL = "postgresql://postgres:password@localhost:5432/cyber_cursor_test" 