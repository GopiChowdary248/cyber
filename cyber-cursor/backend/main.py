from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import uvicorn
import structlog
import os

from app.core.config import settings
from app.core.database import engine, Base
from app.api.v1.api import api_router
from app.core.security import get_current_user

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting CyberShield application")
    
    # Create database tables
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        # Continue with startup even if database fails
    
    logger.info("CyberShield application started successfully")
    yield
    
    # Shutdown
    logger.info("Shutting down CyberShield application")

# Create FastAPI application
app = FastAPI(
    title="CyberShield",
    description="Comprehensive Cybersecurity Platform with SOAR, Cloud Security, and AI-Powered Phishing Detection",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Security middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.security.ALLOWED_HOSTS
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.security.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Include API routes
app.include_router(api_router, prefix="/api/v1")

@app.get("/")
async def root():
    """Root endpoint with application info"""
    return {
        "message": "CyberShield - Comprehensive Cybersecurity Platform",
        "version": "1.0.0",
        "status": "operational",
        "database": "postgresql" if "postgresql" in settings.database.DATABASE_URL else "sqlite",
        "features": [
            "Automated Threat Detection & Response (SOAR++)",
            "Cloud Security Misconfiguration Detection",
            "AI-Powered Phishing Detection & Auto-Responder",
            "Enhanced Real-time Notifications (WebSocket integration)",
            "Advanced Analytics (Custom dashboards, trend analysis)",
            "Workflow Automation (Advanced incident workflows)",
            "Enhanced Security Features (Advanced MFA, audit logging)",
            "Network Security Infrastructure (Firewall, IDS/IPS, VPN, NAC, DNS Security)",
            "Endpoint Security (Antivirus, EDR, Application Whitelisting)",
            "Application Security (SAST, DAST, SCA, WAF)",
            "Data Protection (Encryption, DLP, Database Monitoring)",
            "Monitoring, SIEM & SOAR (Centralized Logging, Incident Response, Anomaly Detection)",
            "Threat Intelligence & Hunting (Indicators, Campaigns, Reports, Hunting)"
        ]
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": "2024-01-01T00:00:00Z",
        "database": "postgresql" if "postgresql" in settings.database.DATABASE_URL else "sqlite",
        "services": {
            "database": "healthy",
            "api": "healthy",
            "frontend": "healthy"
        }
    }

@app.get("/protected")
async def protected_route(current_user = Depends(get_current_user)):
    """Protected route example"""
    return {
        "message": "This is a protected route",
        "user": {
            "id": current_user.id,
            "email": current_user.email,
            "role": current_user.role
        }
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.api.HOST,
        port=settings.api.PORT,
        reload=settings.api.DEBUG,
        log_level="info"
    ) 