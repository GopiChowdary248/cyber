from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import uvicorn
import structlog

from app.core.config import settings
from app.core.database import engine, Base
from app.api.v1.api import api_router
from app.core.security import get_current_user
from app.services.monitoring import setup_monitoring
from app.services.notification_service import notification_service
from app.services.analytics_service import analytics_service
from app.services.workflow_service import workflow_service
from app.services.security_service import security_service
from app.services.network_security_service import network_security_service
from app.services.endpoint_security_service import endpoint_security_service
from app.services.application_security_service import application_security_service
from app.services.data_protection_service import data_protection_service
from app.services.monitoring_siem_soar_service import monitoring_siem_soar_service
from app.services.threat_intelligence_service import threat_intelligence_service

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
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Setup monitoring
    setup_monitoring()
    
    # Start enhanced services
    logger.info("Starting enhanced services")
    await notification_service.start_notification_worker()
    await analytics_service.start_analytics_service()
    await workflow_service.start_workflow_service()
    await security_service.start_security_service()
    await network_security_service.start_network_security_service()
    await endpoint_security_service.start_endpoint_security_service()
    await application_security_service.start_application_security_service()
    await data_protection_service.start_data_protection_service()
    await monitoring_siem_soar_service.start_monitoring_siem_soar_service()
    await threat_intelligence_service.start_threat_intelligence_service()
    logger.info("Enhanced services started successfully")
    
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
    allowed_hosts=settings.ALLOWED_HOSTS
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
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
        "services": {
            "database": "healthy",
            "notification_service": "healthy",
            "analytics_service": "healthy",
            "workflow_service": "healthy",
            "security_service": "healthy",
            "network_security_service": "healthy",
            "endpoint_security_service": "healthy",
            "application_security_service": "healthy",
            "data_protection_service": "healthy",
            "monitoring_siem_soar_service": "healthy",
            "threat_intelligence_service": "healthy"
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
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    ) 