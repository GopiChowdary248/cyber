"""
Main FastAPI application for Cyber Cursor - Comprehensive Security Platform
"""

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
import structlog
from app.core.config import settings
from app.database import create_tables, engine
from app.core.websocket_manager import websocket_manager

# Import all API routers
from app.api.v1.endpoints.dast_project_tools import router as dast_router
from app.api.v1.endpoints.sast import router as sast_router
from app.api.v1.endpoints.rasp_endpoints import router as rasp_router
from app.api.v1.endpoints.cloud_security import router as cloud_security_router
from app.api.v1.endpoints.endpoint_security import router as endpoint_security_router
from app.api.v1.endpoints.network_security import router as network_security_router
from app.api.v1.endpoints.iam_security import router as iam_security_router
from app.api.v1.endpoints.data_security import router as data_security_router
from app.api.v1.endpoints.incident_management import router as incident_router
from app.api.v1.endpoints.threat_intelligence import router as threat_intel_router
from app.api.v1.endpoints.compliance import router as compliance_router
from app.api.v1.endpoints.devsecops import router as devsecops_router
from app.api.v1.endpoints.ai_ml import router as ai_ml_router
from app.api.v1.endpoints.admin import router as admin_router
from app.api.v1.endpoints.user_management import router as user_router
from app.api.v1.endpoints.audit_logs import router as audit_router
from app.api.v1.endpoints.reporting import router as reporting_router
from app.api.v1.endpoints.integrations import router as integrations_router
from app.api.v1.endpoints.auth import router as auth_router

# Security
security = HTTPBearer()

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

# Application lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Cyber Cursor Security Platform...")
    
    # Create database tables
    try:
        create_tables()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}")
    
    # Start WebSocket cleanup task
    import asyncio
    asyncio.create_task(websocket_manager.start_cleanup_task())
    logger.info("WebSocket manager started")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Cyber Cursor Security Platform...")

# Create FastAPI app
app = FastAPI(
    title="Cyber Cursor Security Platform",
    description="Comprehensive Security Testing and Management Platform",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=settings.ALLOWED_METHODS,
    allow_headers=settings.ALLOWED_HEADERS,
)

# Add trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS
)

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current authenticated user"""
    try:
        # This would typically validate JWT tokens
        # For now, we'll accept any valid Bearer token
        if not credentials or not credentials.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"user_id": "authenticated_user", "token": credentials.credentials}
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Include auth router (no auth required for login/register)
app.include_router(
    auth_router,
    prefix="/api/v1/auth",
    tags=["Authentication"],
)

# Include all routers with authentication
app.include_router(
    dast_router, 
    prefix="/api/v1/dast", 
    tags=["DAST - Dynamic Application Security Testing"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    sast_router, 
    prefix="/api/v1/sast", 
    tags=["SAST - Static Application Security Testing"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    rasp_router, 
    prefix="/api/v1/rasp", 
    tags=["RASP - Runtime Application Self-Protection"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    cloud_security_router, 
    prefix="/api/v1/cloud-security", 
    tags=["Cloud Security"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    endpoint_security_router, 
    prefix="/api/v1/endpoint-security", 
    tags=["Endpoint Security"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    network_security_router, 
    prefix="/api/v1/network-security", 
    tags=["Network Security"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    iam_security_router, 
    prefix="/api/v1/iam", 
    tags=["Identity and Access Management"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    data_security_router, 
    prefix="/api/v1/data-security", 
    tags=["Data Security"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    incident_router, 
    prefix="/api/v1/incidents", 
    tags=["Incident Management"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    threat_intel_router, 
    prefix="/api/v1/threat-intelligence", 
    tags=["Threat Intelligence"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    compliance_router, 
    prefix="/api/v1/compliance", 
    tags=["Compliance & Governance"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    devsecops_router, 
    prefix="/api/v1/devsecops", 
    tags=["DevSecOps"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    ai_ml_router, 
    prefix="/api/v1/ai-ml", 
    tags=["AI & Machine Learning"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    admin_router, 
    prefix="/api/v1/admin", 
    tags=["Administration"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    user_router, 
    prefix="/api/v1/users", 
    tags=["User Management"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    audit_router, 
    prefix="/api/v1/audit", 
    tags=["Audit & Logging"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    reporting_router, 
    prefix="/api/v1/reporting", 
    tags=["Reporting & Analytics"],
    dependencies=[Depends(get_current_user)]
)

app.include_router(
    integrations_router, 
    prefix="/api/v1/integrations", 
    tags=["Integrations"],
    dependencies=[Depends(get_current_user)]
)



# Health check endpoint (no auth required)
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Cyber Cursor Security Platform",
        "version": "2.0.0",
        "modules": [
            "DAST", "SAST", "RASP", "Cloud Security", "Endpoint Security",
            "Network Security", "IAM", "Data Security", "Incident Management",
            "Threat Intelligence", "Compliance", "DevSecOps", "AI/ML"
        ]
    }

# Root endpoint (no auth required)
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Welcome to Cyber Cursor Security Platform",
        "version": "2.0.0",
        "description": "Comprehensive Security Testing and Management Platform",
        "features": {
            "application_security": ["DAST", "SAST", "RASP"],
            "infrastructure_security": ["Cloud Security", "Network Security", "Endpoint Security"],
            "identity_security": ["IAM", "Data Security", "Compliance"],
            "operations": ["Incident Management", "Threat Intelligence", "DevSecOps"],
            "intelligence": ["AI/ML", "Analytics", "Reporting"]
        },
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "api": "/api/v1"
        }
    }

# Protected route example
@app.get("/protected")
async def protected_route(current_user: dict = Depends(get_current_user)):
    """Example protected route"""
    return {
        "message": "This is a protected route",
        "user": current_user,
        "timestamp": "2024-01-01T00:00:00Z"
    }

# API status endpoint
@app.get("/api/status")
async def api_status():
    """API status and module information"""
    return {
        "status": "operational",
        "version": "2.0.0",
        "modules": {
            "dast": {
                "status": "active",
                "endpoints": "/api/v1/dast",
                "features": ["Scanner", "Crawler", "Proxy", "Intruder", "Repeater"]
            },
            "sast": {
                "status": "active",
                "endpoints": "/api/v1/sast",
                "features": ["Code Analysis", "Vulnerability Detection", "Quality Metrics"]
            },
            "rasp": {
                "status": "active",
                "endpoints": "/api/v1/rasp",
                "features": ["Runtime Protection", "Behavior Monitoring", "Attack Prevention"]
            },
            "cloud_security": {
                "status": "active",
                "endpoints": "/api/v1/cloud-security",
                "features": ["AWS", "Azure", "GCP", "Kubernetes", "Container Security"]
            },
            "endpoint_security": {
                "status": "active",
                "endpoints": "/api/v1/endpoint-security",
                "features": ["Device Control", "Threat Detection", "Response"]
            },
            "network_security": {
                "status": "active",
                "endpoints": "/api/v1/network-security",
                "features": ["Traffic Analysis", "Firewall", "IDS/IPS"]
            },
            "iam": {
                "status": "active",
                "endpoints": "/api/v1/iam",
                "features": ["User Management", "Role-Based Access", "MFA"]
            },
            "data_security": {
                "status": "active",
                "endpoints": "/api/v1/data-security",
                "features": ["Encryption", "Data Loss Prevention", "Privacy"]
            },
            "incident_management": {
                "status": "active",
                "endpoints": "/api/v1/incidents",
                "features": ["Detection", "Response", "Remediation"]
            },
            "threat_intelligence": {
                "status": "active",
                "endpoints": "/api/v1/threat-intelligence",
                "features": ["IOC Management", "Threat Feeds", "Analysis"]
            },
            "compliance": {
                "status": "active",
                "endpoints": "/api/v1/compliance",
                "features": ["Frameworks", "Audits", "Reporting"]
            },
            "devsecops": {
                "status": "active",
                "endpoints": "/api/v1/devsecops",
                "features": ["CI/CD Security", "Container Security", "Infrastructure as Code"]
            },
            "ai_ml": {
                "status": "active",
                "endpoints": "/api/v1/ai-ml",
                "features": ["Anomaly Detection", "Predictive Analytics", "Automation"]
            }
        },
        "websocket": {
            "status": "active",
            "endpoint": "/ws",
            "features": ["Real-time Updates", "Live Monitoring", "Collaboration"]
        }
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info",
        access_log=True
    )
