from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import uvicorn
import structlog
import os
from datetime import datetime

from app.core.config import settings
from app.core.database import engine, Base, init_db, close_db
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
    
    # Initialize database
    try:
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error("Database initialization failed", error=str(e))
    
    logger.info("CyberShield application started successfully")
    yield
    
    # Shutdown
    logger.info("Shutting down CyberShield application")
    await close_db()

# Create FastAPI application
app = FastAPI(
    title="CyberShield",
    description="Comprehensive Cybersecurity Platform with SAST, DAST, RASP, and Cloud Security",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Import and include Security middleware
try:
    from app.core.security_middleware import get_cors_middleware, get_trusted_host_middleware, get_security_middleware
    from app.core.security_config import security_config
    
    # Add comprehensive security middleware FIRST (before CORS)
    SecurityMiddleware, middleware_kwargs = get_security_middleware()
    app.add_middleware(SecurityMiddleware, **middleware_kwargs)
    
    # Add trusted host middleware
    app.add_middleware(get_trusted_host_middleware())
    
    # Add CORS middleware with secure configuration LAST
    app.add_middleware(get_cors_middleware())
    
    logger.info("Security middleware loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Security middleware: {e}")
    # Fallback to basic CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Allow all origins for development
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Security
security = HTTPBearer()

# Import and include essential endpoints
try:
    from app.api.v1.endpoints.auth import router as auth_router
    from app.api.v1.endpoints.users import router as users_router
    
    # Include essential routers
    app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
    app.include_router(users_router, prefix="/api/v1/users", tags=["Users"])
    
    logger.info("Essential API routers loaded successfully")
except Exception as e:
    logger.error(f"Failed to load essential API routers: {e}")
    import traceback
    logger.error(f"Traceback: {traceback.format_exc()}")

# Import and include SAST endpoints
try:
    from app.api.v1.endpoints.sast import router as sast_router
    app.include_router(sast_router, prefix="/api/v1/sast", tags=["SAST"])
    logger.info("SAST API router loaded successfully")
    logger.info(f"SAST router routes: {[route.path for route in sast_router.routes]}")
except Exception as e:
    logger.error(f"Failed to load SAST API router: {e}")
    import traceback
    logger.error(f"Traceback: {traceback.format_exc()}")

# Import and include RASP endpoints
try:
    from app.api.v1.endpoints.rasp import router as rasp_router
    # Align RASP under /api/v1 for consistency with frontend mappings
    app.include_router(rasp_router, prefix="/api/v1/rasp", tags=["RASP"])
    logger.info("RASP API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load RASP API router: {e}")

# Import and include DAST endpoints
try:
    from app.api.v1.endpoints.dast import router as dast_router
    app.include_router(dast_router, prefix="/api/v1/dast", tags=["DAST"])
    logger.info("DAST API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load DAST API router: {e}")

# Import and include DAST Project Tools endpoints (Burp-like tools under projects)
try:
    from app.api.v1.endpoints.dast_project_tools import router as dast_tools_router
    app.include_router(dast_tools_router, prefix="/api/v1/dast/projects", tags=["DAST Project Tools"])
    logger.info("DAST Project Tools API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load DAST Project Tools API router: {e}")

# Import and include Cloud Security endpoints
try:
    from app.api.v1.endpoints.cloud_security import router as cloud_security_router
    app.include_router(cloud_security_router, prefix="/api/v1/cloud-security", tags=["Cloud Security"])
    logger.info("Cloud Security API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Cloud Security API router: {e}")

# Import and include Security endpoints
try:
    from app.api.v1.endpoints.security import router as security_router
    app.include_router(security_router, prefix="/api/v1/security", tags=["Security"])
    logger.info("Security API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Security API router: {e}")

# Import and include Projects endpoints
try:
    from app.api.v1.endpoints.projects import router as projects_router
    app.include_router(projects_router, prefix="/api/v1/projects", tags=["Projects"])
    logger.info("Projects API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Projects API router: {e}")

# Import and include Reports endpoints
try:
    from app.api.v1.endpoints.reports import router as reports_router
    app.include_router(reports_router, prefix="/api/v1/reports", tags=["Reports"])
    logger.info("Reports API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Reports API router: {e}")

# Import and include CI/CD endpoints
try:
    from app.api.v1.endpoints.cicd import router as cicd_router
    app.include_router(cicd_router, prefix="/api/v1/cicd", tags=["CI/CD"])
    logger.info("CI/CD API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load CI/CD API router: {e}")

# Import and include Quality Goals endpoints
try:
    from app.api.v1.endpoints.quality_goals import router as quality_goals_router
    app.include_router(quality_goals_router, prefix="/api/v1/quality-goals", tags=["Quality Goals"])
    logger.info("Quality Goals API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Quality Goals API router: {e}")

# Import and include Endpoint Antivirus/EDR endpoints
try:
    from app.api.v1.endpoints.endpoint_antivirus_edr import router as endpoint_antivirus_edr_router
    app.include_router(endpoint_antivirus_edr_router, prefix="/api/v1/endpoint-antivirus-edr", tags=["Endpoint Antivirus/EDR"])
    logger.info("Endpoint Antivirus/EDR API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Endpoint Antivirus/EDR API router: {e}")

# Import and include Endpoint Security endpoints
try:
    from app.api.v1.endpoints.endpoint_security import router as endpoint_security_router
    app.include_router(endpoint_security_router, prefix="/api/v1/endpoint-security", tags=["Endpoint Security"])
    logger.info("Endpoint Security API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Endpoint Security API router: {e}")

# Import and include Device Control endpoints
try:
    from app.api.v1.endpoints.device_control import router as device_control_router
    app.include_router(device_control_router, prefix="/api/v1/device-control", tags=["Device Control"])
    logger.info("Device Control API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Device Control API router: {e}")

# Import and include SIEM/SOAR endpoints
try:
    from app.api.v1.endpoints.siem_soar import router as siem_soar_router
    app.include_router(siem_soar_router, prefix="/api/v1/siem-soar", tags=["SIEM/SOAR"])
    logger.info("SIEM/SOAR API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load SIEM/SOAR API router: {e}")

# Import and include Network Security endpoints
try:
    from app.api.v1.endpoints.network_security import router as network_security_router
    app.include_router(network_security_router, prefix="/api/v1/network-security", tags=["Network Security"])
    logger.info("Network Security API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Network Security API router: {e}")

# Import and include Data Protection endpoints
try:
    from app.api.v1.endpoints.data_protection import router as data_protection_router
    app.include_router(data_protection_router, prefix="/api/v1/data-protection", tags=["Data Protection"])
    logger.info("Data Protection API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Data Protection API router: {e}")

# Import and include Monitoring SIEM/SOAR endpoints
try:
    from app.api.v1.endpoints.monitoring_siem_soar import router as monitoring_siem_soar_router
    app.include_router(monitoring_siem_soar_router, prefix="/api/v1/monitoring-siem-soar", tags=["Monitoring SIEM/SOAR"])
    logger.info("Monitoring SIEM/SOAR API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Monitoring SIEM/SOAR API router: {e}")

# Import and include IAM endpoints
try:
    from app.api.v1.endpoints.iam import router as iam_router
    app.include_router(iam_router, prefix="/api/v1/iam", tags=["IAM"])
    logger.info("IAM API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load IAM API router: {e}")

# Import and include Data Security endpoints
try:
    from app.api.v1.endpoints.data_security import router as data_security_router
    app.include_router(data_security_router, prefix="/api/v1/data-security", tags=["Data Security"])
    logger.info("Data Security API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Data Security API router: {e}")

# Import and include Health endpoints
try:
    from app.api.v1.endpoints.health import router as health_router
    app.include_router(health_router, prefix="/api/v1/health", tags=["Health"])
    logger.info("Health API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Health API router: {e}")

# Import and include Analytics endpoints
try:
    from app.api.v1.endpoints.analytics import router as analytics_router
    app.include_router(analytics_router, prefix="/api/v1/analytics", tags=["Analytics"])
    logger.info("Analytics API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Analytics API router: {e}")

# Import and include Threat Intelligence endpoints
try:
    from app.api.v1.endpoints.threat_intelligence import router as threat_intelligence_router
    app.include_router(threat_intelligence_router, prefix="/api/v1/threat-intelligence", tags=["Threat Intelligence"])
    logger.info("Threat Intelligence API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Threat Intelligence API router: {e}")

# Import and include Admin endpoints
try:
    from app.api.v1.endpoints.admin import router as admin_router
    app.include_router(admin_router, prefix="/api/v1/admin", tags=["Admin"])
    logger.info("Admin API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Admin API router: {e}")

# Import and include Dashboard endpoints
try:
    from app.api.v1.endpoints.dashboard import router as dashboard_router
    app.include_router(dashboard_router, prefix="/api/v1/dashboard", tags=["Dashboard"])
    logger.info("Dashboard API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Dashboard API router: {e}")

# Import and include Workflows endpoints
try:
    from app.api.v1.endpoints.workflows import router as workflows_router
    app.include_router(workflows_router, prefix="/api/v1/workflows", tags=["Workflows"])
    logger.info("Workflows API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Workflows API router: {e}")

# Import and include AI/ML endpoints
try:
    from app.api.v1.endpoints.ai_ml import router as ai_ml_router
    app.include_router(ai_ml_router, prefix="/api/v1/ai-ml", tags=["AI/ML"])
    logger.info("AI/ML API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load AI/ML API router: {e}")

# Import and include Integrations endpoints
try:
    from app.api.v1.endpoints.integrations import router as integrations_router
    app.include_router(integrations_router, prefix="/api/v1/integrations", tags=["Integrations"])
    logger.info("Integrations API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Integrations API router: {e}")

# Import and include Compliance endpoints
try:
    from app.api.v1.endpoints.compliance import router as compliance_router
    app.include_router(compliance_router, prefix="/api/v1/compliance", tags=["Compliance"])
    logger.info("Compliance API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Compliance API router: {e}")

# Import and include MFA endpoints
try:
    from app.api.v1.endpoints.mfa import router as mfa_router
    app.include_router(mfa_router, prefix="/api/v1/mfa", tags=["MFA"])
    logger.info("MFA API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load MFA API router: {e}")

# Import and include Phishing endpoints
try:
    from app.api.v1.endpoints.phishing import router as phishing_router
    app.include_router(phishing_router, prefix="/api/v1/phishing", tags=["Phishing"])
    logger.info("Phishing API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Phishing API router: {e}")

# Import and include Incidents endpoints
try:
    from app.api.v1.endpoints.incidents import router as incidents_router
    app.include_router(incidents_router, prefix="/api/v1/incidents", tags=["Incidents"])
    logger.info("Incidents API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Incidents API router: {e}")

# Import and include Application Security endpoints
try:
    from app.api.v1.endpoints.application_security import router as application_security_router
    app.include_router(application_security_router, prefix="/api/v1/application-security", tags=["Application Security"])
    logger.info("Application Security API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Application Security API router: {e}")

# Import and include Enhanced Cloud Security endpoints
try:
    from app.api.v1.endpoints.enhanced_cloud_security import router as enhanced_cloud_security_router
    app.include_router(enhanced_cloud_security_router, prefix="/api/v1/enhanced-cloud-security", tags=["Enhanced Cloud Security"])
    logger.info("Enhanced Cloud Security API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Enhanced Cloud Security API router: {e}")

# Import and include WebSocket support for real-time monitoring
try:
    from app.sast.websocket_manager import get_websocket_manager
    from fastapi import WebSocket, WebSocketDisconnect
    
    @app.websocket("/ws/{connection_id}")
    async def websocket_endpoint(websocket: WebSocket, connection_id: str):
        """WebSocket endpoint for real-time SAST monitoring"""
        try:
            websocket_manager = await get_websocket_manager()
            await websocket_manager.connect_client(websocket, connection_id)
            
            try:
                while True:
                    # Wait for messages from client
                    data = await websocket.receive_json()
                    await websocket_manager.handle_client_message(connection_id, data)
            except WebSocketDisconnect:
                websocket_manager.disconnect_client(connection_id)
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                websocket_manager.disconnect_client(connection_id)
                
        except Exception as e:
            logger.error(f"Failed to establish WebSocket connection: {e}")
    
    logger.info("WebSocket support for real-time monitoring loaded successfully")
except Exception as e:
    logger.error(f"Failed to load WebSocket support: {e}")

# Root endpoints
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "CyberShield Security Platform",
        "version": "2.0.0",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    # Get database type from configuration
    db_url = settings.database.DATABASE_URL
    logger.info(f"Database URL: {db_url}")
    
    if "sqlite" in db_url:
        db_type = "sqlite"
    elif "postgresql" in db_url:
        db_type = "postgresql"
    else:
        db_type = "unknown"
    
    logger.info(f"Database type detected: {db_type}")
    
    return {
        "status": "healthy",
        "message": "CyberShield API is running",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "database": db_type,
        "services": {
            "auth": "running",
            "users": "running",
            "sast": "running",
            "dast": "running",
            "rasp": "running",
            "cloud_security": "running",
            "security": "running",
            "projects": "running",
            "reports": "running",
            "cicd": "running",
            "quality_goals": "running",
            "endpoint_antivirus_edr": "running",
            "device_control": "running",
            "siem_soar": "running",
            "network_security": "running",
            "data_protection": "running",
            "monitoring_siem_soar": "running",
            "iam": "running",
            "data_security": "running",
            "health": "running",
            "database": "connected"
        }
    }

@app.get("/api/v1/health")
async def api_health_check():
    """API health check endpoint"""
    # Get database type from configuration
    db_url = settings.database.DATABASE_URL
    if "sqlite" in db_url:
        db_type = "sqlite"
    elif "postgresql" in db_url:
        db_type = "postgresql"
    else:
        db_type = "unknown"
    
    return {
        "status": "healthy",
        "message": "CyberShield API is running",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "database": db_type,
        "services": {
            "auth": "running",
            "users": "running",
            "sast": "running",
            "dast": "running",
            "rasp": "running",
            "cloud_security": "running",
            "security": "running",
            "projects": "running",
            "reports": "running",
            "cicd": "running",
            "quality_goals": "running",
            "endpoint_antivirus_edr": "running",
            "device_control": "running",
            "siem_soar": "running",
            "network_security": "running",
            "data_protection": "running",
            "monitoring_siem_soar": "running",
            "iam": "running",
            "data_security": "running",
            "health": "running",
            "database": "connected"
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
    # Production vs Development configuration
    is_production = os.getenv("ENVIRONMENT", "development") == "production"
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=not is_production,  # Disable reload in production
        log_level="info",
        access_log=True
    )
