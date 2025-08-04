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
    description="Comprehensive Cybersecurity Platform with SOAR, Cloud Security, and AI-Powered Phishing Detection",
    version="2.0.0",
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

# Import only essential endpoints to avoid import errors
try:
    from app.api.v1.endpoints.auth import router as auth_router
    from app.api.v1.endpoints.users import router as users_router
    
    # Include essential routers
    app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
    app.include_router(users_router, prefix="/api/v1/users", tags=["Users"])
    
    logger.info("Essential API routers loaded successfully")
    logger.info(f"Auth router routes: {[route.path for route in auth_router.routes]}")
except Exception as e:
    logger.error(f"Failed to load some API routers: {e}")
    import traceback
    logger.error(f"Traceback: {traceback.format_exc()}")

# Import and include RASP endpoints
try:
    from app.api.v1.endpoints.rasp import router as rasp_router
    app.include_router(rasp_router, prefix="/api/rasp", tags=["RASP"])
    logger.info("RASP API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load RASP API router: {e}")

# Import and include DAST endpoints if available
try:
    from app.api.v1.endpoints.dast import router as dast_router
    print(f"DAST router type: {type(dast_router)}")
    print(f"DAST router routes: {dast_router.routes}")
    app.include_router(dast_router, prefix="/dast", tags=["DAST"])
    logger.info("DAST API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load DAST API router: {e}")
    import traceback
    logger.error(f"Traceback: {traceback.format_exc()}")

# Import and include Cloud Security endpoints
try:
    from app.api.v1.endpoints.cloud_security import router as cloud_security_router
    app.include_router(cloud_security_router, prefix="/api/v1/cloud-security", tags=["Cloud Security"])
    logger.info("Cloud Security API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Cloud Security API router: {e}")
    # Temporarily disable Cloud Security router due to Session/AsyncSession conflict
    pass

# Import and include SAST endpoints
try:
    from app.api.v1.endpoints.sast import router as sast_router
    app.include_router(sast_router, prefix="/api/v1/sast", tags=["SAST"])
    logger.info("SAST API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load SAST API router: {e}")

# Import and include Device Control endpoints
try:
    from app.api.v1.endpoints.device_control import router as device_control_router
    app.include_router(device_control_router, prefix="/api/v1/device-control", tags=["Device Control"])
    logger.info("Device Control API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Device Control API router: {e}")

# Import and include IAM endpoints
try:
    from app.api.v1.endpoints.iam import router as iam_router
    app.include_router(iam_router, prefix="/api/v1/iam", tags=["IAM"])
    logger.info("IAM API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load IAM API router: {e}")

# Import and include Antivirus/EDR endpoints
try:
    from app.api.v1.endpoints.endpoint_antivirus_edr import router as endpoint_antivirus_edr_router
    app.include_router(endpoint_antivirus_edr_router, prefix="/api/v1/endpoint-antivirus-edr", tags=["Antivirus/EDR"])
    logger.info("Antivirus/EDR API router loaded successfully")
except Exception as e:
    logger.error(f"Failed to load Antivirus/EDR API router: {e}")

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
    return {
        "status": "healthy",
        "message": "CyberShield API with core components is running",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "database": "postgresql",
        "services": {
            "auth": "running",
            "users": "running",
            "database": "connected"
        }
    }

@app.get("/api/v1/health")
async def api_health_check():
    """API health check endpoint"""
    return {
        "status": "healthy",
        "message": "CyberShield API with core components is running",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "database": "postgresql",
        "services": {
            "auth": "running",
            "users": "running",
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

@app.get("/test-dast")
async def test_dast_direct():
    """Test endpoint to verify direct DAST functionality"""
    return {"message": "Direct DAST test endpoint working!", "status": "success"}

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
    
from fastapi.routing import APIRoute

print("=== Loaded Routes ===")
for route in app.routes:
    print(f"{route.path} -> {route.name}")
