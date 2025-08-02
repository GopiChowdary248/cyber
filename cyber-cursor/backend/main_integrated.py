from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import uvicorn
import structlog
from typing import List, Optional
from pydantic import BaseModel
import os

# Import working API routers only
from app.api.v1.endpoints.health import router as health_router
from app.api.v1.endpoints.cloud_security import router as cloud_security_router
from app.api.v1.endpoints.network_security import router as network_security_router
from app.api.v1.endpoints.auth import router as auth_router
from app.api.v1.endpoints.users import router as users_router

# Import SAST components
from app.sast.scanner import SASTScanner, SASTScanManager
from app.sast.ai_recommendations import AIRecommendationEngine, RiskScoringEngine
from app.models.sast import SASTScan, SASTVulnerability, SASTRecommendation
from app.api.v1.sast import router as sast_router
from app.core.database import init_db

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

# Pydantic models
class User(BaseModel):
    id: int
    email: str
    username: str
    role: str
    is_active: bool
    permissions: List[str] = []

class HealthResponse(BaseModel):
    status: str
    message: str
    version: str
    timestamp: str

class SecurityMetrics(BaseModel):
    threats_blocked: int
    vulnerabilities_found: int
    incidents_resolved: int
    security_score: float

# Global variables
security = HTTPBearer(auto_error=False)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting CyberShield API with integrated components")
    
    # Initialize database
    try:
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error("Database initialization error", error=str(e))
    
    yield
    # Shutdown
    logger.info("Shutting down CyberShield API")

# Create FastAPI app
app = FastAPI(
    title="CyberShield API - Integrated",
    description="Comprehensive cybersecurity platform API with Cloud Security and SAST components",
    version="2.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include working API routers with proper prefixes
app.include_router(health_router, prefix="/api/v1/health", tags=["Health"])
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(users_router, prefix="/api/v1/users", tags=["Users"])
app.include_router(cloud_security_router, prefix="/api/v1/cloud-security", tags=["Cloud Security"])
app.include_router(network_security_router, prefix="/api/v1/network-security", tags=["Network Security"])
app.include_router(sast_router, prefix="/api/v1/sast", tags=["SAST"])

# Mock data
mock_users = [
    User(id=1, email="admin@cybershield.com", username="admin", role="admin", is_active=True, permissions=["read:all", "write:all", "delete:all"]),
    User(id=2, email="analyst@cybershield.com", username="analyst", role="analyst", is_active=True, permissions=["read:all", "write:incidents"]),
    User(id=3, email="user@cybershield.com", username="user", role="user", is_active=True, permissions=["read:own", "write:own"])
]

mock_security_metrics = SecurityMetrics(
    threats_blocked=1247,
    vulnerabilities_found=23,
    incidents_resolved=8,
    security_score=94.2
)

# Mock authentication data
mock_tokens = {
    "admin@cybershield.com": "mock_admin_token_123",
    "analyst@cybershield.com": "mock_analyst_token_456", 
    "user@cybershield.com": "mock_user_token_789"
}

# Authentication function
async def get_current_user(credentials = Depends(security)) -> Optional[User]:
    """Get current authenticated user - simplified version"""
    if not credentials:
        return None
    # In a real implementation, you would validate the JWT token
    # For now, return the first user as a mock
    return mock_users[0]

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with all available features"""
    return {
        "message": "CyberShield API - Integrated",
        "version": "2.0.0",
        "status": "running",
                        "features": [
                    "Health Monitoring",
                    "Authentication & User Management",
                    "Cloud Security Management",
                    "Network Security Management",
                    "SAST Code Analysis"
                ],
                        "endpoints": {
                    "health": "/api/v1/health",
                    "auth": "/api/v1/auth",
                    "users": "/api/v1/users",
                    "cloud_security": "/api/v1/cloud-security",
                    "network_security": "/api/v1/network-security",
                    "sast": "/api/v1/sast"
                },
        "documentation": "/docs",
        "alternative_docs": "/redoc"
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    import datetime
    return HealthResponse(
        status="healthy",
        message="CyberShield API with integrated components is running",
        version="2.0.0",
        timestamp=datetime.datetime.now().isoformat()
    )

@app.get("/api/v1/security/metrics", response_model=SecurityMetrics)
async def get_security_metrics(current_user: User = Depends(get_current_user)):
    """Get security metrics"""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return mock_security_metrics

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    
    uvicorn.run(
        "main_integrated:app",
        host=host,
        port=port,
        reload=False,
        log_level="info"
    ) 