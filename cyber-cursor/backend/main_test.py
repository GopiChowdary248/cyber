from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn
import structlog
from datetime import datetime

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
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
    logger.info("Starting CyberShield test application")
    yield
    # Shutdown
    logger.info("Shutting down CyberShield test application")

# Create FastAPI application
app = FastAPI(
    title="CyberShield Test",
    description="Test application with essential endpoints",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import and include only essential routers
try:
    from app.api.v1.endpoints.auth import router as auth_router
    from app.api.v1.endpoints.iam import router as iam_router
    from app.api.v1.endpoints.health import router as health_router
    
    app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
    app.include_router(iam_router, prefix="/api/v1/iam", tags=["IAM"])
    app.include_router(health_router, prefix="/api/v1/health", tags=["Health"])
    
    logger.info("Essential API routers loaded successfully")
except Exception as e:
    logger.error(f"Failed to load essential routers: {e}")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "CyberShield Test Application",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "auth": "/api/v1/auth",
            "iam": "/api/v1/iam",
            "health": "/api/v1/health",
            "docs": "/docs"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "message": "CyberShield test application is running",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "auth": "running",
            "iam": "running",
            "health": "running"
        }
    }

@app.get("/test")
async def test_endpoint():
    """Test endpoint"""
    return {
        "message": "Test endpoint working!",
        "status": "success",
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    uvicorn.run(
        "main_test:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    ) 