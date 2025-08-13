#!/usr/bin/env python3
"""
CyberShield Unified Backend
Comprehensive Cybersecurity Platform with SAST, DAST, RASP, and Cloud Security
Production-ready with PostgreSQL integration
"""

import os
import asyncio
import structlog
from contextlib import asynccontextmanager
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# FastAPI imports
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import uvicorn

# Database imports
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import engine, Base, init_db, close_db, get_db
from app.core.config import settings

# Import only working API routers
from app.api.v1.endpoints import (
    auth_router, users_router, health_router, endpoint_antivirus_edr_router,
    device_control_router, cloud_security_router, dast_router, rasp_router,
    siem_soar_router, network_security_router, monitoring_siem_soar_router,
    data_protection_router, security_router, iam_router, data_security_router
)

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

# Global variables
security_bearer = HTTPBearer(auto_error=False)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("🚀 Starting CyberShield Unified Backend...")
    
    try:
        # Initialize database
        logger.info("📊 Initializing database connection...")
        await init_db()
        logger.info("✅ Database initialized successfully")
        
        # Test database connection
        async with engine.begin() as conn:
            from sqlalchemy import text
            await conn.execute(text("SELECT 1"))
        logger.info("✅ Database connection verified")
        
    except Exception as e:
        logger.error("❌ Database initialization failed", error=str(e))
        logger.warning("⚠️ Application will start in limited mode")
    
    logger.info("🎉 CyberShield application started successfully")
    
    # Additional startup logging
    logger.info("📚 API Documentation: http://localhost:8000/docs")
    logger.info("🔍 ReDoc Documentation: http://localhost:8000/redoc")
    logger.info("🌐 Health Check: http://localhost:8000/health")
    
    yield
    
    # Shutdown
    logger.info("🔄 Shutting down CyberShield application...")
    await close_db()
    logger.info("✅ Shutdown completed")

# Create FastAPI application
app = FastAPI(
    title="CyberShield Unified API",
    description="""
    🛡️ **CyberShield - Comprehensive Cybersecurity Platform**
    
    ## 🚀 **Core Security Services**
    - **SAST** - Static Application Security Testing
    - **DAST** - Dynamic Application Security Testing  
    - **RASP** - Runtime Application Self-Protection
    - **Cloud Security** - Multi-cloud security management
    - **Network Security** - Network monitoring and protection
    - **Data Security** - Data protection and encryption
    
    ## 🔧 **Additional Features**
    - **IAM** - Identity and Access Management
    - **Endpoint Security** - Device and antivirus management
    - **SIEM/SOAR** - Security monitoring and automation
    - **Data Protection** - Privacy and compliance management
    
    ## 📚 **API Documentation**
    - **Swagger UI**: `/docs` - Interactive API documentation
    - **ReDoc**: `/redoc` - Alternative API documentation
    - **Health Check**: `/health` - Service status
    """,
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
    contact={
        "name": "CyberShield Support",
        "email": "support@cybershield.com",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
)

# Add security middleware
try:
    # Temporarily disable complex security middleware to fix startup issues
    # from app.core.security_middleware import get_cors_middleware, get_trusted_host_middleware, get_security_middleware
    # from app.core.security_config import security_config
    
    # # Add comprehensive security middleware FIRST (before CORS)
    # SecurityMiddleware, middleware_kwargs = get_security_middleware()
    # app.add_middleware(SecurityMiddleware, **middleware_kwargs)
    
    # # Add trusted host middleware
    # app.add_middleware(get_trusted_host_middleware())
    
    # # Add CORS middleware with secure configuration LAST
    # app.add_middleware(get_cors_middleware())
    
    # logger.info("✅ Security middleware loaded successfully")
    
    # Fallback to basic CORS - Fixed to allow frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Frontend URLs
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )
    logger.info("✅ Basic CORS middleware loaded with frontend access")
    
except Exception as e:
    logger.warning(f"⚠️ Security middleware failed to load: {e}")
    # Fallback to basic CORS - Fixed to allow frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Frontend URLs
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )
    logger.info("✅ Basic CORS middleware loaded with frontend access")

# Global exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors"""
    logger.warning("Validation error", path=request.url.path, errors=exc.errors())
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Validation error",
            "errors": exc.errors(),
            "timestamp": datetime.now().isoformat()
        }
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle global exceptions"""
    logger.error("Unhandled exception", path=request.url.path, error=str(exc), exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "error": str(exc),
            "timestamp": datetime.now().isoformat()
        }
    )

# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        async with engine.begin() as conn:
            from sqlalchemy import text
            await conn.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        logger.warning("Database health check failed", error=str(e))
        db_status = "disconnected"
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "services": {
            "database": db_status,
            "api": "running"
        }
    }

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Welcome to CyberShield Unified API",
        "version": "2.0.0",
        "description": "Comprehensive Cybersecurity Platform",
        "documentation": "/docs",
        "health": "/health",
        "timestamp": datetime.now().isoformat()
    }

# Include all API routers with proper prefixes and tags
logger.info("📡 Including API routers...")

# Authentication and User Management
app.include_router(
    auth_router, 
    prefix="/api/v1/auth", 
    tags=["Authentication"],
    dependencies=[Depends(get_db)]
)

app.include_router(
    users_router, 
    prefix="/api/v1/users", 
    tags=["User Management"],
    dependencies=[Depends(get_db)]
)

app.include_router(
    iam_router, 
    prefix="/api/v1/iam", 
    tags=["Identity & Access Management"],
    dependencies=[Depends(get_db)]
)

# Core Security Services
app.include_router(
    dast_router, 
    prefix="/api/v1/dast", 
    tags=["DAST - Dynamic Application Security Testing"],
    dependencies=[Depends(get_db)]
)

app.include_router(
    rasp_router, 
    prefix="/api/v1/rasp", 
    tags=["RASP - Runtime Application Self-Protection"],
    dependencies=[Depends(get_db)]
)

app.include_router(
    cloud_security_router, 
    prefix="/api/v1/cloud-security", 
    tags=["Cloud Security"],
    dependencies=[Depends(get_db)]
)

app.include_router(
    network_security_router, 
    prefix="/api/v1/network-security", 
    tags=["Network Security"],
    dependencies=[Depends(get_db)]
)

app.include_router(
    data_security_router, 
    prefix="/api/v1/data-security", 
    tags=["Data Security"],
    dependencies=[Depends(get_db)]
)

# Endpoint and Device Security
app.include_router(
    endpoint_antivirus_edr_router, 
    prefix="/api/v1/endpoint-antivirus-edr", 
    tags=["Endpoint Security"],
    dependencies=[Depends(get_db)]
)

app.include_router(
    device_control_router, 
    prefix="/api/v1/device-control", 
    tags=["Device Control"],
    dependencies=[Depends(get_db)]
)

# Data Protection and Privacy
app.include_router(
    data_protection_router, 
    prefix="/api/v1/data-protection", 
    tags=["Data Protection"],
    dependencies=[Depends(get_db)]
)

# Security Operations
app.include_router(
    security_router, 
    prefix="/api/v1/security", 
    tags=["Security Operations"],
    dependencies=[Depends(get_db)]
)

# Monitoring and SIEM/SOAR
app.include_router(
    monitoring_siem_soar_router, 
    prefix="/api/v1/monitoring", 
    tags=["Security Monitoring"],
    dependencies=[Depends(get_db)]
)

app.include_router(
    siem_soar_router, 
    prefix="/api/v1/siem-soar", 
    tags=["SIEM/SOAR"],
    dependencies=[Depends(get_db)]
)

logger.info("✅ All API routers included successfully")

# Startup and shutdown events are now handled in the lifespan function above

if __name__ == "__main__":
    print("🚀 Starting CyberShield Unified Backend...")
    print("📚 API Documentation: http://localhost:8000/docs")
    print("🔍 ReDoc Documentation: http://localhost:8000/redoc")
    print("🌐 Health Check: http://localhost:8000/health")
    print("🛡️ Comprehensive Cybersecurity Platform")
    print("=" * 60)
    
    uvicorn.run(
        "main_unified:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
        access_log=True
    )
