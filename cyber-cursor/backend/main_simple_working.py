#!/usr/bin/env python3
"""
CyberShield Simple Working Backend
Basic version with core endpoints for frontend integration
"""

import os
import asyncio
import structlog
from contextlib import asynccontextmanager
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

# FastAPI imports
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import uvicorn

# Database imports
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import engine, Base, init_db, close_db, get_db
from app.core.config import settings

# Import only essential working endpoints
from app.api.v1.endpoints.auth import router as auth_router
from app.api.v1.endpoints.users import router as users_router
from app.api.v1.endpoints.health import router as health_router

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
    logger.info("🚀 Starting CyberShield Simple Working Backend...")
    
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
    title="CyberShield Simple Working API",
    description="""
    🛡️ **CyberShield - Basic Working Cybersecurity Platform**
    
    ## 🚀 **Core Services**
    - **Authentication** - User login and registration
    - **User Management** - Basic user operations
    - **Health Check** - Service status monitoring
    
    ## 📚 **API Documentation**
    - **Swagger UI**: `/docs` - Interactive API documentation
    - **ReDoc**: `/redoc` - Alternative API documentation
    - **Health Check**: `/health` - Service status
    """,
    version="1.0.0",
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

# Add basic CORS middleware
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
        "version": "1.0.0",
        "services": {
            "database": db_status,
            "api": "running"
        }
    }

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Welcome to CyberShield Simple Working API",
        "version": "1.0.0",
        "description": "Basic Working Cybersecurity Platform",
        "documentation": "/docs",
        "health": "/health",
        "timestamp": datetime.now().isoformat()
    }

# Include essential API routers
logger.info("📡 Including essential API routers...")

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

logger.info("✅ Essential API routers included successfully")

if __name__ == "__main__":
    print("🚀 Starting CyberShield Simple Working Backend...")
    print("📚 API Documentation: http://localhost:8000/docs")
    print("🔍 ReDoc Documentation: http://localhost:8000/redoc")
    print("🌐 Health Check: http://localhost:8000/health")
    print("🛡️ Basic Working Cybersecurity Platform")
    print("=" * 60)
    
    uvicorn.run(
        "main_simple_working:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
        access_log=True
    )
