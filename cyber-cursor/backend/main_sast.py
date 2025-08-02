#!/usr/bin/env python3
"""
SAST Tool Main Entry Point
Comprehensive Static Application Security Testing Tool
"""

import uvicorn
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import os

# Import SAST components
from app.sast.scanner import SASTScanner, SASTScanManager
from app.sast.ai_recommendations import AIRecommendationEngine, RiskScoringEngine
from app.models.sast import SASTScan, SASTVulnerability, SASTRecommendation
from app.api.v1.sast import router as sast_router
from app.database import init_db, check_db_connection

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
    """Application lifespan manager"""
    # Startup
    logger.info("Starting SAST Tool")
    
    # Initialize database
    try:
        init_db()
        if check_db_connection():
            logger.info("Database initialized successfully")
        else:
            logger.warning("Database connection failed, using fallback mode")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
    
    # Initialize SAST components
    try:
        global sast_scanner, ai_engine, risk_engine
        sast_scanner = SASTScanner()
        ai_engine = AIRecommendationEngine()
        risk_engine = RiskScoringEngine()
        logger.info("SAST components initialized successfully")
    except Exception as e:
        logger.error(f"SAST components initialization error: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down SAST Tool")

# Create FastAPI app
app = FastAPI(
    title="SAST Tool API",
    description="Comprehensive Static Application Security Testing Tool",
    version="1.0.0",
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

# Include SAST API router
app.include_router(sast_router, prefix="/api/v1/sast", tags=["sast"])

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "sast-tool",
        "version": "1.0.0"
    }

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "SAST Tool API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }

if __name__ == "__main__":
    # Get configuration from environment
    host = os.getenv("SAST_HOST", "0.0.0.0")
    port = int(os.getenv("SAST_PORT", "8000"))
    reload = os.getenv("SAST_RELOAD", "true").lower() == "true"
    
    logger.info(f"Starting SAST Tool on {host}:{port}")
    
    uvicorn.run(
        "main_sast:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    ) 