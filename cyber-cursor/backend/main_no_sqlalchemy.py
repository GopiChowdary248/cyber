#!/usr/bin/env python3
"""
CyberShield Backend - No SQLAlchemy Version
Uses raw PostgreSQL connections with asyncpg for better performance and control
"""

import os
import asyncio
import asyncpg
import redis.asyncio as redis
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import uvicorn
import structlog
from datetime import datetime
import json

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

# Global database and Redis connections
db_pool = None
redis_client = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global db_pool, redis_client
    
    # Startup
    logger.info("Starting CyberShield application")
    
    try:
        # Initialize database connection pool
        db_pool = await asyncpg.create_pool(
            host=os.getenv('DB_HOST', 'localhost'),
            port=int(os.getenv('DB_PORT', '5432')),
            user=os.getenv('DB_USER', 'cybershield_user'),
            password=os.getenv('DB_PASSWORD', 'cybershield_password'),
            database=os.getenv('DB_NAME', 'cybershield_dev'),
            min_size=5,
            max_size=20
        )
        logger.info("Database connection pool initialized")
        
        # Initialize Redis connection
        redis_client = redis.Redis(
            host=os.getenv('REDIS_HOST', 'localhost'),
            port=int(os.getenv('REDIS_PORT', '6379')),
            password=os.getenv('REDIS_PASSWORD', 'redis_password'),
            decode_responses=True
        )
        await redis_client.ping()
        logger.info("Redis connection initialized")
        
        # Initialize database tables
        await init_database()
        logger.info("Database tables initialized")
        
    except Exception as e:
        logger.error("Startup failed", error=str(e))
        raise
    
    logger.info("CyberShield application started successfully")
    yield
    
    # Shutdown
    logger.info("Shutting down CyberShield application")
    
    if db_pool:
        await db_pool.close()
        logger.info("Database connections closed")
    
    if redis_client:
        await redis_client.close()
        logger.info("Redis connection closed")

async def init_database():
    """Initialize database tables without SQLAlchemy"""
    async with db_pool.acquire() as conn:
        # Create users table
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                username VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'user',
                is_active BOOLEAN DEFAULT true,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create projects table
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                owner_id INTEGER REFERENCES users(id),
                status VARCHAR(50) DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create sast_scans table
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS sast_scans (
                id SERIAL PRIMARY KEY,
                project_id INTEGER REFERENCES projects(id),
                scan_type VARCHAR(50) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                results JSONB,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create dast_scans table
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS dast_scans (
                id SERIAL PRIMARY KEY,
                project_id INTEGER REFERENCES projects(id),
                target_url VARCHAR(500) NOT NULL,
                scan_type VARCHAR(50) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                results JSONB,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create vulnerabilities table
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id SERIAL PRIMARY KEY,
                project_id INTEGER REFERENCES projects(id),
                scan_id INTEGER,
                scan_type VARCHAR(50) NOT NULL,
                severity VARCHAR(20) NOT NULL,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                location TEXT,
                cwe_id VARCHAR(20),
                cvss_score DECIMAL(3,1),
                status VARCHAR(50) DEFAULT 'open',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create incidents table
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                severity VARCHAR(20) NOT NULL,
                status VARCHAR(50) DEFAULT 'open',
                assigned_to INTEGER REFERENCES users(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create audit_logs table
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                action VARCHAR(100) NOT NULL,
                resource_type VARCHAR(50),
                resource_id INTEGER,
                details JSONB,
                ip_address INET,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insert default admin user if not exists
        await conn.execute('''
            INSERT INTO users (email, username, password_hash, role, is_active)
            VALUES ('admin@cybershield.com', 'admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.i8i.', 'admin', true)
            ON CONFLICT (email) DO NOTHING
        ''')
        
        logger.info("Database tables initialized successfully")

# Create FastAPI application
app = FastAPI(
    title="CyberShield",
    description="Comprehensive Cybersecurity Platform with SAST, DAST, RASP, and Cloud Security",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*"]
)

# Security
security = HTTPBearer()

# Dependency to get database connection
async def get_db():
    """Get database connection from pool"""
    if not db_pool:
        raise HTTPException(status_code=500, detail="Database not available")
    async with db_pool.acquire() as conn:
        yield conn

# Dependency to get Redis client
async def get_redis():
    """Get Redis client"""
    if not redis_client:
        raise HTTPException(status_code=500, detail="Redis not available")
    return redis_client

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check database
        async with db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        
        # Check Redis
        await redis_client.ping()
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "services": {
                "database": "connected",
                "redis": "connected"
            }
        }
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        raise HTTPException(status_code=503, detail="Service unavailable")

# Import and include all endpoint routers
from app.api.v1.endpoints.auth import router as auth_router
from app.api.v1.endpoints.users import router as users_router
from app.api.v1.endpoints.projects import router as projects_router
from app.api.v1.endpoints.sast import router as sast_router
from app.api.v1.endpoints.dast import router as dast_router
from app.api.v1.endpoints.rasp import router as rasp_router
from app.api.v1.endpoints.security import router as security_router
from app.api.v1.endpoints.dashboard import router as dashboard_router
from app.api.v1.endpoints.reports import router as reports_router
from app.api.v1.endpoints.incidents import router as incidents_router
from app.api.v1.endpoints.compliance import router as compliance_router
from app.api.v1.endpoints.threat_intelligence import router as threat_router
from app.api.v1.endpoints.cloud_security import router as cloud_router
from app.api.v1.endpoints.network_security import router as network_router
from app.api.v1.endpoints.data_security import router as data_router
from app.api.v1.endpoints.ai_ml import router as ai_ml_router
from app.api.v1.endpoints.workflows import router as workflows_router
from app.api.v1.endpoints.integrations import router as integrations_router
from app.api.v1.endpoints.mfa import router as mfa_router
from app.api.v1.endpoints.admin import router as admin_router

# Include all routers
app.include_router(auth_router, prefix="/api/v1", tags=["Authentication"])
app.include_router(users_router, prefix="/api/v1", tags=["Users"])
app.include_router(projects_router, prefix="/api/v1", tags=["Projects"])
app.include_router(sast_router, prefix="/api/v1", tags=["SAST"])
app.include_router(dast_router, prefix="/api/v1", tags=["DAST"])
app.include_router(rasp_router, prefix="/api/v1", tags=["RASP"])
app.include_router(security_router, prefix="/api/v1", tags=["Security"])
app.include_router(dashboard_router, prefix="/api/v1", tags=["Dashboard"])
app.include_router(reports_router, prefix="/api/v1", tags=["Reports"])
app.include_router(incidents_router, prefix="/api/v1", tags=["Incidents"])
app.include_router(compliance_router, prefix="/api/v1", tags=["Compliance"])
app.include_router(threat_router, prefix="/api/v1", tags=["Threat Intelligence"])
app.include_router(cloud_router, prefix="/api/v1", tags=["Cloud Security"])
app.include_router(network_router, prefix="/api/v1", tags=["Network Security"])
app.include_router(data_router, prefix="/api/v1", tags=["Data Security"])
app.include_router(ai_ml_router, prefix="/api/v1", tags=["AI/ML"])
app.include_router(workflows_router, prefix="/api/v1", tags=["Workflows"])
app.include_router(integrations_router, prefix="/api/v1", tags=["Integrations"])
app.include_router(mfa_router, prefix="/api/v1", tags=["MFA"])
app.include_router(admin_router, prefix="/api/v1", tags=["Admin"])

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "CyberShield API",
        "version": "2.0.0",
        "status": "running",
        "docs": "/docs",
        "health": "/health"
    }

if __name__ == "__main__":
    uvicorn.run(
        "main_no_sqlalchemy:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
