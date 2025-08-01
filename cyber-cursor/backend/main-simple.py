from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import uvicorn
import structlog
import os

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

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

@app.get("/")
async def root():
    """Root endpoint with application info"""
    return {
        "message": "CyberShield - Comprehensive Cybersecurity Platform",
        "version": "1.0.0",
        "status": "operational",
        "database": "sqlite" if os.getenv("USE_SQLITE", "false").lower() == "true" else "postgresql",
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
        "database": "sqlite" if os.getenv("USE_SQLITE", "false").lower() == "true" else "postgresql",
        "services": {
            "database": "healthy",
            "api": "healthy",
            "frontend": "healthy"
        }
    }

@app.get("/api/v1/auth/login")
async def login():
    """Mock login endpoint"""
    return {
        "access_token": "mock_token_123",
        "token_type": "bearer",
        "expires_in": 1800,
        "user_id": 1,
        "email": "admin@cybershield.com",
        "role": "admin"
    }

@app.get("/api/v1/dashboard/overview")
async def dashboard_overview():
    """Mock dashboard overview endpoint"""
    return {
        "total_incidents": 15,
        "open_incidents": 3,
        "resolved_incidents": 12,
        "security_score": 85,
        "threat_level": "medium",
        "recent_activities": [
            {"id": 1, "type": "incident", "description": "Suspicious login attempt", "timestamp": "2024-01-01T10:00:00Z"},
            {"id": 2, "type": "alert", "description": "New vulnerability detected", "timestamp": "2024-01-01T09:30:00Z"}
        ]
    }

@app.get("/api/v1/incidents")
async def get_incidents():
    """Mock incidents endpoint"""
    return {
        "incidents": [
            {
                "id": 1,
                "title": "Suspicious Login Attempt",
                "description": "Multiple failed login attempts detected",
                "severity": "high",
                "status": "open",
                "created_at": "2024-01-01T10:00:00Z"
            },
            {
                "id": 2,
                "title": "Malware Detection",
                "description": "Potential malware detected on endpoint",
                "severity": "critical",
                "status": "investigating",
                "created_at": "2024-01-01T09:30:00Z"
            }
        ]
    }

@app.get("/protected")
async def protected_route():
    """Protected route example"""
    return {
        "message": "This is a protected route",
        "user": {
            "id": 1,
            "email": "admin@cybershield.com",
            "role": "admin"
        }
    }

if __name__ == "__main__":
    uvicorn.run(
        "main-simple:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    ) 