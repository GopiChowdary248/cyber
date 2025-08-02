from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import uvicorn
import structlog
from typing import List, Optional
from pydantic import BaseModel
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
    logger.info("Starting CyberShield API")
    
    # Initialize database
    try:
        init_db()
        if check_db_connection():
            logger.info("Database initialized successfully")
        else:
            logger.warning("Database connection failed, using fallback mode")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
    
    yield
    # Shutdown
    logger.info("Shutting down CyberShield API")

# Create FastAPI app
app = FastAPI(
    title="CyberShield API",
    description="Comprehensive cybersecurity platform API",
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

# Authentication endpoints
from fastapi import Form

@app.post("/api/v1/auth/login")
async def login(username: str = Form(...), password: str = Form(...)):
    """Mock login endpoint"""
    # Check if user exists in mock data
    user = next((u for u in mock_users if u.email == username), None)
    
    if user and password == "password":  # Simple mock validation
        token = mock_tokens.get(username, "mock_token")
        return {
            "access_token": token,
            "token_type": "bearer",
            "user_id": user.id,
            "email": user.email,
            "role": user.role
        }
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/api/v1/auth/register")
async def register(user_data: dict):
    """Mock registration endpoint"""
    # In a real implementation, you would create a new user
    return {"message": "User registered successfully"}

@app.get("/api/v1/auth/me")
async def get_current_user_profile(credentials = Depends(security)):
    """Get current user profile"""
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Return the first user as mock data
    return mock_users[0]

@app.put("/api/v1/users/me")
async def update_user_profile(user_data: dict, credentials = Depends(security)):
    """Update user profile"""
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # In a real implementation, you would update the user
    return {"message": "Profile updated successfully"}

# Routes
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "CyberShield API",
        "version": "1.0.0",
        "status": "running",
        "features": [
            "Security Dashboard",
            "Incident Management", 
            "Threat Intelligence",
            "Vulnerability Scanning",
            "Compliance Monitoring",
            "User Management"
        ]
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    import datetime
    return HealthResponse(
        status="healthy",
        message="CyberShield API is running",
        version="1.0.0",
        timestamp=datetime.datetime.now().isoformat()
    )

@app.get("/api/v1/users", response_model=List[User])
async def get_users(current_user: User = Depends(get_current_user)):
    """Get all users"""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return mock_users

@app.get("/api/v1/security/metrics", response_model=SecurityMetrics)
async def get_security_metrics(current_user: User = Depends(get_current_user)):
    """Get security metrics"""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return mock_security_metrics

@app.get("/api/v1/incidents")
async def get_incidents(current_user: User = Depends(get_current_user)):
    """Get security incidents"""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    return [
        {
            "id": 1,
            "title": "Suspicious Login Attempt",
            "severity": "medium",
            "status": "investigating",
            "timestamp": "2024-01-15T10:30:00Z",
            "description": "Multiple failed login attempts detected"
        },
        {
            "id": 2,
            "title": "Malware Detection",
            "severity": "high",
            "status": "resolved",
            "timestamp": "2024-01-14T15:45:00Z",
            "description": "Malware detected and quarantined"
        }
    ]

@app.get("/api/v1/threats")
async def get_threats(current_user: User = Depends(get_current_user)):
    """Get threat intelligence data"""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    return [
        {
            "id": 1,
            "type": "malware",
            "name": "Trojan.Generic",
            "severity": "high",
            "description": "Generic trojan detected in network traffic",
            "timestamp": "2024-01-15T09:15:00Z"
        },
        {
            "id": 2,
            "type": "phishing",
            "name": "Phishing Campaign",
            "severity": "medium",
            "description": "Phishing emails targeting employees",
            "timestamp": "2024-01-15T08:30:00Z"
        }
    ]

# Application Security Models
class SASTResult(BaseModel):
    id: int
    file_name: str
    severity: str
    description: str
    recommendation: str
    scan_date: str
    line_number: int
    rule_id: str

class DASTResult(BaseModel):
    id: int
    url: str
    severity: str
    vulnerability_type: str
    recommendation: str
    scan_date: str
    status: str
    cwe_id: str

class RASPLog(BaseModel):
    id: int
    incident_type: str
    status: str
    description: str
    blocked: bool
    timestamp: str
    source_ip: str
    attack_vector: str

class SecuritySummary(BaseModel):
    sast_critical: int
    sast_high: int
    sast_medium: int
    sast_low: int
    dast_critical: int
    dast_high: int
    dast_medium: int
    dast_low: int
    rasp_blocked: int
    rasp_incidents: int

# Mock Application Security Data
mock_sast_results = [
    SASTResult(
        id=1,
        file_name="app/auth/login.py",
        severity="high",
        description="SQL Injection vulnerability detected in user input",
        recommendation="Use parameterized queries or ORM to prevent SQL injection",
        scan_date="2024-01-15T10:30:00Z",
        line_number=45,
        rule_id="SQL_INJECTION_001"
    ),
    SASTResult(
        id=2,
        file_name="frontend/src/components/Login.tsx",
        severity="medium",
        description="XSS vulnerability in user input rendering",
        recommendation="Sanitize user input and use React's built-in XSS protection",
        scan_date="2024-01-15T10:30:00Z",
        line_number=23,
        rule_id="XSS_001"
    ),
    SASTResult(
        id=3,
        file_name="backend/api/users.py",
        severity="critical",
        description="Hardcoded credentials found in source code",
        recommendation="Remove hardcoded credentials and use environment variables",
        scan_date="2024-01-15T10:30:00Z",
        line_number=12,
        rule_id="HARDCODED_CREDS_001"
    )
]

mock_dast_results = [
    DASTResult(
        id=1,
        url="http://localhost:3000/login",
        severity="high",
        vulnerability_type="SQL Injection",
        recommendation="Implement input validation and use prepared statements",
        scan_date="2024-01-15T11:00:00Z",
        status="open",
        cwe_id="CWE-89"
    ),
    DASTResult(
        id=2,
        url="http://localhost:3000/api/users",
        severity="medium",
        vulnerability_type="Cross-Site Scripting (XSS)",
        recommendation="Implement proper output encoding and Content Security Policy",
        scan_date="2024-01-15T11:00:00Z",
        status="open",
        cwe_id="CWE-79"
    ),
    DASTResult(
        id=3,
        url="http://localhost:3000/admin",
        severity="critical",
        vulnerability_type="Authentication Bypass",
        recommendation="Implement proper authentication and authorization checks",
        scan_date="2024-01-15T11:00:00Z",
        status="open",
        cwe_id="CWE-287"
    )
]

mock_rasp_logs = [
    RASPLog(
        id=1,
        incident_type="SQL Injection Attempt",
        status="blocked",
        description="SQL injection attempt detected and blocked",
        blocked=True,
        timestamp="2024-01-15T12:30:00Z",
        source_ip="192.168.1.100",
        attack_vector="SQL_INJECTION"
    ),
    RASPLog(
        id=2,
        incident_type="XSS Attack",
        status="blocked",
        description="Cross-site scripting attempt blocked",
        blocked=True,
        timestamp="2024-01-15T12:35:00Z",
        source_ip="10.0.0.50",
        attack_vector="XSS"
    ),
    RASPLog(
        id=3,
        incident_type="Brute Force Attack",
        status="monitoring",
        description="Multiple failed login attempts detected",
        blocked=False,
        timestamp="2024-01-15T12:40:00Z",
        source_ip="203.0.113.25",
        attack_vector="BRUTE_FORCE"
    )
]

# Application Security Routes
@app.get("/api/v1/security/summary", response_model=SecuritySummary)
async def get_security_summary(current_user: User = Depends(get_current_user)):
    """Get security summary across all tools"""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Calculate summary from mock data
    sast_critical = len([r for r in mock_sast_results if r.severity == "critical"])
    sast_high = len([r for r in mock_sast_results if r.severity == "high"])
    sast_medium = len([r for r in mock_sast_results if r.severity == "medium"])
    sast_low = len([r for r in mock_sast_results if r.severity == "low"])
    
    dast_critical = len([r for r in mock_dast_results if r.severity == "critical"])
    dast_high = len([r for r in mock_dast_results if r.severity == "high"])
    dast_medium = len([r for r in mock_dast_results if r.severity == "medium"])
    dast_low = len([r for r in mock_dast_results if r.severity == "low"])
    
    rasp_blocked = len([r for r in mock_rasp_logs if r.blocked])
    rasp_incidents = len(mock_rasp_logs)
    
    return SecuritySummary(
        sast_critical=sast_critical,
        sast_high=sast_high,
        sast_medium=sast_medium,
        sast_low=sast_low,
        dast_critical=dast_critical,
        dast_high=dast_high,
        dast_medium=dast_medium,
        dast_low=dast_low,
        rasp_blocked=rasp_blocked,
        rasp_incidents=rasp_incidents
    )

@app.get("/api/v1/security/sast/results", response_model=List[SASTResult])
async def get_sast_results(current_user: User = Depends(get_current_user)):
    """Get SAST scan results"""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return mock_sast_results

@app.post("/api/v1/security/sast/scan")
async def trigger_sast_scan(current_user: User = Depends(get_current_user)):
    """Trigger a new SAST scan"""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # In a real implementation, this would trigger SonarQube or other SAST tool
    return {
        "message": "SAST scan triggered successfully",
        "scan_id": "sast_scan_123",
        "estimated_duration": "5-10 minutes"
    }

@app.get("/api/v1/security/dast/results", response_model=List[DASTResult])
async def get_dast_results(current_user: User = Depends(get_current_user)):
    """Get DAST scan results"""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return mock_dast_results

@app.post("/api/v1/security/dast/scan")
async def trigger_dast_scan(current_user: User = Depends(get_current_user)):
    """Trigger a new DAST scan"""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # In a real implementation, this would trigger OWASP ZAP or other DAST tool
    return {
        "message": "DAST scan triggered successfully",
        "scan_id": "dast_scan_456",
        "estimated_duration": "15-30 minutes"
    }

@app.get("/api/v1/security/rasp/logs", response_model=List[RASPLog])
async def get_rasp_logs(current_user: User = Depends(get_current_user)):
    """Get RASP monitoring logs"""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return mock_rasp_logs

@app.get("/api/v1/security/rasp/status")
async def get_rasp_status(current_user: User = Depends(get_current_user)):
    """Get RASP protection status"""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    return {
        "status": "active",
        "protection_enabled": True,
        "threats_blocked_today": 15,
        "active_rules": 25,
        "last_incident": "2024-01-15T12:40:00Z"
    }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    
    uvicorn.run(
        "main_simple:app",
        host=host,
        port=port,
        reload=False,
        log_level="info"
    ) 