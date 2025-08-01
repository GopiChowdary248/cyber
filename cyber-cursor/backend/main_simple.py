from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import uvicorn
import structlog
from typing import List, Optional
from pydantic import BaseModel
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