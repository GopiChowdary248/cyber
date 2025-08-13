#!/usr/bin/env python3
"""
CyberShield Simple Backend
A simplified FastAPI backend for development and testing
"""

import os
import uvicorn
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from typing import List, Optional
import json
from datetime import datetime, timedelta

# Create FastAPI application
app = FastAPI(
    title="CyberShield",
    description="Comprehensive Cybersecurity Platform",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Pydantic models
class UserLogin(BaseModel):
    username: str
    password: str

class User(BaseModel):
    id: int
    email: str
    username: str
    role: str
    is_active: bool

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    user_id: int
    email: str
    role: str
    mfa_required: bool

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    services: dict

# Mock data for development
MOCK_USERS = {
    "admin@cybershield.com": {
        "id": 1,
        "email": "admin@cybershield.com",
        "username": "admin",
        "password": "password",
        "role": "admin",
        "is_active": True
    },
    "analyst@cybershield.com": {
        "id": 2,
        "email": "analyst@cybershield.com",
        "username": "analyst",
        "password": "password",
        "role": "analyst",
        "is_active": True
    },
    "user@cybershield.com": {
        "id": 3,
        "email": "user@cybershield.com",
        "username": "user",
        "password": "password",
        "role": "user",
        "is_active": True
    }
}

# Mock JWT tokens (in production, use proper JWT library)
def create_access_token(data: dict):
    """Create a mock access token"""
    return f"mock_token_{data['username']}_{datetime.now().timestamp()}"

def verify_token(token: str):
    """Verify a mock token"""
    if token.startswith("mock_token_"):
        parts = token.split("_")
        if len(parts) >= 3:
            username = parts[2]
            for user in MOCK_USERS.values():
                if user["username"] == username:
                    return user
    return None

# API endpoints
@app.get("/", response_model=dict)
async def root():
    """Root endpoint"""
    return {
        "message": "CyberShield API",
        "version": "2.0.0",
        "status": "running"
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        services={
            "api": "healthy",
            "database": "healthy",
            "redis": "healthy"
        }
    )

@app.post("/api/v1/auth/login", response_model=Token)
async def login(user_credentials: UserLogin):
    """User login endpoint"""
    # Find user by username or email
    user = None
    for email, user_data in MOCK_USERS.items():
        if (user_data["username"] == user_credentials.username or 
            email == user_credentials.username):
            if user_data["password"] == user_credentials.password:
                user = user_data
                break
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user["is_active"]:
        raise HTTPException(status_code=401, detail="User account is disabled")
    
    # Create access token
    access_token = create_access_token({"username": user["username"]})
    
    return Token(
        access_token=access_token,
        refresh_token=f"refresh_{access_token}",  # Mock refresh token
        token_type="bearer",
        expires_in=1800,  # 30 minutes
        user_id=user["id"],
        email=user["email"],
        role=user["role"],
        mfa_required=False
    )

@app.get("/api/v1/users/profile", response_model=User)
async def get_user_profile(token: str = Depends(security)):
    """Get user profile"""
    user = verify_token(token.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return User(
        id=user["id"],
        email=user["email"],
        username=user["username"],
        role=user["role"],
        is_active=user["is_active"]
    )

@app.get("/api/v1/sast/projects")
async def get_sast_projects(token: str = Depends(security)):
    """Get SAST projects"""
    user = verify_token(token.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Mock SAST projects
    projects = [
        {
            "id": 1,
            "name": "Web Application",
            "language": "Python",
            "status": "active",
            "last_scan": "2025-08-12T10:00:00Z",
            "vulnerabilities": 5
        },
        {
            "id": 2,
            "name": "Mobile App",
            "language": "React Native",
            "status": "active",
            "last_scan": "2025-08-12T09:30:00Z",
            "vulnerabilities": 2
        }
    ]
    
    return {"projects": projects}

@app.get("/api/v1/dast/scans")
async def get_dast_scans(token: str = Depends(security)):
    """Get DAST scans"""
    user = verify_token(token.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Mock DAST scans
    scans = [
        {
            "id": 1,
            "target_url": "https://example.com",
            "status": "completed",
            "start_time": "2025-08-12T08:00:00Z",
            "end_time": "2025-08-12T09:00:00Z",
            "vulnerabilities_found": 3
        }
    ]
    
    return {"scans": scans}

@app.get("/api/v1/dashboard/overview")
async def get_dashboard_overview(token: str = Depends(security)):
    """Get dashboard overview"""
    user = verify_token(token.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Mock dashboard data
    overview = {
        "total_projects": 15,
        "active_scans": 3,
        "vulnerabilities": {
            "critical": 2,
            "high": 8,
            "medium": 15,
            "low": 25
        },
        "recent_activities": [
            {
                "type": "scan_completed",
                "project": "Web Application",
                "timestamp": "2025-08-12T10:00:00Z"
            },
            {
                "type": "vulnerability_found",
                "project": "Mobile App",
                "severity": "high",
                "timestamp": "2025-08-12T09:30:00Z"
            }
        ]
    }
    
    return overview

@app.get("/api/v1/cloud-security/overview")
async def get_cloud_security_overview(token: str = Depends(security)):
    """Get cloud security overview"""
    user = verify_token(token.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Mock cloud security data
    overview = {
        "aws": {
            "status": "secure",
            "resources": 45,
            "compliance_score": 95
        },
        "azure": {
            "status": "warning",
            "resources": 32,
            "compliance_score": 87
        },
        "gcp": {
            "status": "secure",
            "resources": 28,
            "compliance_score": 92
        }
    }
    
    return overview

if __name__ == "__main__":
    print("🚀 Starting CyberShield Backend...")
    print("📚 API Documentation: http://localhost:8000/docs")
    print("🔍 Health Check: http://localhost:8000/health")
    
    uvicorn.run(
        "main-simple:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    ) 