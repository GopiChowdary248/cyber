from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
import uvicorn
import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import json

# Create FastAPI application
app = FastAPI(
    title="CyberShield Demo API",
    description="Comprehensive Cybersecurity Platform with SAST, DAST, RASP, and Cloud Security",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer(auto_error=False)

# Mock data for demonstration
MOCK_SAST_DATA = {
    "projects": [
        {
            "id": "1",
            "name": "Web Application",
            "language": "JavaScript",
            "last_scan": "2024-01-15T10:30:00Z",
            "vulnerabilities": 12,
            "security_hotspots": 5,
            "quality_gate": "PASSED"
        },
        {
            "id": "2", 
            "name": "Mobile App",
            "language": "Swift",
            "last_scan": "2024-01-14T15:45:00Z",
            "vulnerabilities": 8,
            "security_hotspots": 3,
            "quality_gate": "WARNING"
        }
    ],
    "scans": [
        {
            "id": "scan-1",
            "project_id": "1",
            "status": "COMPLETED",
            "started_at": "2024-01-15T09:00:00Z",
            "completed_at": "2024-01-15T10:30:00Z",
            "vulnerabilities_found": 12,
            "security_hotspots": 5
        }
    ],
    "vulnerabilities": [
        {
            "id": "vuln-1",
            "project_id": "1",
            "severity": "HIGH",
            "type": "SQL_INJECTION",
            "file": "src/database.js",
            "line": 45,
            "description": "SQL injection vulnerability in user input",
            "cwe": "CWE-89",
            "status": "OPEN"
        }
    ]
}

MOCK_DAST_DATA = {
    "projects": [
        {
            "id": "1",
            "name": "Web Application",
            "url": "https://example.com",
            "last_scan": "2024-01-15T10:30:00Z",
            "vulnerabilities": 8,
            "status": "ACTIVE"
        }
    ],
    "scans": [
        {
            "id": "dast-scan-1",
            "project_id": "1",
            "status": "RUNNING",
            "started_at": "2024-01-15T09:00:00Z",
            "target_url": "https://example.com",
            "scan_type": "FULL_SCAN",
            "progress": 65
        }
    ],
    "vulnerabilities": [
        {
            "id": "dast-vuln-1",
            "project_id": "1",
            "severity": "CRITICAL",
            "type": "XSS",
            "url": "https://example.com/search",
            "parameter": "q",
            "description": "Cross-site scripting vulnerability",
            "cwe": "CWE-79",
            "status": "OPEN"
        }
    ],
    "payloads": [
        {
            "id": "payload-1",
            "name": "XSS Test Payload",
            "type": "XSS",
            "payload": "<script>alert('XSS')</script>",
            "description": "Basic XSS test payload"
        }
    ]
}

# Authentication endpoints
@app.post("/api/v1/auth/login")
async def login(credentials: dict):
    """Mock login endpoint"""
    email = credentials.get("email", "")
    password = credentials.get("password", "")
    
    if password == "password":  # Demo password
        return {
            "access_token": "demo_token_12345",
            "token_type": "bearer",
            "user": {
                "id": 1,
                "email": email,
                "username": email.split("@")[0],
                "role": "admin" if "admin" in email else "user"
            }
        }
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/api/v1/auth/me")
async def get_current_user():
    """Mock current user endpoint"""
    return {
        "id": 1,
        "email": "admin@cybershield.com",
        "username": "admin",
        "role": "admin"
    }

# SAST Endpoints
@app.get("/api/v1/sast/projects")
async def get_sast_projects():
    """Get all SAST projects"""
    return MOCK_SAST_DATA["projects"]

@app.get("/api/v1/sast/projects/{project_id}")
async def get_sast_project(project_id: str):
    """Get specific SAST project"""
    project = next((p for p in MOCK_SAST_DATA["projects"] if p["id"] == project_id), None)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

@app.get("/api/v1/sast/scans")
async def get_sast_scans():
    """Get all SAST scans"""
    return MOCK_SAST_DATA["scans"]

@app.get("/api/v1/sast/scans/{scan_id}")
async def get_sast_scan(scan_id: str):
    """Get specific SAST scan"""
    scan = next((s for s in MOCK_SAST_DATA["scans"] if s["id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.post("/api/v1/sast/scans")
async def create_sast_scan(scan_data: dict):
    """Create new SAST scan"""
    new_scan = {
        "id": f"scan-{len(MOCK_SAST_DATA['scans']) + 1}",
        "project_id": scan_data.get("project_id"),
        "status": "QUEUED",
        "started_at": datetime.now().isoformat(),
        "vulnerabilities_found": 0,
        "security_hotspots": 0
    }
    MOCK_SAST_DATA["scans"].append(new_scan)
    return new_scan

@app.get("/api/v1/sast/vulnerabilities")
async def get_sast_vulnerabilities():
    """Get all SAST vulnerabilities"""
    return MOCK_SAST_DATA["vulnerabilities"]

@app.get("/api/v1/sast/dashboard")
async def get_sast_dashboard():
    """Get SAST dashboard overview"""
    total_projects = len(MOCK_SAST_DATA["projects"])
    total_vulnerabilities = sum(p["vulnerabilities"] for p in MOCK_SAST_DATA["projects"])
    total_hotspots = sum(p["security_hotspots"] for p in MOCK_SAST_DATA["projects"])
    
    return {
        "total_projects": total_projects,
        "total_vulnerabilities": total_vulnerabilities,
        "total_security_hotspots": total_hotspots,
        "projects_by_language": {
            "JavaScript": 1,
            "Swift": 1
        },
        "vulnerabilities_by_severity": {
            "HIGH": 8,
            "MEDIUM": 3,
            "LOW": 1
        }
    }

# DAST Endpoints
@app.get("/api/v1/dast/projects")
async def get_dast_projects():
    """Get all DAST projects"""
    return MOCK_DAST_DATA["projects"]

@app.get("/api/v1/dast/projects/{project_id}")
async def get_dast_project(project_id: str):
    """Get specific DAST project"""
    project = next((p for p in MOCK_DAST_DATA["projects"] if p["id"] == project_id), None)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

@app.get("/api/v1/dast/scans")
async def get_dast_scans():
    """Get all DAST scans"""
    return MOCK_DAST_DATA["scans"]

@app.get("/api/v1/dast/scans/{scan_id}")
async def get_dast_scan(scan_id: str):
    """Get specific DAST scan"""
    scan = next((s for s in MOCK_DAST_DATA["scans"] if s["id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.post("/api/v1/dast/scans")
async def create_dast_scan(scan_data: dict):
    """Create new DAST scan"""
    new_scan = {
        "id": f"dast-scan-{len(MOCK_DAST_DATA['scans']) + 1}",
        "project_id": scan_data.get("project_id"),
        "status": "QUEUED",
        "started_at": datetime.now().isoformat(),
        "target_url": scan_data.get("target_url"),
        "scan_type": scan_data.get("scan_type", "FULL_SCAN"),
        "progress": 0
    }
    MOCK_DAST_DATA["scans"].append(new_scan)
    return new_scan

@app.get("/api/v1/dast/vulnerabilities")
async def get_dast_vulnerabilities():
    """Get all DAST vulnerabilities"""
    return MOCK_DAST_DATA["vulnerabilities"]

@app.get("/api/v1/dast/payloads")
async def get_dast_payloads():
    """Get all DAST test payloads"""
    return MOCK_DAST_DATA["payloads"]

@app.get("/api/v1/dast/overview")
async def get_dast_overview():
    """Get DAST overview"""
    total_projects = len(MOCK_DAST_DATA["projects"])
    total_vulnerabilities = sum(p["vulnerabilities"] for p in MOCK_DAST_DATA["projects"])
    active_scans = len([s for s in MOCK_DAST_DATA["scans"] if s["status"] == "RUNNING"])
    
    return {
        "total_projects": total_projects,
        "total_vulnerabilities": total_vulnerabilities,
        "active_scans": active_scans,
        "vulnerabilities_by_severity": {
            "CRITICAL": 3,
            "HIGH": 3,
            "MEDIUM": 2
        },
        "scan_types": ["FULL_SCAN", "QUICK_SCAN", "CUSTOM_SCAN"]
    }

# Dashboard endpoints
@app.get("/api/v1/dashboard/overview")
async def get_dashboard_overview():
    """Get main dashboard overview"""
    return {
        "sast": {
            "total_projects": len(MOCK_SAST_DATA["projects"]),
            "total_vulnerabilities": sum(p["vulnerabilities"] for p in MOCK_SAST_DATA["projects"]),
            "quality_gate_passed": len([p for p in MOCK_SAST_DATA["projects"] if p["quality_gate"] == "PASSED"])
        },
        "dast": {
            "total_projects": len(MOCK_DAST_DATA["projects"]),
            "total_vulnerabilities": sum(p["vulnerabilities"] for p in MOCK_DAST_DATA["projects"]),
            "active_scans": len([s for s in MOCK_DAST_DATA["scans"] if s["status"] == "RUNNING"])
        },
        "overall_security_score": 78,
        "recent_activities": [
            {
                "type": "SAST_SCAN_COMPLETED",
                "project": "Web Application",
                "timestamp": "2024-01-15T10:30:00Z"
            },
            {
                "type": "DAST_SCAN_STARTED",
                "project": "Web Application",
                "timestamp": "2024-01-15T09:00:00Z"
            }
        ]
    }

# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    print("🚀 Starting CyberShield Demo API...")
    print("📚 API Documentation: http://localhost:8000/docs")
    print("🔍 ReDoc Documentation: http://localhost:8000/redoc")
    print("🌐 Health Check: http://localhost:8000/health")
    
    uvicorn.run(
        "main_simple_demo:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
