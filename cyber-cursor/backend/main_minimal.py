from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from datetime import datetime
import os

# Pydantic models
class HealthResponse(BaseModel):
    status: str
    message: str
    timestamp: str

class User(BaseModel):
    id: int
    email: str
    username: str
    role: str

class SecurityMetrics(BaseModel):
    threats_blocked: int
    vulnerabilities_found: int
    incidents_resolved: int
    security_score: float

# Create FastAPI app
app = FastAPI(
    title="CyberShield API",
    description="Comprehensive cybersecurity platform API",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Sample data
users = [
    {"id": 1, "email": "admin@cybershield.com", "username": "admin", "role": "admin"},
    {"id": 2, "email": "user@cybershield.com", "username": "user", "role": "user"}
]

security_metrics = {
    "threats_blocked": 1250,
    "vulnerabilities_found": 45,
    "incidents_resolved": 12,
    "security_score": 8.5
}

# Routes
@app.get("/")
async def root():
    return {"message": "CyberShield API is running!"}

@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="healthy",
        message="CyberShield API is operational",
        timestamp=datetime.now().isoformat()
    )

@app.get("/api/v1/users", response_model=list[User])
async def get_users():
    return users

@app.get("/api/v1/security/metrics", response_model=SecurityMetrics)
async def get_security_metrics():
    return security_metrics

@app.get("/api/v1/sast/scans")
async def get_sast_scans():
    return [
        {
            "id": "1",
            "project_name": "Sample Project",
            "status": "completed",
            "start_time": "2024-01-01T10:00:00Z",
            "end_time": "2024-01-01T10:30:00Z",
            "total_vulnerabilities": 5,
            "critical_count": 1,
            "high_count": 2,
            "medium_count": 1,
            "low_count": 1,
            "scan_duration": 1800,
            "created_at": "2024-01-01T10:00:00Z"
        }
    ]

@app.get("/api/v1/sast/summary")
async def get_sast_summary():
    return {
        "total_scans": 10,
        "total_vulnerabilities": 25,
        "critical_count": 3,
        "high_count": 8,
        "medium_count": 10,
        "low_count": 4,
        "average_risk_score": 7.2,
        "most_common_vulnerabilities": [
            {"type": "SQL Injection", "count": 5},
            {"type": "XSS", "count": 3},
            {"type": "CSRF", "count": 2}
        ],
        "scan_trends": [
            {"date": "2024-01-01", "scans": 2, "vulnerabilities": 5},
            {"date": "2024-01-02", "scans": 3, "vulnerabilities": 8}
        ]
    }

@app.post("/api/v1/sast/scan/trigger")
async def trigger_sast_scan():
    return {"id": "new-scan-id", "status": "triggered", "message": "Scan started successfully"}

@app.post("/api/v1/sast/scan/upload")
async def upload_and_scan():
    return {"id": "upload-scan-id", "status": "uploaded", "message": "File uploaded and scan started"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000) 