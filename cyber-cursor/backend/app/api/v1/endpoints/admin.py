from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_user, require_admin
from app.models.user import User
from app.models.incident import Incident
from app.models.cloud_security import CloudMisconfiguration, CloudScan
from app.models.phishing import EmailAnalysis
from app.schemas.admin import (
    AdminDashboardResponse, SystemHealthResponse, UserManagementResponse,
    SecurityMetricsResponse, InfrastructureResponse
)

router = APIRouter()

@router.get("/dashboard", response_model=AdminDashboardResponse)
async def get_admin_dashboard(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get admin dashboard overview"""
    
    # Get system overview
    total_users = await User.count_users(db)
    active_sessions = await User.count_active_sessions(db)
    
    # Get security metrics
    total_incidents = await Incident.count_incidents(db)
    critical_incidents = await Incident.count_by_severity(db, "critical")
    failed_logins = await User.count_failed_logins(db, hours=24)
    
    # Get infrastructure metrics
    cloud_misconfigs = await CloudMisconfiguration.count_misconfigurations(db)
    cloud_scans = await CloudScan.count_scans(db)
    
    return {
        "system_overview": {
            "total_users": total_users,
            "active_sessions": active_sessions,
            "system_health": 98,  # Placeholder
            "uptime": "15 days, 7 hours",  # Placeholder
            "last_backup": "2 hours ago"  # Placeholder
        },
        "security_metrics": {
            "total_incidents": total_incidents,
            "critical_alerts": critical_incidents,
            "failed_logins": failed_logins,
            "suspicious_activities": 8,  # Placeholder
            "security_score": 87  # Placeholder
        },
        "user_management": {
            "total_users": total_users,
            "active_users": active_sessions,
            "pending_approvals": 5,  # Placeholder
            "recent_registrations": 12  # Placeholder
        },
        "infrastructure": {
            "cloud_resources": 89,  # Placeholder
            "misconfigurations": cloud_misconfigs.get("total", 0),
            "compliance_score": 92,  # Placeholder
            "backup_status": "Healthy"  # Placeholder
        }
    }

@router.get("/users", response_model=List[UserManagementResponse])
async def get_all_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    role: Optional[str] = None,
    status: Optional[str] = None,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get all users with filtering"""
    users = await User.get_all_with_filters(db, skip=skip, limit=limit, role=role, status=status)
    return users

@router.post("/users/{user_id}/approve")
async def approve_user(
    user_id: int,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Approve user registration"""
    user = await User.get_by_id(db, user_id=user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    await user.update(db, is_verified=True, is_active=True)
    return {"message": "User approved successfully"}

@router.post("/users/{user_id}/suspend")
async def suspend_user(
    user_id: int,
    reason: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Suspend user account"""
    user = await User.get_by_id(db, user_id=user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot suspend yourself"
        )
    
    await user.update(db, is_active=False)
    return {"message": "User suspended successfully"}

@router.get("/system/health", response_model=SystemHealthResponse)
async def get_system_health(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get system health metrics"""
    return {
        "database_status": "healthy",
        "redis_status": "healthy",
        "api_status": "healthy",
        "uptime": "15 days, 7 hours",
        "memory_usage": 65,
        "cpu_usage": 23,
        "disk_usage": 45,
        "active_connections": 156
    }

@router.get("/security/metrics", response_model=SecurityMetricsResponse)
async def get_security_metrics(
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get security metrics"""
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    incidents = await Incident.get_by_date_range(db, start_date, end_date)
    phishing_analyses = await EmailAnalysis.get_by_date_range(db, start_date, end_date)
    
    return {
        "incidents_by_severity": {
            "critical": incidents.get("critical", 0),
            "high": incidents.get("high", 0),
            "medium": incidents.get("medium", 0),
            "low": incidents.get("low", 0)
        },
        "phishing_detection": {
            "total_analyses": phishing_analyses.get("total", 0),
            "phishing_detected": phishing_analyses.get("phishing", 0),
            "high_threat": phishing_analyses.get("high", 0),
            "critical_threat": phishing_analyses.get("critical", 0)
        },
        "failed_logins": await User.count_failed_logins(db, hours=24),
        "suspicious_activities": 8,  # Placeholder
        "security_score": 87  # Placeholder
    }

@router.get("/infrastructure/overview", response_model=InfrastructureResponse)
async def get_infrastructure_overview(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get infrastructure overview"""
    cloud_misconfigs = await CloudMisconfiguration.count_misconfigurations(db)
    cloud_scans = await CloudScan.count_scans(db)
    
    return {
        "cloud_resources": {
            "aws": 45,  # Placeholder
            "azure": 23,  # Placeholder
            "gcp": 21  # Placeholder
        },
        "misconfigurations": {
            "total": cloud_misconfigs.get("total", 0),
            "critical": cloud_misconfigs.get("critical", 0),
            "high": cloud_misconfigs.get("high", 0),
            "medium": cloud_misconfigs.get("medium", 0)
        },
        "compliance": {
            "overall_score": 92,  # Placeholder
            "aws_compliance": 95,  # Placeholder
            "azure_compliance": 88,  # Placeholder
            "gcp_compliance": 91  # Placeholder
        },
        "backup_status": "Healthy",
        "monitoring_status": "Active"
    }

@router.post("/system/backup")
async def trigger_system_backup(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Trigger system backup"""
    # Placeholder for backup logic
    return {"message": "System backup initiated", "backup_id": "backup_12345"}

@router.get("/logs/system")
async def get_system_logs(
    level: Optional[str] = None,
    hours: int = Query(24, ge=1, le=168),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get system logs"""
    # Placeholder for log retrieval
    logs = [
        {
            "timestamp": datetime.utcnow().isoformat(),
            "level": "INFO",
            "message": "System backup completed successfully",
            "source": "backup_service"
        },
        {
            "timestamp": (datetime.utcnow() - timedelta(minutes=5)).isoformat(),
            "level": "WARNING",
            "message": "High CPU usage detected",
            "source": "monitoring_service"
        },
        {
            "timestamp": (datetime.utcnow() - timedelta(minutes=10)).isoformat(),
            "level": "ERROR",
            "message": "Failed login attempt from suspicious IP",
            "source": "auth_service"
        }
    ]
    
    return {"logs": logs, "total": len(logs)}

@router.post("/alerts/broadcast")
async def broadcast_alert(
    message: str,
    priority: str = "medium",
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Broadcast security alert to all users"""
    # Placeholder for alert broadcasting
    return {"message": "Alert broadcasted successfully", "recipients": 156} 