from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.incident import Incident
from app.models.phishing import EmailAnalysis
from app.schemas.user import (
    UserDashboardResponse, UserIncidentResponse, UserTrainingResponse,
    UserProfileResponse, SecurityTipsResponse
)

router = APIRouter()

@router.get("/dashboard", response_model=UserDashboardResponse)
async def get_user_dashboard(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get user dashboard overview"""
    
    # Get user's incidents
    user_incidents = await Incident.get_by_user(db, current_user.id)
    open_incidents = await Incident.get_by_user_and_status(db, current_user.id, "open")
    resolved_incidents = await Incident.get_by_user_and_status(db, current_user.id, "resolved")
    
    # Get security alerts for user
    security_alerts = await get_user_security_alerts(db, current_user.id)
    
    # Get training progress
    training_progress = await get_user_training_progress(db, current_user.id)
    
    return {
        "my_incidents": {
            "total": len(user_incidents),
            "open": len(open_incidents),
            "resolved": len(resolved_incidents),
            "recent": user_incidents[:5]  # Last 5 incidents
        },
        "security_alerts": {
            "total": len(security_alerts),
            "high_priority": len([a for a in security_alerts if a.get("priority") == "high"]),
            "recent": security_alerts[:5]  # Last 5 alerts
        },
        "training_progress": {
            "completed_modules": training_progress.get("completed", 8),
            "total_modules": training_progress.get("total", 12),
            "next_training": training_progress.get("next_training", "2024-01-20T10:00:00Z"),
            "score": training_progress.get("score", 85)
        },
        "quick_actions": {
            "report_incident": True,
            "request_access": True,
            "view_policies": True
        }
    }

@router.get("/incidents", response_model=List[UserIncidentResponse])
async def get_user_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get user's incidents"""
    incidents = await Incident.get_by_user_with_filters(
        db, current_user.id, skip=skip, limit=limit, status=status
    )
    return incidents

@router.post("/incidents", response_model=UserIncidentResponse)
async def create_user_incident(
    incident_data: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new incident report"""
    incident_data["reported_by"] = current_user.id
    incident_data["assigned_to"] = current_user.id  # Self-assign initially
    
    new_incident = await Incident.create_incident(db, **incident_data)
    return new_incident

@router.get("/incidents/{incident_id}", response_model=UserIncidentResponse)
async def get_user_incident(
    incident_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get specific incident for user"""
    incident = await Incident.get_by_id_and_user(db, incident_id, current_user.id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    return incident

@router.put("/incidents/{incident_id}")
async def update_user_incident(
    incident_id: int,
    update_data: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update user's incident"""
    incident = await Incident.get_by_id_and_user(db, incident_id, current_user.id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    updated_incident = await incident.update(db, **update_data)
    return updated_incident

@router.get("/training", response_model=UserTrainingResponse)
async def get_user_training(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get user's training progress"""
    training_progress = await get_user_training_progress(db, current_user.id)
    
    return {
        "progress": {
            "completed_modules": training_progress.get("completed", 8),
            "total_modules": training_progress.get("total", 12),
            "score": training_progress.get("score", 85),
            "next_training": training_progress.get("next_training", "2024-01-20T10:00:00Z")
        },
        "modules": [
            {
                "id": 1,
                "title": "Phishing Awareness",
                "description": "Learn to identify phishing emails",
                "completed": True,
                "score": 95
            },
            {
                "id": 2,
                "title": "Password Security",
                "description": "Best practices for password management",
                "completed": True,
                "score": 88
            },
            {
                "id": 3,
                "title": "Social Engineering",
                "description": "Recognize social engineering attacks",
                "completed": False,
                "score": 0
            }
        ]
    }

@router.post("/training/{module_id}/complete")
async def complete_training_module(
    module_id: int,
    score: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Mark training module as completed"""
    # Placeholder for training completion logic
    return {"message": "Training module completed", "score": score}

@router.get("/profile", response_model=UserProfileResponse)
async def get_user_profile(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get user profile information"""
    return {
        "id": current_user.id,
        "email": current_user.email,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "department": current_user.department,
        "phone": current_user.phone,
        "is_active": current_user.is_active,
        "is_verified": current_user.is_verified,
        "last_login": current_user.last_login,
        "created_at": current_user.created_at,
        "two_factor_enabled": current_user.two_factor_enabled
    }

@router.put("/profile")
async def update_user_profile(
    profile_data: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update user profile"""
    # Remove sensitive fields that shouldn't be updated via this endpoint
    sensitive_fields = ["role", "is_active", "is_verified", "two_factor_secret"]
    for field in sensitive_fields:
        profile_data.pop(field, None)
    
    updated_user = await current_user.update(db, **profile_data)
    return updated_user

@router.get("/security-tips", response_model=List[SecurityTipsResponse])
async def get_security_tips(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get security tips for user"""
    tips = [
        {
            "id": 1,
            "title": "Strong Password Creation",
            "content": "Use a combination of uppercase, lowercase, numbers, and special characters.",
            "category": "password_security",
            "priority": "high"
        },
        {
            "id": 2,
            "title": "Phishing Email Detection",
            "content": "Check sender addresses carefully and never click suspicious links.",
            "category": "phishing_awareness",
            "priority": "high"
        },
        {
            "id": 3,
            "title": "Two-Factor Authentication",
            "content": "Enable 2FA on all your accounts for additional security.",
            "category": "account_security",
            "priority": "medium"
        },
        {
            "id": 4,
            "title": "Safe Browsing Habits",
            "content": "Only visit trusted websites and avoid downloading files from unknown sources.",
            "category": "browsing_security",
            "priority": "medium"
        }
    ]
    
    return tips

@router.post("/request-access")
async def request_system_access(
    request_data: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Request access to systems or resources"""
    request_data["requested_by"] = current_user.id
    request_data["status"] = "pending"
    
    # Placeholder for access request logic
    return {"message": "Access request submitted successfully", "request_id": "req_12345"}

@router.get("/alerts")
async def get_user_alerts(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get security alerts relevant to user"""
    alerts = await get_user_security_alerts(db, current_user.id)
    return {"alerts": alerts, "total": len(alerts)}

async def get_user_security_alerts(db: AsyncSession, user_id: int) -> List[Dict[str, Any]]:
    """Get security alerts for specific user"""
    # Placeholder for user-specific alerts
    return [
        {
            "id": 1,
            "title": "Phishing Email Detected",
            "description": "A suspicious email was detected in your inbox",
            "priority": "high",
            "created_at": datetime.utcnow().isoformat(),
            "action_required": True
        },
        {
            "id": 2,
            "title": "Password Policy Update",
            "description": "Your password will expire in 7 days",
            "priority": "medium",
            "created_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
            "action_required": True
        }
    ]

async def get_user_training_progress(db: AsyncSession, user_id: int) -> Dict[str, Any]:
    """Get user's training progress"""
    # Placeholder for training progress
    return {
        "completed": 8,
        "total": 12,
        "score": 85,
        "next_training": "2024-01-20T10:00:00Z"
    } 