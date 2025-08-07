from fastapi import APIRouter, Depends, HTTPException, Query, Body, Request
from typing import List, Dict, Any, Optional
import structlog
from datetime import datetime, timedelta

from app.services.security_service import security_service, MFAMethod
from app.models.user import User
from app.core.database import get_db
from app.core.security import get_current_user

logger = structlog.get_logger()
router = APIRouter()

@router.post("/mfa/setup")
async def setup_mfa(
    method: MFAMethod = Body(..., embed=True),
    current_user: User = Depends(get_current_user)
):
    """Setup MFA for the current user"""
    try:
        mfa_data = await security_service.setup_mfa(current_user.id, method)
        
        return {
            "success": True,
            "data": mfa_data,
            "message": f"MFA setup initiated for {method.value}"
        }
    except Exception as e:
        logger.error("Failed to setup MFA", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to setup MFA")

@router.post("/mfa/verify")
async def verify_mfa(
    method: MFAMethod = Body(..., embed=True),
    code: str = Body(..., embed=True),
    current_user: User = Depends(get_current_user)
):
    """Verify MFA code"""
    try:
        is_valid = await security_service.verify_mfa(current_user.id, method, code)
        
        if is_valid:
            return {
                "success": True,
                "message": "MFA verification successful"
            }
        else:
            raise HTTPException(status_code=400, detail="Invalid MFA code")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to verify MFA", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to verify MFA")

@router.delete("/mfa/disable")
async def disable_mfa(
    current_user: User = Depends(get_current_user)
):
    """Disable MFA for the current user"""
    try:
        success = await security_service.disable_mfa(current_user.id)
        
        if success:
            return {
                "success": True,
                "message": "MFA disabled successfully"
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to disable MFA")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to disable MFA", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to disable MFA")

@router.post("/mfa/backup-codes")
async def generate_backup_codes(
    current_user: User = Depends(get_current_user)
):
    """Generate new backup codes for MFA"""
    try:
        backup_codes = await security_service._generate_backup_codes(current_user.id)
        
        return {
            "success": True,
            "data": {"backup_codes": backup_codes},
            "message": "Backup codes generated successfully"
        }
    except Exception as e:
        logger.error("Failed to generate backup codes", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to generate backup codes")

@router.post("/login")
async def authenticate_user(
    user_id: int = Body(..., embed=True),
    password: str = Body(..., embed=True),
    request: Request = None
):
    """Authenticate user with enhanced security"""
    try:
        # Get client IP and user agent
        client_ip = request.client.host if request else "unknown"
        user_agent = request.headers.get("user-agent", "unknown") if request else "unknown"
        
        auth_result = await security_service.authenticate_user(user_id, password, client_ip, user_agent)
        
        if auth_result["success"]:
            return {
                "success": True,
                "session_token": auth_result["session_token"],
                "mfa_required": auth_result["mfa_required"],
                "message": "Authentication successful"
            }
        else:
            raise HTTPException(status_code=401, detail=auth_result["error"])
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Authentication failed", error=str(e))
        raise HTTPException(status_code=500, detail="Authentication failed")

@router.post("/logout")
async def logout_user(
    session_token: str = Body(..., embed=True),
    current_user: User = Depends(get_current_user)
):
    """Logout user and invalidate session"""
    try:
        await security_service.logout_user(session_token, current_user.id)
        
        return {
            "success": True,
            "message": "Logout successful"
        }
    except Exception as e:
        logger.error("Failed to logout user", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to logout")

@router.get("/session/validate")
async def validate_session(
    session_token: str = Query(..., description="Session token"),
    request: Request = None
):
    """Validate session token"""
    try:
        client_ip = request.client.host if request else "unknown"
        user_id = await security_service.validate_session(session_token, client_ip)
        
        if user_id:
            return {
                "success": True,
                "user_id": user_id,
                "valid": True
            }
        else:
            return {
                "success": True,
                "valid": False,
                "message": "Invalid or expired session"
            }
            
    except Exception as e:
        logger.error("Failed to validate session", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to validate session")

@router.get("/audit/events")
async def get_security_events(
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    time_range: str = Query("24h", description="Time range for events"),
    limit: int = Query(100, ge=1, le=1000, description="Number of events to return"),
    current_user: User = Depends(get_current_user)
):
    """Get security audit events"""
    try:
        # Filter events based on parameters
        events = security_service.security_events
        
        # Filter by user if specified
        if user_id:
            events = [e for e in events if e["user_id"] == user_id]
        
        # Filter by event type if specified
        if event_type:
            events = [e for e in events if e["event_type"] == event_type]
        
        # Filter by time range
        if time_range == "24h":
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
        elif time_range == "7d":
            cutoff_time = datetime.utcnow() - timedelta(days=7)
        elif time_range == "30d":
            cutoff_time = datetime.utcnow() - timedelta(days=30)
        else:
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
        
        events = [
            e for e in events 
            if datetime.fromisoformat(e["timestamp"]) >= cutoff_time
        ]
        
        # Sort by timestamp (newest first) and limit
        events.sort(key=lambda x: x["timestamp"], reverse=True)
        events = events[:limit]
        
        return {
            "success": True,
            "data": events,
            "total": len(events),
            "time_range": time_range
        }
    except Exception as e:
        logger.error("Failed to get security events", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get security events")

@router.get("/audit/report")
async def get_security_report(
    user_id: Optional[int] = Query(None, description="User ID for report"),
    time_range: str = Query("24h", description="Time range for report"),
    current_user: User = Depends(get_current_user)
):
    """Get security audit report"""
    try:
        report = await security_service.get_security_report(user_id, time_range)
        
        return {
            "success": True,
            "data": report,
            "time_range": time_range
        }
    except Exception as e:
        logger.error("Failed to get security report", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get security report")

@router.get("/account/status")
async def get_account_security_status(
    current_user: User = Depends(get_current_user)
):
    """Get account security status"""
    try:
        # Check if account is locked
        is_locked = await security_service._is_account_locked(current_user.id)
        
        # Check MFA status
        mfa_enabled = current_user.id in security_service.mfa_secrets
        
        # Get recent failed attempts
        failed_attempts = security_service.failed_login_attempts.get(current_user.id, [])
        recent_failed_attempts = len([
            a for a in failed_attempts 
            if datetime.utcnow() - a < timedelta(hours=1)
        ])
        
        # Get recent security events
        recent_events = [
            e for e in security_service.security_events
            if e["user_id"] == current_user.id and
            datetime.fromisoformat(e["timestamp"]) >= datetime.utcnow() - timedelta(hours=24)
        ]
        
        status = {
            "account_locked": is_locked,
            "mfa_enabled": mfa_enabled,
            "recent_failed_attempts": recent_failed_attempts,
            "recent_security_events": len(recent_events),
            "security_score": 85,  # Mock score
            "last_login": None,  # Would be populated from actual data
            "suspicious_activity_detected": current_user.id in security_service.suspicious_activities
        }
        
        return {
            "success": True,
            "data": status
        }
    except Exception as e:
        logger.error("Failed to get account security status", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get account security status")

@router.post("/account/unlock")
async def unlock_account(
    user_id: int = Body(..., embed=True),
    current_user: User = Depends(get_current_user)
):
    """Unlock user account (admin only)"""
    try:
        # Check if current user is admin
        if current_user.role != "admin":
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        
        # Remove from lockouts
        if user_id in security_service.account_lockouts:
            del security_service.account_lockouts[user_id]
        
        # Clear failed attempts
        if user_id in security_service.failed_login_attempts:
            del security_service.failed_login_attempts[user_id]
        
        # Log security event
        await security_service._log_security_event(
            security_service.SecurityEventType.ACCOUNT_UNLOCKED,
            user_id,
            {"unlocked_by": current_user.id}
        )
        
        return {
            "success": True,
            "message": f"Account {user_id} unlocked successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to unlock account", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to unlock account")

@router.get("/threats/suspicious-activity")
async def get_suspicious_activities(
    current_user: User = Depends(get_current_user)
):
    """Get suspicious activities (admin only)"""
    try:
        # Check if current user is admin
        if current_user.role != "admin":
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        
        suspicious_activities = []
        for user_id, activities in security_service.suspicious_activities.items():
            for activity in activities:
                suspicious_activities.append({
                    "user_id": user_id,
                    "timestamp": activity["timestamp"].isoformat(),
                    "event_type": activity["event_type"],
                    "details": activity["details"]
                })
        
        # Sort by timestamp (newest first)
        suspicious_activities.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return {
            "success": True,
            "data": suspicious_activities,
            "total": len(suspicious_activities)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get suspicious activities", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get suspicious activities")

@router.post("/password/validate")
async def validate_password_strength(
    password: str = Body(..., embed=True)
):
    """Validate password strength against security policy"""
    try:
        policy = security_service.password_policy
        errors = []
        
        # Check minimum length
        if len(password) < policy["min_length"]:
            errors.append(f"Password must be at least {policy['min_length']} characters long")
        
        # Check for uppercase
        if policy["require_uppercase"] and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        # Check for lowercase
        if policy["require_lowercase"] and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        # Check for numbers
        if policy["require_numbers"] and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one number")
        
        # Check for special characters
        if policy["require_special"] and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one special character")
        
        is_valid = len(errors) == 0
        strength_score = 0
        
        if is_valid:
            # Calculate strength score (0-100)
            length_score = min(len(password) * 4, 40)  # Up to 40 points for length
            complexity_score = 0
            if any(c.isupper() for c in password):
                complexity_score += 15
            if any(c.islower() for c in password):
                complexity_score += 15
            if any(c.isdigit() for c in password):
                complexity_score += 15
            if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
                complexity_score += 15
            
            strength_score = length_score + complexity_score
        
        return {
            "success": True,
            "data": {
                "is_valid": is_valid,
                "errors": errors,
                "strength_score": strength_score,
                "strength_level": "weak" if strength_score < 50 else "medium" if strength_score < 80 else "strong"
            }
        }
    except Exception as e:
        logger.error("Failed to validate password strength", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to validate password strength") 

@router.get("/summary")
async def get_security_summary(
    current_user: User = Depends(get_current_user)
):
    """Get security summary dashboard data"""
    try:
        # Mock security summary data
        summary = {
            "threats_blocked": 1247,
            "vulnerabilities": 23,
            "incidents_resolved": 142,
            "security_score": 87,
            "active_threats": 3,
            "critical_alerts": 1,
            "system_status": "healthy",
            "last_scan": datetime.utcnow().isoformat(),
            "security_trends": {
                "threats_trend": "decreasing",
                "vulnerabilities_trend": "stable",
                "incidents_trend": "decreasing"
            },
            "quick_stats": {
                "sast_scans": 45,
                "dast_scans": 32,
                "rasp_events": 156,
                "cloud_misconfigs": 12
            }
        }
        
        return {
            "success": True,
            "data": summary
        }
    except Exception as e:
        logger.error("Failed to get security summary", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get security summary")

@router.get("/sast/results")
async def get_sast_results(
    current_user: User = Depends(get_current_user)
):
    """Get SAST scan results"""
    try:
        # Mock SAST results
        sast_results = {
            "total_scans": 45,
            "last_scan": datetime.utcnow().isoformat(),
            "vulnerabilities_found": 23,
            "critical_issues": 3,
            "high_issues": 8,
            "medium_issues": 7,
            "low_issues": 5,
            "scan_status": "completed",
            "recent_findings": [
                {
                    "id": "SAST-001",
                    "severity": "critical",
                    "type": "SQL Injection",
                    "file": "app/api/v1/endpoints/auth.py",
                    "line": 45,
                    "description": "Potential SQL injection vulnerability",
                    "status": "open"
                },
                {
                    "id": "SAST-002",
                    "severity": "high",
                    "type": "XSS",
                    "file": "frontend/src/components/Login.tsx",
                    "line": 23,
                    "description": "Cross-site scripting vulnerability",
                    "status": "open"
                }
            ],
            "scan_history": [
                {
                    "scan_id": "SAST-2024-001",
                    "timestamp": (datetime.utcnow() - timedelta(days=1)).isoformat(),
                    "vulnerabilities": 25,
                    "status": "completed"
                },
                {
                    "scan_id": "SAST-2024-002",
                    "timestamp": (datetime.utcnow() - timedelta(days=3)).isoformat(),
                    "vulnerabilities": 28,
                    "status": "completed"
                }
            ]
        }
        
        return {
            "success": True,
            "data": sast_results
        }
    except Exception as e:
        logger.error("Failed to get SAST results", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get SAST results")

@router.get("/dast/results")
async def get_dast_results(
    current_user: User = Depends(get_current_user)
):
    """Get DAST scan results"""
    try:
        # Mock DAST results
        dast_results = {
            "total_scans": 32,
            "last_scan": datetime.utcnow().isoformat(),
            "vulnerabilities_found": 15,
            "critical_issues": 2,
            "high_issues": 5,
            "medium_issues": 6,
            "low_issues": 2,
            "scan_status": "completed",
            "target_urls": [
                "https://app.example.com",
                "https://api.example.com",
                "https://admin.example.com"
            ],
            "recent_findings": [
                {
                    "id": "DAST-001",
                    "severity": "critical",
                    "type": "Authentication Bypass",
                    "url": "https://app.example.com/login",
                    "description": "Authentication can be bypassed",
                    "status": "open"
                },
                {
                    "id": "DAST-002",
                    "severity": "high",
                    "type": "CSRF",
                    "url": "https://app.example.com/profile",
                    "description": "Cross-site request forgery vulnerability",
                    "status": "open"
                }
            ],
            "scan_history": [
                {
                    "scan_id": "DAST-2024-001",
                    "timestamp": (datetime.utcnow() - timedelta(days=2)).isoformat(),
                    "vulnerabilities": 18,
                    "status": "completed"
                },
                {
                    "scan_id": "DAST-2024-002",
                    "timestamp": (datetime.utcnow() - timedelta(days=5)).isoformat(),
                    "vulnerabilities": 22,
                    "status": "completed"
                }
            ]
        }
        
        return {
            "success": True,
            "data": dast_results
        }
    except Exception as e:
        logger.error("Failed to get DAST results", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get DAST results")

@router.get("/rasp/logs")
async def get_rasp_logs(
    current_user: User = Depends(get_current_user)
):
    """Get RASP (Runtime Application Self-Protection) logs"""
    try:
        # Mock RASP logs
        rasp_logs = {
            "total_events": 156,
            "last_event": datetime.utcnow().isoformat(),
            "events_today": 23,
            "blocked_attacks": 12,
            "suspicious_activities": 8,
            "recent_events": [
                {
                    "id": "RASP-001",
                    "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "SQL_INJECTION_ATTEMPT",
                    "severity": "high",
                    "source_ip": "192.168.1.100",
                    "endpoint": "/api/v1/users",
                    "action": "blocked",
                    "details": "SQL injection attempt detected and blocked"
                },
                {
                    "id": "RASP-002",
                    "timestamp": (datetime.utcnow() - timedelta(minutes=5)).isoformat(),
                    "event_type": "XSS_ATTEMPT",
                    "severity": "medium",
                    "source_ip": "192.168.1.101",
                    "endpoint": "/api/v1/comments",
                    "action": "blocked",
                    "details": "XSS attempt detected and blocked"
                },
                {
                    "id": "RASP-003",
                    "timestamp": (datetime.utcnow() - timedelta(minutes=10)).isoformat(),
                    "event_type": "SUSPICIOUS_ACTIVITY",
                    "severity": "low",
                    "source_ip": "192.168.1.102",
                    "endpoint": "/api/v1/auth/login",
                    "action": "monitored",
                    "details": "Multiple failed login attempts detected"
                }
            ],
            "event_types": {
                "SQL_INJECTION_ATTEMPT": 5,
                "XSS_ATTEMPT": 3,
                "PATH_TRAVERSAL": 2,
                "SUSPICIOUS_ACTIVITY": 8,
                "AUTHENTICATION_FAILURE": 4,
                "RATE_LIMIT_EXCEEDED": 1
            },
            "top_source_ips": [
                {"ip": "192.168.1.100", "events": 8},
                {"ip": "192.168.1.101", "events": 5},
                {"ip": "192.168.1.102", "events": 3}
            ]
        }
        
        return {
            "success": True,
            "data": rasp_logs
        }
    except Exception as e:
        logger.error("Failed to get RASP logs", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get RASP logs") 