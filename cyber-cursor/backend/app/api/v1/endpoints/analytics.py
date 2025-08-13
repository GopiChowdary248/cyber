from fastapi import APIRouter, Depends, HTTPException, Query, Body
from typing import List, Dict, Any, Optional
import structlog
from datetime import datetime, timedelta

from app.services.analytics_service import analytics_service, TimeRange
from app.models.user import User
from app.core.database import get_db
from app.core.security import get_current_user

logger = structlog.get_logger()
router = APIRouter()

@router.get("/dashboard")
async def get_dashboard_overview(
    time_range: str = Query("7d", description="Time range for analytics"),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive dashboard overview"""
    try:
        dashboard_data = await analytics_service.get_dashboard_overview(current_user.id, get_db())
        return {
            "success": True,
            "data": dashboard_data,
            "time_range": time_range,
            "generated_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error("Failed to get dashboard overview", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get dashboard data")

@router.get("/trends/{metric}")
async def get_trend_analysis(
    metric: str,
    time_range: TimeRange = Query(TimeRange.DAY, description="Time range for trend analysis"),
    filters: Dict[str, Any] = Body({}),
    current_user: User = Depends(get_current_user)
):
    """Get trend analysis for a specific metric"""
    try:
        trend_data = await analytics_service.get_trend_analysis(metric, time_range, filters, get_db())
        return {
            "success": True,
            "data": trend_data,
            "metric": metric,
            "time_range": time_range.value
        }
    except Exception as e:
        logger.error("Failed to get trend analysis", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get trend analysis")

@router.post("/custom-dashboard")
async def create_custom_dashboard(
    dashboard_config: Dict[str, Any] = Body(...),
    current_user: User = Depends(get_current_user)
):
    """Create a custom dashboard"""
    try:
        dashboard_data = await analytics_service.get_custom_dashboard(dashboard_config, current_user.id, get_db())
        return {
            "success": True,
            "data": dashboard_data
        }
    except Exception as e:
        logger.error("Failed to create custom dashboard", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create custom dashboard")

@router.get("/metrics/incidents")
async def get_incident_metrics(
    time_range: str = Query("30d", description="Time range for metrics"),
    current_user: User = Depends(get_current_user)
):
    """Get incident-related metrics"""
    try:
        # This would call the analytics service to get incident metrics
        metrics = {
            "total_incidents": 150,
            "resolved_incidents": 120,
            "open_incidents": 30,
            "avg_resolution_time": 4.5,
            "severity_distribution": {
                "critical": 5,
                "high": 25,
                "medium": 80,
                "low": 40
            },
            "trend_data": [
                {"date": "2024-01-01", "count": 5},
                {"date": "2024-01-02", "count": 8},
                {"date": "2024-01-03", "count": 3}
            ]
        }
        
        return {
            "success": True,
            "data": metrics,
            "time_range": time_range
        }
    except Exception as e:
        logger.error("Failed to get incident metrics", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get incident metrics")

@router.get("/metrics/security")
async def get_security_metrics(
    time_range: str = Query("30d", description="Time range for metrics"),
    current_user: User = Depends(get_current_user)
):
    """Get security-related metrics"""
    try:
        metrics = {
            "security_score": 85.5,
            "threats_detected": 45,
            "vulnerabilities_found": 12,
            "patches_applied": 38,
            "security_events": 156,
            "risk_level": "medium"
        }
        
        return {
            "success": True,
            "data": metrics,
            "time_range": time_range
        }
    except Exception as e:
        logger.error("Failed to get security metrics", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get security metrics")

@router.get("/metrics/compliance")
async def get_compliance_metrics(
    time_range: str = Query("30d", description="Time range for metrics"),
    current_user: User = Depends(get_current_user)
):
    """Get compliance-related metrics"""
    try:
        metrics = {
            "compliance_score": 92.3,
            "policies_compliant": 45,
            "policies_violated": 3,
            "audit_findings": 8,
            "remediation_progress": 85.5
        }
        
        return {
            "success": True,
            "data": metrics,
            "time_range": time_range
        }
    except Exception as e:
        logger.error("Failed to get compliance metrics", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get compliance metrics")

@router.get("/reports/security")
async def get_security_report(
    time_range: str = Query("30d", description="Time range for report"),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive security report"""
    try:
        report = {
            "summary": {
                "total_incidents": 150,
                "resolved_incidents": 120,
                "security_score": 85.5,
                "compliance_score": 92.3
            },
            "trends": {
                "incident_trend": "decreasing",
                "security_score_trend": "improving",
                "compliance_trend": "stable"
            },
            "top_threats": [
                {"type": "phishing", "count": 45},
                {"type": "malware", "count": 32},
                {"type": "unauthorized_access", "count": 28}
            ],
            "recommendations": [
                "Implement additional phishing training",
                "Update endpoint protection",
                "Review access controls"
            ]
        }
        
        return {
            "success": True,
            "data": report,
            "time_range": time_range,
            "generated_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error("Failed to get security report", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get security report") 