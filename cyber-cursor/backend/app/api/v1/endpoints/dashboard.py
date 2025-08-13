from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.incident import Incident
from app.models.cloud_security import Misconfiguration
from app.models.phishing import EmailAnalysis
from app.services.monitoring import update_incident_metrics, update_cloud_metrics, record_phishing_detection
from app.schemas.auth import User

router = APIRouter()

@router.get("/overview")
async def get_dashboard_overview(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get dashboard overview with key metrics"""
    
    # Get date range for last 30 days
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)
    
    # Incident statistics
    incident_stats = await Incident.get_stats(db)
    
    # Cloud security statistics
    cloud_misconfigs = await Misconfiguration.count_misconfigurations(db)
    cloud_scans = {"total": 0, "recent": 0}  # Placeholder until CloudScan is implemented
    
    # Phishing statistics
    phishing_analyses = await EmailAnalysis.count_analyses(db)
    high_threat_emails = await EmailAnalysis.count_by_threat_level(db, "high")
    critical_threat_emails = await EmailAnalysis.count_by_threat_level(db, "critical")
    
    # Recent activity
    recent_incidents = await Incident.get_recent(db, limit=5)
    recent_misconfigs = await Misconfiguration.get_recent(db, limit=5)
    recent_phishing = await EmailAnalysis.get_recent(db, limit=5)
    
    # Update metrics for monitoring
    update_incident_metrics("high", "phishing", incident_stats.get("high_severity", 0))
    update_incident_metrics("medium", "malware", incident_stats.get("medium_severity", 0))
    update_cloud_metrics("aws", "high", cloud_misconfigs.get("aws_high", 0))
    update_cloud_metrics("azure", "medium", cloud_misconfigs.get("azure_medium", 0))
    
    return {
        "incidents": {
            "total": incident_stats.get("total", 0),
            "active": incident_stats.get("active", 0),
            "resolved": incident_stats.get("resolved", 0),
            "high_severity": incident_stats.get("high_severity", 0),
            "critical_severity": incident_stats.get("critical_severity", 0),
            "recent": recent_incidents
        },
        "cloud_security": {
            "total_misconfigurations": cloud_misconfigs.get("total", 0),
            "high_severity": cloud_misconfigs.get("high", 0),
            "total_scans": cloud_scans.get("total", 0),
            "recent_scans": cloud_scans.get("recent", 0),
            "recent_misconfigs": recent_misconfigs
        },
        "phishing_detection": {
            "total_analyses": phishing_analyses.get("total", 0),
            "high_threat": high_threat_emails,
            "critical_threat": critical_threat_emails,
            "phishing_detected": phishing_analyses.get("phishing", 0),
            "recent_analyses": recent_phishing
        },
        "security_score": calculate_security_score(
            incident_stats, cloud_misconfigs, phishing_analyses
        )
    }

@router.get("/incidents/chart")
async def get_incidents_chart(
    days: int = 30,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get incident data for charts"""
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    # Get incidents by day
    incidents_by_day = await Incident.get_by_date_range(db, start_date, end_date)
    
    # Format for chart
    chart_data = []
    for date, count in incidents_by_day.items():
        chart_data.append({
            "date": date.strftime("%Y-%m-%d"),
            "incidents": count
        })
    
    return {
        "chart_data": chart_data,
        "total_incidents": sum(incidents_by_day.values()),
        "average_per_day": sum(incidents_by_day.values()) / len(incidents_by_day) if incidents_by_day else 0
    }

@router.get("/cloud-security/chart")
async def get_cloud_security_chart(
    days: int = 30,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get cloud security data for charts"""
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    # Get misconfigurations by provider and severity
    misconfigs_by_provider = await Misconfiguration.get_by_provider(db, start_date, end_date)
    
    return {
        "providers": misconfigs_by_provider,
        "total_misconfigs": sum(sum(provider.values()) for provider in misconfigs_by_provider.values()),
        "most_affected_provider": max(misconfigs_by_provider.keys(), 
                                    key=lambda x: sum(misconfigs_by_provider[x].values())) if misconfigs_by_provider else None
    }

@router.get("/phishing/chart")
async def get_phishing_chart(
    days: int = 30,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get phishing detection data for charts"""
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    # Get phishing analyses by threat level
    analyses_by_threat = await EmailAnalysis.get_by_threat_level(db, start_date, end_date)
    
    return {
        "threat_levels": analyses_by_threat,
        "total_analyses": sum(analyses_by_threat.values()),
        "phishing_rate": (analyses_by_threat.get("phishing", 0) / sum(analyses_by_threat.values()) * 100) if analyses_by_threat else 0
    }

@router.get("/alerts")
async def get_recent_alerts(
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get recent security alerts"""
    
    # Get recent high/critical incidents
    critical_incidents = await Incident.get_by_severity(db, ["critical", "high"], limit=limit//2)
    
    # Get recent high/critical misconfigurations
    critical_misconfigs = await Misconfiguration.get_by_severity(db, ["critical", "high"], limit=limit//2)
    
    # Get recent high/critical phishing emails
    critical_phishing = await EmailAnalysis.get_by_threat_level(db, ["critical", "high"], limit=limit//2)
    
    # Combine and sort by date
    alerts = []
    
    for incident in critical_incidents:
        alerts.append({
            "id": incident.id,
            "type": "incident",
            "title": incident.title,
            "severity": incident.severity,
            "timestamp": incident.created_at,
            "description": f"Incident: {incident.title}"
        })
    
    for misconfig in critical_misconfigs:
        alerts.append({
            "id": misconfig.id,
            "type": "misconfiguration",
            "title": misconfig.title,
            "severity": misconfig.severity,
            "timestamp": misconfig.created_at,
            "description": f"Cloud Misconfiguration: {misconfig.title}"
        })
    
    for phishing in critical_phishing:
        alerts.append({
            "id": phishing.id,
            "type": "phishing",
            "title": phishing.subject,
            "severity": phishing.threat_level,
            "timestamp": phishing.created_at,
            "description": f"Phishing Email: {phishing.subject}"
        })
    
    # Sort by timestamp (most recent first)
    alerts.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return {
        "alerts": alerts[:limit],
        "total_alerts": len(alerts)
    }

@router.get("/performance")
async def get_system_performance(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get system performance metrics"""
    
    # Calculate response times (placeholder - implement actual metrics)
    avg_response_time = 0.15  # seconds
    uptime_percentage = 99.8
    active_users = 1  # current user
    
    # Get database performance
    db_connections = 5
    db_query_time = 0.02  # seconds
    
    return {
        "response_time": {
            "average": avg_response_time,
            "unit": "seconds"
        },
        "uptime": {
            "percentage": uptime_percentage,
            "unit": "%"
        },
        "users": {
            "active": active_users,
            "total": 1  # placeholder
        },
        "database": {
            "connections": db_connections,
            "query_time": db_query_time,
            "unit": "seconds"
        }
    }

def calculate_security_score(
    incident_stats: Dict[str, Any],
    cloud_misconfigs: Dict[str, Any],
    phishing_analyses: Dict[str, Any]
) -> int:
    """Calculate overall security score (0-100)"""
    
    base_score = 100
    
    # Deduct points for incidents
    incident_penalty = (
        incident_stats.get("critical_severity", 0) * 10 +
        incident_stats.get("high_severity", 0) * 5 +
        incident_stats.get("medium_severity", 0) * 2
    )
    
    # Deduct points for cloud misconfigurations
    cloud_penalty = (
        cloud_misconfigs.get("critical", 0) * 8 +
        cloud_misconfigs.get("high", 0) * 4 +
        cloud_misconfigs.get("medium", 0) * 2
    )
    
    # Deduct points for phishing threats
    phishing_penalty = (
        phishing_analyses.get("critical", 0) * 6 +
        phishing_analyses.get("high", 0) * 3 +
        phishing_analyses.get("medium", 0) * 1
    )
    
    total_penalty = incident_penalty + cloud_penalty + phishing_penalty
    final_score = max(0, base_score - total_penalty)
    
    return final_score 