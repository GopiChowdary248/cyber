"""
SAST (Static Application Security Testing) API Endpoints
Provides comprehensive REST API for SAST functionality
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends, Query, UploadFile, File
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid
import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.models.sast import SASTProject, SASTScan, SASTVulnerability, ScanStatus
from app.models.user import User
from app.core.security import get_current_user
from app.services.sast_service import sast_service
from app.schemas.sast_schemas import (
    SASTProjectCreate, SASTScanCreate, SASTOverviewResponse, SASTProjectsResponse,
    SASTVulnerabilitiesResponse, SASTProjectDetailResponse, SASTScanHistoryResponse,
    SASTStatisticsResponse, SASTDashboardStats, SASTVulnerabilityFilter, SASTScanFilter
)

router = APIRouter()

# ============================================================================
# Dashboard & Overview Endpoints
# ============================================================================

@router.get("/dashboard", response_model=SASTDashboardStats)
async def get_sast_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get SAST dashboard statistics"""
    try:
        # Get total projects
        projects_result = await db.execute(select(func.count(SASTProject.id)))
        total_projects = projects_result.scalar() or 0
        
        # Get active scans
        active_scans_result = await db.execute(
            select(func.count(SASTScan.id)).where(SASTScan.status == ScanStatus.RUNNING)
        )
        active_scans = active_scans_result.scalar() or 0
        
        # Get total vulnerabilities
        vulns_result = await db.execute(select(func.count(SASTVulnerability.id)))
        total_vulnerabilities = vulns_result.scalar() or 0
        
        # Get vulnerabilities by severity
        critical_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == "critical")
        )
        critical_vulns = critical_result.scalar() or 0
        
        high_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == "high")
        )
        high_vulns = high_result.scalar() or 0
        
        medium_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == "medium")
        )
        medium_vulns = medium_result.scalar() or 0
        
        low_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == "low")
        )
        low_vulns = low_result.scalar() or 0
        
        # Calculate security score
        security_score = max(0, 100 - (critical_vulns * 20 + high_vulns * 10 + medium_vulns * 5 + low_vulns * 1))
        
        # Get recent activity (last 10 scans)
        recent_scans_result = await db.execute(
            select(SASTScan)
            .order_by(SASTScan.started_at.desc())
            .limit(10)
        )
        recent_scans = recent_scans_result.scalars().all()
        
        recent_activity = [
            {
                "id": str(scan.id),
                "type": "scan",
                "project_id": scan.project_id,
                "status": scan.status,
                "timestamp": scan.started_at.isoformat() if scan.started_at else None,
                "vulnerabilities_found": scan.vulnerabilities_found or 0
            }
            for scan in recent_scans
        ]
        
        return SASTDashboardStats(
            total_projects=total_projects,
            active_scans=active_scans,
            total_vulnerabilities=total_vulnerabilities,
            critical_vulnerabilities=critical_vulns,
            high_vulnerabilities=high_vulns,
            medium_vulnerabilities=medium_vulns,
            low_vulnerabilities=low_vulns,
            security_score=security_score,
            recent_activity=recent_activity
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting SAST dashboard: {str(e)}")

@router.get("/overview", response_model=SASTOverviewResponse)
async def get_sast_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get SAST overview statistics"""
    try:
        # Get total projects
        projects_result = await db.execute(select(func.count(SASTProject.id)))
        total_projects = projects_result.scalar() or 0
        
        # Get total scans
        scans_result = await db.execute(select(func.count(SASTScan.id)))
        total_scans = scans_result.scalar() or 0
        
        # Get active scans
        active_scans_result = await db.execute(
            select(func.count(SASTScan.id)).where(SASTScan.status == ScanStatus.RUNNING)
        )
        active_scans = active_scans_result.scalar() or 0
        
        # Get total vulnerabilities
        vulns_result = await db.execute(select(func.count(SASTVulnerability.id)))
        total_vulnerabilities = vulns_result.scalar() or 0
        
        # Get vulnerabilities by severity
        critical_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == "critical")
        )
        critical_vulns = critical_result.scalar() or 0
        
        high_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == "high")
        )
        high_vulns = high_result.scalar() or 0
        
        medium_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == "medium")
        )
        medium_vulns = medium_result.scalar() or 0
        
        low_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == "low")
        )
        low_vulns = low_result.scalar() or 0
        
        # Calculate security score
        security_score = max(0, 100 - (critical_vulns * 20 + high_vulns * 10 + medium_vulns * 5 + low_vulns * 1))
        
        return SASTOverviewResponse(
            overview={
                "totalProjects": total_projects,
                "totalScans": total_scans,
                "activeScans": active_scans,
                "totalVulnerabilities": total_vulnerabilities,
                "vulnerabilitiesBySeverity": {
                    "critical": critical_vulns,
                    "high": high_vulns,
                    "medium": medium_vulns,
                    "low": low_vulns
                },
                "securityScore": security_score
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting SAST overview: {str(e)}")

# ============================================================================
# Project Management Endpoints
# ============================================================================

@router.get("/projects", response_model=SASTProjectsResponse)
async def get_sast_projects(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all SAST projects"""
    try:
        result = await db.execute(
            select(SASTProject).offset(skip).limit(limit)
        )
        projects = result.scalars().all()
        
        return SASTProjectsResponse(
            projects=[
                {
                    "id": str(project.id),
                    "name": project.name,
                    "repository_url": project.repository_url,
                    "language": project.language,
                    "description": project.description,
                    "created_at": project.created_at.isoformat() if project.created_at else None,
                    "total_scans": project.total_scans or 0,
                    "security_score": project.security_score or 0
                }
                for project in projects
            ]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting SAST projects: {str(e)}")

@router.post("/projects", response_model=Dict[str, Any])
async def create_sast_project(
    project_data: SASTProjectCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new SAST project"""
    try:
        project = await sast_service.create_project(db, project_data)
        
        return {
            "message": "SAST project created successfully",
            "project": {
                "id": str(project.id),
                "name": project.name,
                "repository_url": project.repository_url,
                "language": project.language,
                "description": project.description,
                "created_at": project.created_at.isoformat() if project.created_at else None
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating SAST project: {str(e)}")

@router.get("/projects/{project_id}", response_model=SASTProjectDetailResponse)
async def get_sast_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get specific SAST project details"""
    try:
        project_overview = await sast_service.get_project_overview(db, project_id)
        return SASTProjectDetailResponse(project=project_overview)
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting SAST project: {str(e)}")

# ============================================================================
# Scan Management Endpoints
# ============================================================================

@router.post("/scans", response_model=Dict[str, Any])
async def start_sast_scan(
    scan_data: SASTScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start a new SAST scan"""
    try:
        scan = await sast_service.start_scan(db, scan_data)
        
        return {
            "message": "SAST scan started successfully",
            "scan": {
                "id": str(scan.id),
                "project_id": scan.project_id,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "started_at": scan.started_at.isoformat() if scan.started_at else None
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting SAST scan: {str(e)}")

@router.get("/scans/{scan_id}", response_model=Dict[str, Any])
async def get_sast_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get specific SAST scan details"""
    try:
        result = await db.execute(select(SASTScan).where(SASTScan.id == scan_id))
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return {
            "scan": {
                "id": str(scan.id),
                "project_id": scan.project_id,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "vulnerabilities_found": scan.vulnerabilities_found or 0,
                "files_scanned": scan.files_scanned or 0,
                "lines_of_code": scan.lines_of_code or 0,
                "scan_duration": scan.scan_duration or 0,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "scan_summary": scan.scan_summary
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting SAST scan: {str(e)}")

@router.get("/projects/{project_id}/scans", response_model=SASTScanHistoryResponse)
async def get_project_scan_history(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get scan history for a project"""
    try:
        scans = await sast_service.get_scan_history(db, project_id)
        return SASTScanHistoryResponse(scans=scans)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting scan history: {str(e)}")

# ============================================================================
# Vulnerability Management Endpoints
# ============================================================================

@router.get("/vulnerabilities", response_model=SASTVulnerabilitiesResponse)
async def get_sast_vulnerabilities(
    severity: Optional[str] = Query(None),
    project_id: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all SAST vulnerabilities with optional filtering"""
    try:
        query = select(SASTVulnerability)
        
        if severity:
            query = query.where(SASTVulnerability.severity == severity)
        if project_id:
            query = query.where(SASTVulnerability.project_id == project_id)
            
        result = await db.execute(query.offset(skip).limit(limit))
        vulnerabilities = result.scalars().all()
        
        return SASTVulnerabilitiesResponse(
            vulnerabilities=[
                {
                    "id": str(vuln.id),
                    "scan_id": str(vuln.scan_id),
                    "project_id": str(vuln.project_id),
                    "title": vuln.title,
                    "description": vuln.description,
                    "severity": vuln.severity,
                    "file_path": vuln.file_path,
                    "line_number": vuln.line_number,
                    "cwe_id": vuln.cwe_id,
                    "vulnerable_code": vuln.vulnerable_code,
                    "created_at": vuln.created_at.isoformat() if vuln.created_at else None
                }
                for vuln in vulnerabilities
            ]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting SAST vulnerabilities: {str(e)}")

@router.get("/projects/{project_id}/vulnerabilities", response_model=SASTVulnerabilitiesResponse)
async def get_project_vulnerabilities(
    project_id: str,
    severity: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get vulnerabilities for a specific project"""
    try:
        vulnerabilities = await sast_service.get_vulnerabilities(db, project_id, severity)
        return SASTVulnerabilitiesResponse(vulnerabilities=vulnerabilities)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting project vulnerabilities: {str(e)}")

# ============================================================================
# Statistics & Analytics Endpoints
# ============================================================================

@router.get("/statistics", response_model=SASTStatisticsResponse)
async def get_sast_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive SAST statistics"""
    try:
        # Get total projects
        projects_result = await db.execute(select(func.count(SASTProject.id)))
        total_projects = projects_result.scalar() or 0
        
        # Get total scans
        scans_result = await db.execute(select(func.count(SASTScan.id)))
        total_scans = scans_result.scalar() or 0
        
        # Get total vulnerabilities
        vulns_result = await db.execute(select(func.count(SASTVulnerability.id)))
        total_vulnerabilities = vulns_result.scalar() or 0
        
        # Get vulnerabilities by severity
        critical_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == "critical")
        )
        critical_vulns = critical_result.scalar() or 0
        
        high_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == "high")
        )
        high_vulns = high_result.scalar() or 0
        
        medium_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == "medium")
        )
        medium_vulns = medium_result.scalar() or 0
        
        low_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == "low")
        )
        low_vulns = low_result.scalar() or 0
        
        # Calculate security score
        security_score = max(0, 100 - (critical_vulns * 20 + high_vulns * 10 + medium_vulns * 5 + low_vulns * 1))
        
        # Get recent scans
        recent_scans_result = await db.execute(
            select(SASTScan)
            .order_by(SASTScan.started_at.desc())
            .limit(5)
        )
        recent_scans = recent_scans_result.scalars().all()
        
        recent_scans_data = [
            {
                "id": str(scan.id),
                "project_id": scan.project_id,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "vulnerabilities_found": scan.vulnerabilities_found or 0,
                "started_at": scan.started_at.isoformat() if scan.started_at else None
            }
            for scan in recent_scans
        ]
        
        # Get top vulnerabilities
        top_vulns_result = await db.execute(
            select(SASTVulnerability)
            .order_by(SASTVulnerability.created_at.desc())
            .limit(10)
        )
        top_vulns = top_vulns_result.scalars().all()
        
        top_vulnerabilities = [
            {
                "id": str(vuln.id),
                "title": vuln.title,
                "severity": vuln.severity,
                "cwe_id": vuln.cwe_id,
                "file_path": vuln.file_path,
                "created_at": vuln.created_at.isoformat() if vuln.created_at else None
            }
            for vuln in top_vulns
        ]
        
        return SASTStatisticsResponse(
            total_projects=total_projects,
            total_scans=total_scans,
            total_vulnerabilities=total_vulnerabilities,
            vulnerabilities_by_severity={
                "critical": critical_vulns,
                "high": high_vulns,
                "medium": medium_vulns,
                "low": low_vulns
            },
            security_score=security_score,
            recent_scans=recent_scans_data,
            top_vulnerabilities=top_vulnerabilities
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting SAST statistics: {str(e)}")

# ============================================================================
# Configuration & Rules Endpoints
# ============================================================================

@router.get("/rules")
async def get_detection_rules(
    language: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get available detection rules"""
    try:
        rules = sast_service.scan_rules
        
        if language:
            rules = {lang: rules[lang] for lang in rules if lang == language}
        
        return {
            "rules": rules,
            "supported_languages": list(sast_service.supported_languages.keys())
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting detection rules: {str(e)}")

@router.get("/languages")
async def get_supported_languages(
    current_user: User = Depends(get_current_user)
):
    """Get supported programming languages"""
    try:
        return {
            "languages": sast_service.supported_languages,
            "rules": sast_service.scan_rules
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting supported languages: {str(e)}") 