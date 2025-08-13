"""
SAST (Static Application Security Testing) API Endpoints
Enhanced with SonarQube-like comprehensive functionality
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends, Query, UploadFile, File, status, Form, Response
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta, timezone
import uuid
import json
import shutil
import zipfile
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, update, delete
import logging

from app.core.database import get_db
from app.models.sast import (
    SASTProject, SASTScan, SASTIssue, SASTSecurityHotspot, SASTCodeCoverage,
    SASTDuplication, SASTQualityGate, SASTProjectConfiguration, SASTRule,
    ScanStatus, IssueSeverity, IssueType, IssueStatus, SecurityHotspotStatus,
    QualityGateStatus, Rating
)
from app.models.user import User
from app.core.security import get_current_user
from app.schemas.sast_schemas import (
    SASTProjectCreate, SASTScanCreate, SASTIssueCreate, SecurityHotspotCreate,
    QualityGateCreate, SASTOverviewResponse, SASTProjectsResponse,
    SASTVulnerabilitiesResponse, SASTProjectDetailResponse, SASTScanHistoryResponse,
    SASTStatisticsResponse, SASTDashboardStats, SASTVulnerabilityFilter, SASTScanFilter,
    SecurityHotspotsResponse, QualityGatesResponse, CodeCoveragesResponse,
    DuplicationsResponse, SecurityHotspotFilter
)
from app.schemas.sast import (
    SASTProjectResponse, SASTProjectListResponse, SASTProjectDuplicate, SASTProjectUpdate
)

# Import advanced analysis engines
from app.sast.advanced_analyzer import AdvancedCodeAnalyzer
from app.sast.data_flow_engine import DataFlowAnalyzer
from app.sast.taint_analyzer import TaintAnalyzer

router = APIRouter()

# ============================================================================
# Helper Functions
# ============================================================================

async def simulate_scan_progress(scan_id: str, db: AsyncSession):
    """Simulate scan progress for demonstration"""
    import asyncio
    import time
    
    # Simulate scan running
    await asyncio.sleep(2)
    
    # Update scan status to running
    scan_result = await db.execute(
        select(SASTScan).where(SASTScan.id == scan_id)
    )
    scan = scan_result.scalar_one_or_none()
    if scan:
        scan.status = ScanStatus.IN_PROGRESS
        scan.started_at = time.time()
        await db.commit()
    
    # Simulate scan completion
    await asyncio.sleep(5)
    
    if scan:
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = time.time()
        scan.vulnerabilities_found = 5  # Simulate finding 5 vulnerabilities
        await db.commit()

async def get_vulnerability_counts_by_severity(db: AsyncSession) -> Dict[str, int]:
    """Get vulnerability counts by severity"""
    counts = {}
    for severity in IssueSeverity:
        result = await db.execute(
            select(func.count(SASTIssue.id)).where(SASTIssue.severity == severity)
        )
        counts[severity.value.lower()] = result.scalar() or 0
    return counts

async def calculate_security_score(critical: int, major: int, minor: int, info: int) -> int:
    """Calculate security score based on vulnerability counts"""
    return max(0, 100 - (critical * 20 + major * 10 + minor * 5 + info * 1))

# ============================================================================
# Dashboard & Overview Endpoints
# ============================================================================

@router.get("/dashboard", response_model=SASTDashboardStats)
async def get_sast_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get SAST dashboard statistics with comprehensive metrics"""
    try:
        # Get total projects
        projects_result = await db.execute(select(func.count(SASTProject.id)))
        total_projects = projects_result.scalar() or 0
        
        # Get active scans
        active_scans_result = await db.execute(
            select(func.count(SASTScan.id)).where(SASTScan.status == ScanStatus.IN_PROGRESS)
        )
        active_scans = active_scans_result.scalar() or 0
        
        # Get total issues by type
        vulnerabilities_result = await db.execute(
            select(func.count(SASTIssue.id)).where(SASTIssue.type == IssueType.VULNERABILITY)
        )
        total_vulnerabilities = vulnerabilities_result.scalar() or 0
        
        bugs_result = await db.execute(
            select(func.count(SASTIssue.id)).where(SASTIssue.type == IssueType.BUG)
        )
        total_bugs = bugs_result.scalar() or 0
        
        code_smells_result = await db.execute(
            select(func.count(SASTIssue.id)).where(SASTIssue.type == IssueType.CODE_SMELL)
        )
        total_code_smells = code_smells_result.scalar() or 0
        
        # Get total issues
        total_issues_result = await db.execute(select(func.count(SASTIssue.id)))
        total_issues = total_issues_result.scalar() or 0
        
        # Get vulnerabilities by severity
        severity_counts = await get_vulnerability_counts_by_severity(db)
        
        # Get security hotspots
        hotspots_result = await db.execute(select(func.count(SASTSecurityHotspot.id)))
        total_hotspots = hotspots_result.scalar() or 0
        
        reviewed_hotspots_result = await db.execute(
            select(func.count(SASTSecurityHotspot.id)).where(
                SASTSecurityHotspot.status.in_([SecurityHotspotStatus.REVIEWED, SecurityHotspotStatus.SAFE, SecurityHotspotStatus.FIXED])
            )
        )
        reviewed_hotspots = reviewed_hotspots_result.scalar() or 0
        
        # Calculate ratings (mock data for now - would be calculated based on actual metrics)
        security_rating = "B"  # Would be calculated based on vulnerability density
        reliability_rating = "A"  # Would be calculated based on bug density
        maintainability_rating = "B"  # Would be calculated based on code smell density
        
        # Get coverage data
        coverage_result = await db.execute(
            select(func.avg(SASTCodeCoverage.line_coverage))
        )
        avg_coverage = coverage_result.scalar() or 75.0
        
        # Get technical debt (mock data)
        technical_debt_hours = 45
        
        # Get scan statistics
        completed_scans_result = await db.execute(
            select(func.count(SASTScan.id)).where(SASTScan.status == ScanStatus.COMPLETED)
        )
        completed_scans = completed_scans_result.scalar() or 0
        
        total_scans_result = await db.execute(select(func.count(SASTScan.id)))
        total_scans = total_scans_result.scalar() or 0
        
        scan_success_rate = (completed_scans / total_scans * 100) if total_scans > 0 else 0
        
        # Calculate average scan duration (mock data)
        average_scan_duration = 3.5  # minutes
        
        # Get last scan date
        last_scan_result = await db.execute(
            select(SASTScan.started_at)
            .order_by(SASTScan.started_at.desc())
            .limit(1)
        )
        last_scan_date = last_scan_result.scalar()
        
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
                "status": scan.status.value,
                "timestamp": scan.started_at.isoformat() if scan.started_at else None,
                "vulnerabilities_found": scan.vulnerabilities_found or 0
            }
            for scan in recent_scans
        ]
        
        return SASTDashboardStats(
            total_projects=total_projects,
            active_scans=active_scans,
            total_issues=total_issues,
            critical_issues=severity_counts.get('critical', 0),
            high_issues=severity_counts.get('major', 0),
            medium_issues=severity_counts.get('minor', 0),
            low_issues=severity_counts.get('info', 0),
            info_issues=severity_counts.get('info', 0),
            security_rating=security_rating,
            reliability_rating=reliability_rating,
            maintainability_rating=maintainability_rating,
            coverage_percentage=avg_coverage,
            technical_debt_hours=technical_debt_hours,
            last_scan_date=last_scan_date.isoformat() if last_scan_date else None,
            scan_success_rate=scan_success_rate,
            average_scan_duration=average_scan_duration,
            total_lines_of_code=150000,  # Mock data
            duplicated_lines=5000,  # Mock data
            duplicated_lines_density=3.3,  # Mock data
            uncovered_lines=25000,  # Mock data
            uncovered_conditions=5000,  # Mock data
            security_hotspots=total_hotspots,
            security_hotspots_reviewed=reviewed_hotspots,
            vulnerabilities=total_vulnerabilities,
            bugs=total_bugs,
            code_smells=total_code_smells,
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
            select(func.count(SASTScan.id)).where(SASTScan.status == ScanStatus.IN_PROGRESS)
        )
        active_scans = active_scans_result.scalar() or 0
        
        # Get total vulnerabilities
        vulns_result = await db.execute(select(func.count(SASTIssue.id)))
        total_vulnerabilities = vulns_result.scalar() or 0
        
        # Get vulnerabilities by severity
        severity_counts = await get_vulnerability_counts_by_severity(db)
        
        # Calculate security score
        security_score = await calculate_security_score(
            severity_counts.get('critical', 0),
            severity_counts.get('major', 0),
            severity_counts.get('minor', 0),
            severity_counts.get('info', 0)
        )
        
        return SASTOverviewResponse(
            overview={
                "totalProjects": total_projects,
                "totalScans": total_scans,
                "activeScans": active_scans,
                "totalVulnerabilities": total_vulnerabilities,
                "vulnerabilitiesBySeverity": {
                    "critical": severity_counts.get('critical', 0),
                    "high": severity_counts.get('major', 0),
                    "medium": severity_counts.get('minor', 0),
                    "low": severity_counts.get('info', 0)
                },
                "securityScore": security_score
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting SAST overview: {str(e)}")

# ============================================================================
# Project Management Endpoints
# ============================================================================

@router.post("/projects", response_model=SASTProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_sast_project(
    project_data: SASTProjectCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new SAST project"""
    try:
        from sqlalchemy import select
        
        # Check if project key already exists
        existing_project_query = select(SASTProject).where(SASTProject.key == project_data.key)
        existing_project_result = await db.execute(existing_project_query)
        existing_project = existing_project_result.scalar_one_or_none()
        
        if existing_project:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Project with key '{project_data.key}' already exists"
            )
        
        # Create new project
        new_project = SASTProject(
            name=project_data.name,
            key=project_data.key,
            language=project_data.language,
            repository_url=project_data.repository_url,
            branch=project_data.branch or "main",
            created_by=current_user.id,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
            updated_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        
        db.add(new_project)
        await db.commit()
        await db.refresh(new_project)
        
        return SASTProjectResponse(
            id=new_project.id,
            name=new_project.name,
            key=new_project.key,
            language=new_project.language,
            repository_url=new_project.repository_url,
            branch=new_project.branch,
            quality_gate=new_project.quality_gate,
            maintainability_rating=new_project.maintainability_rating,
            security_rating=new_project.security_rating,
            reliability_rating=new_project.reliability_rating,
            vulnerability_count=new_project.vulnerability_count or 0,
            bug_count=new_project.bug_count or 0,
            code_smell_count=new_project.code_smell_count or 0,
            security_hotspot_count=new_project.security_hotspot_count or 0,
            lines_of_code=new_project.lines_of_code or 0,
            coverage=new_project.coverage or 0.0,
            technical_debt=new_project.technical_debt or 0,
            created_by=current_user.email,
            created_at=new_project.created_at,
            updated_at=new_project.updated_at,
            last_analysis=new_project.last_analysis
        )
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create project: {str(e)}"
        )

@router.get("/projects", response_model=SASTProjectListResponse)
async def get_sast_projects(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None),
    language: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all SAST projects with filtering and pagination"""
    try:
        from sqlalchemy import select, func
        
        # Build base query
        query = select(SASTProject)
        
        # Apply search filter
        if search:
            query = query.where(
                SASTProject.name.ilike(f"%{search}%") | 
                SASTProject.key.ilike(f"%{search}%")
            )
        
        # Apply language filter
        if language and language != "all":
            query = query.where(SASTProject.language == language)
        
        # Apply status filter
        if status_filter and status_filter != "all":
            if status_filter == "active":
                # Projects with running scans
                query = query.join(SASTScan).where(SASTScan.status == "IN_PROGRESS")
            elif status_filter == "completed":
                # Projects with completed scans
                query = query.join(SASTScan).where(SASTScan.status == "COMPLETED")
            elif status_filter == "failed":
                # Projects with failed scans
                query = query.join(SASTScan).where(SASTScan.status == "FAILED")
        
        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_count_result = await db.execute(count_query)
        total_count = total_count_result.scalar()
        
        # Apply pagination
        query = query.offset(skip).limit(limit)
        projects_result = await db.execute(query)
        projects = projects_result.scalars().all()
        
        # Convert to response format
        project_responses = []
        for project in projects:
            # Get last scan
            last_scan_query = select(SASTScan).where(
                SASTScan.project_id == project.id
            ).order_by(SASTScan.started_at.desc())
            last_scan_result = await db.execute(last_scan_query)
            last_scan = last_scan_result.scalar_one_or_none()
            
            # Get issue counts
            issues_query = select(SASTIssue).where(SASTIssue.project_id == project.id)
            issues_result = await db.execute(issues_query)
            issues = issues_result.scalars().all()
            issue_counts = {
                "critical": len([i for i in issues if i.severity == "CRITICAL"]),
                "high": len([i for i in issues if i.severity == "HIGH"]),
                "medium": len([i for i in issues if i.severity == "MEDIUM"]),
                "low": len([i for i in issues if i.severity == "LOW"])
            }
            
            project_responses.append(SASTProjectResponse(
                id=project.id,
                name=project.name,
                key=project.key,
                language=project.language,
                repository_url=project.repository_url,
                branch=project.branch,
                quality_gate=project.quality_gate,
                maintainability_rating=project.maintainability_rating,
                security_rating=project.security_rating,
                reliability_rating=project.reliability_rating,
                vulnerability_count=project.vulnerability_count or 0,
                bug_count=project.bug_count or 0,
                code_smell_count=project.code_smell_count or 0,
                security_hotspot_count=project.security_hotspot_count or 0,
                lines_of_code=project.lines_of_code or 0,
                coverage=project.coverage or 0.0,
                technical_debt=project.technical_debt or 0,
                created_by=current_user.email,  # This should be the actual creator's email
                created_at=project.created_at,
                updated_at=project.updated_at,
                last_analysis=project.last_analysis,
                last_scan=last_scan,
                issues=issue_counts
            ))
        
        return SASTProjectListResponse(
            projects=project_responses,
            total=total_count,
            page=skip // limit + 1,
            pages=(total_count + limit - 1) // limit
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch projects: {str(e)}"
        )

@router.get("/projects/{project_id}", response_model=SASTProjectResponse)
async def get_sast_project(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific SAST project by ID"""
    try:
        from sqlalchemy import select
        
        project_query = select(SASTProject).where(SASTProject.id == project_id)
        project_result = await db.execute(project_query)
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Get last scan
        last_scan_query = select(SASTScan).where(
            SASTScan.project_id == project.id
        ).order_by(SASTScan.started_at.desc())
        last_scan_result = await db.execute(last_scan_query)
        last_scan = last_scan_result.scalar_one_or_none()
        
        # Get issue counts
        issues_query = select(SASTIssue).where(SASTIssue.project_id == project.id)
        issues_result = await db.execute(issues_query)
        issues = issues_result.scalars().all()
        issue_counts = {
            "critical": len([i for i in issues if i.severity == "CRITICAL"]),
            "high": len([i for i in issues if i.severity == "HIGH"]),
            "medium": len([i for i in issues if i.severity == "MEDIUM"]),
            "low": len([i for i in issues if i.severity == "LOW"])
        }
        
        return SASTProjectResponse(
            id=project.id,
            name=project.name,
            key=project.key,
            language=project.language,
            repository_url=project.repository_url,
            branch=project.branch,
            quality_gate=project.quality_gate,
            maintainability_rating=project.maintainability_rating,
            security_rating=project.security_rating,
            reliability_rating=project.reliability_rating,
            vulnerability_count=project.vulnerability_count or 0,
            bug_count=project.bug_count or 0,
            code_smell_count=project.code_smell_count or 0,
            security_hotspot_count=project.security_hotspot_count or 0,
            lines_of_code=project.lines_of_code or 0,
            coverage=project.coverage or 0.0,
            technical_debt=project.technical_debt or 0,
            created_by=current_user.email,  # This should be the actual creator's email
            created_at=project.created_at,
            updated_at=project.updated_at,
            last_analysis=project.last_analysis,
            last_scan=last_scan,
            issues=issue_counts
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch project: {str(e)}"
        )

@router.post("/projects/{project_id}/duplicate", response_model=SASTProjectResponse, status_code=status.HTTP_201_CREATED)
async def duplicate_sast_project(
    project_id: int,
    duplicate_data: SASTProjectDuplicate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Duplicate an existing SAST project"""
    try:
        from sqlalchemy import select
        
        # Get original project
        original_project_query = select(SASTProject).where(SASTProject.id == project_id)
        original_project_result = await db.execute(original_project_query)
        original_project = original_project_result.scalar_one_or_none()
        
        if not original_project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Original project not found"
            )
        
        # Check if new project key already exists
        existing_project_query = select(SASTProject).where(SASTProject.key == duplicate_data.key)
        existing_project_result = await db.execute(existing_project_query)
        existing_project = existing_project_result.scalar_one_or_none()
        
        if existing_project:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Project with key '{duplicate_data.key}' already exists"
            )
        
        # Create duplicated project
        duplicated_project = SASTProject(
            name=duplicate_data.name,
            key=duplicate_data.key,
            language=original_project.language,
            repository_url=original_project.repository_url,
            branch=original_project.branch,
            created_by=current_user.id,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
            updated_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        
        db.add(duplicated_project)
        await db.commit()
        await db.refresh(duplicated_project)
        
        return SASTProjectResponse(
            id=duplicated_project.id,
            name=duplicated_project.name,
            key=duplicated_project.key,
            language=duplicated_project.language,
            repository_url=duplicated_project.repository_url,
            branch=duplicated_project.branch,
            quality_gate=duplicated_project.quality_gate,
            maintainability_rating=duplicated_project.maintainability_rating,
            security_rating=duplicated_project.security_rating,
            reliability_rating=duplicated_project.reliability_rating,
            vulnerability_count=duplicated_project.vulnerability_count or 0,
            bug_count=duplicated_project.bug_count or 0,
            code_smell_count=duplicated_project.code_smell_count or 0,
            security_hotspot_count=duplicated_project.security_hotspot_count or 0,
            lines_of_code=duplicated_project.lines_of_code or 0,
            coverage=duplicated_project.coverage or 0.0,
            technical_debt=duplicated_project.technical_debt or 0,
            created_by=current_user.email,
            created_at=duplicated_project.created_at,
            updated_at=duplicated_project.updated_at,
            last_analysis=duplicated_project.last_analysis
        )
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to duplicate project: {str(e)}"
        )

@router.put("/projects/{project_id}", response_model=SASTProjectResponse)
async def update_sast_project(
    project_id: int,
    project_data: SASTProjectUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update an existing SAST project"""
    try:
        from sqlalchemy import select
        
        project_query = select(SASTProject).where(SASTProject.id == project_id)
        project_result = await db.execute(project_query)
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Update fields
        if project_data.name is not None:
            project.name = project_data.name
        if project_data.key is not None:
            # Check if new key already exists
            existing_project_query = select(SASTProject).where(
                SASTProject.key == project_data.key,
                SASTProject.id != project_id
            )
            existing_project_result = await db.execute(existing_project_query)
            existing_project = existing_project_result.scalar_one_or_none()
            if existing_project:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Project with key '{project_data.key}' already exists"
                )
            project.key = project_data.key
        if project_data.language is not None:
            project.language = project_data.language
        if project_data.repository_url is not None:
            project.repository_url = project_data.repository_url
        if project_data.branch is not None:
            project.branch = project_data.branch
        
        project.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        
        await db.commit()
        await db.refresh(project)
        
        return SASTProjectResponse(
            id=project.id,
            name=project.name,
            key=project.key,
            language=project.language,
            repository_url=project.repository_url,
            branch=project.branch,
            quality_gate=project.quality_gate,
            maintainability_rating=project.maintainability_rating,
            security_rating=project.security_rating,
            reliability_rating=project.reliability_rating,
            vulnerability_count=project.vulnerability_count or 0,
            bug_count=project.bug_count or 0,
            code_smell_count=project.code_smell_count or 0,
            security_hotspot_count=project.security_hotspot_count or 0,
            lines_of_code=project.lines_of_code or 0,
            coverage=project.coverage or 0.0,
            technical_debt=project.technical_debt or 0,
            created_by=current_user.email,  # This should be the actual creator's email
            created_at=project.created_at,
            updated_at=project.updated_at,
            last_analysis=project.last_analysis
        )
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update project: {str(e)}"
        )

@router.delete("/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sast_project(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a SAST project and all associated data"""
    try:
        from sqlalchemy import select, delete
        
        project_query = select(SASTProject).where(SASTProject.id == project_id)
        project_result = await db.execute(project_query)
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Check if user has permission to delete (admin or project creator)
        if current_user.role != "admin" and project.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to delete this project"
            )
        
        # Delete associated data (cascade should handle this, but being explicit)
        await db.execute(delete(SASTIssue).where(SASTIssue.project_id == project_id))
        await db.execute(delete(SASTSecurityHotspot).where(SASTSecurityHotspot.project_id == project_id))
        await db.execute(delete(SASTQualityGate).where(SASTQualityGate.project_id == project_id))
        await db.execute(delete(SASTScan).where(SASTScan.project_id == project_id))
        
        # Delete the project
        await db.execute(delete(SASTProject).where(SASTProject.id == project_id))
        await db.commit()
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete project: {str(e)}"
            )

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
        # Start scan directly in database
        scan = SASTScan(
            project_id=scan_data.project_id,
            scan_type=scan_data.scan_type,
            branch=scan_data.branch,
            status=ScanStatus.PENDING,
            started_by=current_user.id
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        
        # Simulate scan progress in background
        background_tasks.add_task(simulate_scan_progress, scan.id, db)
        
        return {
            "message": "SAST scan started successfully",
            "scan": {
                "id": str(scan.id),
                "project_id": scan.project_id,
                "scan_type": scan.scan_type,
                "branch": scan.branch,
                "status": scan.status.value,
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
        result = await db.execute(select(SASTScan).where(SASTScan.id == int(scan_id)))
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return {
            "scan": {
                "id": str(scan.id),
                "project_id": scan.project_id,
                "scan_type": scan.scan_type,
                "branch": scan.branch,
                "status": scan.status.value,
                "progress": scan.progress,
                "issues_found": scan.issues_found,
                "vulnerabilities_found": scan.vulnerabilities_found,
                "bugs_found": scan.bugs_found,
                "code_smells_found": scan.code_smells_found,
                "security_hotspots_found": scan.security_hotspots_found,
                "lines_of_code": scan.lines_of_code,
                "coverage": scan.coverage,
                "technical_debt": scan.technical_debt,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration": scan.duration,
                "error_message": scan.error_message
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
        # Get scan history directly from database
        scans_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == project_id)
            .order_by(SASTScan.started_at.desc())
        )
        scans = scans_result.scalars().all()
        return SASTScanHistoryResponse(scans=scans)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting scan history: {str(e)}")

# ============================================================================
# Vulnerability Management Endpoints
# ============================================================================

@router.get("/vulnerabilities", response_model=SASTVulnerabilitiesResponse)
async def get_sast_vulnerabilities(
    severity: Optional[str] = Query(None),
    type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    project_id: Optional[str] = Query(None),
    cwe_id: Optional[str] = Query(None),
    owasp_category: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all SAST vulnerabilities with advanced filtering"""
    try:
        query = select(SASTIssue)
        
        # Apply filters
        if severity:
            try:
                severity_enum = IssueSeverity(severity.upper())
                query = query.where(SASTIssue.severity == severity_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")
        
        if type:
            try:
                type_enum = IssueType(type.upper())
                query = query.where(SASTIssue.type == type_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid type: {type}")
        
        if status:
            try:
                status_enum = IssueStatus(status.upper())
                query = query.where(SASTIssue.status == status_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
        
        if project_id:
            query = query.where(SASTIssue.project_id == int(project_id))
        
        if cwe_id:
            query = query.where(SASTIssue.cwe_id == cwe_id)
        
        if owasp_category:
            query = query.where(SASTIssue.owasp_category == owasp_category)
            
        result = await db.execute(query.offset(skip).limit(limit))
        vulnerabilities = result.scalars().all()
        
        return SASTVulnerabilitiesResponse(
            vulnerabilities=[
                {
                    "id": str(vuln.id),
                    "scan_id": str(vuln.scan_id) if vuln.scan_id else None,
                    "project_id": str(vuln.project_id),
                    "rule_id": vuln.rule_id,
                    "rule_name": vuln.rule_name,
                    "message": vuln.message,
                    "description": vuln.description,
                    "severity": vuln.severity.value,
                    "type": vuln.type.value,
                    "status": vuln.status.value,
                    "file_path": vuln.file_path,
                    "line_number": vuln.line_number,
                    "cwe_id": vuln.cwe_id,
                    "cvss_score": vuln.cvss_score,
                    "owasp_category": vuln.owasp_category,
                    "effort": vuln.effort,
                    "debt": vuln.debt,
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
        # Get vulnerabilities directly from database
        query = select(SASTIssue).where(SASTIssue.project_id == project_id)
        if severity:
            query = query.where(SASTIssue.severity == severity)
        
        vulnerabilities_result = await db.execute(query)
        vulnerabilities = vulnerabilities_result.scalars().all()
        return SASTVulnerabilitiesResponse(vulnerabilities=vulnerabilities)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting project vulnerabilities: {str(e)}")

# ============================================================================
# Security Hotspots Endpoints
# ============================================================================

@router.get("/security-hotspots", response_model=SecurityHotspotsResponse)
async def get_security_hotspots(
    status: Optional[str] = Query(None),
    project_id: Optional[str] = Query(None),
    cwe_id: Optional[str] = Query(None),
    owasp_category: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get security hotspots with filtering"""
    try:
        query = select(SASTSecurityHotspot)
        
        # Apply filters
        if status:
            try:
                status_enum = SecurityHotspotStatus(status.upper())
                query = query.where(SASTSecurityHotspot.status == status_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
        
        if project_id:
            query = query.where(SASTSecurityHotspot.project_id == int(project_id))
        
        if cwe_id:
            query = query.where(SASTSecurityHotspot.cwe_id == cwe_id)
        
        if owasp_category:
            query = query.where(SASTSecurityHotspot.owasp_category == owasp_category)
        
        result = await db.execute(query.offset(skip).limit(limit))
        hotspots = result.scalars().all()
        
        return SecurityHotspotsResponse(
            hotspots=[
                {
                    "id": str(hotspot.id),
                    "scan_id": str(hotspot.scan_id) if hotspot.scan_id else None,
                    "project_id": str(hotspot.project_id),
                    "rule_id": hotspot.rule_id,
                    "rule_name": hotspot.rule_name,
                    "message": hotspot.message,
                    "description": hotspot.description,
                    "status": hotspot.status.value,
                    "resolution": hotspot.resolution.value if hotspot.resolution else None,
                    "file_path": hotspot.file_path,
                    "line_number": hotspot.line_number,
                    "cwe_id": hotspot.cwe_id,
                    "cvss_score": hotspot.cvss_score,
                    "owasp_category": hotspot.owasp_category,
                    "reviewed_by": hotspot.reviewed_by,
                    "reviewed_at": hotspot.reviewed_at.isoformat() if hotspot.reviewed_at else None,
                    "review_comment": hotspot.review_comment,
                    "created_at": hotspot.created_at.isoformat() if hotspot.created_at else None
                }
                for hotspot in hotspots
            ]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting security hotspots: {str(e)}")

@router.get("/projects/{project_id}/security-hotspots", response_model=SecurityHotspotsResponse)
async def get_project_security_hotspots(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get security hotspots for a specific project"""
    try:
        # Get security hotspots directly from database
        hotspots_result = await db.execute(
            select(SASTSecurityHotspot).where(SASTSecurityHotspot.project_id == project_id)
        )
        hotspots = hotspots_result.scalars().all()
        return SecurityHotspotsResponse(hotspots=hotspots)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting project security hotspots: {str(e)}")

# ============================================================================
# Quality Gates Endpoints
# ============================================================================

@router.get("/quality-gates", response_model=QualityGatesResponse)
async def get_quality_gates(
    project_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get quality gates with filtering"""
    try:
        query = select(SASTQualityGate)
        
        if project_id:
            query = query.where(SASTQualityGate.project_id == int(project_id))
        
        if status:
            try:
                status_enum = QualityGateStatus(status.upper())
                query = query.where(SASTQualityGate.status == status_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
        
        result = await db.execute(query)
        quality_gates = result.scalars().all()
        
        return QualityGatesResponse(
            quality_gates=[
                {
                    "id": str(qg.id),
                    "project_id": str(qg.project_id),
                    "status": qg.status.value,
                    "max_blocker_issues": qg.max_blocker_issues,
                    "max_critical_issues": qg.max_critical_issues,
                    "max_major_issues": qg.max_major_issues,
                    "max_minor_issues": qg.max_minor_issues,
                    "max_info_issues": qg.max_info_issues,
                    "min_coverage": qg.min_coverage,
                    "min_branch_coverage": qg.min_branch_coverage,
                    "max_debt_ratio": qg.max_debt_ratio,
                    "max_technical_debt": qg.max_technical_debt,
                    "max_duplicated_lines": qg.max_duplicated_lines,
                    "max_duplicated_blocks": qg.max_duplicated_blocks,
                    "min_maintainability_rating": qg.min_maintainability_rating.value,
                    "min_security_rating": qg.min_security_rating.value,
                    "min_reliability_rating": qg.min_reliability_rating.value,
                    "last_evaluation": qg.last_evaluation.isoformat() if qg.last_evaluation else None,
                    "evaluation_results": qg.evaluation_results,
                    "created_at": qg.created_at.isoformat() if qg.created_at else None,
                    "updated_at": qg.updated_at.isoformat() if qg.updated_at else None
                }
                for qg in quality_gates
            ]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality gates: {str(e)}")

@router.get("/projects/{project_id}/quality-gate")
async def get_project_quality_gate(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get quality gate for a specific project"""
    try:
        # Get quality gate directly from database
        quality_gate_result = await db.execute(
            select(SASTQualityGate).where(SASTQualityGate.project_id == project_id)
        )
        quality_gate = quality_gate_result.scalar_one_or_none()
        if not quality_gate:
            raise HTTPException(status_code=404, detail="Quality gate not found")
        return quality_gate
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting project quality gate: {str(e)}")

# ============================================================================
# Code Coverage Endpoints
# ============================================================================

@router.get("/code-coverage", response_model=CodeCoveragesResponse)
async def get_code_coverage(
    project_id: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None),
    min_coverage: Optional[float] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get code coverage data"""
    try:
        query = select(SASTCodeCoverage)
        
        if project_id:
            query = query.where(SASTCodeCoverage.project_id == int(project_id))
        
        if scan_id:
            query = query.where(SASTCodeCoverage.scan_id == int(scan_id))
        
        if min_coverage is not None:
            query = query.where(SASTCodeCoverage.overall_coverage >= min_coverage)
        
        result = await db.execute(query)
        coverages = result.scalars().all()
        
        return CodeCoveragesResponse(
            coverages=[
                {
                    "id": str(coverage.id),
                    "project_id": str(coverage.project_id),
                    "scan_id": str(coverage.scan_id) if coverage.scan_id else None,
                    "file_path": coverage.file_path,
                    "lines_to_cover": coverage.lines_to_cover,
                    "uncovered_lines": coverage.uncovered_lines,
                    "covered_lines": coverage.covered_lines,
                    "line_coverage": coverage.line_coverage,
                    "conditions_to_cover": coverage.conditions_to_cover,
                    "uncovered_conditions": coverage.uncovered_conditions,
                    "covered_conditions": coverage.covered_conditions,
                    "branch_coverage": coverage.branch_coverage,
                    "overall_coverage": coverage.overall_coverage,
                    "created_at": coverage.created_at.isoformat() if coverage.created_at else None
                }
                for coverage in coverages
            ]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting code coverage: {str(e)}")

# ============================================================================
# Code Duplications Endpoints
# ============================================================================

@router.get("/duplications", response_model=DuplicationsResponse)
async def get_duplications(
    project_id: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None),
    min_duplicated_lines: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get code duplications"""
    try:
        query = select(SASTDuplication)
        
        if project_id:
            query = query.where(SASTDuplication.project_id == int(project_id))
        
        if scan_id:
            query = query.where(SASTDuplication.scan_id == int(scan_id))
        
        if min_duplicated_lines is not None:
            query = query.where(SASTDuplication.duplicated_lines >= min_duplicated_lines)
        
        result = await db.execute(query)
        duplications = result.scalars().all()
        
        return DuplicationsResponse(
            duplications=[
                {
                    "id": str(dup.id),
                    "project_id": str(dup.project_id),
                    "scan_id": str(dup.scan_id) if dup.scan_id else None,
                    "file_path": dup.file_path,
                    "start_line": dup.start_line,
                    "end_line": dup.end_line,
                    "duplicated_lines": dup.duplicated_lines,
                    "duplicated_blocks": dup.duplicated_blocks,
                    "created_at": dup.created_at.isoformat() if dup.created_at else None
                }
                for dup in duplications
            ]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting duplications: {str(e)}")

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
        vulns_result = await db.execute(select(func.count(SASTIssue.id)))
        total_vulnerabilities = vulns_result.scalar() or 0
        
        # Get vulnerabilities by severity
        severity_counts = await get_vulnerability_counts_by_severity(db)
        
        # Calculate security score
        security_score = await calculate_security_score(
            severity_counts.get('critical', 0),
            severity_counts.get('major', 0),
            severity_counts.get('minor', 0),
            severity_counts.get('info', 0)
        )
        
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
                "status": scan.status.value,
                "vulnerabilities_found": scan.vulnerabilities_found or 0,
                "started_at": scan.started_at.isoformat() if scan.started_at else None
            }
            for scan in recent_scans
        ]
        
        # Get top vulnerabilities
        top_vulns_result = await db.execute(
            select(SASTIssue)
            .order_by(SASTIssue.created_at.desc())
            .limit(10)
        )
        top_vulns = top_vulns_result.scalars().all()
        
        top_vulnerabilities = [
            {
                "id": str(vuln.id),
                "rule_name": vuln.rule_name,
                "severity": vuln.severity.value,
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
            security_score=security_score,
            severity_distribution=severity_counts,
            recent_scans=recent_scans_data,
            top_vulnerabilities=top_vulnerabilities
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting statistics: {str(e)}")

# ============================================================================
# Configuration & Rules Endpoints
# ============================================================================

@router.get("/rules")
async def get_detection_rules(
    language: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get available detection rules with filtering"""
    try:
        query = select(SASTRule)
        
        if language:
            query = query.where(SASTRule.languages.contains([language]))
        
        if severity:
            try:
                severity_enum = IssueSeverity(severity.upper())
                query = query.where(SASTRule.severity == severity_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")
        
        if category:
            query = query.where(SASTRule.category == category)
        
        result = await db.execute(query)
        rules = result.scalars().all()
        
        return {
            "rules": [
                {
                    "id": str(rule.id),
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "description": rule.description,
                    "category": rule.category,
                    "subcategory": rule.subcategory,
                    "severity": rule.severity.value,
                    "type": rule.type.value,
                    "cwe_id": rule.cwe_id,
                    "owasp_category": rule.owasp_category,
                    "tags": rule.tags,
                    "enabled": rule.enabled,
                    "effort": rule.effort,
                    "languages": rule.languages,
                    "created_at": rule.created_at.isoformat() if rule.created_at else None
                }
                for rule in rules
            ],
            "supported_languages": ["java", "python", "javascript", "typescript", "csharp", "php", "go", "rust"]
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
            "languages": {
                "java": {"name": "Java", "extensions": [".java"]},
                "python": {"name": "Python", "extensions": [".py"]},
                "javascript": {"name": "JavaScript", "extensions": [".js"]},
                "typescript": {"name": "TypeScript", "extensions": [".ts"]},
                "csharp": {"name": "C#", "extensions": [".cs"]},
                "php": {"name": "PHP", "extensions": [".php"]},
                "go": {"name": "Go", "extensions": [".go"]},
                "rust": {"name": "Rust", "extensions": [".rs"]}
            },
            "rules": {
                "java": ["S1488", "S1172", "S1135"],
                "python": ["S1488", "S1172", "S1135"],
                "javascript": ["S1488", "S1172", "S1135"]
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting supported languages: {str(e)}")

# ============================================================================
# Quality Management Endpoints
# ============================================================================

@router.get("/projects/{project_id}/quality-overview")
async def get_project_quality_overview(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive quality overview for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get quality gate
        quality_gate_result = await db.execute(
            select(SASTQualityGate).where(SASTQualityGate.project_id == project_id)
        )
        quality_gate = quality_gate_result.scalar_one_or_none()
        
        # Get recent scan for metrics
        recent_scan_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == project_id)
            .order_by(SASTScan.created_at.desc())
            .limit(1)
        )
        recent_scan = recent_scan_result.scalar_one_or_none()
        
        # Calculate quality metrics
        quality_metrics = {
            "project_id": project_id,
            "project_name": project.name,
            "quality_gate_status": quality_gate.status if quality_gate else QualityGateStatus.PASSED,
            "ratings": {
                "maintainability": project.maintainability_rating,
                "security": project.security_rating,
                "reliability": project.reliability_rating
            },
            "issue_counts": {
                "vulnerabilities": project.vulnerability_count,
                "bugs": project.bug_count,
                "code_smells": project.code_smell_count,
                "security_hotspots": project.security_hotspot_count
            },
            "code_metrics": {
                "lines_of_code": project.lines_of_code,
                "lines_of_comment": project.lines_of_comment,
                "duplicated_lines": project.duplicated_lines,
                "duplicated_blocks": project.duplicated_blocks
            },
            "coverage_metrics": {
                "coverage": project.coverage,
                "uncovered_lines": project.uncovered_lines,
                "uncovered_conditions": project.uncovered_conditions
            },
            "technical_debt": {
                "total_debt": project.technical_debt,
                "debt_ratio": project.debt_ratio,
                "debt_hours": round(project.technical_debt / 60, 2) if project.technical_debt else 0
            },
            "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None,
            "scan_status": recent_scan.status if recent_scan else None
        }
        
        return quality_metrics
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality overview: {str(e)}")

@router.get("/projects/{project_id}/quality-metrics")
async def get_project_quality_metrics(
    project_id: str,
    metric_type: Optional[str] = Query(None, description="Type of metrics: 'security', 'reliability', 'maintainability', 'coverage', 'duplications'"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get detailed quality metrics for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        if not metric_type:
            # Return all metrics
            return {
                "project_id": project_id,
                "project_name": project.name,
                "security_metrics": {
                    "rating": project.security_rating,
                    "vulnerability_count": project.vulnerability_count,
                    "security_hotspot_count": project.security_hotspot_count
                },
                "reliability_metrics": {
                    "rating": project.reliability_rating,
                    "bug_count": project.bug_count
                },
                "maintainability_metrics": {
                    "rating": project.maintainability_rating,
                    "code_smell_count": project.code_smell_count,
                    "technical_debt": project.technical_debt,
                    "debt_ratio": project.debt_ratio
                },
                "coverage_metrics": {
                    "coverage": project.coverage,
                    "uncovered_lines": project.uncovered_lines,
                    "uncovered_conditions": project.uncovered_conditions
                },
                "duplication_metrics": {
                    "duplicated_lines": project.duplicated_lines,
                    "duplicated_blocks": project.duplicated_blocks
                }
            }
        
        # Return specific metric type
        if metric_type == "security":
            return {
                "project_id": project_id,
                "metric_type": "security",
                "rating": project.security_rating,
                "vulnerability_count": project.vulnerability_count,
                "security_hotspot_count": project.security_hotspot_count,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "reliability":
            return {
                "project_id": project_id,
                "metric_type": "reliability",
                "rating": project.reliability_rating,
                "bug_count": project.bug_count,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "maintainability":
            return {
                "project_id": project_id,
                "metric_type": "maintainability",
                "rating": project.maintainability_rating,
                "code_smell_count": project.code_smell_count,
                "technical_debt": project.technical_debt,
                "debt_ratio": project.debt_ratio,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "coverage":
            return {
                "project_id": project_id,
                "metric_type": "coverage",
                "coverage": project.coverage,
                "line_number": project.coverage,
                "uncovered_lines": project.uncovered_lines,
                "uncovered_conditions": project.uncovered_conditions,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "duplications":
            return {
                "project_id": project_id,
                "metric_type": "duplications",
                "duplicated_lines": project.duplicated_lines,
                "duplicated_blocks": project.duplicated_blocks,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        else:
            raise HTTPException(status_code=400, detail="Invalid metric type")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality metrics: {str(e)}")

@router.get("/projects/{project_id}/quality-trends")
async def get_project_quality_trends(
    project_id: str,
    days: int = Query(30, description="Number of days for trend analysis"),
    metric: str = Query("all", description="Specific metric to analyze: 'security', 'reliability', 'maintainability', 'coverage', 'debt'"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get quality trends for a project over time"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get scans within the specified time period
        from datetime import datetime, timedelta
        cutoff_date = datetime.now() - timedelta(days=days)
        
        scans_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == project_id)
            .where(SASTScan.created_at >= cutoff_date)
            .order_by(SASTScan.created_at.asc())
        )
        scans = scans_result.scalars().all()
        
        # Generate trend data
        trends = []
        for scan in scans:
            trend_point = {
                "date": scan.created_at.isoformat(),
                "scan_id": str(scan.id),
                "scan_status": scan.status
            }
            
            if metric == "all" or metric == "security":
                trend_point["security_rating"] = getattr(scan, 'security_rating', None)
                trend_point["vulnerability_count"] = getattr(scan, 'vulnerabilities_found', 0)
            
            if metric == "all" or metric == "reliability":
                trend_point["reliability_rating"] = getattr(scan, 'reliability_rating', None)
                trend_point["bug_count"] = getattr(scan, 'bugs_found', 0)
            
            if metric == "all" or metric == "maintainability":
                trend_point["maintainability_rating"] = getattr(scan, 'maintainability_rating', None)
                trend_point["code_smell_count"] = getattr(scan, 'code_smells_found', 0)
            
            if metric == "all" or metric == "coverage":
                trend_point["coverage"] = getattr(scan, 'coverage', 0.0)
            
            if metric == "all" or metric == "debt":
                trend_point["technical_debt"] = getattr(scan, 'technical_debt', 0)
            
            trends.append(trend_point)
        
        return {
            "project_id": project_id,
            "project_name": project.name,
            "metric": metric,
            "period_days": days,
            "trends": trends,
            "summary": {
                "total_scans": len(trends),
                "period_start": cutoff_date.isoformat(),
                "period_end": datetime.now().isoformat()
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality trends: {str(e)}")

@router.get("/projects/{project_id}/quality-report")
async def get_project_quality_report(
    project_id: str,
    format: str = Query("json", description="Report format: 'json', 'pdf', 'csv'"),
    include_details: bool = Query(True, description="Include detailed issue information"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate comprehensive quality report for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get quality gate
        quality_gate_result = await db.execute(
            select(SASTQualityGate).where(SASTQualityGate.project_id == project_id)
        )
        quality_gate = quality_gate_result.scalar_one_or_none()
        
        # Get recent scan
        recent_scan_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == project_id)
            .order_by(SASTScan.created_at.desc())
            .limit(1)
        )
        recent_scan = recent_scan_result.scalar_one_or_none()
        
        # Get issues if details are requested
        issues = []
        if include_details:
            issues_result = await db.execute(
                select(SASTIssue)
                .where(SASTIssue.project_id == project_id)
                .order_by(SASTIssue.severity.desc(), SASTIssue.created_at.desc())
                .limit(100)  # Limit for performance
            )
            issues = issues_result.scalars().all()
        
        # Generate report data
        report_data = {
            "project": {
                "id": project_id,
                "name": project.name,
                "key": project.key,
                "language": project.language,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            },
            "quality_gate": {
                "status": quality_gate.status if quality_gate else QualityGateStatus.PASSED,
                "evaluated_at": quality_gate.last_evaluation.isoformat() if quality_gate and quality_gate.last_evaluation else None
            },
            "ratings": {
                "maintainability": project.maintainability_rating,
                "security": project.security_rating,
                "reliability": project.reliability_rating
            },
            "metrics_summary": {
                "lines_of_code": project.lines_of_code,
                "coverage": project.coverage,
                "technical_debt": project.technical_debt,
                "debt_ratio": project.debt_ratio,
                "duplicated_lines": project.duplicated_lines
            },
            "issue_summary": {
                "total_issues": len(issues),
                "vulnerabilities": project.vulnerability_count,
                "bugs": project.bug_count,
                "code_smells": project.code_smell_count,
                "security_hotspots": project.security_hotspot_count
            },
            "scan_information": {
                "last_scan_id": str(recent_scan.id) if recent_scan else None,
                "last_scan_status": recent_scan.status if recent_scan else None,
                "last_scan_date": recent_scan.created_at.isoformat() if recent_scan else None
            },
            "generated_at": datetime.now().isoformat()
        }
        
        if include_details and issues:
            report_data["detailed_issues"] = [
                {
                    "id": str(issue.id),
                    "type": issue.type,
                    "severity": issue.severity,
                    "status": issue.status,
                    "file_path": issue.file_path,
                    "line_number": issue.line_number,
                    "message": issue.message,
                    "effort": issue.effort,
                    "created_at": issue.created_at.isoformat()
                }
                for issue in issues
            ]
        
        # Return based on format
        if format == "json":
            return report_data
        elif format == "csv":
            # Generate CSV response
            import csv
            from io import StringIO
            
            output = StringIO()
            writer = csv.writer(output)
            
            # Write headers
            writer.writerow(["Quality Report", project.name])
            writer.writerow([])
            writer.writerow(["Project Information"])
            writer.writerow(["ID", project_id])
            writer.writerow(["Name", project.name])
            writer.writerow(["Language", project.language])
            writer.writerow([])
            writer.writerow(["Quality Metrics"])
            writer.writerow(["Maintainability Rating", project.maintainability_rating])
            writer.writerow(["Security Rating", project.security_rating])
            writer.writerow(["Reliability Rating", project.reliability_rating])
            writer.writerow(["Coverage", f"{project.coverage}%"])
            writer.writerow(["Technical Debt", f"{project.technical_debt} minutes"])
            writer.writerow(["Debt Ratio", f"{project.debt_ratio}%"])
            
            output.seek(0)
            return Response(content=output.getvalue(), media_type="text/csv")
        else:
            raise HTTPException(status_code=400, detail="Unsupported format")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating quality report: {str(e)}")

@router.post("/projects/{project_id}/quality-gate/evaluate")
async def evaluate_project_quality_gate(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Manually evaluate quality gate for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get quality gate
        quality_gate_result = await db.execute(
            select(SASTQualityGate).where(SASTQualityGate.project_id == project_id)
        )
        quality_gate = quality_gate_result.scalar_one_or_none()
        
        if not quality_gate:
            raise HTTPException(status_code=404, detail="Quality gate not found")
        
        # Evaluate quality gate based on current project metrics
        evaluation_results = {}
        gate_status = QualityGateStatus.PASSED
        
        # Check vulnerability thresholds
        if project.vulnerability_count > quality_gate.max_blocker_issues:
            evaluation_results["blocker_issues"] = f"Failed: {project.vulnerability_count} > {quality_gate.max_blocker_issues}"
            gate_status = QualityGateStatus.FAILED
        else:
            evaluation_results["blocker_issues"] = f"Passed: {project.vulnerability_count} <= {quality_gate.max_blocker_issues}"
        
        # Check coverage threshold
        if project.coverage < quality_gate.min_coverage:
            evaluation_results["coverage"] = f"Failed: {project.coverage}% < {quality_gate.min_coverage}%"
            gate_status = QualityGateStatus.FAILED
        else:
            evaluation_results["coverage"] = f"Passed: {project.coverage}% >= {quality_gate.min_coverage}%"
        
        # Check technical debt threshold
        if project.debt_ratio > quality_gate.max_debt_ratio:
            evaluation_results["debt_ratio"] = f"Failed: {project.debt_ratio}% > {quality_gate.max_debt_ratio}%"
            gate_status = QualityGateStatus.FAILED
        else:
            evaluation_results["debt_ratio"] = f"Passed: {project.debt_ratio}% <= {quality_gate.max_debt_ratio}%"
        
        # Update quality gate status
        quality_gate.status = gate_status
        quality_gate.last_evaluation = datetime.now()
        quality_gate.evaluation_results = evaluation_results
        
        await db.commit()
        
        return {
            "project_id": project_id,
            "quality_gate_status": gate_status,
            "evaluation_results": evaluation_results,
            "evaluated_at": quality_gate.last_evaluation.isoformat(),
            "next_evaluation": "Automatic on next scan or manual trigger"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error evaluating quality gate: {str(e)}")

@router.get("/quality-management/dashboard")
async def get_quality_management_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get quality management dashboard overview"""
    try:
        # Get total projects
        total_projects_result = await db.execute(select(func.count(SASTProject.id)))
        total_projects = total_projects_result.scalar() or 0
        
        # Get projects by quality gate status
        passed_projects_result = await db.execute(
            select(func.count(SASTProject.id))
            .select_from(SASTProject)
            .join(SASTQualityGate)
            .where(SASTQualityGate.status == QualityGateStatus.PASSED)
        )
        passed_projects = passed_projects_result.scalar() or 0
        
        failed_projects_result = await db.execute(
            select(func.count(SASTProject.id))
            .select_from(SASTProject)
            .join(SASTQualityGate)
            .where(SASTQualityGate.status == QualityGateStatus.FAILED)
        )
        failed_projects = failed_projects_result.scalar() or 0
        
        # Get average ratings
        avg_maintainability_result = await db.execute(
            select(func.avg(SASTProject.maintainability_rating))
        )
        avg_maintainability = avg_maintainability_result.scalar()
        
        avg_security_result = await db.execute(
            select(func.avg(SASTProject.security_rating))
        )
        avg_security = avg_security_result.scalar()
        
        avg_reliability_result = await db.execute(
            select(func.avg(SASTProject.reliability_rating))
        )
        avg_reliability = avg_reliability_result.scalar()
        
        # Get total technical debt
        total_debt_result = await db.execute(
            select(func.sum(SASTProject.technical_debt))
        )
        total_debt = total_debt_result.scalar() or 0
        
        # Get average coverage
        avg_coverage_result = await db.execute(
            select(func.avg(SASTProject.coverage))
        )
        avg_coverage = avg_coverage_result.scalar() or 0
        
        return {
            "summary": {
                "total_projects": total_projects,
                "passed_projects": passed_projects,
                "failed_projects": failed_projects,
                "pass_rate": round((passed_projects / total_projects * 100), 2) if total_projects > 0 else 0
            },
            "average_ratings": {
                "maintainability": avg_maintainability,
                "security": avg_security,
                "reliability": avg_reliability
            },
            "overall_metrics": {
                "total_technical_debt_hours": round(total_debt / 60, 2),
                "average_coverage": round(avg_coverage, 2)
            },
            "quality_distribution": {
                "excellent": 0,  # A rating
                "good": 0,       # B rating
                "moderate": 0,   # C rating
                "poor": 0,       # D rating
                "very_poor": 0   # E rating
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality management dashboard: {str(e)}")

# ============================================================================
# Project Configuration Endpoints
# ============================================================================

@router.get("/projects/{project_id}/configuration")
async def get_project_configuration(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get project configuration"""
    try:
        result = await db.execute(
            select(SASTProjectConfiguration).where(SASTProjectConfiguration.project_id == int(project_id))
        )
        config = result.scalar_one_or_none()
        
        if not config:
            return {
                "project_id": project_id,
                "scan_patterns": [],
                "excluded_files": [],
                "excluded_directories": [],
                "enabled_rules": [],
                "disabled_rules": [],
                "rule_severities": {},
                "quality_gate_id": None
            }
        
        return {
            "project_id": str(config.project_id),
            "scan_patterns": config.scan_patterns or [],
            "excluded_files": config.excluded_files or [],
            "excluded_directories": config.excluded_directories or [],
            "enabled_rules": config.enabled_rules or [],
            "disabled_rules": config.disabled_rules or [],
            "rule_severities": config.rule_severities or {},
            "quality_gate_id": str(config.quality_gate_id) if config.quality_gate_id else None
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting project configuration: {str(e)}")

@router.put("/projects/{project_id}/configuration")
async def update_project_configuration(
    project_id: str,
    config_data: SASTProjectCreate, # Changed from SASTProjectConfigSchema to SASTProjectCreate to match existing schema
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update project configuration"""
    try:
        result = await db.execute(
            select(SASTProjectConfiguration).where(SASTProjectConfiguration.project_id == int(project_id))
        )
        config = result.scalar_one_or_none()
        
        if config:
            # Update existing configuration
            config.scan_patterns = config_data.scan_patterns
            config.excluded_files = config_data.excluded_files
            config.excluded_directories = config_data.excluded_directories
            config.enabled_rules = config_data.enabled_rules
            config.disabled_rules = config_data.disabled_rules
            config.rule_severities = config_data.rule_severities
            config.quality_gate_id = int(config_data.quality_gate_id) if config_data.quality_gate_id else None
            config.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        else:
            # Create new configuration
            config = SASTProjectConfiguration(
                project_id=int(project_id),
                scan_patterns=config_data.scan_patterns,
                excluded_files=config_data.excluded_files,
                excluded_directories=config_data.excluded_directories,
                enabled_rules=config_data.enabled_rules,
                disabled_rules=config_data.disabled_rules,
                rule_severities=config_data.rule_severities,
                quality_gate_id=int(config_data.quality_gate_id) if config_data.quality_gate_id else None
            )
            db.add(config)
        
        await db.commit()
        
        return {
            "message": "Project configuration updated successfully",
            "configuration": {
                "project_id": str(config.project_id),
                "scan_patterns": config.scan_patterns,
                "excluded_files": config.excluded_files,
                "excluded_directories": config.excluded_directories,
                "enabled_rules": config.enabled_rules,
                "disabled_rules": config.disabled_rules,
                "rule_severities": config.rule_severities,
                "quality_gate_id": str(config.quality_gate_id) if config.quality_gate_id else None
            }
        }
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating project configuration: {str(e)}") 

# Add new endpoints after the existing ones

# ============================================================================
# Duplications Endpoints
# ============================================================================

@router.get("/projects/{project_id}/duplications")
async def get_project_duplications(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get code duplications for a specific project from database"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == int(project_id))
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get duplications for this project
        duplications_result = await db.execute(
            select(SASTDuplication).where(SASTDuplication.project_id == int(project_id))
        )
        duplications = duplications_result.scalars().all()
        
        # Calculate summary
        total_duplicated_lines = sum(d.duplicated_lines for d in duplications)
        total_duplicated_blocks = sum(d.duplicated_blocks for d in duplications)
        duplication_density = sum(d.duplication_density for d in duplications) / len(duplications) if duplications else 0
        files_with_duplications = len(duplications)
        
        # Group by language
        language_stats = {}
        for dup in duplications:
            if dup.language not in language_stats:
                language_stats[dup.language] = {
                    "duplicatedLines": 0,
                    "duplicatedFiles": 0,
                    "duplicationDensity": 0,
                    "count": 0
                }
            language_stats[dup.language]["duplicatedLines"] += dup.duplicated_lines
            language_stats[dup.language]["duplicatedFiles"] += 1
            language_stats[dup.language]["duplicationDensity"] += dup.duplication_density
            language_stats[dup.language]["count"] += 1
        
        # Calculate average density per language and add colors
        duplications_by_language = []
        colors = ["#3b82f6", "#ef4444", "#10b981", "#f59e0b", "#8b5cf6", "#06b6d4"]
        for i, (lang, stats) in enumerate(language_stats.items()):
            avg_density = stats["duplicationDensity"] / stats["count"] if stats["count"] > 0 else 0
            duplications_by_language.append({
                "language": lang,
                "duplicatedLines": stats["duplicatedLines"],
                "duplicatedFiles": stats["duplicatedFiles"],
                "duplicationDensity": round(avg_density, 1),
                "color": colors[i % len(colors)]
            })
        
        # Sort by duplicated lines
        duplications_by_language.sort(key=lambda x: x["duplicatedLines"], reverse=True)
        
        # Get file-level details
        duplications_by_file = []
        for dup in duplications:
            duplications_by_file.append({
                "file": dup.file_path,
                "duplicatedLines": dup.duplicated_lines,
                "duplicatedBlocks": dup.duplicated_blocks,
                "duplicationDensity": round(dup.duplication_density, 1),
                "lastModified": dup.last_modified.isoformat() if dup.last_modified else None
            })
        
        # Sort by duplicated lines
        duplications_by_file.sort(key=lambda x: x["duplicatedLines"], reverse=True)
        
        # Generate trends (last 5 scans)
        duplication_trend = []
        scans_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == int(project_id))
            .order_by(SASTScan.started_at.desc())
            .limit(5)
        )
        scans = scans_result.scalars().all()
        
        for scan in reversed(scans):
            scan_duplications_result = await db.execute(
                select(SASTDuplication).where(SASTDuplication.scan_id == scan.id)
            )
            scan_duplications = scan_duplications_result.scalars().all()
            
            total_lines = sum(d.duplicated_lines for d in scan_duplications)
            total_files = len(scan_duplications)
            avg_density = sum(d.duplication_density for d in scan_duplications) / len(scan_duplications) if scan_duplications else 0
            
            duplication_trend.append({
                "date": scan.started_at.strftime("%Y-%m-%d"),
                "duplicatedLines": total_lines,
                "duplicatedFiles": total_files,
                "duplicationDensity": round(avg_density, 1)
            })
        
        return {
            "duplicatedLines": total_duplicated_lines,
            "duplicatedFiles": files_with_duplications,
            "duplicatedBlocks": total_duplicated_blocks,
            "duplicationDensity": round(duplication_density, 1),
            "duplicationsByLanguage": duplications_by_language,
            "duplicationsByFile": duplications_by_file[:10],  # Top 10 files
            "duplicationTrend": duplication_trend
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching duplications: {str(e)}")

# ============================================================================
# Security Reports Endpoints
# ============================================================================

@router.get("/projects/{project_id}/security-reports")
async def get_project_security_reports(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive security reports for a project"""
    try:
        # Mock data for security reports
        security_reports = {
            "overallSecurityRating": "B",
            "securityScore": 75,
            "vulnerabilitiesByCategory": [
                {"category": "SQL Injection", "count": 3, "severity": "CRITICAL", "percentage": 25, "color": "#ef4444"},
                {"category": "XSS", "count": 2, "severity": "MAJOR", "percentage": 17, "color": "#f59e0b"}
            ],
            "owaspTop10Mapping": [
                {"category": "A01:2021 - Broken Access Control", "count": 2, "severity": "CRITICAL", "description": "Access control vulnerabilities", "color": "#ef4444"},
                {"category": "A03:2021 - Injection", "count": 5, "severity": "CRITICAL", "description": "SQL injection and XSS vulnerabilities", "color": "#ef4444"}
            ],
            "cweMapping": [
                {"cweId": "CWE-89", "name": "SQL Injection", "count": 3, "severity": "CRITICAL", "description": "SQL injection vulnerabilities"},
                {"cweId": "CWE-79", "name": "Cross-site Scripting", "count": 2, "severity": "MAJOR", "description": "XSS vulnerabilities"}
            ],
            "securityTrend": [
                {"date": "2024-01-10", "vulnerabilities": 15, "securityScore": 65, "securityRating": "C"},
                {"date": "2024-01-15", "vulnerabilities": 12, "securityScore": 75, "securityRating": "B"}
            ]
        }
        return security_reports
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching security reports: {str(e)}")

# ============================================================================
# Reliability Endpoints
# ============================================================================

@router.get("/projects/{project_id}/reliability")
async def get_project_reliability(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get reliability metrics for a project"""
    try:
        # Mock data for reliability
        reliability_data = {
            "reliabilityRating": "A",
            "bugCount": 8,
            "bugDensity": 0.5,
            "bugsBySeverity": [
                {"severity": "BLOCKER", "count": 1, "percentage": 12.5, "color": "#dc2626"},
                {"severity": "CRITICAL", "count": 2, "percentage": 25, "color": "#ea580c"}
            ],
            "bugsByCategory": [
                {"category": "Null Pointer Exception", "count": 3, "description": "Null pointer dereference bugs", "color": "#ef4444"},
                {"category": "Array Index Out of Bounds", "count": 2, "description": "Array access violations", "color": "#f59e0b"}
            ],
            "reliabilityTrend": [
                {"date": "2024-01-10", "bugCount": 12, "bugDensity": 0.8, "reliabilityRating": "B"},
                {"date": "2024-01-15", "bugCount": 8, "bugDensity": 0.5, "reliabilityRating": "A"}
            ],
            "newBugs": 2,
            "resolvedBugs": 6
        }
        return reliability_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching reliability data: {str(e)}")

# ============================================================================
# Maintainability Endpoints
# ============================================================================

@router.get("/projects/{project_id}/maintainability")
async def get_project_maintainability(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get maintainability metrics for a project"""
    try:
        # Mock data for maintainability
        maintainability_data = {
            "maintainabilityRating": "A",
            "codeSmellCount": 25,
            "codeSmellDensity": 1.6,
            "complexity": 15,
            "cognitiveComplexity": 8,
            "codeSmellsByCategory": [
                {"category": "Code Smells", "count": 15, "description": "General code quality issues", "color": "#3b82f6"},
                {"category": "Unused Code", "count": 5, "description": "Dead code and unused variables", "color": "#10b981"}
            ],
            "maintainabilityTrend": [
                {"date": "2024-01-10", "codeSmellCount": 30, "maintainabilityRating": "B", "complexity": 18},
                {"date": "2024-01-15", "codeSmellCount": 25, "maintainabilityRating": "A", "complexity": 15}
            ]
        }
        return maintainability_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching maintainability data: {str(e)}")

# ============================================================================
# Activity Endpoints
# ============================================================================

@router.get("/projects/{project_id}/activity")
async def get_project_activity(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get project activity and contributor information"""
    try:
        # Mock data for activity
        activity_data = {
            "recentCommits": [
                {"id": "abc123", "author": "john.doe@example.com", "message": "Fix SQL injection vulnerability", "timestamp": "2024-01-15T10:30:00Z", "filesChanged": 3, "linesAdded": 15, "linesRemoved": 8},
                {"id": "def456", "author": "jane.smith@example.com", "message": "Add input validation", "timestamp": "2024-01-15T09:15:00Z", "filesChanged": 2, "linesAdded": 12, "linesRemoved": 5}
            ],
            "recentIssues": [
                {"id": 1, "type": "VULNERABILITY", "severity": "CRITICAL", "status": "RESOLVED", "author": "john.doe@example.com", "timestamp": "2024-01-15T10:30:00Z", "message": "SQL injection fixed"},
                {"id": 2, "type": "BUG", "severity": "MAJOR", "status": "OPEN", "author": "jane.smith@example.com", "timestamp": "2024-01-15T09:15:00Z", "message": "Null pointer exception"}
            ],
            "activityMetrics": {
                "totalCommits": 45,
                "totalIssues": 12,
                "totalHotspots": 8,
                "activeContributors": 5,
                "averageCommitFrequency": 3.2
            },
            "contributors": [
                {"name": "john.doe@example.com", "commits": 15, "issues": 4, "hotspots": 3, "lastActivity": "2024-01-15T10:30:00Z"},
                {"name": "jane.smith@example.com", "commits": 12, "issues": 3, "hotspots": 2, "lastActivity": "2024-01-15T09:15:00Z"}
            ],
            "activityTrend": [
                {"date": "2024-01-10", "commits": 5, "issues": 2, "hotspots": 1},
                {"date": "2024-01-15", "commits": 3, "issues": 2, "hotspots": 2}
            ]
        }
        return activity_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching activity data: {str(e)}")

# ============================================================================
# Administration Endpoints
# ============================================================================

@router.get("/projects/{project_id}/configuration")
async def get_project_configuration(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get project configuration and settings"""
    try:
        # Mock data for project configuration
        configuration_data = {
            "id": 1,
            "name": "Web Application Security",
            "key": "web-app-sec",
            "description": "Main web application security project",
            "language": "JavaScript",
            "repositoryUrl": "https://github.com/example/web-app",
            "branch": "main",
            "qualityProfile": "Sonar way",
            "qualityGate": "Default Quality Gate",
            "exclusions": ["**/node_modules/**", "**/dist/**", "**/coverage/**"],
            "settings": {
                "scanSchedule": "0 2 * * *",
                "autoScan": True,
                "notifications": {
                    "email": True,
                    "slack": False,
                    "webhook": "https://hooks.slack.com/services/xxx/yyy/zzz"
                },
                "integrations": {
                    "gitHub": True,
                    "gitLab": False,
                    "bitbucket": False,
                    "jenkins": True
                }
            },
            "permissions": {
                "users": [
                    {"username": "john.doe@example.com", "role": "Admin", "permissions": ["read", "write", "admin"]},
                    {"username": "jane.smith@example.com", "role": "User", "permissions": ["read", "write"]}
                ],
                "groups": [
                    {"groupName": "developers", "role": "User", "permissions": ["read", "write"]},
                    {"groupName": "security-team", "role": "Admin", "permissions": ["read", "write", "admin"]}
                ]
            }
        }
        return configuration_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching project configuration: {str(e)}")

@router.put("/projects/{project_id}/configuration")
async def update_project_configuration(
    project_id: str,
    configuration_data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update project configuration and settings"""
    try:
        # Mock update - replace with actual database update
        return {"message": "Project configuration updated successfully", "project_id": project_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating project configuration: {str(e)}")

# ============================================================================
# Additional Utility Endpoints
# ============================================================================

@router.get("/projects/{project_id}/metrics")
async def get_project_metrics(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive project metrics"""
    try:
        # Mock comprehensive metrics
        metrics_data = {
            "overview": {
                "linesOfCode": 15420,
                "files": 245,
                "functions": 1200,
                "classes": 89,
                "complexity": 15.2
            },
            "quality": {
                "maintainabilityRating": "A",
                "securityRating": "B",
                "reliabilityRating": "A",
                "coverage": 78.5,
                "duplicationDensity": 3.2
            },
            "issues": {
                "total": 19,
                "bugs": 5,
                "vulnerabilities": 2,
                "codeSmells": 12,
                "securityHotspots": 3
            },
            "technicalDebt": {
                "totalDebt": 120,
                "debtRatio": 8.5,
                "effortToFix": "2h 30m"
            }
        }
        return metrics_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching project metrics: {str(e)}")

@router.get("/projects/{project_id}/trends")
async def get_project_trends(
    project_id: str,
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get project trends over time"""
    try:
        # Mock trend data
        trends_data = {
            "issues": [
                {"date": "2024-01-10", "total": 25, "bugs": 8, "vulnerabilities": 5, "codeSmells": 12},
                {"date": "2024-01-15", "total": 19, "bugs": 5, "vulnerabilities": 2, "codeSmells": 12}
            ],
            "coverage": [
                {"date": "2024-01-10", "coverage": 75.0},
                {"date": "2024-01-15", "coverage": 78.5}
            ],
            "duplications": [
                {"date": "2024-01-10", "duplicationDensity": 3.8},
                {"date": "2024-01-15", "duplicationDensity": 3.2}
            ],
            "complexity": [
                {"date": "2024-01-10", "complexity": 16.5},
                {"date": "2024-01-15", "complexity": 15.2}
            ]
        }
        return trends_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching project trends: {str(e)}")

# ============================================================================
# Quality Profiles Endpoints
# ============================================================================

@router.get("/quality-profiles")
async def get_quality_profiles(
    language: Optional[str] = Query(None),
    is_default: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get quality profiles with filtering"""
    try:
        # Mock quality profiles data
        profiles_data = [
            {
                "id": "1",
                "name": "Sonar way",
                "description": "Default profile for most languages with common security and quality rules",
                "language": "java",
                "is_default": True,
                "active_rule_count": 156,
                "deprecated_rule_count": 12,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-15T00:00:00Z"
            },
            {
                "id": "2",
                "name": "Security Profile",
                "description": "High-security profile with strict security rules enabled",
                "language": "java",
                "is_default": False,
                "active_rule_count": 89,
                "deprecated_rule_count": 5,
                "created_at": "2024-01-05T00:00:00Z",
                "updated_at": "2024-01-15T00:00:00Z"
            },
            {
                "id": "3",
                "name": "Python Best Practices",
                "description": "Profile optimized for Python development with PEP 8 compliance",
                "language": "python",
                "is_default": False,
                "active_rule_count": 78,
                "deprecated_rule_count": 3,
                "created_at": "2024-01-10T00:00:00Z",
                "updated_at": "2024-01-15T00:00:00Z"
            },
            {
                "id": "4",
                "name": "JavaScript ES6+",
                "description": "Modern JavaScript profile with ES6+ and security rules",
                "language": "javascript",
                "is_default": False,
                "active_rule_count": 92,
                "deprecated_rule_count": 8,
                "created_at": "2024-01-12T00:00:00Z",
                "updated_at": "2024-01-15T00:00:00Z"
            }
        ]

        # Apply filters
        if language:
            profiles_data = [p for p in profiles_data if p["language"] == language]
        
        if is_default is not None:
            profiles_data = [p for p in profiles_data if p["is_default"] == is_default]

        return {
            "profiles": profiles_data,
            "total": len(profiles_data),
            "languages": ["java", "python", "javascript", "typescript", "csharp", "php"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality profiles: {str(e)}")

@router.post("/quality-profiles")
async def create_quality_profile(
    profile_data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new quality profile"""
    try:
        # Mock profile creation
        new_profile = {
            "id": str(len(profile_data) + 1),  # Simple ID generation
            "name": profile_data.get("name", "New Profile"),
            "description": profile_data.get("description", ""),
            "language": profile_data.get("language", "java"),
            "is_default": False,
            "active_rule_count": 0,
            "deprecated_rule_count": 0,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        return {
            "message": "Quality profile created successfully",
            "profile": new_profile
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating quality profile: {str(e)}")

@router.put("/quality-profiles/{profile_id}")
async def update_quality_profile(
    profile_id: str,
    profile_data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update an existing quality profile"""
    try:
        # Mock profile update
        updated_profile = {
            "id": profile_id,
            "name": profile_data.get("name", "Updated Profile"),
            "description": profile_data.get("description", ""),
            "language": profile_data.get("language", "java"),
            "is_default": profile_data.get("is_default", False),
            "active_rule_count": profile_data.get("active_rule_count", 0),
            "deprecated_rule_count": profile_data.get("deprecated_rule_count", 0),
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": datetime.utcnow().isoformat()
        }
        
        return {
            "message": "Quality profile updated successfully",
            "profile": updated_profile
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating quality profile: {str(e)}")

@router.delete("/quality-profiles/{profile_id}")
async def delete_quality_profile(
    profile_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a quality profile"""
    try:
        # Mock profile deletion
        return {
            "message": "Quality profile deleted successfully",
            "profile_id": profile_id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting quality profile: {str(e)}")

@router.post("/quality-profiles/{profile_id}/duplicate")
async def duplicate_quality_profile(
    profile_id: str,
    duplicate_data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Duplicate an existing quality profile"""
    try:
        # Mock profile duplication
        duplicated_profile = {
            "id": str(int(profile_id) + 100),  # Simple ID generation
            "name": duplicate_data.get("name", f"Profile {profile_id} - Copy"),
            "description": duplicate_data.get("description", "Duplicated profile"),
            "language": duplicate_data.get("language", "java"),
            "is_default": False,
            "active_rule_count": 0,
            "deprecated_rule_count": 0,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        return {
            "message": "Quality profile duplicated successfully",
            "profile": duplicated_profile
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error duplicating quality profile: {str(e)}")

@router.post("/quality-profiles/{profile_id}/set-default")
async def set_default_quality_profile(
    profile_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Set a quality profile as default for its language"""
    try:
        # Mock setting default profile
        return {
            "message": "Quality profile set as default successfully",
            "profile_id": profile_id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error setting default quality profile: {str(e)}")

@router.get("/quality-profiles/{profile_id}/rules")
async def get_profile_rules(
    profile_id: str,
    enabled_only: Optional[bool] = Query(False),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get rules for a specific quality profile"""
    try:
        # Mock profile rules data
        rules_data = [
            {
                "id": "1",
                "rule_id": "S1488",
                "name": "Local variables should not be declared and then immediately returned",
                "severity": "minor",
                "category": "Code Smell",
                "enabled": True,
                "effort": "5min"
            },
            {
                "id": "2",
                "rule_id": "S1172",
                "name": "Unused function parameters should be removed",
                "severity": "major",
                "category": "Code Smell",
                "enabled": True,
                "effort": "5min"
            },
            {
                "id": "3",
                "rule_id": "S1135",
                "name": "Track uses of 'FIXME' tags",
                "severity": "info",
                "category": "Code Smell",
                "enabled": False,
                "effort": "10min"
            }
        ]

        # Apply enabled filter if requested
        if enabled_only:
            rules_data = [r for r in rules_data if r["enabled"]]

        return {
            "profile_id": profile_id,
            "rules": rules_data,
            "total": len(rules_data),
            "enabled_count": len([r for r in rules_data if r["enabled"]]),
            "disabled_count": len([r for r in rules_data if not r["enabled"]])
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting profile rules: {str(e)}")

@router.put("/quality-profiles/{profile_id}/rules/{rule_id}")
async def update_profile_rule(
    profile_id: str,
    rule_id: str,
    rule_data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a rule in a quality profile (enable/disable, change severity, etc.)"""
    try:
        # Mock rule update
        updated_rule = {
            "id": rule_id,
            "rule_id": rule_data.get("rule_id", "S0000"),
            "name": rule_data.get("name", "Updated Rule"),
            "severity": rule_data.get("severity", "minor"),
            "category": rule_data.get("category", "Code Smell"),
            "enabled": rule_data.get("enabled", True),
            "effort": rule_data.get("effort", "5min")
        }
        
        return {
            "message": "Profile rule updated successfully",
            "rule": updated_rule
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating profile rule: {str(e)}")

# ============================================================================
# Bulk Operations Endpoints
# ============================================================================

@router.put("/vulnerabilities/bulk-update")
async def bulk_update_vulnerabilities(
    update_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Bulk update vulnerabilities"""
    try:
        vulnerability_ids = update_data.get("vulnerability_ids", [])
        updates = update_data.get("updates", {})
        
        if not vulnerability_ids:
            raise HTTPException(status_code=400, detail="No vulnerability IDs provided")
        
        # Update vulnerabilities
        for vuln_id in vulnerability_ids:
            await db.execute(
                update(SASTIssue)
                .where(SASTIssue.id == int(vuln_id))
                .values(**updates, updated_at=datetime.now(timezone.utc).replace(tzinfo=None))
            )
        
        await db.commit()
        return {"message": f"Successfully updated {len(vulnerability_ids)} vulnerabilities"}
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error bulk updating vulnerabilities: {str(e)}")

@router.delete("/vulnerabilities/bulk-delete")
async def bulk_delete_vulnerabilities(
    delete_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Bulk delete vulnerabilities"""
    try:
        vulnerability_ids = delete_data.get("vulnerability_ids", [])
        
        if not vulnerability_ids:
            raise HTTPException(status_code=400, detail="No vulnerability IDs provided")
        
        # Delete vulnerabilities
        for vuln_id in vulnerability_ids:
            await db.execute(delete(SASTIssue).where(SASTIssue.id == int(vuln_id)))
        
        await db.commit()
        return {"message": f"Successfully deleted {len(vulnerability_ids)} vulnerabilities"}
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error bulk deleting vulnerabilities: {str(e)}")

# ============================================================================
# File Upload and Scanning Endpoints
# ============================================================================

@router.post("/scan/upload")
async def upload_and_scan_file(
    file: UploadFile = File(...),
    project_id: str = Form(...),
    scan_config: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Upload a file and start scanning"""
    try:
        # Parse scan config
        config = json.loads(scan_config) if scan_config else {}
        
        # Create scan record
        scan = SASTScan(
            project_id=int(project_id),
            scan_type=config.get("scan_type", "upload"),
            branch=config.get("branch", "main"),
            status=ScanStatus.PENDING,
            started_by=current_user.id
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        
        # Save uploaded file
        upload_dir = Path("uploads/sast")
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        file_path = upload_dir / f"{scan.id}_{file.filename}"
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Start background scan
        background_tasks.add_task(process_uploaded_file, str(file_path), scan.id, db)
        
        return {
            "message": "File uploaded and scan started",
            "scan_id": str(scan.id),
            "file_path": str(file_path)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error uploading file: {str(e)}")

async def process_uploaded_file(file_path: str, scan_id: str, db: AsyncSession):
    """Process uploaded file in background"""
    try:
        # Extract and analyze file
        if file_path.endswith('.zip'):
            # Handle zip files
            extract_dir = Path(file_path).parent / f"extract_{scan_id}"
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Scan extracted files
            scanner = SASTScanner(str(extract_dir), scan_id)
            vulnerabilities = await scanner.scan_project()
        else:
            # Handle single file
            scanner = SASTScanner(str(Path(file_path).parent), scan_id)
            vulnerabilities = await scanner.scan_project()
        
        # Update scan with results
        await update_scan_results(scan_id, vulnerabilities, db)
        
    except Exception as e:
        logger.error(f"Error processing uploaded file: {e}")
        # Update scan status to failed
        await update_scan_status(scan_id, ScanStatus.FAILED, str(e), db)

async def update_scan_results(scan_id: str, vulnerabilities: List[Any], db: AsyncSession):
    """Update scan with results"""
    try:
        scan_result = await db.execute(select(SASTScan).where(SASTScan.id == int(scan_id)))
        scan = scan_result.scalar_one_or_none()
        
        if scan:
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            scan.vulnerabilities_found = len(vulnerabilities)
            scan.issues_found = len(vulnerabilities)
            
            # Store vulnerabilities
            for vuln in vulnerabilities:
                issue = SASTIssue(
                    project_id=scan.project_id,
                    scan_id=scan.id,
                    rule_id=vuln.rule_id,
                    rule_name=vuln.rule_name,
                    message=vuln.description,
                    file_path=vuln.file_name,
                    line_number=vuln.line_number,
                    severity=IssueSeverity(vuln.severity.upper()),
                    type=IssueType.VULNERABILITY,
                    cwe_id=vuln.cwe_id,
                    created_at=datetime.now(timezone.utc).replace(tzinfo=None)
                )
                db.add(issue)
            
            await db.commit()
            
    except Exception as e:
        logger.error(f"Error updating scan results: {e}")

async def update_scan_status(scan_id: str, status: ScanStatus, error_message: str, db: AsyncSession):
    """Update scan status"""
    try:
        scan_result = await db.execute(select(SASTScan).where(SASTScan.id == int(scan_id)))
        scan = scan_result.scalar_one_or_none()
        
        if scan:
            scan.status = status
            scan.error_message = error_message
            if status == ScanStatus.COMPLETED:
                scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            
            await db.commit()
            
    except Exception as e:
        logger.error(f"Error updating scan status: {e}")

# ============================================================================
# Enhanced Rule Management Endpoints
# ============================================================================

@router.post("/rules", response_model=Dict[str, Any])
async def create_custom_rule(
    rule_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a custom SAST rule"""
    try:
        # Validate rule data
        required_fields = ["rule_id", "name", "category", "severity", "type", "languages"]
        for field in required_fields:
            if field not in rule_data:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Create new rule
        new_rule = SASTRule(
            rule_id=rule_data["rule_id"],
            name=rule_data["name"],
            description=rule_data.get("description", ""),
            category=rule_data["category"],
            subcategory=rule_data.get("subcategory"),
            severity=IssueSeverity(rule_data["severity"].upper()),
            type=IssueType(rule_data["type"].upper()),
            cwe_id=rule_data.get("cwe_id"),
            owasp_category=rule_data.get("owasp_category"),
            tags=rule_data.get("tags", []),
            enabled=rule_data.get("enabled", True),
            effort=rule_data.get("effort", 0),
            languages=rule_data["languages"],
            created_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        
        db.add(new_rule)
        await db.commit()
        await db.refresh(new_rule)
        
        return {
            "message": "Custom rule created successfully",
            "rule": {
                "id": str(new_rule.id),
                "rule_id": new_rule.rule_id,
                "name": new_rule.name,
                "category": new_rule.category,
                "severity": new_rule.severity.value,
                "type": new_rule.type.value,
                "languages": new_rule.languages
            }
        }
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating custom rule: {str(e)}")

@router.put("/rules/{rule_id}", response_model=Dict[str, Any])
async def update_rule(
    rule_id: str,
    rule_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update an existing SAST rule"""
    try:
        rule_result = await db.execute(select(SASTRule).where(SASTRule.rule_id == rule_id))
        rule = rule_result.scalar_one_or_none()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        
        # Update fields
        updateable_fields = ["name", "description", "category", "subcategory", "severity", 
                           "type", "cwe_id", "owasp_category", "tags", "enabled", "effort", "languages"]
        
        for field in updateable_fields:
            if field in rule_data:
                if field == "severity":
                    rule.severity = IssueSeverity(rule_data[field].upper())
                elif field == "type":
                    rule.type = IssueType(rule_data[field].upper())
                else:
                    setattr(rule, field, rule_data[field])
        
        rule.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        await db.commit()
        await db.refresh(rule)
        
        return {
            "message": "Rule updated successfully",
            "rule": {
                "id": str(rule.id),
                "rule_id": rule.rule_id,
                "name": rule.name,
                "category": rule.category,
                "severity": rule.severity.value,
                "type": rule.type.value,
                "languages": rule.languages
            }
        }
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating rule: {str(e)}")

@router.delete("/rules/{rule_id}")
async def delete_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a SAST rule"""
    try:
        rule_result = await db.execute(select(SASTRule).where(SASTRule.rule_id == rule_id))
        rule = rule_result.scalar_one_or_none()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        
        # Check if rule is being used
        usage_result = await db.execute(
            select(func.count(SASTIssue.id)).where(SASTIssue.rule_id == rule_id)
        )
        usage_count = usage_result.scalar() or 0
        
        if usage_count > 0:
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot delete rule: it is used by {usage_count} existing issues"
            )
        
        await db.delete(rule)
        await db.commit()
        
        return {"message": "Rule deleted successfully"}
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting rule: {str(e)}")

# ============================================================================
# Scan Management Enhancement Endpoints
# ============================================================================

@router.post("/scans/{scan_id}/stop")
async def stop_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Stop a running scan"""
    try:
        scan_result = await db.execute(select(SASTScan).where(SASTScan.id == int(scan_id)))
        scan = scan_result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if scan.status not in [ScanStatus.PENDING, ScanStatus.IN_PROGRESS]:
            raise HTTPException(status_code=400, detail="Scan is not running")
        
        scan.status = ScanStatus.CANCELLED
        scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        await db.commit()
        
        return {"message": "Scan stopped successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error stopping scan: {str(e)}")

@router.get("/scans/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    format: str = Query("json", regex="^(json|pdf|csv)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get scan report in specified format"""
    try:
        scan_result = await db.execute(select(SASTScan).where(SASTScan.id == int(scan_id)))
        scan = scan_result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get scan issues
        issues_result = await db.execute(
            select(SASTIssue).where(SASTIssue.scan_id == int(scan_id))
        )
        issues = issues_result.scalars().all()
        
        # Generate report data
        report_data = {
            "scan_id": str(scan.id),
            "project_id": scan.project_id,
            "status": scan.status.value,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration": scan.duration,
            "total_issues": len(issues),
            "vulnerabilities": len([i for i in issues if i.type == IssueType.VULNERABILITY]),
            "bugs": len([i for i in issues if i.type == IssueType.BUG]),
            "code_smells": len([i for i in issues if i.type == IssueType.CODE_SMELL]),
            "issues_by_severity": {},
            "issues_by_type": {},
            "issues": []
        }
        
        # Group issues by severity and type
        for issue in issues:
            severity = issue.severity.value.lower()
            issue_type = issue.type.value.lower()
            
            report_data["issues_by_severity"][severity] = report_data["issues_by_severity"].get(severity, 0) + 1
            report_data["issues_by_type"][issue_type] = report_data["issues_by_type"].get(issue_type, 0) + 1
            
            report_data["issues"].append({
                "id": str(issue.id),
                "rule_id": issue.rule_id,
                "rule_name": issue.rule_name,
                "message": issue.message,
                "severity": issue.severity.value,
                "type": issue.type.value,
                "file_path": issue.file_path,
                "line_number": issue.line_number,
                "cwe_id": issue.cwe_id,
                "cvss_score": issue.cvss_score,
                "owasp_category": issue.owasp_category
            })
        
        if format == "json":
            return report_data
        elif format == "csv":
            # Generate CSV content
            csv_content = generate_csv_report(report_data)
            return Response(
                content=csv_content,
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=scan_report_{scan_id}.csv"}
            )
        elif format == "pdf":
            # Generate PDF content (placeholder)
            pdf_content = generate_pdf_report(report_data)
            return Response(
                content=pdf_content,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=scan_report_{scan_id}.pdf"}
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating scan report: {str(e)}")

def generate_csv_report(report_data: Dict[str, Any]) -> str:
    """Generate CSV report content"""
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(["Scan Report"])
    writer.writerow([f"Scan ID: {report_data['scan_id']}"])
    writer.writerow([f"Total Issues: {report_data['total_issues']}"])
    writer.writerow([])
    
    # Write summary
    writer.writerow(["Issues by Severity"])
    for severity, count in report_data["issues_by_severity"].items():
        writer.writerow([severity.title(), count])
    
    writer.writerow([])
    writer.writerow(["Issues by Type"])
    for issue_type, count in report_data["issues_by_type"].items():
        writer.writerow([issue_type.title(), count])
    
    writer.writerow([])
    
    # Write detailed issues
    writer.writerow(["Issue Details"])
    writer.writerow(["ID", "Rule", "Message", "Severity", "Type", "File", "Line", "CWE", "CVSS", "OWASP"])
    
    for issue in report_data["issues"]:
        writer.writerow([
            issue["id"],
            issue["rule_name"],
            issue["message"],
            issue["severity"],
            issue["type"],
            issue["file_path"],
            issue["line_number"],
            issue["cwe_id"] or "",
            issue["cvss_score"] or "",
            issue["owasp_category"] or ""
        ])
    
    return output.getvalue()

def generate_pdf_report(report_data: Dict[str, Any]) -> bytes:
    """Generate PDF report content (placeholder)"""
    # This is a placeholder - in production you'd use a proper PDF library
    pdf_content = f"""
    Scan Report
    ===========
    
    Scan ID: {report_data['scan_id']}
    Total Issues: {report_data['total_issues']}
    
    Issues by Severity:
    {chr(10).join([f"- {k.title()}: {v}" for k, v in report_data['issues_by_severity'].items()])}
    
    Issues by Type:
    {chr(10).join([f"- {k.title()}: {v}" for k, v in report_data['issues_by_type'].items()])}
    """.encode('utf-8')
    
    return pdf_content

# ============================================================================
# Project Report Endpoints
# ============================================================================

@router.get("/projects/{project_id}/report")
async def get_project_report(
    project_id: str,
    format: str = Query("json", regex="^(json|pdf|csv)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive project report"""
    try:
        # Get project
        project_result = await db.execute(select(SASTProject).where(SASTProject.id == int(project_id)))
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get project scans
        scans_result = await db.execute(
            select(SASTScan).where(SASTScan.project_id == int(project_id))
        )
        scans = scans_result.scalars().all()
        
        # Get project issues
        issues_result = await db.execute(
            select(SASTIssue).where(SASTIssue.project_id == int(project_id))
        )
        issues = issues_result.scalars().all()
        
        # Generate report data
        report_data = {
            "project": {
                "id": str(project.id),
                "name": project.name,
                "key": project.key,
                "language": project.language,
                "quality_gate": project.quality_gate.value if project.quality_gate else "UNKNOWN",
                "security_rating": project.security_rating.value if project.security_rating else "UNKNOWN",
                "reliability_rating": project.reliability_rating.value if project.reliability_rating else "UNKNOWN",
                "maintainability_rating": project.maintainability_rating.value if project.maintainability_rating else "UNKNOWN"
            },
            "summary": {
                "total_scans": len(scans),
                "total_issues": len(issues),
                "vulnerabilities": len([i for i in issues if i.type == IssueType.VULNERABILITY]),
                "bugs": len([i for i in issues if i.type == IssueType.BUG]),
                "code_smells": len([i for i in issues if i.type == IssueType.CODE_SMELL]),
                "lines_of_code": project.lines_of_code or 0,
                "coverage": project.coverage or 0.0,
                "technical_debt": project.technical_debt or 0
            },
            "scans": [
                {
                    "id": str(scan.id),
                    "status": scan.status.value,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "issues_found": scan.issues_found or 0,
                    "vulnerabilities_found": scan.vulnerabilities_found or 0
                }
                for scan in scans
            ],
            "issues_by_severity": {},
            "issues_by_type": {},
            "recent_issues": []
        }
        
        # Group issues by severity and type
        for issue in issues:
            severity = issue.severity.value.lower()
            issue_type = issue.type.value.lower()
            
            report_data["issues_by_severity"][severity] = report_data["issues_by_severity"].get(severity, 0) + 1
            report_data["issues_by_type"][issue_type] = report_data["issues_by_type"].get(issue_type, 0) + 1
        
        # Get recent issues
        recent_issues = sorted(issues, key=lambda x: x.created_at, reverse=True)[:20]
        report_data["recent_issues"] = [
            {
                "id": str(issue.id),
                "rule_name": issue.rule_name,
                "severity": issue.severity.value,
                "type": issue.type.value,
                "file_path": issue.file_path,
                "line_number": issue.line_number,
                "created_at": issue.created_at.isoformat() if issue.created_at else None
            }
            for issue in recent_issues
        ]
        
        if format == "json":
            return report_data
        elif format == "csv":
            csv_content = generate_project_csv_report(report_data)
            return Response(
                content=csv_content,
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=project_report_{project_id}.csv"}
            )
        elif format == "pdf":
            pdf_content = generate_project_pdf_report(report_data)
            return Response(
                content=pdf_content,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=project_report_{project_id}.pdf"}
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating project report: {str(e)}")

def generate_project_csv_report(report_data: Dict[str, Any]) -> str:
    """Generate project CSV report content"""
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(["Project Report"])
    writer.writerow([f"Project: {report_data['project']['name']} ({report_data['project']['key']})"])
    writer.writerow([f"Language: {report_data['project']['language']}"])
    writer.writerow([])
    
    # Write summary
    writer.writerow(["Summary"])
    writer.writerow(["Total Scans", report_data["summary"]["total_scans"]])
    writer.writerow(["Total Issues", report_data["summary"]["total_issues"]])
    writer.writerow(["Vulnerabilities", report_data["summary"]["vulnerabilities"]])
    writer.writerow(["Bugs", report_data["summary"]["bugs"]])
    writer.writerow(["Code Smells", report_data["summary"]["code_smells"]])
    writer.writerow(["Lines of Code", report_data["summary"]["lines_of_code"]])
    writer.writerow(["Coverage", f"{report_data['summary']['coverage']}%"])
    writer.writerow(["Technical Debt", f"{report_data['summary']['technical_debt']} minutes"])
    writer.writerow([])
    
    # Write ratings
    writer.writerow(["Quality Ratings"])
    writer.writerow(["Security", report_data["project"]["security_rating"]])
    writer.writerow(["Reliability", report_data["project"]["reliability_rating"]])
    writer.writerow(["Maintainability", report_data["project"]["maintainability_rating"]])
    writer.writerow([])
    
    # Write issues breakdown
    writer.writerow(["Issues by Severity"])
    for severity, count in report_data["issues_by_severity"].items():
        writer.writerow([severity.title(), count])
    
    writer.writerow([])
    writer.writerow(["Issues by Type"])
    for issue_type, count in report_data["issues_by_type"].items():
        writer.writerow([issue_type.title(), count])
    
    return output.getvalue()

def generate_project_pdf_report(report_data: Dict[str, Any]) -> bytes:
    """Generate project PDF report content (placeholder)"""
    pdf_content = f"""
    Project Report
    ==============
    
    Project: {report_data['project']['name']} ({report_data['project']['key']})
    Language: {report_data['project']['language']}
    
    Summary:
    - Total Scans: {report_data['summary']['total_scans']}
    - Total Issues: {report_data['summary']['total_issues']}
    - Vulnerabilities: {report_data['summary']['vulnerabilities']}
    - Bugs: {report_data['summary']['bugs']}
    - Code Smells: {report_data['summary']['code_smells']}
    - Lines of Code: {report_data['summary']['lines_of_code']}
    - Coverage: {report_data['summary']['coverage']}%
    - Technical Debt: {report_data['summary']['technical_debt']} minutes
    
    Quality Ratings:
    - Security: {report_data['project']['security_rating']}
    - Reliability: {report_data['project']['reliability_rating']}
    - Maintainability: {report_data['project']['maintainability_rating']}
    """.encode('utf-8')
    
    return pdf_content

# ============================================================================
# Advanced Analysis Endpoints
# ============================================================================

@router.post("/advanced-analysis/{project_id}")
async def start_advanced_analysis(
    project_id: str,
    analysis_types: List[str] = Query(["data_flow", "taint_analysis", "security_pattern"]),
    languages: List[str] = Query(["python", "javascript", "java"]),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start advanced code analysis for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Initialize advanced analyzer
        advanced_analyzer = AdvancedCodeAnalyzer()
        
        # Perform analysis
        analysis_result = await advanced_analyzer.analyze_project(
            project_path=project.repository_url or f"projects/{project_id}",
            project_id=project_id,
            scan_id=str(uuid.uuid4()),
            languages=languages
        )
        
        return {
            "message": "Advanced analysis completed successfully",
            "analysis_id": analysis_result.analysis_id,
            "summary": analysis_result.summary,
            "vulnerabilities_found": len(analysis_result.vulnerabilities),
            "data_flow_paths": len(analysis_result.data_flow_paths),
            "taint_flows": len(analysis_result.taint_flows)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during advanced analysis: {str(e)}")

@router.get("/advanced-analysis/{analysis_id}")
async def get_advanced_analysis_result(
    analysis_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get results of advanced code analysis"""
    try:
        advanced_analyzer = AdvancedCodeAnalyzer()
        result = advanced_analyzer.get_analysis_result(analysis_id)
        
        if not result:
            raise HTTPException(status_code=404, detail="Analysis result not found")
        
        return {
            "analysis_id": result.analysis_id,
            "project_id": result.project_id,
            "scan_id": result.scan_id,
            "analysis_type": result.analysis_type.value,
            "summary": result.summary,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "title": v.title,
                    "description": v.description,
                    "category": v.category.value,
                    "severity": v.severity,
                    "confidence": v.confidence,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "cwe_id": v.cwe_id,
                    "owasp_category": v.owasp_category,
                    "evidence": v.evidence,
                    "recommendations": v.recommendations
                }
                for v in result.vulnerabilities
            ],
            "data_flow_paths": len(result.data_flow_paths),
            "taint_flows": len(result.taint_flows),
            "created_at": result.created_at.isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving analysis result: {str(e)}")

@router.get("/advanced-analysis/{analysis_id}/export")
async def export_advanced_analysis(
    analysis_id: str,
    format: str = Query("json", regex="^(json|csv|pdf)$"),
    current_user: User = Depends(get_current_user)
):
    """Export advanced analysis results"""
    try:
        advanced_analyzer = AdvancedCodeAnalyzer()
        result = advanced_analyzer.get_analysis_result(analysis_id)
        
        if not result:
            raise HTTPException(status_code=404, detail="Analysis result not found")
        
        if format == "json":
            # Export as JSON
            export_path = f"exports/advanced_analysis_{analysis_id}.json"
            success = advanced_analyzer.export_analysis_report(analysis_id, export_path)
            
            if success:
                return {"message": "Analysis exported successfully", "file_path": export_path}
            else:
                raise HTTPException(status_code=500, detail="Failed to export analysis")
        
        elif format == "csv":
            # Export as CSV (simplified)
            csv_content = "Vulnerability ID,Title,Category,Severity,File Path,Line Number,CWE ID\n"
            for vuln in result.vulnerabilities:
                csv_content += f"{vuln.id},{vuln.title},{vuln.category.value},{vuln.severity},{vuln.file_path},{vuln.line_number},{vuln.cwe_id or ''}\n"
            
            return Response(
                content=csv_content,
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=advanced_analysis_{analysis_id}.csv"}
            )
        
        else:
            raise HTTPException(status_code=400, detail="Unsupported export format")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error exporting analysis: {str(e)}")

@router.get("/data-flow-analysis/{project_id}")
async def get_data_flow_analysis(
    project_id: str,
    file_path: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user)
):
    """Get data flow analysis for a project or specific file"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Initialize data flow analyzer
        data_flow_analyzer = DataFlowAnalyzer()
        
        # Analyze project files
        project_path = project.repository_url or f"projects/{project_id}"
        languages = [project.language] if project.language else ["python", "javascript", "java"]
        
        all_paths = []
        for language in languages:
            if file_path:
                # Analyze specific file
                file_path_obj = Path(project_path) / file_path
                if file_path_obj.exists():
                    paths = data_flow_analyzer.analyze_file(file_path_obj, language)
                    all_paths.extend(paths)
            else:
                # Analyze all files of this language
                language_files = data_flow_analyzer._find_language_files(Path(project_path), language)
                for lang_file in language_files:
                    paths = data_flow_analyzer.analyze_file(lang_file, language)
                    all_paths.extend(paths)
        
        # Get summary
        summary = data_flow_analyzer.get_data_flow_summary()
        
        return {
            "project_id": project_id,
            "file_path": file_path,
            "summary": summary,
            "data_flow_paths": [
                {
                    "path_id": path.path_id,
                    "source": {
                        "name": path.source.name,
                        "type": path.source.node_type,
                        "file_path": path.source.file_path,
                        "line_number": path.source.line_number
                    },
                    "sink": {
                        "name": path.sink.name,
                        "type": path.sink.node_type,
                        "file_path": path.sink.file_path,
                        "line_number": path.sink.line_number
                    },
                    "risk_level": path.risk_level,
                    "description": path.description,
                    "node_count": len(path.nodes),
                    "edge_count": len(path.edges)
                }
                for path in all_paths
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during data flow analysis: {str(e)}")

@router.get("/taint-analysis/{project_id}")
async def get_taint_analysis(
    project_id: str,
    file_path: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user)
):
    """Get taint analysis for a project or specific file"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Initialize taint analyzer
        taint_analyzer = TaintAnalyzer()
        
        # Analyze project files
        project_path = project.repository_url or f"projects/{project_id}"
        languages = [project.language] if project.language else ["python", "javascript", "java"]
        
        all_flows = []
        for language in languages:
            if file_path:
                # Analyze specific file
                file_path_obj = Path(project_path) / file_path
                if file_path_obj.exists():
                    flows = taint_analyzer.analyze_file(file_path_obj, language)
                    all_flows.extend(flows)
            else:
                # Analyze all files of this language
                language_files = taint_analyzer._find_language_files(Path(project_path), language)
                for lang_file in language_files:
                    flows = taint_analyzer.analyze_file(lang_file, language)
                    all_flows.extend(flows)
        
        # Get summary
        summary = taint_analyzer.get_taint_summary()
        
        return {
            "project_id": project_id,
            "file_path": file_path,
            "summary": summary,
            "taint_flows": [
                {
                    "id": flow.id,
                    "source": {
                        "name": flow.source.name,
                        "taint_type": flow.source.taint_type.value,
                        "file_path": flow.source.file_path,
                        "line_number": flow.source.line_number,
                        "severity": flow.source.severity.value
                    },
                    "sink": {
                        "name": flow.sink.name,
                        "sink_type": flow.sink.sink_type,
                        "file_path": flow.sink.file_path,
                        "line_number": flow.sink.line_number,
                        "severity": flow.sink.severity.value,
                        "cwe_id": flow.sink.cwe_id,
                        "owasp_category": flow.sink.owasp_category
                    },
                    "taint_status": flow.taint_status.value,
                    "severity": flow.severity.value,
                    "description": flow.description,
                    "flow_path": flow.flow_path,
                    "sanitization_points": flow.sanitization_points,
                    "blocking_points": flow.blocking_points
                }
                for flow in all_flows
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during taint analysis: {str(e)}")

@router.get("/advanced-analysis/{analysis_id}/data-flow")
async def get_analysis_data_flow(
    analysis_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get data flow paths from advanced analysis"""
    try:
        advanced_analyzer = AdvancedCodeAnalyzer()
        result = advanced_analyzer.get_analysis_result(analysis_id)
        
        if not result:
            raise HTTPException(status_code=404, detail="Analysis result not found")
        
        return {
            "analysis_id": analysis_id,
            "data_flow_paths": [
                {
                    "path_id": path.path_id,
                    "source": {
                        "name": path.source.name,
                        "type": path.source.node_type,
                        "file_path": path.source.file_path,
                        "line_number": path.source.line_number
                    },
                    "sink": {
                        "name": path.sink.name,
                        "type": path.sink.node_type,
                        "file_path": path.sink.file_path,
                        "line_number": path.sink.line_number
                    },
                    "risk_level": path.risk_level,
                    "description": path.description,
                    "node_count": len(path.nodes),
                    "edge_count": len(path.edges)
                }
                for path in result.data_flow_paths
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving data flow: {str(e)}")

@router.get("/advanced-analysis/{analysis_id}/taint-flows")
async def get_analysis_taint_flows(
    analysis_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get taint flows from advanced analysis"""
    try:
        advanced_analyzer = AdvancedCodeAnalyzer()
        result = advanced_analyzer.get_analysis_result(analysis_id)
        
        if not result:
            raise HTTPException(status_code=404, detail="Analysis result not found")
        
        return {
            "analysis_id": analysis_id,
            "taint_flows": [
                {
                    "id": flow.id,
                    "source": {
                        "name": flow.source.name,
                        "taint_type": flow.source.taint_type.value,
                        "file_path": flow.source.file_path,
                        "line_number": flow.source.line_number,
                        "severity": flow.source.severity.value
                    },
                    "sink": {
                        "name": flow.sink.name,
                        "sink_type": flow.sink.sink_type,
                        "file_path": flow.sink.file_path,
                        "line_number": flow.sink.line_number,
                        "severity": flow.sink.severity.value,
                        "cwe_id": flow.sink.cwe_id,
                        "owasp_category": flow.sink.owasp_category
                    },
                    "taint_status": flow.taint_status.value,
                    "severity": flow.severity.value,
                    "description": flow.description,
                    "flow_path": flow.flow_path,
                    "sanitization_points": flow.sanitization_points,
                    "blocking_points": flow.blocking_points
                }
                for flow in result.taint_flows
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving taint flows: {str(e)}")

# ============================================================================
# Real-time Monitoring Endpoints
# ============================================================================

@router.post("/realtime/start/{project_id}")
async def start_realtime_monitoring(
    project_id: str,
    config: Optional[Dict[str, Any]] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start real-time monitoring for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        # Import real-time analyzer
        from app.sast.realtime_analyzer import start_realtime_monitoring
        
        # Start monitoring
        await start_realtime_monitoring(project.repository_url or f"projects/{project_id}", config)
        
        return {
            "message": "Real-time monitoring started successfully",
            "project_id": project_id,
            "status": "monitoring"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting real-time monitoring: {str(e)}")

@router.post("/realtime/stop/{project_id}")
async def stop_realtime_monitoring(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Stop real-time monitoring for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        # Import real-time analyzer
        from app.sast.realtime_analyzer import stop_realtime_monitoring
        
        # Stop monitoring
        await stop_realtime_monitoring(project.repository_url or f"projects/{project_id}")
        
        return {
            "message": "Real-time monitoring stopped successfully",
            "project_id": project_id,
            "status": "stopped"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error stopping real-time monitoring: {str(e)}")

@router.get("/realtime/stats/{project_id}")
async def get_realtime_stats(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get real-time monitoring statistics for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        # Import real-time analyzer
        from app.sast.realtime_analyzer import get_realtime_analyzer
        
        # Get analyzer instance
        analyzer = await get_realtime_analyzer(project.repository_url or f"projects/{project_id}")
        
        # Get statistics
        stats = analyzer.get_statistics()
        
        return {
            "project_id": project_id,
            "statistics": stats
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting real-time stats: {str(e)}")

@router.get("/realtime/export/{project_id}")
async def export_realtime_data(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Export real-time monitoring data for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        # Import real-time analyzer
        from app.sast.realtime_analyzer import get_realtime_analyzer
        
        # Get analyzer instance
        analyzer = await get_realtime_analyzer(project.repository_url or f"projects/{project_id}")
        
        # Export data
        export_data = analyzer.export_analysis_data()
        
        return {
            "project_id": project_id,
            "export_data": export_data,
            "exported_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error exporting real-time data: {str(e)}")

# ============================================================================
# Quality Management Endpoints
# ============================================================================

@router.get("/projects/{project_id}/quality-overview")
async def get_project_quality_overview(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive quality overview for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get quality gate
        quality_gate_result = await db.execute(
            select(SASTQualityGate).where(SASTQualityGate.project_id == project_id)
        )
        quality_gate = quality_gate_result.scalar_one_or_none()
        
        # Get recent scan for metrics
        recent_scan_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == project_id)
            .order_by(SASTScan.created_at.desc())
            .limit(1)
        )
        recent_scan = recent_scan_result.scalar_one_or_none()
        
        # Calculate quality metrics
        quality_metrics = {
            "project_id": project_id,
            "project_name": project.name,
            "quality_gate_status": quality_gate.status if quality_gate else QualityGateStatus.PASSED,
            "ratings": {
                "maintainability": project.maintainability_rating,
                "security": project.security_rating,
                "reliability": project.reliability_rating
            },
            "issue_counts": {
                "vulnerabilities": project.vulnerability_count,
                "bugs": project.bug_count,
                "code_smells": project.code_smell_count,
                "security_hotspots": project.security_hotspot_count
            },
            "code_metrics": {
                "lines_of_code": project.lines_of_code,
                "lines_of_comment": project.lines_of_comment,
                "duplicated_lines": project.duplicated_lines,
                "duplicated_blocks": project.duplicated_blocks
            },
            "coverage_metrics": {
                "coverage": project.coverage,
                "uncovered_lines": project.uncovered_lines,
                "uncovered_conditions": project.uncovered_conditions
            },
            "technical_debt": {
                "total_debt": project.technical_debt,
                "debt_ratio": project.debt_ratio,
                "debt_hours": round(project.technical_debt / 60, 2) if project.technical_debt else 0
            },
            "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None,
            "scan_status": recent_scan.status if recent_scan else None
        }
        
        return quality_metrics
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality overview: {str(e)}")

@router.get("/projects/{project_id}/quality-metrics")
async def get_project_quality_metrics(
    project_id: str,
    metric_type: Optional[str] = Query(None, description="Type of metrics: 'security', 'reliability', 'maintainability', 'coverage', 'duplications'"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get detailed quality metrics for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        if not metric_type:
            # Return all metrics
            return {
                "project_id": project_id,
                "project_name": project.name,
                "security_metrics": {
                    "rating": project.security_rating,
                    "vulnerability_count": project.vulnerability_count,
                    "security_hotspot_count": project.security_hotspot_count
                },
                "reliability_metrics": {
                    "rating": project.reliability_rating,
                    "bug_count": project.bug_count
                },
                "maintainability_metrics": {
                    "rating": project.maintainability_rating,
                    "code_smell_count": project.code_smell_count,
                    "technical_debt": project.technical_debt,
                    "debt_ratio": project.debt_ratio
                },
                "coverage_metrics": {
                    "coverage": project.coverage,
                    "uncovered_lines": project.uncovered_lines,
                    "uncovered_conditions": project.uncovered_conditions
                },
                "duplication_metrics": {
                    "duplicated_lines": project.duplicated_lines,
                    "duplicated_blocks": project.duplicated_blocks
                }
            }
        
        # Return specific metric type
        if metric_type == "security":
            return {
                "project_id": project_id,
                "metric_type": "security",
                "rating": project.security_rating,
                "vulnerability_count": project.vulnerability_count,
                "security_hotspot_count": project.security_hotspot_count,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "reliability":
            return {
                "project_id": project_id,
                "metric_type": "reliability",
                "rating": project.reliability_rating,
                "bug_count": project.bug_count,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "maintainability":
            return {
                "project_id": project_id,
                "metric_type": "maintainability",
                "rating": project.maintainability_rating,
                "code_smell_count": project.code_smell_count,
                "technical_debt": project.technical_debt,
                "debt_ratio": project.debt_ratio,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "coverage":
            return {
                "project_id": project_id,
                "metric_type": "coverage",
                "coverage": project.coverage,
                "uncovered_lines": project.uncovered_lines,
                "uncovered_conditions": project.uncovered_conditions,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        elif metric_type == "duplications":
            return {
                "project_id": project_id,
                "metric_type": "duplications",
                "duplicated_lines": project.duplicated_lines,
                "duplicated_blocks": project.duplicated_blocks,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            }
        else:
            raise HTTPException(status_code=400, detail="Invalid metric type")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality metrics: {str(e)}")

@router.get("/projects/{project_id}/quality-trends")
async def get_project_quality_trends(
    project_id: str,
    days: int = Query(30, description="Number of days for trend analysis"),
    metric: str = Query("all", description="Specific metric to analyze: 'security', 'reliability', 'maintainability', 'coverage', 'debt'"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get quality trends for a project over time"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get scans within the specified time period
        from datetime import datetime, timedelta
        cutoff_date = datetime.now() - timedelta(days=days)
        
        scans_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == project_id)
            .where(SASTScan.created_at >= cutoff_date)
            .order_by(SASTScan.created_at.asc())
        )
        scans = scans_result.scalars().all()
        
        # Generate trend data
        trends = []
        for scan in scans:
            trend_point = {
                "date": scan.created_at.isoformat(),
                "scan_id": str(scan.id),
                "scan_status": scan.status
            }
            
            if metric == "all" or metric == "security":
                trend_point["security_rating"] = getattr(scan, 'security_rating', None)
                trend_point["vulnerability_count"] = getattr(scan, 'vulnerabilities_found', 0)
            
            if metric == "all" or metric == "reliability":
                trend_point["reliability_rating"] = getattr(scan, 'reliability_rating', None)
                trend_point["bug_count"] = getattr(scan, 'bugs_found', 0)
            
            if metric == "all" or metric == "maintainability":
                trend_point["maintainability_rating"] = getattr(scan, 'maintainability_rating', None)
                trend_point["code_smell_count"] = getattr(scan, 'code_smells_found', 0)
            
            if metric == "all" or metric == "coverage":
                trend_point["coverage"] = getattr(scan, 'coverage', 0.0)
            
            if metric == "all" or metric == "debt":
                trend_point["technical_debt"] = getattr(scan, 'technical_debt', 0)
            
            trends.append(trend_point)
        
        return {
            "project_id": project_id,
            "project_name": project.name,
            "metric": metric,
            "period_days": days,
            "trends": trends,
            "summary": {
                "total_scans": len(trends),
                "period_start": cutoff_date.isoformat(),
                "period_end": datetime.now().isoformat()
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality trends: {str(e)}")

@router.get("/projects/{project_id}/quality-report")
async def get_project_quality_report(
    project_id: str,
    format: str = Query("json", description="Report format: 'json', 'pdf', 'csv'"),
    include_details: bool = Query(True, description="Include detailed issue information"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate comprehensive quality report for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get quality gate
        quality_gate_result = await db.execute(
            select(SASTQualityGate).where(SASTQualityGate.project_id == project_id)
        )
        quality_gate = quality_gate_result.scalar_one_or_none()
        
        # Get recent scan
        recent_scan_result = await db.execute(
            select(SASTScan)
            .where(SASTScan.project_id == project_id)
            .order_by(SASTScan.created_at.desc())
            .limit(1)
        )
        recent_scan = recent_scan_result.scalar_one_or_none()
        
        # Get issues if details are requested
        issues = []
        if include_details:
            issues_result = await db.execute(
                select(SASTIssue)
                .where(SASTIssue.project_id == project_id)
                .order_by(SASTIssue.severity.desc(), SASTIssue.created_at.desc())
                .limit(100)  # Limit for performance
            )
            issues = issues_result.scalars().all()
        
        # Generate report data
        report_data = {
            "project": {
                "id": project_id,
                "name": project.name,
                "key": project.key,
                "language": project.language,
                "last_analysis": project.last_analysis.isoformat() if project.last_analysis else None
            },
            "quality_gate": {
                "status": quality_gate.status if quality_gate else QualityGateStatus.PASSED,
                "evaluated_at": quality_gate.last_evaluation.isoformat() if quality_gate and quality_gate.last_evaluation else None
            },
            "ratings": {
                "maintainability": project.maintainability_rating,
                "security": project.security_rating,
                "reliability": project.reliability_rating
            },
            "metrics_summary": {
                "lines_of_code": project.lines_of_code,
                "coverage": project.coverage,
                "technical_debt": project.technical_debt,
                "debt_ratio": project.debt_ratio,
                "duplicated_lines": project.duplicated_lines
            },
            "issue_summary": {
                "total_issues": len(issues),
                "vulnerabilities": project.vulnerability_count,
                "bugs": project.bug_count,
                "code_smells": project.code_smell_count,
                "security_hotspots": project.security_hotspot_count
            },
            "scan_information": {
                "last_scan_id": str(recent_scan.id) if recent_scan else None,
                "last_scan_status": recent_scan.status if recent_scan else None,
                "last_scan_date": recent_scan.created_at.isoformat() if recent_scan else None
            },
            "generated_at": datetime.now().isoformat()
        }
        
        if include_details and issues:
            report_data["detailed_issues"] = [
                {
                    "id": str(issue.id),
                    "type": issue.type,
                    "severity": issue.severity,
                    "status": issue.status,
                    "file_path": issue.file_path,
                    "line_number": issue.line_number,
                    "message": issue.message,
                    "effort": issue.effort,
                    "created_at": issue.created_at.isoformat()
                }
                for issue in issues
            ]
        
        # Return based on format
        if format == "json":
            return report_data
        elif format == "csv":
            # Generate CSV response
            import csv
            from io import StringIO
            
            output = StringIO()
            writer = csv.writer(output)
            
            # Write headers
            writer.writerow(["Quality Report", project.name])
            writer.writerow([])
            writer.writerow(["Project Information"])
            writer.writerow(["ID", project_id])
            writer.writerow(["Name", project.name])
            writer.writerow(["Language", project.language])
            writer.writerow([])
            writer.writerow(["Quality Metrics"])
            writer.writerow(["Maintainability Rating", project.maintainability_rating])
            writer.writerow(["Security Rating", project.security_rating])
            writer.writerow(["Reliability Rating", project.reliability_rating])
            writer.writerow(["Coverage", f"{project.coverage}%"])
            writer.writerow(["Technical Debt", f"{project.technical_debt} minutes"])
            writer.writerow(["Debt Ratio", f"{project.debt_ratio}%"])
            
            output.seek(0)
            return Response(content=output.getvalue(), media_type="text/csv")
        else:
            raise HTTPException(status_code=400, detail="Unsupported format")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating quality report: {str(e)}")

@router.post("/projects/{project_id}/quality-gate/evaluate")
async def evaluate_project_quality_gate(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Manually evaluate quality gate for a project"""
    try:
        # Get project
        project_result = await db.execute(
            select(SASTProject).where(SASTProject.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get quality gate
        quality_gate_result = await db.execute(
            select(SASTQualityGate).where(SASTQualityGate.project_id == project_id)
        )
        quality_gate = quality_gate_result.scalar_one_or_none()
        
        if not quality_gate:
            raise HTTPException(status_code=404, detail="Quality gate not found")
        
        # Evaluate quality gate based on current project metrics
        evaluation_results = {}
        gate_status = QualityGateStatus.PASSED
        
        # Check vulnerability thresholds
        if project.vulnerability_count > quality_gate.max_blocker_issues:
            evaluation_results["blocker_issues"] = f"Failed: {project.vulnerability_count} > {quality_gate.max_blocker_issues}"
            gate_status = QualityGateStatus.FAILED
        else:
            evaluation_results["blocker_issues"] = f"Passed: {project.vulnerability_count} <= {quality_gate.max_blocker_issues}"
        
        # Check coverage threshold
        if project.coverage < quality_gate.min_coverage:
            evaluation_results["coverage"] = f"Failed: {project.coverage}% < {quality_gate.min_coverage}%"
            gate_status = QualityGateStatus.FAILED
        else:
            evaluation_results["coverage"] = f"Passed: {project.coverage}% >= {quality_gate.min_coverage}%"
        
        # Check technical debt threshold
        if project.debt_ratio > quality_gate.max_debt_ratio:
            evaluation_results["debt_ratio"] = f"Failed: {project.debt_ratio}% > {quality_gate.max_debt_ratio}%"
            gate_status = QualityGateStatus.FAILED
        else:
            evaluation_results["debt_ratio"] = f"Passed: {project.debt_ratio}% <= {quality_gate.max_debt_ratio}%"
        
        # Update quality gate status
        quality_gate.status = gate_status
        quality_gate.last_evaluation = datetime.now()
        quality_gate.evaluation_results = evaluation_results
        
        await db.commit()
        
        return {
            "project_id": project_id,
            "quality_gate_status": gate_status,
            "evaluation_results": evaluation_results,
            "evaluated_at": quality_gate.last_evaluation.isoformat(),
            "next_evaluation": "Automatic on next scan or manual trigger"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error evaluating quality gate: {str(e)}")

@router.get("/quality-management/dashboard")
async def get_quality_management_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get quality management dashboard overview"""
    try:
        # Get total projects
        total_projects_result = await db.execute(select(func.count(SASTProject.id)))
        total_projects = total_projects_result.scalar() or 0
        
        # Get projects by quality gate status
        passed_projects_result = await db.execute(
            select(func.count(SASTProject.id))
            .select_from(SASTProject)
            .join(SASTQualityGate)
            .where(SASTQualityGate.status == QualityGateStatus.PASSED)
        )
        passed_projects = passed_projects_result.scalar() or 0
        
        failed_projects_result = await db.execute(
            select(func.count(SASTProject.id))
            .select_from(SASTProject)
            .join(SASTQualityGate)
            .where(SASTQualityGate.status == QualityGateStatus.FAILED)
        )
        failed_projects = failed_projects_result.scalar() or 0
        
        # Get average ratings
        avg_maintainability_result = await db.execute(
            select(func.avg(SASTProject.maintainability_rating))
        )
        avg_maintainability = avg_maintainability_result.scalar()
        
        avg_security_result = await db.execute(
            select(func.avg(SASTProject.security_rating))
        )
        avg_security = avg_security_result.scalar()
        
        avg_reliability_result = await db.execute(
            select(func.avg(SASTProject.reliability_rating))
        )
        avg_reliability = avg_reliability_result.scalar()
        
        # Get total technical debt
        total_debt_result = await db.execute(
            select(func.sum(SASTProject.technical_debt))
        )
        total_debt = total_debt_result.scalar() or 0
        
        # Get average coverage
        avg_coverage_result = await db.execute(
            select(func.avg(SASTProject.coverage))
        )
        avg_coverage = avg_coverage_result.scalar() or 0
        
        return {
            "summary": {
                "total_projects": total_projects,
                "passed_projects": passed_projects,
                "failed_projects": failed_projects,
                "pass_rate": round((passed_projects / total_projects * 100), 2) if total_projects > 0 else 0
            },
            "average_ratings": {
                "maintainability": avg_maintainability,
                "security": avg_security,
                "reliability": avg_reliability
            },
            "overall_metrics": {
                "total_technical_debt_hours": round(total_debt / 60, 2),
                "average_coverage": round(avg_coverage, 2)
            },
            "quality_distribution": {
                "excellent": 0,  # A rating
                "good": 0,       # B rating
                "moderate": 0,   # C rating
                "poor": 0,       # D rating
                "very_poor": 0   # E rating
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting quality management dashboard: {str(e)}")
