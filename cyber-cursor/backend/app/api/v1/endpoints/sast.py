"""
SAST (Static Application Security Testing) API Endpoints
Enhanced with SonarQube-like comprehensive functionality
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends, Query, UploadFile, File, status
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid
import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.sast import (
    SASTProject, SASTScan, SASTIssue, SASTSecurityHotspot, SASTCodeCoverage,
    SASTDuplication, SASTQualityGate, SASTProjectConfiguration, SASTRule,
    ScanStatus, IssueSeverity, IssueType, IssueStatus, SecurityHotspotStatus,
    QualityGateStatus, Rating
)
from app.models.user import User
from app.core.security import get_current_user
# from app.services.sast_service import sast_service  # Removed during cleanup
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
        scan.status = ScanStatus.RUNNING
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
            select(func.count(SASTScan.id)).where(SASTScan.status == ScanStatus.RUNNING)
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
            select(func.count(SASTScan.id)).where(SASTScan.status == ScanStatus.RUNNING)
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
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new SAST project"""
    try:
        # Check if project key already exists
        existing_project = db.query(SASTProject).filter(SASTProject.key == project_data.key).first()
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
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        db.add(new_project)
        db.commit()
        db.refresh(new_project)
        
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
        db.rollback()
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
                query = query.join(SASTScan).where(SASTScan.status == "RUNNING")
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
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific SAST project by ID"""
    try:
        project = db.query(SASTProject).filter(SASTProject.id == project_id).first()
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Get last scan
        last_scan = db.query(SASTScan).filter(
            SASTScan.project_id == project.id
        ).order_by(SASTScan.started_at.desc()).first()
        
        # Get issue counts
        issues = db.query(SASTIssue).filter(SASTIssue.project_id == project.id).all()
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
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Duplicate an existing SAST project"""
    try:
        # Get original project
        original_project = db.query(SASTProject).filter(SASTProject.id == project_id).first()
        if not original_project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Original project not found"
            )
        
        # Check if new project key already exists
        existing_project = db.query(SASTProject).filter(SASTProject.key == duplicate_data.key).first()
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
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        db.add(duplicated_project)
        db.commit()
        db.refresh(duplicated_project)
        
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
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to duplicate project: {str(e)}"
        )

@router.put("/projects/{project_id}", response_model=SASTProjectResponse)
async def update_sast_project(
    project_id: int,
    project_data: SASTProjectUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update an existing SAST project"""
    try:
        project = db.query(SASTProject).filter(SASTProject.id == project_id).first()
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
            existing_project = db.query(SASTProject).filter(
                SASTProject.key == project_data.key,
                SASTProject.id != project_id
            ).first()
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
        
        project.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(project)
        
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
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update project: {str(e)}"
        )

@router.delete("/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sast_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a SAST project and all associated data"""
    try:
        project = db.query(SASTProject).filter(SASTProject.id == project_id).first()
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
        db.query(SASTIssue).filter(SASTIssue.project_id == project_id).delete()
        db.query(SASTSecurityHotspot).filter(SASTSecurityHotspot.project_id == project_id).delete()
        db.query(SASTQualityGate).filter(SASTQualityGate.project_id == project_id).delete()
        db.query(SASTScan).filter(SASTScan.project_id == project_id).delete()
        
        # Delete the project
        db.delete(project)
        db.commit()
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
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
                    "duplicated_code": dup.duplicated_code,
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
            vulnerabilities_by_severity={
                "critical": severity_counts.get('critical', 0),
                "high": severity_counts.get('major', 0),
                "medium": severity_counts.get('minor', 0),
                "low": severity_counts.get('info', 0)
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
            config.updated_at = datetime.utcnow()
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
