from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File, Form
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from typing import List, Optional
from datetime import datetime
import os
import zipfile
import tempfile
import shutil
import uuid
import json
import asyncio
import subprocess
import subprocess
import asyncio
import json
import logging

from app.core.database import get_db
from app.core.security import get_current_user, require_analyst
from app.models.project import Project, ProjectScan, ProjectIssue, Team, TeamMember
from app.models.user import User
from app.schemas.project import *
from app.schemas.auth import User as UserSchema
from app.services.vulnerability_scanner import VulnerabilityScanner
from app.services.vulnerability_scanner import VulnerabilityScanner

router = APIRouter()
logger = logging.getLogger(__name__)

# ============================================================================
# Project Management Endpoints
# ============================================================================

@router.post("/", response_model=ProjectResponse)
async def create_project(
    project: ProjectCreate,
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new project"""
    try:
        # Check if project key already exists
        existing_project = await Project.get_by_key(db, project.key)
        if existing_project:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Project with key '{project.key}' already exists"
            )
        
        # Set default values
        project_data = project.dict()
        project_data["created_by"] = current_user.id
        project_data["owner_id"] = project_data.get("owner_id") or current_user.id
        
        # Create project
        new_project = await Project.create_project(db, **project_data)
        return new_project
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create project: {str(e)}"
        )

@router.get("/", response_model=ProjectList)
async def get_projects(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    project_type: Optional[ProjectType] = None,
    status: Optional[ProjectStatus] = None,
    language: Optional[str] = None,
    search: Optional[str] = None,
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get projects with filtering and pagination"""
    try:
        # Build query
        query = select(Project)
        
        # Apply filters
        filters = []
        if project_type:
            filters.append(Project.project_type == project_type)
        if status:
            filters.append(Project.status == status)
        if language:
            filters.append(Project.language == language)
        if search:
            search_filter = or_(
                Project.name.ilike(f"%{search}%"),
                Project.description.ilike(f"%{search}%"),
                Project.key.ilike(f"%{search}%")
            )
            filters.append(search_filter)
        
        # Add user access filter (user can see projects they own or are team members of)
        user_filter = or_(
            Project.owner_id == current_user.id,
            Project.created_by == current_user.id
        )
        filters.append(user_filter)
        
        if filters:
            query = query.where(and_(*filters))
        
        # Get total count
        count_query = select(Project).where(and_(*filters)) if filters else select(Project)
        total_result = await db.execute(count_query)
        total = len(total_result.scalars().all())
        
        # Get paginated results
        query = query.offset(skip).limit(limit).order_by(Project.created_at.desc())
        result = await db.execute(query)
        projects = result.scalars().all()
        
        return ProjectList(
            projects=projects,
            total=total,
            page=skip // limit + 1,
            size=limit,
            pages=(total + limit - 1) // limit
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get projects: {str(e)}"
        )

@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: int,
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get project by ID"""
    try:
        project = await Project.get_by_id(db, project_id)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Check access permissions
        if project.owner_id != current_user.id and project.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        return project
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get project: {str(e)}"
        )

@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: int,
    project_update: ProjectUpdate,
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update project"""
    try:
        project = await Project.get_by_id(db, project_id)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Check access permissions
        if project.owner_id != current_user.id and project.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Update project
        update_data = project_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(project, field, value)
        
        project.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(project)
        
        return project
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update project: {str(e)}"
        )

@router.delete("/{project_id}")
async def delete_project(
    project_id: int,
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete project (soft delete)"""
    try:
        project = await Project.get_by_id(db, project_id)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Check access permissions
        if project.owner_id != current_user.id and project.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Soft delete
        project.status = ProjectStatus.DELETED
        project.updated_at = datetime.utcnow()
        await db.commit()
        
        return {"message": "Project deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete project: {str(e)}"
        )

# ============================================================================
# Code Upload Endpoints
# ============================================================================

@router.post("/{project_id}/upload", response_model=CodeUploadResponse)
async def upload_code(
    project_id: int,
    upload_type: str = Form(...),
    file: Optional[UploadFile] = File(None),
    git_url: Optional[str] = Form(None),
    git_branch: Optional[str] = Form("main"),
    git_username: Optional[str] = Form(None),
    git_token: Optional[str] = Form(None),
    scan_after_upload: bool = Form(True),
    scan_type: Optional[str] = Form("sast"),
    scan_config: Optional[str] = Form("{}"),
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Upload source code to project with enhanced validation and scanning"""
    try:
        # Verify project exists and user has access
        project = await Project.get_by_id(db, project_id)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Check user permissions
        if project.owner_id != current_user.id and project.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )

        upload_id = str(uuid.uuid4())
        source_path = None
        files_count = 0
        total_size = 0
        supported_extensions = ['.py', '.js', '.ts', '.java', '.cpp', '.c', '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala', '.html', '.css', '.xml', '.json', '.yaml', '.yml', '.toml', '.ini', '.conf', '.sh', '.bat', '.ps1']

        if upload_type == "zip":
            if not file:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="File is required for ZIP upload"
                )
            
            # Validate file type
            if not file.filename.endswith('.zip'):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Only ZIP files are supported"
                )
            
            # Create upload directory
            upload_dir = f"uploads/projects/{project_id}/{upload_id}"
            os.makedirs(upload_dir, exist_ok=True)
            
            # Save and extract ZIP file
            zip_path = os.path.join(upload_dir, file.filename)
            with open(zip_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            
            # Extract ZIP file
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(upload_dir)
            
            # Count files and calculate size
            for root, dirs, files in os.walk(upload_dir):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    if any(file_name.endswith(ext) for ext in supported_extensions):
                        files_count += 1
                        total_size += os.path.getsize(file_path)
            
            source_path = upload_dir
            
        elif upload_type == "git":
            if not git_url:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Git URL is required for Git upload"
                )
            
            # Create upload directory
            upload_dir = f"uploads/projects/{project_id}/{upload_id}"
            os.makedirs(upload_dir, exist_ok=True)
            
            # Clone repository
            git_cmd = ["git", "clone", "--depth", "1"]
            if git_branch and git_branch != "main":
                git_cmd.extend(["-b", git_branch])
            
            # Add authentication if provided
            if git_username and git_token:
                # Replace username in URL with token
                if "://" in git_url:
                    protocol, rest = git_url.split("://", 1)
                    git_url = f"{protocol}://{git_username}:{git_token}@{rest}"
            
            git_cmd.append(git_url)
            git_cmd.append(upload_dir)
            
            try:
                result = subprocess.run(git_cmd, capture_output=True, text=True, timeout=300)
                if result.returncode != 0:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Failed to clone repository: {result.stderr}"
                    )
            except subprocess.TimeoutExpired:
                raise HTTPException(
                    status_code=status.HTTP_408_REQUEST_TIMEOUT,
                    detail="Git clone operation timed out"
                )
            
            # Count files and calculate size
            for root, dirs, files in os.walk(upload_dir):
                # Skip .git directory
                if '.git' in dirs:
                    dirs.remove('.git')
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    if any(file_name.endswith(ext) for ext in supported_extensions):
                        files_count += 1
                        total_size += os.path.getsize(file_path)
            
            source_path = upload_dir
            
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid upload type. Supported: zip, git"
            )

        # Update project with source path
        project.source_path = source_path
        project.last_sync = datetime.utcnow()
        project.updated_at = datetime.utcnow()
        await db.commit()

        # Create scan if requested
        scan_id = None
        if scan_after_upload:
            try:
                scan_config_dict = json.loads(scan_config) if scan_config else {}
                scan_data = {
                    "project_id": project_id,
                    "scan_type": scan_type or "sast",
                    "scan_name": f"Auto scan after {upload_type} upload",
                    "scan_config": scan_config_dict,
                    "status": "pending",
                    "progress": 0,
                    "created_by": current_user.id
                }
                
                new_scan = await ProjectScan.create_scan(db, **scan_data)
                scan_id = new_scan.id
                
                # Trigger scan in background (simulated)
                # In production, this would be a background task
                await trigger_background_scan(scan_id, source_path, scan_type, scan_config_dict)
                
            except Exception as e:
                logger.error(f"Failed to create scan: {e}")

        return CodeUploadResponse(
            upload_id=upload_id,
            status="success",
            message="Code uploaded successfully",
            source_path=source_path,
            files_count=files_count,
            total_size=total_size,
            scan_id=scan_id
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload code: {str(e)}"
        )

async def trigger_background_scan(scan_id: int, source_path: str, scan_type: str, scan_config: dict):
    """Trigger background scan (simulated)"""
    # In production, this would be a Celery task or similar
    logger.info(f"Triggering {scan_type} scan for scan_id {scan_id}")
    # Simulate scan processing
    await asyncio.sleep(2)
    logger.info(f"Scan {scan_id} completed")

# ============================================================================
# Scan Management Endpoints
# ============================================================================

@router.post("/{project_id}/scans", response_model=ProjectScanResponse)
async def create_scan(
    project_id: int,
    scan: ProjectScanCreate,
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new scan for a project with vulnerability detection"""
    try:
        # Verify project exists and user has access
        project = await Project.get_by_id(db, project_id)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Check user permissions
        if project.owner_id != current_user.id and project.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Check if project has source code
        if not project.source_path:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Project has no source code uploaded. Please upload code first."
            )
        
        # Set scan data
        scan_data = scan.dict()
        scan_data["created_by"] = current_user.id
        scan_data["status"] = "pending"
        scan_data["progress"] = 0
        
        # Create scan
        new_scan = await ProjectScan.create_scan(db, **scan_data)
        
        # Trigger vulnerability scan in background
        asyncio.create_task(
            run_vulnerability_scan(
                scan_id=new_scan.id,
                project_id=project_id,
                source_path=project.source_path,
                scan_type=scan.scan_type,
                scan_config=scan.scan_config or {},
                user_id=current_user.id,
                db=db
            )
        )
        
        return new_scan
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create scan: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create scan: {str(e)}"
        )

async def run_vulnerability_scan(
    scan_id: int,
    project_id: int,
    source_path: str,
    scan_type: str,
    scan_config: dict,
    user_id: int,
    db: AsyncSession
):
    """Run vulnerability scan in background"""
    try:
        # Update scan status to running
        await ProjectScan.update_scan(db, scan_id, {"status": "running", "progress": 10})
        
        # Initialize vulnerability scanner
        scanner = VulnerabilityScanner()
        
        # Run scan
        scan_results = await scanner.scan_directory(source_path)
        
        # Update scan with results
        scan_summary = scan_results["summary"]
        await ProjectScan.update_scan(db, scan_id, {
            "status": "completed",
            "progress": 100,
            "total_issues": scan_summary["total_vulnerabilities"],
            "critical_issues": scan_summary["critical"],
            "high_issues": scan_summary["high"],
            "medium_issues": scan_summary["medium"],
            "low_issues": scan_summary["low"],
            "files_scanned": scan_summary["files_scanned"],
            "lines_scanned": scan_summary["lines_scanned"],
            "scan_duration": scan_summary["scan_duration"],
            "completed_at": datetime.utcnow()
        })
        
        # Create issue records for each vulnerability
        for vuln in scan_results["vulnerabilities"]:
            issue_data = {
                "project_id": project_id,
                "scan_id": scan_id,
                "issue_type": vuln["category"],
                "severity": vuln["severity"],
                "status": "open",
                "title": vuln["name"],
                "description": vuln["description"],
                "recommendation": vuln["remediation"],
                "file_path": vuln["file_path"],
                "line_number": vuln["line_number"],
                "start_line": vuln["start_line"],
                "end_line": vuln["end_line"],
                "cwe_id": vuln["cwe_id"],
                "cvss_score": vuln["cvss_score"],
                "owasp_category": vuln["owasp_category"],
                "created_by": user_id
            }
            
            await ProjectIssue.create_issue(db, **issue_data)
        
        logger.info(f"Vulnerability scan completed for scan_id {scan_id}")
        
    except Exception as e:
        logger.error(f"Vulnerability scan failed for scan_id {scan_id}: {e}")
        await ProjectScan.update_scan(db, scan_id, {
            "status": "failed",
            "error_message": str(e),
            "completed_at": datetime.utcnow()
        })
        await db.refresh(new_scan)
        
        return new_scan
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create scan: {str(e)}"
        )

@router.get("/{project_id}/scans", response_model=ProjectScanList)
async def get_project_scans(
    project_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get scans for a project"""
    try:
        # Verify project exists and user has access
        project = await Project.get_by_id(db, project_id)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        if project.owner_id != current_user.id and project.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Get scans
        scans = await ProjectScan.get_by_project(db, project_id, skip, limit)
        total = len(await ProjectScan.get_by_project(db, project_id, 0, 1000))  # Get total count
        
        return ProjectScanList(
            scans=scans,
            total=total,
            page=skip // limit + 1,
            size=limit,
            pages=(total + limit - 1) // limit
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scans: {str(e)}"
        )

# ============================================================================
# Issue Management Endpoints
# ============================================================================

@router.get("/{project_id}/issues", response_model=ProjectIssueList)
async def get_project_issues(
    project_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get issues for a project"""
    try:
        # Verify project exists and user has access
        project = await Project.get_by_id(db, project_id)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        if project.owner_id != current_user.id and project.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Get issues with filters
        issues = await ProjectIssue.get_by_project(db, project_id, skip, limit)
        total = len(await ProjectIssue.get_by_project(db, project_id, 0, 1000))  # Get total count
        
        # Apply additional filters
        if severity:
            issues = [issue for issue in issues if issue.severity == severity]
        if status:
            issues = [issue for issue in issues if issue.status == status]
        
        return ProjectIssueList(
            issues=issues,
            total=total,
            page=skip // limit + 1,
            size=limit,
            pages=(total + limit - 1) // limit
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get issues: {str(e)}"
        )

# ============================================================================
# Statistics and Summary Endpoints
# ============================================================================

@router.get("/{project_id}/summary", response_model=ProjectSummary)
async def get_project_summary(
    project_id: int,
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get project summary with statistics"""
    try:
        # Verify project exists and user has access
        project = await Project.get_by_id(db, project_id)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        if project.owner_id != current_user.id and project.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Get recent scans
        recent_scans = await ProjectScan.get_recent_scans(db, project_id, 5)
        
        # Get recent issues
        recent_issues = await ProjectIssue.get_by_project(db, project_id, 0, 10)
        
        # Calculate statistics
        all_scans = await ProjectScan.get_by_project(db, project_id, 0, 1000)
        all_issues = await ProjectIssue.get_by_project(db, project_id, 0, 1000)
        
        total_scans = len(all_scans)
        total_issues = len(all_issues)
        critical_issues = len([i for i in all_issues if i.severity == "critical"])
        high_issues = len([i for i in all_issues if i.severity == "high"])
        medium_issues = len([i for i in all_issues if i.severity == "medium"])
        low_issues = len([i for i in all_issues if i.severity == "low"])
        
        # Get projects by type (for this user)
        user_projects = await Project.get_by_user(db, current_user.id, 0, 1000)
        projects_by_type = {}
        for p in user_projects:
            projects_by_type[p.project_type.value] = projects_by_type.get(p.project_type.value, 0) + 1
        
        stats = ProjectStats(
            total_projects=len(user_projects),
            active_projects=len([p for p in user_projects if p.status == ProjectStatus.ACTIVE]),
            total_scans=total_scans,
            total_issues=total_issues,
            critical_issues=critical_issues,
            high_issues=high_issues,
            medium_issues=medium_issues,
            low_issues=low_issues,
            projects_by_type=projects_by_type,
            recent_scans=recent_scans
        )
        
        return ProjectSummary(
            project=project,
            stats=stats,
            recent_scans=recent_scans,
            recent_issues=recent_issues
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get project summary: {str(e)}"
        )

# ============================================================================
# Team Management Endpoints
# ============================================================================

@router.post("/teams", response_model=TeamResponse)
async def create_team(
    team: TeamCreate,
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new team"""
    try:
        team_data = team.dict()
        team_data["created_by"] = current_user.id
        
        new_team = Team(**team_data)
        db.add(new_team)
        await db.commit()
        await db.refresh(new_team)
        
        return new_team
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create team: {str(e)}"
        )

@router.get("/teams", response_model=List[TeamResponse])
async def get_teams(
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get teams for current user"""
    try:
        # Get teams where user is a member
        result = await db.execute(
            select(Team)
            .join(TeamMember)
            .where(TeamMember.user_id == current_user.id)
        )
        teams = result.scalars().all()
        
        return teams
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get teams: {str(e)}"
        ) 