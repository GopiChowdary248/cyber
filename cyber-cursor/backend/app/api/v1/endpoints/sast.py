"""
SAST (Static Application Security Testing) API Endpoints
Provides comprehensive REST API for SAST functionality including:
- Project management
- Code scanning
- Vulnerability analysis
- Report generation
- CI/CD integration
"""

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Query
from fastapi.responses import FileResponse
from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog
import os
import tempfile
import zipfile
import shutil
from pathlib import Path

from app.core.security import get_current_user
from app.services.sast_database import SASTDatabaseService
from app.services.sast_scanner import SASTScanner, SASTScanManager
from app.services.sast_reports import SASTReportService
from app.models.sast_models import Project, SASTScan, SASTResult, SASTReport
from app.schemas.sast_schemas import (
    ProjectCreate, ProjectResponse, ScanCreate, ScanResponse, 
    VulnerabilityResponse, ScanSummary, ProjectSummary
)

logger = structlog.get_logger()
router = APIRouter()

# Initialize services
sast_db_service = SASTDatabaseService()
sast_report_service = SASTReportService()

# Project Management Endpoints
@router.post("/projects", response_model=ProjectResponse)
async def create_project(
    project: ProjectCreate,
    current_user = Depends(get_current_user)
):
    """Create a new SAST project"""
    try:
        project_data = project.dict()
        project_data["created_by"] = current_user.id
        created_project = await sast_db_service.create_project(project_data)
        return ProjectResponse(**created_project)
    except Exception as e:
        logger.error("Error creating project", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create project")

@router.get("/projects", response_model=List[ProjectResponse])
async def get_projects(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user = Depends(get_current_user)
):
    """Get all SAST projects"""
    try:
        projects = await sast_db_service.get_projects(skip=skip, limit=limit)
        return [ProjectResponse(**project) for project in projects]
    except Exception as e:
        logger.error("Error getting projects", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve projects")

@router.get("/projects/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: int,
    current_user = Depends(get_current_user)
):
    """Get a specific SAST project"""
    try:
        project = await sast_db_service.get_project(project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        return ProjectResponse(**project)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error getting project", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve project")

@router.delete("/projects/{project_id}")
async def delete_project(
    project_id: int,
    current_user = Depends(get_current_user)
):
    """Delete a SAST project"""
    try:
        success = await sast_db_service.delete_project(project_id)
        if not success:
            raise HTTPException(status_code=404, detail="Project not found")
        return {"message": "Project deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error deleting project", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to delete project")

# Scan Management Endpoints
@router.post("/projects/{project_id}/scan", response_model=ScanResponse)
async def start_scan(
    project_id: int,
    scan_config: Optional[Dict[str, Any]] = Form(None),
    current_user = Depends(get_current_user)
):
    """Start a SAST scan for a project"""
    try:
        # Verify project exists
        project = await sast_db_service.get_project(project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Create scan record
        scan_data = {
            "project_id": project_id,
            "triggered_by": current_user.email,
            "scan_config": scan_config or {},
            "status": "running"
        }
        
        scan = await sast_db_service.create_scan(scan_data)
        
        # Start scan in background (in production, use Celery)
        # For now, we'll run it synchronously
        try:
            await run_sast_scan(scan["id"], project_id, scan_config or {})
        except Exception as scan_error:
            logger.error("Scan failed", scan_id=scan["id"], error=str(scan_error))
            await sast_db_service.update_scan_status(scan["id"], "failed")
            raise HTTPException(status_code=500, detail="Scan failed to complete")
        
        return ScanResponse(**scan)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error starting scan", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to start scan")

@router.post("/scan/upload", response_model=ScanResponse)
async def upload_and_scan(
    file: UploadFile = File(...),
    project_name: str = Form(...),
    scan_config: Optional[str] = Form(None),
    current_user = Depends(get_current_user)
):
    """Upload code and start SAST scan"""
    try:
        # Validate file
        if not file.filename.endswith('.zip'):
            raise HTTPException(status_code=400, detail="Only ZIP files are supported")
        
        # Create temporary directory
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, file.filename)
        
        try:
            # Save uploaded file
            with open(zip_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            
            # Extract ZIP file
            extract_path = os.path.join(temp_dir, "extracted")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
            
            # Create project
            project_data = {
                "name": project_name,
                "description": f"Uploaded project: {project_name}",
                "created_by": current_user.id
            }
            project = await sast_db_service.create_project(project_data)
            
            # Create scan record
            scan_config_dict = {}
            if scan_config:
                import json
                scan_config_dict = json.loads(scan_config)
            
            scan_data = {
                "project_id": project["id"],
                "triggered_by": current_user.email,
                "scan_config": scan_config_dict,
                "status": "running"
            }
            
            scan = await sast_db_service.create_scan(scan_data)
            
            # Run scan
            await run_sast_scan(scan["id"], project["id"], scan_config_dict, extract_path)
            
            return ScanResponse(**scan)
            
        finally:
            # Cleanup temporary files
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error uploading and scanning", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to upload and scan code")

@router.get("/scans", response_model=List[ScanResponse])
async def get_scans(
    project_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user = Depends(get_current_user)
):
    """Get all SAST scans with optional filtering"""
    try:
        filters = {}
        if project_id:
            filters["project_id"] = project_id
        if status:
            filters["status"] = status
            
        scans = await sast_db_service.get_scans(filters=filters, skip=skip, limit=limit)
        return [ScanResponse(**scan) for scan in scans]
    except Exception as e:
        logger.error("Error getting scans", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve scans")

@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    current_user = Depends(get_current_user)
):
    """Get a specific SAST scan"""
    try:
        scan = await sast_db_service.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return ScanResponse(**scan)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error getting scan", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve scan")

@router.get("/scans/{scan_id}/progress")
async def get_scan_progress(
    scan_id: int,
    current_user = Depends(get_current_user)
):
    """Get scan progress"""
    try:
        scan = await sast_db_service.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        progress = {
            "scan_id": scan_id,
            "status": scan["status"],
            "start_time": scan["start_time"],
            "end_time": scan["end_time"],
            "total_files": scan.get("total_files", 0),
            "scanned_files": scan.get("scanned_files", 0),
            "vulnerabilities_found": scan.get("vulnerabilities_found", 0)
        }
        
        if scan["status"] == "running":
            progress["progress_percentage"] = min(
                (scan.get("scanned_files", 0) / max(scan.get("total_files", 1), 1)) * 100, 
                100
            )
        else:
            progress["progress_percentage"] = 100
            
        return progress
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error getting scan progress", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get scan progress")

# Vulnerability Endpoints
@router.get("/scans/{scan_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def get_scan_vulnerabilities(
    scan_id: int,
    severity: Optional[str] = Query(None),
    tool_name: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user = Depends(get_current_user)
):
    """Get vulnerabilities for a specific scan"""
    try:
        # Verify scan exists
        scan = await sast_db_service.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        filters = {"scan_id": scan_id}
        if severity:
            filters["severity"] = severity
        if tool_name:
            filters["tool_name"] = tool_name
            
        vulnerabilities = await sast_db_service.get_vulnerabilities(filters=filters, skip=skip, limit=limit)
        return [VulnerabilityResponse(**vuln) for vuln in vulnerabilities]
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error getting vulnerabilities", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve vulnerabilities")

@router.put("/vulnerabilities/{vuln_id}/status")
async def update_vulnerability_status(
    vuln_id: int,
    status: str = Form(...),
    current_user = Depends(get_current_user)
):
    """Update vulnerability status"""
    try:
        valid_statuses = ["open", "fixed", "false_positive", "wont_fix", "in_progress"]
        if status not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")
        
        success = await sast_db_service.update_vulnerability_status(vuln_id, status)
        if not success:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        return {"message": "Vulnerability status updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error updating vulnerability status", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to update vulnerability status")

# Summary and Analytics Endpoints
@router.get("/scans/{scan_id}/summary", response_model=ScanSummary)
async def get_scan_summary(
    scan_id: int,
    current_user = Depends(get_current_user)
):
    """Get summary for a specific scan"""
    try:
        scan = await sast_db_service.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        summary = await sast_db_service.get_scan_summary(scan_id)
        return ScanSummary(**summary)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error getting scan summary", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve scan summary")

@router.get("/projects/{project_id}/summary", response_model=ProjectSummary)
async def get_project_summary(
    project_id: int,
    current_user = Depends(get_current_user)
):
    """Get summary for a specific project"""
    try:
        project = await sast_db_service.get_project(project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        summary = await sast_db_service.get_project_summary(project_id)
        return ProjectSummary(**summary)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error getting project summary", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve project summary")

@router.get("/summary")
async def get_sast_summary(current_user = Depends(get_current_user)):
    """Get overall SAST summary"""
    try:
        summary = await sast_db_service.get_overall_summary()
        return summary
    except Exception as e:
        logger.error("Error getting SAST summary", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve SAST summary")

# Report Generation Endpoints
@router.get("/scans/{scan_id}/reports/{report_type}")
async def generate_report(
    scan_id: int,
    report_type: str,
    current_user = Depends(get_current_user)
):
    """Generate and download a report"""
    try:
        scan = await sast_db_service.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        valid_types = ["pdf", "csv", "json", "html"]
        if report_type not in valid_types:
            raise HTTPException(status_code=400, detail=f"Invalid report type. Must be one of: {valid_types}")
        
        # Generate report
        report_path = await sast_report_service.generate_report(scan_id, report_type)
        
        # Return file
        filename = f"sast_report_{scan_id}_{report_type}.{report_type}"
        return FileResponse(
            path=report_path,
            filename=filename,
            media_type="application/octet-stream"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error generating report", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to generate report")

# CI/CD Integration Endpoints
@router.post("/webhook/github")
async def github_webhook(
    payload: Dict[str, Any],
    current_user = Depends(get_current_user)
):
    """Handle GitHub webhook for automatic scanning"""
    try:
        # Verify webhook signature (implement proper verification)
        event_type = payload.get("ref_type")
        repository = payload.get("repository", {})
        repo_url = repository.get("clone_url")
        
        if not repo_url:
            raise HTTPException(status_code=400, detail="Invalid webhook payload")
        
        # Create or get project
        project = await sast_db_service.get_project_by_repo_url(repo_url)
        if not project:
            project_data = {
                "name": repository.get("name", "Unknown"),
                "repo_url": repo_url,
                "description": f"Auto-created from GitHub webhook",
                "created_by": current_user.id
            }
            project = await sast_db_service.create_project(project_data)
        
        # Start scan
        scan_data = {
            "project_id": project["id"],
            "triggered_by": "github_webhook",
            "scan_config": {"auto_scan": True},
            "status": "running"
        }
        
        scan = await sast_db_service.create_scan(scan_data)
        
        # Run scan in background
        # In production, use Celery for background tasks
        await run_sast_scan(scan["id"], project["id"], {"auto_scan": True})
        
        return {"message": "Webhook processed successfully", "scan_id": scan["id"]}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error processing webhook", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to process webhook")

# Helper function to run SAST scan
async def run_sast_scan(scan_id: int, project_id: int, scan_config: Dict[str, Any], project_path: Optional[str] = None):
    """Run SAST scan and store results"""
    try:
        # Update scan status to running
        await sast_db_service.update_scan_status(scan_id, "running")
        
        # Get project path if not provided
        if not project_path:
            project = await sast_db_service.get_project(project_id)
            if project.get("repo_url"):
                # Clone repository
                project_path = await clone_repository(project["repo_url"])
            else:
                raise Exception("No project path or repository URL available")
        
        # Run SAST scan
        with SASTScanner(project_path) as scanner:
            vulnerabilities = scanner.scan_project(scan_config.get("scan_type", "full"))
        
        # Store vulnerabilities
        for vuln in vulnerabilities:
            vuln_data = {
                "scan_id": scan_id,
                "file_path": vuln.file_path,
                "line_no": vuln.line_no,
                "column_no": vuln.column_no,
                "vulnerability": vuln.vulnerability,
                "severity": vuln.severity,
                "recommendation": vuln.recommendation,
                "tool_name": vuln.tool_name,
                "cwe_id": vuln.cwe_id,
                "confidence": vuln.confidence
            }
            await sast_db_service.create_vulnerability(vuln_data)
        
        # Update scan status to completed
        await sast_db_service.update_scan_status(scan_id, "completed")
        
        logger.info("SAST scan completed", scan_id=scan_id, vulnerabilities_found=len(vulnerabilities))
        
    except Exception as e:
        logger.error("SAST scan failed", scan_id=scan_id, error=str(e))
        await sast_db_service.update_scan_status(scan_id, "failed")
        raise

async def clone_repository(repo_url: str) -> str:
    """Clone repository to temporary directory"""
    import git
    temp_dir = tempfile.mkdtemp()
    try:
        git.Repo.clone_from(repo_url, temp_dir)
        return temp_dir
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception(f"Failed to clone repository: {str(e)}") 