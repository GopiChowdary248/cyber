from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List, Optional
import logging
import os
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

from ...database import get_db
from ...services.sast_database import SASTDatabaseService
from ...services.sast_scanner import SASTScanner, SASTScanManager
from ...services.sast_reports import SASTReportGenerator
from ...schemas.sast_schemas import (
    ProjectCreate, ProjectUpdate, ProjectResponse, ProjectListResponse,
    ScanRequest, SASTScanResponse, SASTScanListResponse,
    SASTResultResponse, SASTResultListResponse,
    SASTReportResponse, SASTReportListResponse,
    ScanSummaryResponse, ProjectSummaryResponse,
    VulnerabilityStatusUpdate, ScanProgressResponse
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sast", tags=["SAST"])

# Initialize report generator
report_generator = SASTReportGenerator()

# Project Management Endpoints
@router.post("/projects", response_model=ProjectResponse)
async def create_project(
    project_data: ProjectCreate,
    db: Session = Depends(get_db)
):
    """Create a new project for SAST scanning"""
    try:
        db_service = SASTDatabaseService(db)
        project = db_service.create_project(project_data)
        return project
    except Exception as e:
        logger.error(f"Error creating project: {e}")
        raise HTTPException(status_code=500, detail="Failed to create project")

@router.get("/projects", response_model=ProjectListResponse)
async def get_projects(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """Get all projects with pagination"""
    try:
        db_service = SASTDatabaseService(db)
        projects = db_service.get_projects(skip=skip, limit=limit)
        total = len(projects)  # In a real app, you'd get total count separately
        
        return ProjectListResponse(projects=projects, total=total)
    except Exception as e:
        logger.error(f"Error getting projects: {e}")
        raise HTTPException(status_code=500, detail="Failed to get projects")

@router.get("/projects/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: int,
    db: Session = Depends(get_db)
):
    """Get project by ID"""
    try:
        db_service = SASTDatabaseService(db)
        project = db_service.get_project(project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        return project
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting project {project_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get project")

@router.put("/projects/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: int,
    project_data: ProjectUpdate,
    db: Session = Depends(get_db)
):
    """Update project"""
    try:
        db_service = SASTDatabaseService(db)
        project = db_service.update_project(project_id, project_data)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        return project
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating project {project_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update project")

@router.delete("/projects/{project_id}")
async def delete_project(
    project_id: int,
    db: Session = Depends(get_db)
):
    """Delete project and all related data"""
    try:
        db_service = SASTDatabaseService(db)
        success = db_service.delete_project(project_id)
        if not success:
            raise HTTPException(status_code=404, detail="Project not found")
        return {"message": "Project deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting project {project_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete project")

# Scan Management Endpoints
@router.post("/projects/{project_id}/scan", response_model=SASTScanResponse)
async def trigger_scan(
    project_id: int,
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Trigger a new SAST scan for a project"""
    try:
        # Verify project exists
        db_service = SASTDatabaseService(db)
        project = db_service.get_project(project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Create scan record
        scan = db_service.create_scan(scan_request)
        
        # Add background task to run the scan
        background_tasks.add_task(
            run_sast_scan_background,
            scan.id,
            project_id,
            scan_request.scan_type.value,
            db
        )
        
        return scan
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error triggering scan for project {project_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to trigger scan")

@router.post("/scan/upload", response_model=SASTScanResponse)
async def upload_and_scan(
    project_id: int,
    scan_type: str = Query("full"),
    triggered_by: str = Query("user"),
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db)
):
    """Upload code and trigger SAST scan"""
    try:
        # Verify project exists
        db_service = SASTDatabaseService(db)
        project = db_service.get_project(project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Validate file type
        if not file.filename.endswith('.zip'):
            raise HTTPException(status_code=400, detail="Only ZIP files are supported")
        
        # Save uploaded file
        upload_dir = Path("uploads")
        upload_dir.mkdir(exist_ok=True)
        
        file_path = upload_dir / f"upload_{project_id}_{file.filename}"
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Create scan record
        scan_request = ScanRequest(
            project_id=project_id,
            scan_type=scan_type,
            triggered_by=triggered_by
        )
        scan = db_service.create_scan(scan_request)
        
        # Add background task to run the scan
        if background_tasks:
            background_tasks.add_task(
                run_upload_scan_background,
                scan.id,
                project_id,
                str(file_path),
                scan_type,
                db
            )
        
        return scan
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading and scanning for project {project_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to upload and scan")

@router.get("/scans", response_model=SASTScanListResponse)
async def get_scans(
    project_id: Optional[int] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """Get all scans with optional project filter"""
    try:
        db_service = SASTDatabaseService(db)
        
        if project_id:
            scans = db_service.get_project_scans(project_id, skip=skip, limit=limit)
        else:
            scans = db_service.get_recent_scans(limit=limit)
        
        total = len(scans)  # In a real app, you'd get total count separately
        
        return SASTScanListResponse(scans=scans, total=total)
    except Exception as e:
        logger.error(f"Error getting scans: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scans")

@router.get("/scans/{scan_id}", response_model=SASTScanResponse)
async def get_scan(
    scan_id: int,
    db: Session = Depends(get_db)
):
    """Get scan by ID"""
    try:
        db_service = SASTDatabaseService(db)
        scan = db_service.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan")

@router.get("/scans/{scan_id}/progress", response_model=ScanProgressResponse)
async def get_scan_progress(
    scan_id: int,
    db: Session = Depends(get_db)
):
    """Get scan progress information"""
    try:
        db_service = SASTDatabaseService(db)
        scan = db_service.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Calculate progress
        progress_percentage = 0
        if scan.total_files > 0:
            progress_percentage = (scan.scanned_files / scan.total_files) * 100
        
        return ScanProgressResponse(
            scan_id=scan.id,
            status=scan.status,
            progress_percentage=progress_percentage,
            files_scanned=scan.scanned_files,
            total_files=scan.total_files,
            current_tool=None,  # Would be updated during scan
            estimated_completion=None  # Would be calculated during scan
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan progress {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan progress")

# Vulnerability Endpoints
@router.get("/scans/{scan_id}/vulnerabilities", response_model=SASTResultListResponse)
async def get_scan_vulnerabilities(
    scan_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    tool: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Get vulnerabilities for a scan with optional filtering"""
    try:
        db_service = SASTDatabaseService(db)
        
        # Verify scan exists
        scan = db_service.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get vulnerabilities
        vulnerabilities = db_service.get_scan_vulnerabilities(scan_id, skip=skip, limit=limit)
        
        # Apply filters
        if severity:
            vulnerabilities = [v for v in vulnerabilities if v.severity.lower() == severity.lower()]
        if tool:
            vulnerabilities = [v for v in vulnerabilities if v.tool_name.lower() == tool.lower()]
        
        # Get summary
        summary = db_service.get_vulnerability_summary(scan_id)
        
        return SASTResultListResponse(
            results=vulnerabilities,
            total=len(vulnerabilities),
            summary=summary
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting vulnerabilities for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get vulnerabilities")

@router.get("/vulnerabilities/{vuln_id}", response_model=SASTResultResponse)
async def get_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db)
):
    """Get vulnerability by ID"""
    try:
        db_service = SASTDatabaseService(db)
        vulnerability = db_service.get_vulnerability(vuln_id)
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return vulnerability
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting vulnerability {vuln_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get vulnerability")

@router.put("/vulnerabilities/{vuln_id}/status", response_model=SASTResultResponse)
async def update_vulnerability_status(
    vuln_id: int,
    status_update: VulnerabilityStatusUpdate,
    db: Session = Depends(get_db)
):
    """Update vulnerability status"""
    try:
        db_service = SASTDatabaseService(db)
        vulnerability = db_service.update_vulnerability_status(vuln_id, status_update)
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return vulnerability
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating vulnerability status {vuln_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update vulnerability status")

# Report Endpoints
@router.get("/scans/{scan_id}/summary", response_model=ScanSummaryResponse)
async def get_scan_summary(
    scan_id: int,
    db: Session = Depends(get_db)
):
    """Get comprehensive scan summary"""
    try:
        db_service = SASTDatabaseService(db)
        summary = db_service.get_scan_summary(scan_id)
        if not summary:
            raise HTTPException(status_code=404, detail="Scan not found")
        return summary
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan summary {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan summary")

@router.get("/projects/{project_id}/summary", response_model=ProjectSummaryResponse)
async def get_project_summary(
    project_id: int,
    db: Session = Depends(get_db)
):
    """Get project summary with scan statistics"""
    try:
        db_service = SASTDatabaseService(db)
        summary = db_service.get_project_summary(project_id)
        if not summary:
            raise HTTPException(status_code=404, detail="Project not found")
        return summary
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting project summary {project_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get project summary")

@router.get("/scans/{scan_id}/reports", response_model=SASTReportListResponse)
async def get_scan_reports(
    scan_id: int,
    db: Session = Depends(get_db)
):
    """Get all reports for a scan"""
    try:
        db_service = SASTDatabaseService(db)
        
        # Verify scan exists
        scan = db_service.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        reports = db_service.get_scan_reports(scan_id)
        return SASTReportListResponse(reports=reports, total=len(reports))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting reports for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get reports")

@router.post("/scans/{scan_id}/reports/{report_type}")
async def generate_report(
    scan_id: int,
    report_type: str,
    db: Session = Depends(get_db)
):
    """Generate a new report for a scan"""
    try:
        db_service = SASTDatabaseService(db)
        
        # Get scan and project
        scan = db_service.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        project = db_service.get_project(scan.project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get vulnerabilities
        vulnerabilities = db_service.get_scan_vulnerabilities(scan_id)
        
        # Get summary
        summary = db_service.get_scan_summary(scan_id)
        if not summary:
            raise HTTPException(status_code=404, detail="Scan summary not found")
        
        # Generate report based on type
        report_path = None
        if report_type == "pdf":
            report_path = report_generator.generate_summary_report(scan, project, vulnerabilities, summary)
        elif report_type == "csv":
            report_path = report_generator.generate_csv_report(scan, vulnerabilities)
        elif report_type == "excel":
            report_path = report_generator.generate_excel_report(scan, project, vulnerabilities, summary)
        elif report_type == "json":
            report_path = report_generator.generate_json_report(scan, project, vulnerabilities, summary)
        else:
            raise HTTPException(status_code=400, detail="Unsupported report type")
        
        # Save report record to database
        report_data = {
            "report_type": report_type,
            "file_path": report_path,
            "generated_at": datetime.now().isoformat()
        }
        report = db_service.create_report(scan_id, report_type, report_data, report_path)
        
        return {
            "message": f"{report_type.upper()} report generated successfully",
            "report_id": report.id,
            "file_path": report_path
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating {report_type} report for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate {report_type} report")

@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: int,
    db: Session = Depends(get_db)
):
    """Download a generated report"""
    try:
        db_service = SASTDatabaseService(db)
        report = db_service.get_report(report_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        if not report.file_path or not os.path.exists(report.file_path):
            raise HTTPException(status_code=404, detail="Report file not found")
        
        return FileResponse(
            report.file_path,
            media_type='application/octet-stream',
            filename=os.path.basename(report.file_path)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading report {report_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to download report")

# Background task functions
async def run_sast_scan_background(scan_id: int, project_id: int, scan_type: str, db: Session):
    """Background task to run SAST scan"""
    try:
        logger.info(f"Starting background SAST scan {scan_id} for project {project_id}")
        
        db_service = SASTDatabaseService(db)
        
        # Get project path (in real implementation, this would be from repo or uploaded files)
        project_path = f"/tmp/project_{project_id}"  # Mock path
        
        # Run scan
        with SASTScanner(project_path) as scanner:
            vulnerabilities = scanner.scan_project(scan_type)
            
            # Convert to database format
            vuln_data = []
            for vuln in vulnerabilities:
                vuln_data.append({
                    "file_path": vuln.file_path,
                    "line_no": vuln.line_no,
                    "column_no": vuln.column_no,
                    "vulnerability": vuln.vulnerability,
                    "severity": vuln.severity,
                    "recommendation": vuln.recommendation,
                    "tool_name": vuln.tool_name,
                    "cwe_id": vuln.cwe_id,
                    "confidence": vuln.confidence
                })
            
            # Save vulnerabilities
            db_service.save_vulnerabilities(scan_id, vuln_data)
            
            # Update scan status
            db_service.update_scan_status(scan_id, "completed")
            
        logger.info(f"Completed background SAST scan {scan_id}")
        
    except Exception as e:
        logger.error(f"Error in background SAST scan {scan_id}: {e}")
        db_service.update_scan_status(scan_id, "failed")

async def run_upload_scan_background(scan_id: int, project_id: int, upload_path: str, scan_type: str, db: Session):
    """Background task to run SAST scan on uploaded code"""
    try:
        logger.info(f"Starting background upload scan {scan_id} for project {project_id}")
        
        db_service = SASTDatabaseService(db)
        
        # Extract uploaded code
        temp_dir = SASTScanManager.extract_uploaded_code(upload_path, project_id)
        
        try:
            # Run scan
            with SASTScanner(temp_dir) as scanner:
                vulnerabilities = scanner.scan_project(scan_type)
                
                # Convert to database format
                vuln_data = []
                for vuln in vulnerabilities:
                    vuln_data.append({
                        "file_path": vuln.file_path,
                        "line_no": vuln.line_no,
                        "column_no": vuln.column_no,
                        "vulnerability": vuln.vulnerability,
                        "severity": vuln.severity,
                        "recommendation": vuln.recommendation,
                        "tool_name": vuln.tool_name,
                        "cwe_id": vuln.cwe_id,
                        "confidence": vuln.confidence
                    })
                
                # Save vulnerabilities
                db_service.save_vulnerabilities(scan_id, vuln_data)
                
                # Update scan status
                db_service.update_scan_status(scan_id, "completed")
                
        finally:
            # Cleanup
            SASTScanManager.cleanup_temp_directory(temp_dir)
            if os.path.exists(upload_path):
                os.remove(upload_path)
        
        logger.info(f"Completed background upload scan {scan_id}")
        
    except Exception as e:
        logger.error(f"Error in background upload scan {scan_id}: {e}")
        db_service.update_scan_status(scan_id, "failed") 