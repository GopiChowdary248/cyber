#!/usr/bin/env python3
"""
SAST (Static Application Security Testing) API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks, Query
from fastapi.responses import FileResponse, StreamingResponse
from typing import List, Optional, Dict, Any
import asyncio
import json
import os
import tempfile
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

from ...core.security import get_current_user
from ...core.database import get_db
from ...sast.scanner import SASTScanManager, SASTScanner
from ...sast.ai_recommendations import AIRecommendationEngine, RiskScoringEngine
from ...models.sast import (
    SASTScan, SASTVulnerability, SASTProject,
    SASTReport, SASTRule
)
from ...sast.ai_recommendations import AIRecommendation
from ...schemas.auth import User
from ...schemas.sast_schemas import (
    ScanCreate as SASTScanCreate,
    ScanResponse as SASTScanResponse,
    VulnerabilityResponse as SASTVulnerabilityResponse
)
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime

# Simple recommendation response schema
class SASTRecommendationResponse(BaseModel):
    vulnerability_id: str
    recommendation_type: str
    title: str
    description: str
    code_fix: Optional[str] = None
    confidence_score: float
    reasoning: str
    tags: List[str]
    created_at: datetime

router = APIRouter(prefix="/api/v1/sast", tags=["SAST"])

# Initialize engines
scan_manager = SASTScanManager()
ai_engine = AIRecommendationEngine()
risk_engine = RiskScoringEngine()

@router.post("/scan", response_model=Dict[str, Any])
async def trigger_sast_scan(
    background_tasks: BackgroundTasks,
    scan_request: SASTScanCreate,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Trigger a new SAST scan"""
    try:
        # Create scan record
        scan_id = f"sast_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        scan_record = SASTScan(
            id=scan_id,
            project_name=scan_request.project_name,
            project_path=scan_request.project_path,
            triggered_by=current_user.id,
            scan_config=scan_request.scan_config or {}
        )
        
        db.add(scan_record)
        db.commit()
        
        # Start background scan
        background_tasks.add_task(
            run_sast_scan_background,
            scan_id,
            scan_request.project_path,
            current_user.id,
            db
        )
        
        return {
            "message": "SAST scan triggered successfully",
            "scan_id": scan_id,
            "status": "running",
            "estimated_duration": "5-15 minutes"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to trigger scan: {str(e)}")

@router.post("/scan/upload")
async def upload_and_scan_code(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    project_name: str = Query(..., description="Project name"),
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Upload code and trigger SAST scan"""
    try:
        # Validate file type
        if not file.filename.endswith(('.zip', '.tar.gz', '.tar')):
            raise HTTPException(status_code=400, detail="Only ZIP and TAR files are supported")
        
        # Save uploaded file
        temp_dir = tempfile.mkdtemp()
        file_path = os.path.join(temp_dir, file.filename)
        
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        # Create scan record
        scan_id = f"sast_upload_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        scan_record = SASTScan(
            id=scan_id,
            project_name=project_name,
            project_path=file_path,
            triggered_by=current_user.id,
            scan_config={"upload_type": file.filename.split('.')[-1]}
        )
        
        db.add(scan_record)
        db.commit()
        
        # Start background scan
        background_tasks.add_task(
            run_upload_scan_background,
            scan_id,
            file_path,
            current_user.id,
            db
        )
        
        return {
            "message": "Code uploaded and scan triggered successfully",
            "scan_id": scan_id,
            "status": "running",
            "file_size": len(content),
            "estimated_duration": "5-15 minutes"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload and scan: {str(e)}")

@router.get("/scans", response_model=List[SASTScanResponse])
async def get_sast_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = Query(None),
    project_name: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Get list of SAST scans"""
    try:
        query = db.query(SASTScan)
        
        if status:
            query = query.filter(SASTScan.status == status)
        if project_name:
            query = query.filter(SASTScan.project_name.ilike(f"%{project_name}%"))
        
        scans = query.order_by(SASTScan.created_at.desc()).offset(skip).limit(limit).all()
        
        return [
            SASTScanResponse(
                id=scan.id,
                project_name=scan.project_name,
                status=scan.status,
                start_time=scan.start_time,
                end_time=scan.end_time,
                total_vulnerabilities=scan.total_vulnerabilities,
                critical_count=scan.critical_count,
                high_count=scan.high_count,
                medium_count=scan.medium_count,
                low_count=scan.low_count,
                scan_duration=scan.scan_duration,
                languages_detected=scan.languages_detected,
                tools_used=scan.tools_used,
                created_at=scan.created_at
            )
            for scan in scans
        ]
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve scans: {str(e)}")

@router.get("/scans/{scan_id}", response_model=SASTScanResponse)
async def get_sast_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Get specific SAST scan details"""
    try:
        scan = db.query(SASTScan).filter(SASTScan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return SASTScanResponse(
            id=scan.id,
            project_name=scan.project_name,
            status=scan.status,
            start_time=scan.start_time,
            end_time=scan.end_time,
            total_vulnerabilities=scan.total_vulnerabilities,
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=scan.medium_count,
            low_count=scan.low_count,
            scan_duration=scan.scan_duration,
            languages_detected=scan.languages_detected,
            tools_used=scan.tools_used,
            created_at=scan.created_at
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve scan: {str(e)}")

@router.get("/scans/{scan_id}/vulnerabilities", response_model=List[SASTVulnerabilityResponse])
async def get_sast_vulnerabilities(
    scan_id: str,
    severity: Optional[str] = Query(None),
    tool: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Get vulnerabilities for a specific scan"""
    try:
        query = db.query(SASTVulnerability).filter(SASTVulnerability.scan_id == scan_id)
        
        if severity:
            query = query.filter(SASTVulnerability.severity == severity)
        if tool:
            query = query.filter(SASTVulnerability.tool == tool)
        if status:
            query = query.filter(SASTVulnerability.status == status)
        
        vulnerabilities = query.order_by(SASTVulnerability.severity.desc()).offset(skip).limit(limit).all()
        
        return [
            SASTVulnerabilityResponse(
                id=vuln.id,
                scan_id=vuln.scan_id,
                file_name=vuln.file_name,
                line_number=vuln.line_number,
                column=vuln.column,
                severity=vuln.severity,
                vulnerability_type=vuln.vulnerability_type,
                description=vuln.description,
                recommendation=vuln.recommendation,
                rule_id=vuln.rule_id,
                tool=vuln.tool,
                cwe_id=vuln.cwe_id,
                scan_date=vuln.scan_date,
                code_snippet=vuln.code_snippet,
                risk_score=vuln.risk_score,
                status=vuln.status,
                assigned_to=vuln.assigned_to,
                created_at=vuln.created_at
            )
            for vuln in vulnerabilities
        ]
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve vulnerabilities: {str(e)}")

@router.get("/vulnerabilities/{vuln_id}/recommendations", response_model=List[SASTRecommendationResponse])
async def get_vulnerability_recommendations(
    vuln_id: str,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Get AI recommendations for a specific vulnerability"""
    try:
        # Get vulnerability
        vuln = db.query(SASTVulnerability).filter(SASTVulnerability.id == vuln_id).first()
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        # Get existing recommendations
        recommendations = db.query(SASTRecommendation).filter(
            SASTRecommendation.vulnerability_id == vuln_id
        ).all()
        
        # If no recommendations exist, generate new ones
        if not recommendations:
            vuln_dict = {
                "id": vuln.id,
                "vulnerability_type": vuln.vulnerability_type,
                "description": vuln.description,
                "severity": vuln.severity,
                "file_name": vuln.file_name,
                "line_number": vuln.line_number,
                "tool": vuln.tool
            }
            
            ai_recommendation = await ai_engine.generate_recommendation(vuln_dict)
            
            # Save recommendation to database
            rec_record = SASTRecommendation(
                scan_id=vuln.scan_id,
                vulnerability_id=vuln.id,
                recommendation_type=ai_recommendation.recommendation_type,
                title=ai_recommendation.title,
                description=ai_recommendation.description,
                code_fix=ai_recommendation.code_fix,
                before_code=ai_recommendation.before_code,
                after_code=ai_recommendation.after_code,
                confidence_score=ai_recommendation.confidence_score,
                reasoning=ai_recommendation.reasoning,
                tags=ai_recommendation.tags,
                ai_model=ai_engine.model
            )
            
            db.add(rec_record)
            db.commit()
            db.refresh(rec_record)
            
            recommendations = [rec_record]
        
        return [
            SASTRecommendationResponse(
                id=rec.id,
                vulnerability_id=rec.vulnerability_id,
                recommendation_type=rec.recommendation_type,
                title=rec.title,
                description=rec.description,
                code_fix=rec.code_fix,
                before_code=rec.before_code,
                after_code=rec.after_code,
                confidence_score=rec.confidence_score,
                reasoning=rec.reasoning,
                tags=rec.tags,
                ai_model=rec.ai_model,
                created_at=rec.created_at
            )
            for rec in recommendations
        ]
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get recommendations: {str(e)}")

@router.get("/summary")
async def get_sast_summary(
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Get SAST summary statistics"""
    try:
        # Get total scans
        total_scans = db.query(SASTScan).count()
        
        # Get vulnerability counts
        total_vulns = db.query(SASTVulnerability).count()
        critical_count = db.query(SASTVulnerability).filter(SASTVulnerability.severity == 'critical').count()
        high_count = db.query(SASTVulnerability).filter(SASTVulnerability.severity == 'high').count()
        medium_count = db.query(SASTVulnerability).filter(SASTVulnerability.severity == 'medium').count()
        low_count = db.query(SASTVulnerability).filter(SASTVulnerability.severity == 'low').count()
        
        # Calculate average risk score
        vulns_with_score = db.query(SASTVulnerability).filter(SASTVulnerability.risk_score.isnot(None)).all()
        avg_risk_score = sum(v.risk_score for v in vulns_with_score) / len(vulns_with_score) if vulns_with_score else 0
        
        # Get most common vulnerabilities
        vuln_types = db.query(SASTVulnerability.vulnerability_type, db.func.count(SASTVulnerability.id)).group_by(
            SASTVulnerability.vulnerability_type
        ).order_by(db.func.count(SASTVulnerability.id).desc()).limit(10).all()
        
        most_common = [{"type": v[0], "count": v[1]} for v in vuln_types]
        
        # Get scan trends (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_scans = db.query(SASTScan).filter(SASTScan.created_at >= thirty_days_ago).all()
        
        scan_trends = []
        for i in range(30):
            date = thirty_days_ago + timedelta(days=i)
            day_scans = [s for s in recent_scans if s.created_at.date() == date.date()]
            scan_trends.append({
                "date": date.strftime("%Y-%m-%d"),
                "scans": len(day_scans),
                "vulnerabilities": sum(s.total_vulnerabilities for s in day_scans)
            })
        
        return {
            "total_scans": total_scans,
            "total_vulnerabilities": total_vulns,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "average_risk_score": round(avg_risk_score, 2),
            "most_common_vulnerabilities": most_common,
            "scan_trends": scan_trends
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get summary: {str(e)}")

@router.post("/vulnerabilities/{vuln_id}/status")
async def update_vulnerability_status(
    vuln_id: str,
    status: str,
    assigned_to: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Update vulnerability status"""
    try:
        vuln = db.query(SASTVulnerability).filter(SASTVulnerability.id == vuln_id).first()
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        vuln.status = status
        if assigned_to:
            vuln.assigned_to = assigned_to
        vuln.updated_at = datetime.utcnow()
        
        db.commit()
        
        return {"message": "Vulnerability status updated successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update status: {str(e)}")

@router.get("/reports/{scan_id}")
async def generate_sast_report(
    scan_id: str,
    format: str = Query("pdf", regex="^(pdf|csv|json|html)$"),
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Generate SAST report for a scan"""
    try:
        scan = db.query(SASTScan).filter(SASTScan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get vulnerabilities
        vulnerabilities = db.query(SASTVulnerability).filter(
            SASTVulnerability.scan_id == scan_id
        ).all()
        
        # Generate report based on format
        if format == "json":
            report_data = {
                "scan": {
                    "id": scan.id,
                    "project_name": scan.project_name,
                    "status": scan.status,
                    "start_time": scan.start_time.isoformat(),
                    "end_time": scan.end_time.isoformat() if scan.end_time else None,
                    "total_vulnerabilities": scan.total_vulnerabilities,
                    "scan_duration": scan.scan_duration
                },
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "file_name": v.file_name,
                        "line_number": v.line_number,
                        "severity": v.severity,
                        "vulnerability_type": v.vulnerability_type,
                        "description": v.description,
                        "recommendation": v.recommendation,
                        "tool": v.tool,
                        "risk_score": v.risk_score
                    }
                    for v in vulnerabilities
                ]
            }
            
            return StreamingResponse(
                iter([json.dumps(report_data, indent=2)]),
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=sast_report_{scan_id}.json"}
            )
        
        elif format == "csv":
            csv_content = "ID,File,Line,Severity,Type,Description,Tool,Risk Score\n"
            for v in vulnerabilities:
                csv_content += f"{v.id},{v.file_name},{v.line_number},{v.severity},{v.vulnerability_type},{v.description},{v.tool},{v.risk_score or 0}\n"
            
            return StreamingResponse(
                iter([csv_content]),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=sast_report_{scan_id}.csv"}
            )
        
        else:
            # For PDF and HTML, return a placeholder
            return {"message": f"{format.upper()} report generation not implemented yet"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

# Background task functions
async def run_sast_scan_background(scan_id: str, project_path: str, user_id: str, db):
    """Background task to run SAST scan"""
    try:
        # Update scan status to running
        scan = db.query(SASTScan).filter(SASTScan.id == scan_id).first()
        if scan:
            scan.status = "running"
            db.commit()
        
        # Run scan
        scanner = SASTScanner(project_path, scan_id)
        vulnerabilities = await scanner.scan_project()
        
        # Calculate risk scores
        for vuln in vulnerabilities:
            vuln.risk_score = risk_engine.calculate_vulnerability_risk_score({
                "severity": vuln.severity,
                "vulnerability_type": vuln.vulnerability_type,
                "context": vuln.context or {}
            })
        
        # Save vulnerabilities to database
        for vuln in vulnerabilities:
            vuln_record = SASTVulnerability(
                scan_id=scan_id,
                original_id=vuln.id,
                file_name=vuln.file_name,
                line_number=vuln.line_number,
                column=vuln.column,
                severity=vuln.severity,
                vulnerability_type=vuln.vulnerability_type,
                description=vuln.description,
                recommendation=vuln.recommendation,
                rule_id=vuln.rule_id,
                tool=vuln.tool,
                cwe_id=vuln.cwe_id,
                scan_date=vuln.scan_date,
                code_snippet=vuln.code_snippet,
                context=vuln.context,
                risk_score=vuln.risk_score
            )
            db.add(vuln_record)
        
        # Update scan record
        scan_summary = scanner.get_scan_summary()
        scan.total_vulnerabilities = scan_summary['total_vulnerabilities']
        scan.critical_count = scan_summary['severity_breakdown']['critical']
        scan.high_count = scan_summary['severity_breakdown']['high']
        scan.medium_count = scan_summary['severity_breakdown']['medium']
        scan.low_count = scan_summary['severity_breakdown']['low']
        scan.scan_duration = scan_summary['scan_duration']
        scan.languages_detected = list(scan_summary.get('language_breakdown', {}).keys())
        scan.tools_used = list(scan_summary.get('tool_breakdown', {}).keys())
        scan.status = "completed"
        scan.end_time = datetime.utcnow()
        
        db.commit()
        
    except Exception as e:
        # Update scan status to failed
        scan = db.query(SASTScan).filter(SASTScan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.error_message = str(e)
            scan.end_time = datetime.utcnow()
            db.commit()

async def run_upload_scan_background(scan_id: str, file_path: str, user_id: str, db):
    """Background task to run scan on uploaded code"""
    try:
        # Update scan status to running
        scan = db.query(SASTScan).filter(SASTScan.id == scan_id).first()
        if scan:
            scan.status = "running"
            db.commit()
        
        # Run scan on uploaded file
        vulnerabilities = await scan_manager.scan_uploaded_code(file_path, scan_id)
        
        # Calculate risk scores and save to database (same as above)
        for vuln in vulnerabilities:
            vuln.risk_score = risk_engine.calculate_vulnerability_risk_score({
                "severity": vuln.severity,
                "vulnerability_type": vuln.vulnerability_type,
                "context": vuln.context or {}
            })
            
            vuln_record = SASTVulnerability(
                scan_id=scan_id,
                original_id=vuln.id,
                file_name=vuln.file_name,
                line_number=vuln.line_number,
                column=vuln.column,
                severity=vuln.severity,
                vulnerability_type=vuln.vulnerability_type,
                description=vuln.description,
                recommendation=vuln.recommendation,
                rule_id=vuln.rule_id,
                tool=vuln.tool,
                cwe_id=vuln.cwe_id,
                scan_date=vuln.scan_date,
                code_snippet=vuln.code_snippet,
                context=vuln.context,
                risk_score=vuln.risk_score
            )
            db.add(vuln_record)
        
        # Update scan record
        scan.total_vulnerabilities = len(vulnerabilities)
        scan.critical_count = len([v for v in vulnerabilities if v.severity == 'critical'])
        scan.high_count = len([v for v in vulnerabilities if v.severity == 'high'])
        scan.medium_count = len([v for v in vulnerabilities if v.severity == 'medium'])
        scan.low_count = len([v for v in vulnerabilities if v.severity == 'low'])
        scan.status = "completed"
        scan.end_time = datetime.utcnow()
        
        db.commit()
        
        # Clean up uploaded file
        if os.path.exists(file_path):
            os.remove(file_path)
        
    except Exception as e:
        # Update scan status to failed
        scan = db.query(SASTScan).filter(SASTScan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.error_message = str(e)
            scan.end_time = datetime.utcnow()
            db.commit() 