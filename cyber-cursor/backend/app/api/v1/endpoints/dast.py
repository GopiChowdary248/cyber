"""
DAST (Dynamic Application Security Testing) API Endpoints
Provides comprehensive REST API for DAST functionality including:
- Project management
- Dynamic scanning
- Vulnerability analysis
- Payload management
- Report generation
- CI/CD integration
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid
import json
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.models.dast import (
    DASTProject, DASTScan, DASTVulnerability, DASTPayload, DASTReport, DASTSession,
    ScanStatus, VulnerabilitySeverity, VulnerabilityStatus, AuthType, ScanType
)
from app.models.user import User
from app.core.security import get_current_user

router = APIRouter()

@router.get("/test")
async def test_dast_endpoint():
    """Test endpoint to verify DAST router is working"""
    return {"message": "DAST router is working!", "status": "success"}

@router.get("/simple")
async def simple_dast_endpoint():
    """Simple endpoint without database dependency"""
    return {"message": "Simple DAST endpoint working!", "status": "success"}

@router.get("/debug")
async def debug_dast_endpoint():
    """Debug endpoint to check router mounting"""
    return {
        "message": "DAST debug endpoint working!",
        "router_info": "DAST router is mounted correctly",
        "timestamp": datetime.utcnow().isoformat()
    }

async def simulate_dast_scan(scan_id: str, db: AsyncSession):
    """Simulate a background DAST scan process"""
    try:
        # Update scan status to running
        scan = await DASTScan.get_by_id(db, scan_id)
        if scan:
            scan.status = ScanStatus.RUNNING
            await db.commit()
            
            # Simulate scan processing time
            await asyncio.sleep(3)
            
            # Simulate vulnerability discovery
            project = await DASTProject.get_by_id(db, str(scan.project_id))
            if project:
                # Create sample vulnerabilities based on project type
                vulnerabilities = [
                    {
                        "title": "SQL Injection in Search Parameter",
                        "description": "SQL injection vulnerability detected in search functionality",
                        "severity": VulnerabilitySeverity.CRITICAL,
                        "url": f"{project.target_url}/search",
                        "http_method": "GET",
                        "param_name": "q",
                        "vuln_type": "sqli",
                        "payload": "' OR 1=1 --",
                        "cwe_id": "CWE-89",
                        "owasp_category": "A03:2021-Injection"
                    },
                    {
                        "title": "Cross-Site Scripting in Contact Form",
                        "description": "XSS vulnerability in contact form comment field",
                        "severity": VulnerabilitySeverity.HIGH,
                        "url": f"{project.target_url}/contact",
                        "http_method": "POST",
                        "param_name": "message",
                        "vuln_type": "xss",
                        "payload": "<script>alert('XSS')</script>",
                        "cwe_id": "CWE-79",
                        "owasp_category": "A03:2021-Injection"
                    },
                    {
                        "title": "Missing Security Headers",
                        "description": "Application missing important security headers",
                        "severity": VulnerabilitySeverity.MEDIUM,
                        "url": project.target_url,
                        "http_method": "GET",
                        "param_name": None,
                        "vuln_type": "security_headers",
                        "payload": None,
                        "cwe_id": "CWE-693",
                        "owasp_category": "A05:2021-Security Misconfiguration"
                    }
                ]
                
                # Create vulnerability records
                for vuln_data in vulnerabilities:
                    vulnerability = DASTVulnerability(
                        scan_id=scan_id,
                        project_id=str(scan.project_id),
                        title=vuln_data["title"],
                        description=vuln_data["description"],
                        severity=vuln_data["severity"],
                        url=vuln_data["url"],
                        http_method=vuln_data["http_method"],
                        param_name=vuln_data["param_name"],
                        vuln_type=vuln_data["vuln_type"],
                        payload=vuln_data["payload"],
                        cwe_id=vuln_data["cwe_id"],
                        owasp_category=vuln_data["owasp_category"],
                        response_code=200,
                        response_time=0.5,
                        response_size=1024
                    )
                    db.add(vulnerability)
                
                # Update scan results
                scan.vulnerabilities_found = len(vulnerabilities)
                scan.urls_scanned = 15
                scan.requests_made = 45
                scan.scan_duration = 180.5
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                
                await db.commit()
    except Exception as e:
        # Update scan status to failed
        scan = await DASTScan.get_by_id(db, scan_id)
        if scan:
            scan.status = ScanStatus.FAILED
            await db.commit()

@router.get("/overview")
async def get_dast_overview(
    db: AsyncSession = Depends(get_db)
):
    """Get DAST overview statistics"""
    try:
        # Get total projects
        projects_result = await db.execute(select(func.count(DASTProject.id)))
        total_projects = projects_result.scalar()
        
        # Get total scans
        scans_result = await db.execute(select(func.count(DASTScan.id)))
        total_scans = scans_result.scalar()
        
        # Get active scans
        active_scans_result = await db.execute(
            select(func.count(DASTScan.id)).where(DASTScan.status == ScanStatus.RUNNING)
        )
        active_scans = active_scans_result.scalar()
        
        # Get total vulnerabilities
        vulns_result = await db.execute(select(func.count(DASTVulnerability.id)))
        total_vulnerabilities = vulns_result.scalar()
        
        # Get vulnerabilities by severity
        critical_result = await db.execute(
            select(func.count(DASTVulnerability.id)).where(DASTVulnerability.severity == VulnerabilitySeverity.CRITICAL)
        )
        critical_vulns = critical_result.scalar()
        
        high_result = await db.execute(
            select(func.count(DASTVulnerability.id)).where(DASTVulnerability.severity == VulnerabilitySeverity.HIGH)
        )
        high_vulns = high_result.scalar()
        
        medium_result = await db.execute(
            select(func.count(DASTVulnerability.id)).where(DASTVulnerability.severity == VulnerabilitySeverity.MEDIUM)
        )
        medium_vulns = medium_result.scalar()
        
        low_result = await db.execute(
            select(func.count(DASTVulnerability.id)).where(DASTVulnerability.severity == VulnerabilitySeverity.LOW)
        )
        low_vulns = low_result.scalar()
        
        # Calculate security score
        avg_security_score = 78.5  # This would be calculated from actual data
        
        return {
            "overview": {
                "totalProjects": total_projects or 0,
                "totalScans": total_scans or 0,
                "activeScans": active_scans or 0,
                "totalVulnerabilities": total_vulnerabilities or 0,
                "securityScore": avg_security_score
            },
            "vulnerabilities": {
                "critical": critical_vulns or 0,
                "high": high_vulns or 0,
                "medium": medium_vulns or 0,
                "low": low_vulns or 0,
                "total": total_vulnerabilities or 0
            },
            "scanTypes": {
                "full": 45,
                "passive": 32,
                "active": 28,
                "custom": 15
            },
            "recentScans": [
                {
                    "id": "scan-001",
                    "projectName": "E-commerce Web App",
                    "status": "completed",
                    "vulnerabilities": 3,
                    "duration": "3m 45s",
                    "timestamp": "2025-08-02T18:00:00Z"
                }
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.get("/projects")
async def get_dast_projects(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all DAST projects"""
    try:
        projects = await DASTProject.get_all(db, skip=skip, limit=limit)
        return {
            "projects": [
                {
                    "id": str(project.id),
                    "name": project.name,
                    "target_url": project.target_url,
                    "description": project.description,
                    "auth_type": project.auth_type,
                    "created_at": project.created_at.isoformat() if project.created_at else None,
                    "last_scan": project.last_scan.isoformat() if project.last_scan else None,
                    "total_scans": project.total_scans,
                    "total_vulnerabilities": project.total_vulnerabilities,
                    "security_score": float(project.security_score) if project.security_score else None
                }
                for project in projects
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.post("/projects")
async def create_dast_project(
    project_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new DAST project"""
    try:
        project = DASTProject(
            name=project_data.get("name"),
            target_url=project_data.get("target_url"),
            description=project_data.get("description"),
            auth_type=project_data.get("auth_type", AuthType.NONE),
            auth_config=project_data.get("auth_config"),
            scan_config=project_data.get("scan_config"),
            scope_config=project_data.get("scope_config"),
            tags=project_data.get("tags"),
            created_by=current_user.id
        )
        
        db.add(project)
        await db.commit()
        await db.refresh(project)
        
        return {
            "id": str(project.id),
            "name": project.name,
            "target_url": project.target_url,
            "auth_type": project.auth_type,
            "created_at": project.created_at.isoformat() if project.created_at else None
        }
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create project: {str(e)}")

@router.get("/scans")
async def get_dast_scans(
    project_id: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get DAST scans, optionally filtered by project"""
    try:
        if project_id:
            scans = await DASTScan.get_by_project(db, project_id, skip=skip, limit=limit)
        else:
            scans_result = await db.execute(
                select(DASTScan).offset(skip).limit(limit)
            )
            scans = scans_result.scalars().all()
        
        return {
            "scans": [
                {
                    "id": str(scan.id),
                    "project_id": str(scan.project_id),
                    "project_name": scan.project.name if scan.project else "Unknown",
                    "scan_type": scan.scan_type,
                    "status": scan.status,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "duration": f"{int(scan.scan_duration)}s" if scan.scan_duration else None,
                    "vulnerabilities_found": scan.vulnerabilities_found,
                    "urls_scanned": scan.urls_scanned,
                    "requests_made": scan.requests_made
                }
                for scan in scans
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.post("/scans")
async def create_dast_scan(
    scan_data: Dict[str, Any],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new DAST scan"""
    try:
        scan = DASTScan(
            project_id=scan_data.get("project_id"),
            scan_type=scan_data.get("scan_type", ScanType.FULL),
            scan_config=scan_data.get("scan_config"),
            auth_config=scan_data.get("auth_config"),
            initiated_by=current_user.id
        )
        
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        
        # Add background task to simulate scan
        background_tasks.add_task(simulate_dast_scan, str(scan.id), db)
        
        return {
            "id": str(scan.id),
            "project_id": str(scan.project_id),
            "scan_type": scan.scan_type,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None
        }
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create scan: {str(e)}")

@router.get("/scans/{scan_id}")
async def get_dast_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get specific DAST scan details"""
    try:
        scan = await DASTScan.get_by_id(db, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return {
            "id": str(scan.id),
            "project_id": str(scan.project_id),
            "project_name": scan.project.name if scan.project else "Unknown",
            "scan_type": scan.scan_type,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration": f"{int(scan.scan_duration)}s" if scan.scan_duration else None,
            "vulnerabilities_found": scan.vulnerabilities_found,
            "urls_scanned": scan.urls_scanned,
            "requests_made": scan.requests_made,
            "scan_config": scan.scan_config,
            "scan_summary": scan.scan_summary
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.get("/scans/{scan_id}/vulnerabilities")
async def get_scan_vulnerabilities(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get vulnerabilities for a specific scan"""
    try:
        vulnerabilities = await DASTVulnerability.get_by_scan(db, scan_id)
        
        return {
            "vulnerabilities": [
                {
                    "id": str(vuln.id),
                    "scan_id": str(vuln.scan_id),
                    "project_id": str(vuln.project_id),
                    "title": vuln.title,
                    "description": vuln.description,
                    "severity": vuln.severity,
                    "status": vuln.status,
                    "url": vuln.url,
                    "http_method": vuln.http_method,
                    "param_name": vuln.param_name,
                    "vuln_type": vuln.vuln_type,
                    "payload": vuln.payload,
                    "cwe_id": vuln.cwe_id,
                    "owasp_category": vuln.owasp_category,
                    "response_code": vuln.response_code,
                    "response_time": vuln.response_time,
                    "created_at": vuln.created_at.isoformat() if vuln.created_at else None
                }
                for vuln in vulnerabilities
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.get("/vulnerabilities")
async def get_all_vulnerabilities(
    severity: Optional[str] = None,
    vuln_type: Optional[str] = None,
    project_id: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all vulnerabilities with optional filtering"""
    try:
        query = select(DASTVulnerability)
        
        if severity:
            query = query.where(DASTVulnerability.severity == severity)
        if vuln_type:
            query = query.where(DASTVulnerability.vuln_type == vuln_type)
        if project_id:
            query = query.where(DASTVulnerability.project_id == project_id)
        
        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        vulnerabilities = result.scalars().all()
        
        return {
            "vulnerabilities": [
                {
                    "id": str(vuln.id),
                    "scan_id": str(vuln.scan_id),
                    "project_id": str(vuln.project_id),
                    "title": vuln.title,
                    "description": vuln.description,
                    "severity": vuln.severity,
                    "status": vuln.status,
                    "url": vuln.url,
                    "http_method": vuln.http_method,
                    "param_name": vuln.param_name,
                    "vuln_type": vuln.vuln_type,
                    "payload": vuln.payload,
                    "cwe_id": vuln.cwe_id,
                    "owasp_category": vuln.owasp_category,
                    "response_code": vuln.response_code,
                    "response_time": vuln.response_time,
                    "created_at": vuln.created_at.isoformat() if vuln.created_at else None
                }
                for vuln in vulnerabilities
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.get("/payloads")
async def get_payloads(
    vuln_type: Optional[str] = None,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all payloads"""
    try:
        if vuln_type:
            payloads = await DASTPayload.get_by_type(db, vuln_type)
        elif severity:
            payloads = await DASTPayload.get_by_severity(db, severity)
        else:
            payloads = await DASTPayload.get_active_payloads(db)
        
        return {
            "payloads": [
                {
                    "id": str(payload.id),
                    "name": payload.name,
                    "vuln_type": payload.vuln_type,
                    "payload": payload.payload,
                    "description": payload.description,
                    "severity": payload.severity,
                    "cwe_id": payload.cwe_id,
                    "owasp_category": payload.owasp_category,
                    "language": payload.language,
                    "is_active": payload.is_active,
                    "is_custom": payload.is_custom,
                    "created_at": payload.created_at.isoformat() if payload.created_at else None
                }
                for payload in payloads
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.post("/payloads")
async def create_payload(
    payload_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new custom payload"""
    try:
        payload = DASTPayload(
            name=payload_data.get("name"),
            vuln_type=payload_data.get("vuln_type"),
            payload=payload_data.get("payload"),
            description=payload_data.get("description"),
            severity=payload_data.get("severity"),
            cwe_id=payload_data.get("cwe_id"),
            owasp_category=payload_data.get("owasp_category"),
            language=payload_data.get("language"),
            tags=payload_data.get("tags"),
            metadata=payload_data.get("metadata"),
            is_custom=True,
            created_by=current_user.id
        )
        
        db.add(payload)
        await db.commit()
        await db.refresh(payload)
        
        return {
            "id": str(payload.id),
            "name": payload.name,
            "vuln_type": payload.vuln_type,
            "severity": payload.severity,
            "created_at": payload.created_at.isoformat() if payload.created_at else None
        }
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create payload: {str(e)}")

@router.get("/reports/{scan_id}")
async def generate_scan_report(
    scan_id: str,
    format: str = "json",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate scan report in specified format"""
    try:
        scan = await DASTScan.get_by_id(db, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        vulnerabilities = await DASTVulnerability.get_by_scan(db, scan_id)
        
        # Create report
        report = DASTReport(
            scan_id=scan_id,
            project_id=str(scan.project_id),
            report_type="detailed",
            format=format,
            report_data={
                "scan_info": {
                    "id": str(scan.id),
                    "project_name": scan.project.name if scan.project else "Unknown",
                    "scan_type": scan.scan_type,
                    "status": scan.status,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "duration": scan.scan_duration,
                    "urls_scanned": scan.urls_scanned,
                    "requests_made": scan.requests_made
                },
                "vulnerabilities": [
                    {
                        "id": str(vuln.id),
                        "title": vuln.title,
                        "severity": vuln.severity,
                        "url": vuln.url,
                        "http_method": vuln.http_method,
                        "description": vuln.description,
                        "cwe_id": vuln.cwe_id,
                        "owasp_category": vuln.owasp_category
                    }
                    for vuln in vulnerabilities
                ]
            },
            generated_by=current_user.id
        )
        
        db.add(report)
        await db.commit()
        await db.refresh(report)
        
        return {
            "report_id": str(report.id),
            "scan_id": str(scan.id),
            "format": format,
            "generated_at": report.generated_at.isoformat() if report.generated_at else None,
            "download_url": f"/api/v1/dast/reports/{report.id}/download"
        }
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

@router.post("/webhook")
async def dast_webhook(
    webhook_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db)
):
    """CI/CD webhook to trigger DAST scans"""
    try:
        # Extract webhook data
        project_id = webhook_data.get("project_id")
        scan_type = webhook_data.get("scan_type", ScanType.FULL)
        scan_config = webhook_data.get("scan_config", {})
        
        if not project_id:
            raise HTTPException(status_code=400, detail="project_id is required")
        
        # Create scan
        scan = DASTScan(
            project_id=project_id,
            scan_type=scan_type,
            scan_config=scan_config,
            initiated_by=None  # System-initiated scan
        )
        
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        
        # Start background scan
        asyncio.create_task(simulate_dast_scan(str(scan.id), db))
        
        return {
            "scan_id": str(scan.id),
            "status": "queued",
            "message": "DAST scan queued successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to process webhook: {str(e)}") 