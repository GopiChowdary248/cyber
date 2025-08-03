"""
SAST (Static Application Security Testing) API Endpoints
Provides comprehensive REST API for SAST functionality including:
- Project management
- Code scanning
- Vulnerability analysis
- Report generation
- CI/CD integration
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid
import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.models.sast import (
    SASTProject, SASTScan, SASTVulnerability, SASTRule, SASTReport,
    ScanStatus, VulnerabilitySeverity, VulnerabilityStatus, AutoFixStatus
)
from app.models.user import User
from app.core.security import get_current_user

router = APIRouter()

async def simulate_scan(scan_id: str, db: AsyncSession):
    """Simulate a background scan process"""
    try:
        # Update scan status to running
        scan = await SASTScan.get_by_id(db, scan_id)
        if scan:
            scan.status = ScanStatus.RUNNING
            await db.commit()
            
            # Simulate scan processing time
            import asyncio
            await asyncio.sleep(2)
            
            # Update scan status to completed
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.scan_duration = 120.5  # Simulated duration
            await db.commit()
    except Exception as e:
        # Update scan status to failed
        scan = await SASTScan.get_by_id(db, scan_id)
        if scan:
            scan.status = ScanStatus.FAILED
            await db.commit()

@router.get("/overview")
async def get_sast_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get SAST overview statistics"""
    try:
        # Get total projects
        projects_result = await db.execute(select(func.count(SASTProject.id)))
        total_projects = projects_result.scalar()
        
        # Get total scans
        scans_result = await db.execute(select(func.count(SASTScan.id)))
        total_scans = scans_result.scalar()
        
        # Get active scans
        active_scans_result = await db.execute(
            select(func.count(SASTScan.id)).where(SASTScan.status == ScanStatus.RUNNING)
        )
        active_scans = active_scans_result.scalar()
        
        # Get total vulnerabilities
        vulns_result = await db.execute(select(func.count(SASTVulnerability.id)))
        total_vulnerabilities = vulns_result.scalar()
        
        # Get vulnerabilities by severity
        critical_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == VulnerabilitySeverity.CRITICAL)
        )
        critical_vulns = critical_result.scalar()
        
        high_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == VulnerabilitySeverity.HIGH)
        )
        high_vulns = high_result.scalar()
        
        medium_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == VulnerabilitySeverity.MEDIUM)
        )
        medium_vulns = medium_result.scalar()
        
        low_result = await db.execute(
            select(func.count(SASTVulnerability.id)).where(SASTVulnerability.severity == VulnerabilitySeverity.LOW)
        )
        low_vulns = low_result.scalar()
        
        # Calculate security score
        avg_security_score = 85.5  # This would be calculated from actual data
        
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
            "languages": {
                "python": 45,
                "javascript": 32,
                "java": 18,
                "csharp": 12,
                "php": 8
            },
            "recentScans": [
                {
                    "id": "scan-001",
                    "projectName": "E-commerce Platform",
                    "status": "completed",
                    "vulnerabilities": 3,
                    "duration": "2m 34s",
                    "timestamp": "2025-08-02T18:00:00Z"
                }
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.get("/projects")
async def get_sast_projects(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all SAST projects"""
    try:
        projects = await SASTProject.get_all(db, skip=skip, limit=limit)
        return {
            "projects": [
                {
                    "id": str(project.id),
                    "name": project.name,
                    "repository_url": project.repository_url,
                    "language": project.language,
                    "created_at": project.created_at.isoformat() if project.created_at else None,
                    "last_scan": project.last_scan.isoformat() if project.last_scan else None,
                    "total_scans": project.total_scans,
                    "avg_vulnerabilities": float(project.avg_vulnerabilities) if project.avg_vulnerabilities else 0.0,
                    "security_score": float(project.security_score) if project.security_score else None
                }
                for project in projects
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.post("/projects")
async def create_sast_project(
    project_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new SAST project"""
    try:
        project = SASTProject(
            name=project_data.get("name"),
            repository_url=project_data.get("repository_url"),
            language=project_data.get("language"),
            description=project_data.get("description"),
            scan_config=project_data.get("scan_config"),
            rules_config=project_data.get("rules_config"),
            created_by=current_user.id
        )
        
        db.add(project)
        await db.commit()
        await db.refresh(project)
        
        return {
            "id": str(project.id),
            "name": project.name,
            "repository_url": project.repository_url,
            "language": project.language,
            "created_at": project.created_at.isoformat() if project.created_at else None
        }
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create project: {str(e)}")

@router.get("/scans")
async def get_sast_scans(
    project_id: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get SAST scans, optionally filtered by project"""
    try:
        if project_id:
            scans = await SASTScan.get_by_project(db, project_id, skip=skip, limit=limit)
        else:
            scans_result = await db.execute(
                select(SASTScan).offset(skip).limit(limit)
            )
            scans = scans_result.scalars().all()
        
        return {
            "scans": [
                {
                    "id": str(scan.id),
                    "project_id": str(scan.project_id),
                    "project_name": scan.project.name if scan.project else "Unknown",
                    "status": scan.status,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "duration": f"{int(scan.scan_duration)}s" if scan.scan_duration else None,
                    "vulnerabilities_found": scan.vulnerabilities_found,
                    "files_scanned": scan.files_scanned,
                    "lines_of_code": scan.lines_of_code
                }
                for scan in scans
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.post("/scans")
async def create_sast_scan(
    scan_data: Dict[str, Any],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new SAST scan"""
    try:
        scan = SASTScan(
            project_id=scan_data.get("project_id"),
            scan_type=scan_data.get("scan_type", "full"),
            scan_config=scan_data.get("scan_config"),
            rules_enabled=scan_data.get("rules_enabled"),
            initiated_by=current_user.id
        )
        
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        
        # Add background task to simulate scan
        background_tasks.add_task(simulate_scan, str(scan.id), db)
        
        return {
            "id": str(scan.id),
            "project_id": str(scan.project_id),
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None
        }
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create scan: {str(e)}")

@router.get("/scans/{scan_id}")
async def get_sast_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get specific SAST scan details"""
    try:
        scan = await SASTScan.get_by_id(db, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return {
            "id": str(scan.id),
            "project_id": str(scan.project_id),
            "project_name": scan.project.name if scan.project else "Unknown",
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration": f"{int(scan.scan_duration)}s" if scan.scan_duration else None,
            "vulnerabilities_found": scan.vulnerabilities_found,
            "files_scanned": scan.files_scanned,
            "lines_of_code": scan.lines_of_code,
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
        vulnerabilities = await SASTVulnerability.get_by_scan(db, scan_id)
        
        return {
            "vulnerabilities": [
                {
                    "id": str(vuln.id),
                    "scan_id": str(vuln.scan_id),
                    "project_id": str(vuln.project_id),
                    "file_path": vuln.file_path,
                    "line_number": vuln.line_number,
                    "language": vuln.language,
                    "severity": vuln.severity,
                    "cwe_id": vuln.cwe_id,
                    "owasp_category": vuln.owasp_category,
                    "title": vuln.title,
                    "description": vuln.description,
                    "vulnerable_code": vuln.vulnerable_code,
                    "fixed_code": vuln.fixed_code,
                    "auto_fix_available": vuln.auto_fix_available,
                    "auto_fix_suggestion": vuln.auto_fix_suggestion,
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
    language: Optional[str] = None,
    project_id: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all vulnerabilities with optional filtering"""
    try:
        query = select(SASTVulnerability)
        
        if severity:
            query = query.where(SASTVulnerability.severity == severity)
        if language:
            query = query.where(SASTVulnerability.language == language)
        if project_id:
            query = query.where(SASTVulnerability.project_id == project_id)
        
        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        vulnerabilities = result.scalars().all()
        
        return {
            "vulnerabilities": [
                {
                    "id": str(vuln.id),
                    "scan_id": str(vuln.scan_id),
                    "project_id": str(vuln.project_id),
                    "file_path": vuln.file_path,
                    "line_number": vuln.line_number,
                    "language": vuln.language,
                    "severity": vuln.severity,
                    "cwe_id": vuln.cwe_id,
                    "owasp_category": vuln.owasp_category,
                    "title": vuln.title,
                    "description": vuln.description,
                    "vulnerable_code": vuln.vulnerable_code,
                    "fixed_code": vuln.fixed_code,
                    "auto_fix_available": vuln.auto_fix_available,
                    "auto_fix_suggestion": vuln.auto_fix_suggestion,
                    "created_at": vuln.created_at.isoformat() if vuln.created_at else None
                }
                for vuln in vulnerabilities
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.get("/rules")
async def get_detection_rules(
    language: Optional[str] = None,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all detection rules"""
    try:
        if language:
            rules = await SASTRule.get_by_language(db, language)
        elif severity:
            rules = await SASTRule.get_by_severity(db, severity)
        else:
            rules = await SASTRule.get_active_rules(db)
        
        return {
            "rules": [
                {
                    "id": str(rule.id),
                    "name": rule.name,
                    "title": rule.title,
                    "description": rule.description,
                    "language": rule.language,
                    "regex_pattern": rule.regex_pattern,
                    "ast_pattern": rule.ast_pattern,
                    "severity": rule.severity,
                    "cwe_id": rule.cwe_id,
                    "owasp_category": rule.owasp_category,
                    "auto_fix_available": rule.auto_fix_available,
                    "auto_fix_template": rule.auto_fix_template,
                    "recommendation": rule.recommendation,
                    "is_active": rule.is_active,
                    "is_custom": rule.is_custom,
                    "created_at": rule.created_at.isoformat() if rule.created_at else None
                }
                for rule in rules
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.post("/rules")
async def create_detection_rule(
    rule_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new detection rule"""
    try:
        rule = SASTRule(
            name=rule_data.get("name"),
            title=rule_data.get("title"),
            description=rule_data.get("description"),
            language=rule_data.get("language"),
            regex_pattern=rule_data.get("regex_pattern"),
            ast_pattern=rule_data.get("ast_pattern"),
            severity=rule_data.get("severity"),
            cwe_id=rule_data.get("cwe_id"),
            owasp_category=rule_data.get("owasp_category"),
            auto_fix_available=rule_data.get("auto_fix_available", False),
            auto_fix_template=rule_data.get("auto_fix_template"),
            recommendation=rule_data.get("recommendation"),
            tags=rule_data.get("tags"),
            metadata=rule_data.get("metadata"),
            is_custom=True,
            created_by=current_user.id
        )
        
        db.add(rule)
        await db.commit()
        await db.refresh(rule)
        
        return {
            "id": str(rule.id),
            "name": rule.name,
            "title": rule.title,
            "language": rule.language,
            "severity": rule.severity,
            "created_at": rule.created_at.isoformat() if rule.created_at else None
        }
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create rule: {str(e)}")

@router.get("/auto-fix/{vulnerability_id}")
async def get_auto_fix_suggestion(
    vulnerability_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get auto-fix suggestion for a vulnerability"""
    try:
        vulnerability = await SASTVulnerability.get_by_id(db, vulnerability_id)
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        if not vulnerability.auto_fix_available:
            raise HTTPException(status_code=400, detail="Auto-fix not available for this vulnerability")
        
        return {
            "vulnerability_id": str(vulnerability.id),
            "title": vulnerability.title,
            "vulnerable_code": vulnerability.vulnerable_code,
            "fixed_code": vulnerability.fixed_code,
            "suggestion": vulnerability.auto_fix_suggestion,
            "status": vulnerability.auto_fix_status
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.post("/auto-fix/{vulnerability_id}/apply")
async def apply_auto_fix(
    vulnerability_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Apply auto-fix for a vulnerability"""
    try:
        vulnerability = await SASTVulnerability.get_by_id(db, vulnerability_id)
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        if not vulnerability.auto_fix_available:
            raise HTTPException(status_code=400, detail="Auto-fix not available for this vulnerability")
        
        # Update vulnerability status
        vulnerability.status = VulnerabilityStatus.FIXED
        vulnerability.auto_fix_status = AutoFixStatus.APPLIED
        vulnerability.fixed_at = datetime.utcnow()
        
        await db.commit()
        
        return {
            "vulnerability_id": str(vulnerability.id),
            "status": "fixed",
            "applied_at": vulnerability.fixed_at.isoformat() if vulnerability.fixed_at else None,
            "message": "Auto-fix applied successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to apply auto-fix: {str(e)}")

@router.get("/reports/{scan_id}")
async def generate_scan_report(
    scan_id: str,
    format: str = "json",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate scan report in specified format"""
    try:
        scan = await SASTScan.get_by_id(db, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        vulnerabilities = await SASTVulnerability.get_by_scan(db, scan_id)
        
        # Create report
        report = SASTReport(
            scan_id=scan_id,
            project_id=str(scan.project_id),
            report_type="detailed",
            format=format,
            report_data={
                "scan_info": {
                    "id": str(scan.id),
                    "project_name": scan.project.name if scan.project else "Unknown",
                    "status": scan.status,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "duration": scan.scan_duration,
                    "files_scanned": scan.files_scanned,
                    "lines_of_code": scan.lines_of_code
                },
                "vulnerabilities": [
                    {
                        "id": str(vuln.id),
                        "title": vuln.title,
                        "severity": vuln.severity,
                        "file_path": vuln.file_path,
                        "line_number": vuln.line_number,
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
            "download_url": f"/api/v1/sast/reports/{report.id}/download"
        }
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}") 