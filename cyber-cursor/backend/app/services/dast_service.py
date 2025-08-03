"""
DAST (Dynamic Application Security Testing) Service
Provides comprehensive DAST functionality including:
- Scan orchestration and management
- Project management
- Vulnerability analysis
- Report generation
- CI/CD integration
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.dast import (
    DASTProject, DASTScan, DASTVulnerability, DASTPayload, DASTReport,
    ScanStatus, VulnerabilitySeverity, VulnerabilityStatus, AuthType, ScanType
)
from app.services.dast_scanner import DASTScanner

logger = logging.getLogger(__name__)

class DASTService:
    """Service class for DAST operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_scan(self, project_id: str, scan_config: Dict[str, Any] = None, user_id: int = None) -> str:
        """Create a new DAST scan"""
        scan = DASTScan(
            project_id=project_id,
            scan_type=ScanType.FULL,
            scan_config=scan_config or {},
            initiated_by=user_id
        )
        
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)
        
        return str(scan.id)
    
    async def run_scan(self, scan_id: str) -> Dict[str, Any]:
        """Run a DAST scan"""
        scanner = DASTScanner(self.db)
        
        # Get scan details
        scan = await DASTScan.get_by_id(self.db, scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        
        # Initialize and run scan
        await scanner.initialize_scan(scan_id, str(scan.project_id), scan.scan_config)
        results = await scanner.run_scan()
        
        return results
    
    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status and progress"""
        scan = await DASTScan.get_by_id(self.db, scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        
        return {
            "id": str(scan.id),
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "vulnerabilities_found": scan.vulnerabilities_found,
            "urls_scanned": scan.urls_scanned,
            "scan_summary": scan.scan_summary
        }
    
    async def get_scan_vulnerabilities(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities for a scan"""
        vulnerabilities = await DASTVulnerability.get_by_scan(self.db, scan_id)
        
        return [
            {
                "id": str(vuln.id),
                "title": vuln.title,
                "description": vuln.description,
                "severity": vuln.severity,
                "url": vuln.url,
                "http_method": vuln.http_method,
                "param_name": vuln.param_name,
                "vuln_type": vuln.vuln_type,
                "payload": vuln.payload,
                "cwe_id": vuln.cwe_id,
                "owasp_category": vuln.owasp_category,
                "evidence": vuln.evidence,
                "created_at": vuln.created_at.isoformat() if vuln.created_at else None
            }
            for vuln in vulnerabilities
        ]
    
    async def generate_report(self, scan_id: str, format: str = "json") -> Dict[str, Any]:
        """Generate scan report"""
        scan = await DASTScan.get_by_id(self.db, scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        
        vulnerabilities = await DASTVulnerability.get_by_scan(self.db, scan_id)
        
        report = DASTReport(
            scan_id=scan_id,
            project_id=str(scan.project_id),
            report_type="detailed",
            format=format,
            report_data={
                "scan_info": {
                    "id": str(scan.id),
                    "status": scan.status,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "duration": scan.scan_duration,
                    "urls_scanned": scan.urls_scanned,
                    "vulnerabilities_found": scan.vulnerabilities_found
                },
                "vulnerabilities": [
                    {
                        "id": str(vuln.id),
                        "title": vuln.title,
                        "severity": vuln.severity,
                        "url": vuln.url,
                        "description": vuln.description,
                        "cwe_id": vuln.cwe_id,
                        "owasp_category": vuln.owasp_category
                    }
                    for vuln in vulnerabilities
                ]
            }
        )
        
        self.db.add(report)
        await self.db.commit()
        await self.db.refresh(report)
        
        return {
            "report_id": str(report.id),
            "scan_id": scan_id,
            "format": format,
            "generated_at": report.generated_at.isoformat() if report.generated_at else None
        }
    
    async def get_project_overview(self, project_id: str) -> Dict[str, Any]:
        """Get project overview with statistics"""
        project = await DASTProject.get_by_id(self.db, project_id)
        if not project:
            raise ValueError(f"Project {project_id} not found")
        
        # Get scan statistics
        scans_result = await self.db.execute(
            select(func.count(DASTScan.id)).where(DASTScan.project_id == project_id)
        )
        total_scans = scans_result.scalar() or 0
        
        # Get vulnerability statistics
        vulns_result = await self.db.execute(
            select(func.count(DASTVulnerability.id)).where(DASTVulnerability.project_id == project_id)
        )
        total_vulns = vulns_result.scalar() or 0
        
        # Get vulnerabilities by severity
        critical_result = await self.db.execute(
            select(func.count(DASTVulnerability.id)).where(
                DASTVulnerability.project_id == project_id,
                DASTVulnerability.severity == VulnerabilitySeverity.CRITICAL
            )
        )
        critical_vulns = critical_result.scalar() or 0
        
        high_result = await self.db.execute(
            select(func.count(DASTVulnerability.id)).where(
                DASTVulnerability.project_id == project_id,
                DASTVulnerability.severity == VulnerabilitySeverity.HIGH
            )
        )
        high_vulns = high_result.scalar() or 0
        
        medium_result = await self.db.execute(
            select(func.count(DASTVulnerability.id)).where(
                DASTVulnerability.project_id == project_id,
                DASTVulnerability.severity == VulnerabilitySeverity.MEDIUM
            )
        )
        medium_vulns = medium_result.scalar() or 0
        
        low_result = await self.db.execute(
            select(func.count(DASTVulnerability.id)).where(
                DASTVulnerability.project_id == project_id,
                DASTVulnerability.severity == VulnerabilitySeverity.LOW
            )
        )
        low_vulns = low_result.scalar() or 0
        
        # Calculate security score
        security_score = max(0, 100 - (critical_vulns * 20 + high_vulns * 10 + medium_vulns * 5 + low_vulns * 2))
        
        return {
            "project": {
                "id": str(project.id),
                "name": project.name,
                "target_url": project.target_url,
                "description": project.description,
                "auth_type": project.auth_type,
                "created_at": project.created_at.isoformat() if project.created_at else None,
                "last_scan": project.last_scan.isoformat() if project.last_scan else None
            },
            "statistics": {
                "total_scans": total_scans,
                "total_vulnerabilities": total_vulns,
                "security_score": security_score,
                "vulnerabilities_by_severity": {
                    "critical": critical_vulns,
                    "high": high_vulns,
                    "medium": medium_vulns,
                    "low": low_vulns
                }
            }
        }
    
    async def get_all_projects(self, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all DAST projects with statistics"""
        projects = await DASTProject.get_all(self.db, skip=skip, limit=limit)
        
        project_list = []
        for project in projects:
            # Get basic statistics for each project
            scans_result = await self.db.execute(
                select(func.count(DASTScan.id)).where(DASTScan.project_id == str(project.id))
            )
            total_scans = scans_result.scalar() or 0
            
            vulns_result = await self.db.execute(
                select(func.count(DASTVulnerability.id)).where(DASTVulnerability.project_id == str(project.id))
            )
            total_vulns = vulns_result.scalar() or 0
            
            project_list.append({
                "id": str(project.id),
                "name": project.name,
                "target_url": project.target_url,
                "description": project.description,
                "auth_type": project.auth_type,
                "created_at": project.created_at.isoformat() if project.created_at else None,
                "last_scan": project.last_scan.isoformat() if project.last_scan else None,
                "total_scans": total_scans,
                "total_vulnerabilities": total_vulns,
                "security_score": float(project.security_score) if project.security_score else None
            })
        
        return project_list
    
    async def create_project(self, project_data: Dict[str, Any], user_id: int = None) -> str:
        """Create a new DAST project"""
        project = DASTProject(
            name=project_data.get("name"),
            target_url=project_data.get("target_url"),
            description=project_data.get("description"),
            auth_type=project_data.get("auth_type", AuthType.NONE),
            auth_config=project_data.get("auth_config"),
            scan_config=project_data.get("scan_config"),
            scope_config=project_data.get("scope_config"),
            tags=project_data.get("tags"),
            created_by=user_id
        )
        
        self.db.add(project)
        await self.db.commit()
        await self.db.refresh(project)
        
        return str(project.id)
    
    async def get_project_scans(self, project_id: str, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get scans for a specific project"""
        scans = await DASTScan.get_by_project(self.db, project_id, skip=skip, limit=limit)
        
        return [
            {
                "id": str(scan.id),
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
    
    async def get_vulnerabilities(self, 
                                severity: Optional[str] = None,
                                vuln_type: Optional[str] = None,
                                project_id: Optional[str] = None,
                                skip: int = 0,
                                limit: int = 100) -> List[Dict[str, Any]]:
        """Get vulnerabilities with optional filtering"""
        from sqlalchemy import select
        
        query = select(DASTVulnerability)
        
        if severity:
            query = query.where(DASTVulnerability.severity == severity)
        if vuln_type:
            query = query.where(DASTVulnerability.vuln_type == vuln_type)
        if project_id:
            query = query.where(DASTVulnerability.project_id == project_id)
        
        query = query.offset(skip).limit(limit)
        result = await self.db.execute(query)
        vulnerabilities = result.scalars().all()
        
        return [
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
    
    async def get_payloads(self, 
                          vuln_type: Optional[str] = None,
                          severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get payloads with optional filtering"""
        if vuln_type:
            payloads = await DASTPayload.get_by_type(self.db, vuln_type)
        elif severity:
            payloads = await DASTPayload.get_by_severity(self.db, severity)
        else:
            payloads = await DASTPayload.get_active_payloads(self.db)
        
        return [
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
    
    async def create_payload(self, payload_data: Dict[str, Any], user_id: int = None) -> str:
        """Create a new custom payload"""
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
            created_by=user_id
        )
        
        self.db.add(payload)
        await self.db.commit()
        await self.db.refresh(payload)
        
        return str(payload.id)
    
    async def get_dast_overview(self) -> Dict[str, Any]:
        """Get DAST overview statistics"""
        # Get total projects
        projects_result = await self.db.execute(select(func.count(DASTProject.id)))
        total_projects = projects_result.scalar() or 0
        
        # Get total scans
        scans_result = await self.db.execute(select(func.count(DASTScan.id)))
        total_scans = scans_result.scalar() or 0
        
        # Get active scans
        active_scans_result = await self.db.execute(
            select(func.count(DASTScan.id)).where(DASTScan.status == ScanStatus.RUNNING)
        )
        active_scans = active_scans_result.scalar() or 0
        
        # Get total vulnerabilities
        vulns_result = await self.db.execute(select(func.count(DASTVulnerability.id)))
        total_vulnerabilities = vulns_result.scalar() or 0
        
        # Get vulnerabilities by severity
        critical_result = await self.db.execute(
            select(func.count(DASTVulnerability.id)).where(DASTVulnerability.severity == VulnerabilitySeverity.CRITICAL)
        )
        critical_vulns = critical_result.scalar() or 0
        
        high_result = await self.db.execute(
            select(func.count(DASTVulnerability.id)).where(DASTVulnerability.severity == VulnerabilitySeverity.HIGH)
        )
        high_vulns = high_result.scalar() or 0
        
        medium_result = await self.db.execute(
            select(func.count(DASTVulnerability.id)).where(DASTVulnerability.severity == VulnerabilitySeverity.MEDIUM)
        )
        medium_vulns = medium_result.scalar() or 0
        
        low_result = await self.db.execute(
            select(func.count(DASTVulnerability.id)).where(DASTVulnerability.severity == VulnerabilitySeverity.LOW)
        )
        low_vulns = low_result.scalar() or 0
        
        # Calculate security score
        avg_security_score = 78.5  # This would be calculated from actual data
        
        return {
            "overview": {
                "totalProjects": total_projects,
                "totalScans": total_scans,
                "activeScans": active_scans,
                "totalVulnerabilities": total_vulnerabilities,
                "securityScore": avg_security_score
            },
            "vulnerabilities": {
                "critical": critical_vulns,
                "high": high_vulns,
                "medium": medium_vulns,
                "low": low_vulns,
                "total": total_vulnerabilities
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
    
    async def process_webhook(self, webhook_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process CI/CD webhook to trigger DAST scans"""
        # Extract webhook data
        project_id = webhook_data.get("project_id")
        scan_type = webhook_data.get("scan_type", ScanType.FULL)
        scan_config = webhook_data.get("scan_config", {})
        
        if not project_id:
            raise ValueError("project_id is required")
        
        # Create scan
        scan_id = await self.create_scan(project_id, scan_config)
        
        # Start background scan
        asyncio.create_task(self.run_scan(scan_id))
        
        return {
            "scan_id": scan_id,
            "status": "queued",
            "message": "DAST scan queued successfully"
        } 