from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging

from ..models.sast_models import Project, SASTScan, SASTResult, SASTReport
from ..schemas.sast_schemas import (
    ProjectCreate, ProjectUpdate, ScanRequest, VulnerabilityStatusUpdate,
    ScanSummaryResponse, ProjectSummaryResponse
)

logger = logging.getLogger(__name__)

class SASTDatabaseService:
    def __init__(self, db: Session):
        self.db = db
    
    # Project operations
    def create_project(self, project_data: ProjectCreate) -> Project:
        """Create a new project"""
        project = Project(
            name=project_data.name,
            repo_url=str(project_data.repo_url) if project_data.repo_url else None,
            description=project_data.description
        )
        self.db.add(project)
        self.db.commit()
        self.db.refresh(project)
        logger.info(f"Created project: {project.name} (ID: {project.id})")
        return project
    
    def get_project(self, project_id: int) -> Optional[Project]:
        """Get project by ID"""
        return self.db.query(Project).filter(Project.id == project_id).first()
    
    def get_projects(self, skip: int = 0, limit: int = 100) -> List[Project]:
        """Get all projects with pagination"""
        return self.db.query(Project).offset(skip).limit(limit).all()
    
    def update_project(self, project_id: int, project_data: ProjectUpdate) -> Optional[Project]:
        """Update project"""
        project = self.get_project(project_id)
        if not project:
            return None
        
        update_data = project_data.dict(exclude_unset=True)
        if "repo_url" in update_data and update_data["repo_url"]:
            update_data["repo_url"] = str(update_data["repo_url"])
        
        for field, value in update_data.items():
            setattr(project, field, value)
        
        self.db.commit()
        self.db.refresh(project)
        logger.info(f"Updated project: {project.name} (ID: {project.id})")
        return project
    
    def delete_project(self, project_id: int) -> bool:
        """Delete project and all related data"""
        project = self.get_project(project_id)
        if not project:
            return False
        
        self.db.delete(project)
        self.db.commit()
        logger.info(f"Deleted project: {project.name} (ID: {project.id})")
        return True
    
    # Scan operations
    def create_scan(self, scan_data: ScanRequest) -> SASTScan:
        """Create a new scan"""
        scan = SASTScan(
            project_id=scan_data.project_id,
            triggered_by=scan_data.triggered_by,
            scan_type=scan_data.scan_type.value
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        logger.info(f"Created scan: {scan.id} for project {scan_data.project_id}")
        return scan
    
    def get_scan(self, scan_id: int) -> Optional[SASTScan]:
        """Get scan by ID"""
        return self.db.query(SASTScan).filter(SASTScan.id == scan_id).first()
    
    def get_project_scans(self, project_id: int, skip: int = 0, limit: int = 100) -> List[SASTScan]:
        """Get all scans for a project"""
        return (self.db.query(SASTScan)
                .filter(SASTScan.project_id == project_id)
                .order_by(desc(SASTScan.created_at))
                .offset(skip)
                .limit(limit)
                .all())
    
    def update_scan_status(self, scan_id: int, status: str, end_time: Optional[datetime] = None) -> Optional[SASTScan]:
        """Update scan status"""
        scan = self.get_scan(scan_id)
        if not scan:
            return None
        
        scan.status = status
        if end_time:
            scan.end_time = end_time
        
        self.db.commit()
        self.db.refresh(scan)
        logger.info(f"Updated scan {scan_id} status to: {status}")
        return scan
    
    def update_scan_progress(self, scan_id: int, scanned_files: int, total_files: int) -> Optional[SASTScan]:
        """Update scan progress"""
        scan = self.get_scan(scan_id)
        if not scan:
            return None
        
        scan.scanned_files = scanned_files
        scan.total_files = total_files
        
        self.db.commit()
        self.db.refresh(scan)
        return scan
    
    # Vulnerability operations
    def save_vulnerabilities(self, scan_id: int, vulnerabilities: List[Dict[str, Any]]) -> List[SASTResult]:
        """Save vulnerabilities to database"""
        results = []
        for vuln_data in vulnerabilities:
            result = SASTResult(
                scan_id=scan_id,
                file_path=vuln_data["file_path"],
                line_no=vuln_data.get("line_no"),
                column_no=vuln_data.get("column_no"),
                vulnerability=vuln_data["vulnerability"],
                severity=vuln_data["severity"],
                recommendation=vuln_data.get("recommendation"),
                tool_name=vuln_data["tool_name"],
                cwe_id=vuln_data.get("cwe_id"),
                confidence=vuln_data.get("confidence", "medium")
            )
            results.append(result)
        
        self.db.add_all(results)
        self.db.commit()
        
        for result in results:
            self.db.refresh(result)
        
        logger.info(f"Saved {len(results)} vulnerabilities for scan {scan_id}")
        return results
    
    def get_scan_vulnerabilities(self, scan_id: int, skip: int = 0, limit: int = 100) -> List[SASTResult]:
        """Get vulnerabilities for a scan"""
        return (self.db.query(SASTResult)
                .filter(SASTResult.scan_id == scan_id)
                .order_by(desc(SASTResult.severity))
                .offset(skip)
                .limit(limit)
                .all())
    
    def get_vulnerability(self, vuln_id: int) -> Optional[SASTResult]:
        """Get vulnerability by ID"""
        return self.db.query(SASTResult).filter(SASTResult.id == vuln_id).first()
    
    def update_vulnerability_status(self, vuln_id: int, status_update: VulnerabilityStatusUpdate) -> Optional[SASTResult]:
        """Update vulnerability status"""
        vuln = self.get_vulnerability(vuln_id)
        if not vuln:
            return None
        
        vuln.status = status_update.status.value
        self.db.commit()
        self.db.refresh(vuln)
        logger.info(f"Updated vulnerability {vuln_id} status to: {status_update.status}")
        return vuln
    
    def get_vulnerability_summary(self, scan_id: int) -> Dict[str, int]:
        """Get vulnerability summary for a scan"""
        summary = (self.db.query(
                    SASTResult.severity,
                    func.count(SASTResult.id).label('count')
                )
                .filter(SASTResult.scan_id == scan_id)
                .group_by(SASTResult.severity)
                .all())
        
        result = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for severity, count in summary:
            result[severity.lower()] = count
        
        return result
    
    # Report operations
    def create_report(self, scan_id: int, report_type: str, report_data: Dict[str, Any], file_path: Optional[str] = None) -> SASTReport:
        """Create a new report"""
        report = SASTReport(
            scan_id=scan_id,
            report_type=report_type,
            report_data=report_data,
            file_path=file_path
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)
        logger.info(f"Created {report_type} report for scan {scan_id}")
        return report
    
    def get_scan_reports(self, scan_id: int) -> List[SASTReport]:
        """Get all reports for a scan"""
        return self.db.query(SASTReport).filter(SASTReport.scan_id == scan_id).all()
    
    def get_report(self, report_id: int) -> Optional[SASTReport]:
        """Get report by ID"""
        return self.db.query(SASTReport).filter(SASTReport.id == report_id).first()
    
    # Summary operations
    def get_scan_summary(self, scan_id: int) -> Optional[ScanSummaryResponse]:
        """Get comprehensive scan summary"""
        scan = self.get_scan(scan_id)
        if not scan:
            return None
        
        project = self.get_project(scan.project_id)
        if not project:
            return None
        
        vulnerability_summary = self.get_vulnerability_summary(scan_id)
        
        # Calculate scan duration
        scan_duration = None
        if scan.end_time and scan.start_time:
            scan_duration = (scan.end_time - scan.start_time).total_seconds()
        
        return ScanSummaryResponse(
            scan_id=scan.id,
            project_name=project.name,
            total_vulnerabilities=sum(vulnerability_summary.values()),
            critical_count=vulnerability_summary["critical"],
            high_count=vulnerability_summary["high"],
            medium_count=vulnerability_summary["medium"],
            low_count=vulnerability_summary["low"],
            info_count=vulnerability_summary["info"],
            scan_duration=scan_duration,
            files_scanned=scan.scanned_files,
            scan_status=scan.status
        )
    
    def get_project_summary(self, project_id: int) -> Optional[ProjectSummaryResponse]:
        """Get project summary with scan statistics"""
        project = self.get_project(project_id)
        if not project:
            return None
        
        # Get scan statistics
        scan_stats = (self.db.query(
                        func.count(SASTScan.id).label('total_scans'),
                        func.max(SASTScan.created_at).label('last_scan_date')
                    )
                    .filter(SASTScan.project_id == project_id)
                    .first())
        
        # Get vulnerability statistics across all scans
        vuln_stats = (self.db.query(
                        func.count(SASTResult.id).label('total_vulns'),
                        func.sum(func.case((SASTResult.severity == 'critical', 1), else_=0)).label('critical_vulns'),
                        func.sum(func.case((SASTResult.severity == 'high', 1), else_=0)).label('high_vulns'),
                        func.sum(func.case((SASTResult.severity == 'medium', 1), else_=0)).label('medium_vulns'),
                        func.sum(func.case((SASTResult.severity == 'low', 1), else_=0)).label('low_vulns')
                    )
                    .join(SASTScan, SASTResult.scan_id == SASTScan.id)
                    .filter(SASTScan.project_id == project_id)
                    .first())
        
        return ProjectSummaryResponse(
            project_id=project.id,
            project_name=project.name,
            total_scans=scan_stats.total_scans or 0,
            last_scan_date=scan_stats.last_scan_date,
            total_vulnerabilities=vuln_stats.total_vulns or 0,
            critical_vulnerabilities=vuln_stats.critical_vulns or 0,
            high_vulnerabilities=vuln_stats.high_vulns or 0,
            medium_vulnerabilities=vuln_stats.medium_vulns or 0,
            low_vulnerabilities=vuln_stats.low_vulns or 0
        )
    
    def get_recent_scans(self, limit: int = 10) -> List[SASTScan]:
        """Get recent scans across all projects"""
        return (self.db.query(SASTScan)
                .order_by(desc(SASTScan.created_at))
                .limit(limit)
                .all())
    
    def get_vulnerability_trends(self, project_id: int, days: int = 30) -> List[Dict[str, Any]]:
        """Get vulnerability trends over time"""
        from datetime import timedelta
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        trends = (self.db.query(
                    func.date(SASTScan.created_at).label('date'),
                    func.count(SASTResult.id).label('vulnerability_count'),
                    SASTResult.severity
                )
                .join(SASTResult, SASTScan.id == SASTResult.scan_id)
                .filter(SASTScan.project_id == project_id)
                .filter(SASTScan.created_at >= start_date)
                .group_by(func.date(SASTScan.created_at), SASTResult.severity)
                .order_by(func.date(SASTScan.created_at))
                .all())
        
        return [
            {
                "date": trend.date.isoformat(),
                "vulnerability_count": trend.vulnerability_count,
                "severity": trend.severity
            }
            for trend in trends
        ] 