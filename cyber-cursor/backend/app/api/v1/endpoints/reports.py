from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import json
import csv
import io
import zipfile
import os
from pathlib import Path

from app.core.database import get_db
from app.core.security import get_current_user, require_analyst
from app.models.project import Project, ProjectScan, ProjectIssue
from app.models.user import User
from app.schemas.auth import User as UserSchema
from app.services.vulnerability_scanner import VulnerabilityScanner

router = APIRouter()

# ============================================================================
# Report Generation Endpoints
# ============================================================================

@router.post("/generate/{project_id}")
async def generate_project_report(
    project_id: int,
    report_type: str = Query(..., description="Report type: summary, detailed, executive"),
    format: str = Query("json", description="Output format: json, csv, pdf, html"),
    date_from: Optional[datetime] = Query(None, description="Start date for report"),
    date_to: Optional[datetime] = Query(None, description="End date for report"),
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate comprehensive project security report"""
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
        
        # Build date filter
        date_filter = None
        if date_from or date_to:
            date_filter = []
            if date_from:
                date_filter.append(ProjectScan.created_at >= date_from)
            if date_to:
                date_filter.append(ProjectScan.created_at <= date_to)
        
        # Get project scans
        scan_query = select(ProjectScan).where(ProjectScan.project_id == project_id)
        if date_filter:
            scan_query = scan_query.where(and_(*date_filter))
        
        result = await db.execute(scan_query)
        scans = result.scalars().all()
        
        # Get project issues
        issue_query = select(ProjectIssue).where(ProjectIssue.project_id == project_id)
        if date_filter:
            issue_query = issue_query.where(and_(*date_filter))
        
        result = await db.execute(issue_query)
        issues = result.scalars().all()
        
        # Generate report data
        report_data = {
            "project_info": {
                "id": project.id,
                "name": project.name,
                "key": project.key,
                "description": project.description,
                "project_type": project.project_type,
                "language": project.language,
                "framework": project.framework,
                "created_at": project.created_at.isoformat(),
                "last_scan": project.last_scan.isoformat() if project.last_scan else None
            },
            "scan_summary": {
                "total_scans": len(scans),
                "successful_scans": len([s for s in scans if s.status == "completed"]),
                "failed_scans": len([s for s in scans if s.status == "failed"]),
                "last_scan_date": max([s.created_at for s in scans]).isoformat() if scans else None,
                "average_scan_duration": sum([s.scan_duration or 0 for s in scans]) / len(scans) if scans else 0
            },
            "vulnerability_summary": {
                "total_issues": len(issues),
                "critical_issues": len([i for i in issues if i.severity == "critical"]),
                "high_issues": len([i for i in issues if i.severity == "high"]),
                "medium_issues": len([i for i in issues if i.severity == "medium"]),
                "low_issues": len([i for i in issues if i.severity == "low"]),
                "open_issues": len([i for i in issues if i.status == "open"]),
                "resolved_issues": len([i for i in issues if i.status == "resolved"])
            },
            "vulnerability_by_category": {},
            "vulnerability_by_severity": {},
            "recent_scans": [],
            "recent_issues": [],
            "trends": {},
            "recommendations": []
        }
        
        # Group vulnerabilities by category
        for issue in issues:
            category = issue.category
            if category not in report_data["vulnerability_by_category"]:
                report_data["vulnerability_by_category"][category] = 0
            report_data["vulnerability_by_category"][category] += 1
        
        # Group vulnerabilities by severity
        for issue in issues:
            severity = issue.severity
            if severity not in report_data["vulnerability_by_severity"]:
                report_data["vulnerability_by_severity"][severity] = 0
            report_data["vulnerability_by_severity"][severity] += 1
        
        # Add recent scans
        recent_scans = sorted(scans, key=lambda x: x.created_at, reverse=True)[:10]
        for scan in recent_scans:
            report_data["recent_scans"].append({
                "id": scan.id,
                "scan_name": scan.scan_name,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "created_at": scan.created_at.isoformat(),
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "total_issues": scan.total_issues,
                "critical_issues": scan.critical_issues,
                "high_issues": scan.high_issues,
                "medium_issues": scan.medium_issues,
                "low_issues": scan.low_issues
            })
        
        # Add recent issues
        recent_issues = sorted(issues, key=lambda x: x.created_at, reverse=True)[:20]
        for issue in recent_issues:
            report_data["recent_issues"].append({
                "id": issue.id,
                "title": issue.title,
                "severity": issue.severity,
                "category": issue.category,
                "status": issue.status,
                "file_path": issue.file_path,
                "line_number": issue.line_number,
                "created_at": issue.created_at.isoformat()
            })
        
        # Generate trends (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_issues_30d = [i for i in issues if i.created_at >= thirty_days_ago]
        
        report_data["trends"] = {
            "issues_last_30_days": len(recent_issues_30d),
            "critical_trend": len([i for i in recent_issues_30d if i.severity == "critical"]),
            "high_trend": len([i for i in recent_issues_30d if i.severity == "high"]),
            "resolution_rate": len([i for i in recent_issues_30d if i.status == "resolved"]) / len(recent_issues_30d) if recent_issues_30d else 0
        }
        
        # Generate recommendations
        recommendations = []
        if report_data["vulnerability_summary"]["critical_issues"] > 0:
            recommendations.append("Immediate action required: Critical vulnerabilities need immediate attention")
        if report_data["vulnerability_summary"]["high_issues"] > 0:
            recommendations.append("High priority: Address high severity vulnerabilities within 1 week")
        if report_data["vulnerability_summary"]["open_issues"] > 10:
            recommendations.append("Issue backlog: Consider prioritizing issue resolution")
        if report_data["trends"]["resolution_rate"] < 0.5:
            recommendations.append("Low resolution rate: Improve vulnerability remediation process")
        
        report_data["recommendations"] = recommendations
        
        # Generate report based on type
        if report_type == "summary":
            # Remove detailed data for summary report
            report_data.pop("recent_issues", None)
            report_data.pop("recent_scans", None)
        elif report_type == "executive":
            # Keep only high-level information
            report_data = {
                "project_info": report_data["project_info"],
                "vulnerability_summary": report_data["vulnerability_summary"],
                "trends": report_data["trends"],
                "recommendations": report_data["recommendations"]
            }
        
        # Return report in requested format
        if format == "json":
            return report_data
        elif format == "csv":
            return generate_csv_report(report_data, report_type)
        elif format == "html":
            return generate_html_report(report_data, report_type)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported format. Supported: json, csv, html"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate report: {str(e)}"
        )

@router.get("/export/{project_id}")
async def export_project_data(
    project_id: int,
    include_scans: bool = Query(True, description="Include scan data"),
    include_issues: bool = Query(True, description="Include issue data"),
    include_source: bool = Query(False, description="Include source code"),
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export project data as ZIP file"""
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
        
        # Create temporary ZIP file
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            
            # Add project metadata
            project_data = {
                "id": project.id,
                "name": project.name,
                "key": project.key,
                "description": project.description,
                "project_type": project.project_type,
                "language": project.language,
                "framework": project.framework,
                "created_at": project.created_at.isoformat(),
                "exported_at": datetime.utcnow().isoformat()
            }
            zip_file.writestr("project_metadata.json", json.dumps(project_data, indent=2))
            
            # Add scan data
            if include_scans:
                result = await db.execute(select(ProjectScan).where(ProjectScan.project_id == project_id))
                scans = result.scalars().all()
                
                scan_data = []
                for scan in scans:
                    scan_data.append({
                        "id": scan.id,
                        "scan_name": scan.scan_name,
                        "scan_type": scan.scan_type,
                        "status": scan.status,
                        "created_at": scan.created_at.isoformat(),
                        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                        "total_issues": scan.total_issues,
                        "critical_issues": scan.critical_issues,
                        "high_issues": scan.high_issues,
                        "medium_issues": scan.medium_issues,
                        "low_issues": scan.low_issues,
                        "scan_results": scan.scan_results
                    })
                
                zip_file.writestr("scans.json", json.dumps(scan_data, indent=2))
            
            # Add issue data
            if include_issues:
                result = await db.execute(select(ProjectIssue).where(ProjectIssue.project_id == project_id))
                issues = result.scalars().all()
                
                issue_data = []
                for issue in issues:
                    issue_data.append({
                        "id": issue.id,
                        "title": issue.title,
                        "description": issue.description,
                        "severity": issue.severity,
                        "category": issue.category,
                        "status": issue.status,
                        "file_path": issue.file_path,
                        "line_number": issue.line_number,
                        "line_content": issue.line_content,
                        "vulnerability_type": issue.vulnerability_type,
                        "created_at": issue.created_at.isoformat(),
                        "resolved_at": issue.resolved_at.isoformat() if issue.resolved_at else None
                    })
                
                zip_file.writestr("issues.json", json.dumps(issue_data, indent=2))
            
            # Add source code
            if include_source and project.source_path and os.path.exists(project.source_path):
                for root, dirs, files in os.walk(project.source_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arc_name = os.path.relpath(file_path, project.source_path)
                        zip_file.write(file_path, f"source_code/{arc_name}")
        
        zip_buffer.seek(0)
        
        return StreamingResponse(
            io.BytesIO(zip_buffer.getvalue()),
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename=project_{project.key}_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.zip"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to export project data: {str(e)}"
        )

@router.get("/dashboard")
async def get_dashboard_reports(
    current_user: UserSchema = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get dashboard reports for all user projects"""
    try:
        # Get user's projects
        result = await db.execute(
            select(Project).where(
                (Project.owner_id == current_user.id) | (Project.created_by == current_user.id)
            )
        )
        projects = result.scalars().all()
        
        dashboard_data = {
            "total_projects": len(projects),
            "total_issues": 0,
            "critical_issues": 0,
            "high_issues": 0,
            "medium_issues": 0,
            "low_issues": 0,
            "projects_summary": [],
            "recent_activity": [],
            "trends": {}
        }
        
        # Calculate totals and project summaries
        for project in projects:
            # Get project issues
            result = await db.execute(select(ProjectIssue).where(ProjectIssue.project_id == project.id))
            issues = result.scalars().all()
            
            project_summary = {
                "id": project.id,
                "name": project.name,
                "key": project.key,
                "total_issues": len(issues),
                "critical_issues": len([i for i in issues if i.severity == "critical"]),
                "high_issues": len([i for i in issues if i.severity == "high"]),
                "medium_issues": len([i for i in issues if i.severity == "medium"]),
                "low_issues": len([i for i in issues if i.severity == "low"]),
                "last_scan": project.last_scan.isoformat() if project.last_scan else None
            }
            
            dashboard_data["projects_summary"].append(project_summary)
            dashboard_data["total_issues"] += len(issues)
            dashboard_data["critical_issues"] += project_summary["critical_issues"]
            dashboard_data["high_issues"] += project_summary["high_issues"]
            dashboard_data["medium_issues"] += project_summary["medium_issues"]
            dashboard_data["low_issues"] += project_summary["low_issues"]
        
        # Get recent activity (last 10 scans and issues)
        result = await db.execute(
            select(ProjectScan).where(
                ProjectScan.project_id.in_([p.id for p in projects])
            ).order_by(ProjectScan.created_at.desc()).limit(10)
        )
        recent_scans = result.scalars().all()
        
        for scan in recent_scans:
            dashboard_data["recent_activity"].append({
                "type": "scan",
                "project_name": next((p.name for p in projects if p.id == scan.project_id), "Unknown"),
                "action": f"{scan.scan_type.upper()} scan {scan.status}",
                "timestamp": scan.created_at.isoformat(),
                "details": f"Found {scan.total_issues} issues"
            })
        
        result = await db.execute(
            select(ProjectIssue).where(
                ProjectIssue.project_id.in_([p.id for p in projects])
            ).order_by(ProjectIssue.created_at.desc()).limit(10)
        )
        recent_issues = result.scalars().all()
        
        for issue in recent_issues:
            dashboard_data["recent_activity"].append({
                "type": "issue",
                "project_name": next((p.name for p in projects if p.id == issue.project_id), "Unknown"),
                "action": f"New {issue.severity} {issue.category} issue",
                "timestamp": issue.created_at.isoformat(),
                "details": issue.title
            })
        
        # Sort recent activity by timestamp
        dashboard_data["recent_activity"].sort(key=lambda x: x["timestamp"], reverse=True)
        dashboard_data["recent_activity"] = dashboard_data["recent_activity"][:10]
        
        return dashboard_data
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get dashboard reports: {str(e)}"
        )

def generate_csv_report(report_data: Dict[str, Any], report_type: str) -> StreamingResponse:
    """Generate CSV report"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write project info
    writer.writerow(["Project Information"])
    writer.writerow(["Name", report_data["project_info"]["name"]])
    writer.writerow(["Key", report_data["project_info"]["key"]])
    writer.writerow(["Type", report_data["project_info"]["project_type"]])
    writer.writerow(["Language", report_data["project_info"]["language"]])
    writer.writerow([])
    
    # Write vulnerability summary
    writer.writerow(["Vulnerability Summary"])
    writer.writerow(["Total Issues", report_data["vulnerability_summary"]["total_issues"]])
    writer.writerow(["Critical", report_data["vulnerability_summary"]["critical_issues"]])
    writer.writerow(["High", report_data["vulnerability_summary"]["high_issues"]])
    writer.writerow(["Medium", report_data["vulnerability_summary"]["medium_issues"]])
    writer.writerow(["Low", report_data["vulnerability_summary"]["low_issues"]])
    writer.writerow([])
    
    # Write vulnerabilities by category
    writer.writerow(["Vulnerabilities by Category"])
    for category, count in report_data["vulnerability_by_category"].items():
        writer.writerow([category, count])
    writer.writerow([])
    
    # Write recent issues if detailed report
    if report_type == "detailed" and "recent_issues" in report_data:
        writer.writerow(["Recent Issues"])
        writer.writerow(["Title", "Severity", "Category", "Status", "File", "Line"])
        for issue in report_data["recent_issues"]:
            writer.writerow([
                issue["title"],
                issue["severity"],
                issue["category"],
                issue["status"],
                issue["file_path"],
                issue["line_number"]
            ])
    
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=security_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"}
    )

def generate_html_report(report_data: Dict[str, Any], report_type: str) -> StreamingResponse:
    """Generate HTML report"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Report - {report_data['project_info']['name']}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
            .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
            .summary {{ display: flex; justify-content: space-around; text-align: center; }}
            .summary-item {{ padding: 10px; }}
            .critical {{ color: #d32f2f; font-weight: bold; }}
            .high {{ color: #f57c00; font-weight: bold; }}
            .medium {{ color: #fbc02d; font-weight: bold; }}
            .low {{ color: #388e3c; font-weight: bold; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Security Report</h1>
            <h2>{report_data['project_info']['name']}</h2>
            <p>Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="section">
            <h3>Project Information</h3>
            <table>
                <tr><td>Name</td><td>{report_data['project_info']['name']}</td></tr>
                <tr><td>Key</td><td>{report_data['project_info']['key']}</td></tr>
                <tr><td>Type</td><td>{report_data['project_info']['project_type']}</td></tr>
                <tr><td>Language</td><td>{report_data['project_info']['language']}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h3>Vulnerability Summary</h3>
            <div class="summary">
                <div class="summary-item">
                    <div class="critical">{report_data['vulnerability_summary']['critical_issues']}</div>
                    <div>Critical</div>
                </div>
                <div class="summary-item">
                    <div class="high">{report_data['vulnerability_summary']['high_issues']}</div>
                    <div>High</div>
                </div>
                <div class="summary-item">
                    <div class="medium">{report_data['vulnerability_summary']['medium_issues']}</div>
                    <div>Medium</div>
                </div>
                <div class="summary-item">
                    <div class="low">{report_data['vulnerability_summary']['low_issues']}</div>
                    <div>Low</div>
                </div>
            </div>
        </div>
    """
    
    if report_type == "detailed" and "recent_issues" in report_data:
        html_content += """
        <div class="section">
            <h3>Recent Issues</h3>
            <table>
                <tr>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Status</th>
                    <th>File</th>
                    <th>Line</th>
                </tr>
        """
        
        for issue in report_data["recent_issues"]:
            severity_class = issue["severity"]
            html_content += f"""
                <tr>
                    <td>{issue['title']}</td>
                    <td class="{severity_class}">{issue['severity']}</td>
                    <td>{issue['category']}</td>
                    <td>{issue['status']}</td>
                    <td>{issue['file_path']}</td>
                    <td>{issue['line_number']}</td>
                </tr>
            """
        
        html_content += """
            </table>
        </div>
        """
    
    html_content += """
    </body>
    </html>
    """
    
    return StreamingResponse(
        io.BytesIO(html_content.encode()),
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename=security_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"}
    ) 