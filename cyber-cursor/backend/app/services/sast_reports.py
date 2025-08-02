import os
import json
import csv
import tempfile
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging

from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
import pandas as pd

from ..models.sast_models import SASTScan, SASTResult, Project
from ..schemas.sast_schemas import ScanSummaryResponse

logger = logging.getLogger(__name__)

class SASTReportGenerator:
    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(exist_ok=True)
    
    def generate_summary_report(self, scan: SASTScan, project: Project, 
                              vulnerabilities: List[SASTResult], 
                              summary: ScanSummaryResponse) -> str:
        """Generate a comprehensive PDF summary report"""
        filename = f"sast_summary_report_{scan.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = self.reports_dir / filename
        
        doc = SimpleDocTemplate(str(filepath), pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        story.append(Paragraph("SAST Security Scan Report", title_style))
        story.append(Spacer(1, 20))
        
        # Project Information
        story.append(Paragraph("Project Information", styles['Heading2']))
        project_info = [
            ["Project Name:", project.name],
            ["Repository URL:", project.repo_url or "N/A"],
            ["Scan ID:", str(scan.id)],
            ["Scan Type:", scan.scan_type],
            ["Triggered By:", scan.triggered_by],
            ["Scan Date:", scan.start_time.strftime("%Y-%m-%d %H:%M:%S")],
            ["Scan Status:", scan.status]
        ]
        
        project_table = Table(project_info, colWidths=[2*inch, 4*inch])
        project_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.grey),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(project_table)
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        summary_text = f"""
        This security scan analyzed {scan.scanned_files} files and identified {summary.total_vulnerabilities} security vulnerabilities.
        The scan was completed in {summary.scan_duration:.2f} seconds.
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Vulnerability Summary
        story.append(Paragraph("Vulnerability Summary", styles['Heading2']))
        vuln_summary = [
            ["Severity", "Count", "Percentage"],
            ["Critical", str(summary.critical_count), f"{(summary.critical_count/summary.total_vulnerabilities*100):.1f}%" if summary.total_vulnerabilities > 0 else "0%"],
            ["High", str(summary.high_count), f"{(summary.high_count/summary.total_vulnerabilities*100):.1f}%" if summary.total_vulnerabilities > 0 else "0%"],
            ["Medium", str(summary.medium_count), f"{(summary.medium_count/summary.total_vulnerabilities*100):.1f}%" if summary.total_vulnerabilities > 0 else "0%"],
            ["Low", str(summary.low_count), f"{(summary.low_count/summary.total_vulnerabilities*100):.1f}%" if summary.total_vulnerabilities > 0 else "0%"],
            ["Info", str(summary.info_count), f"{(summary.info_count/summary.total_vulnerabilities*100):.1f}%" if summary.total_vulnerabilities > 0 else "0%"]
        ]
        
        vuln_table = Table(vuln_summary, colWidths=[1.5*inch, 1*inch, 1.5*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (0, 1), colors.red),
            ('BACKGROUND', (0, 2), (0, 2), colors.orange),
            ('BACKGROUND', (0, 3), (0, 3), colors.yellow),
            ('BACKGROUND', (0, 4), (0, 4), colors.lightblue),
            ('BACKGROUND', (0, 5), (0, 5), colors.lightgrey)
        ]))
        story.append(vuln_table)
        story.append(Spacer(1, 20))
        
        # Detailed Vulnerabilities
        if vulnerabilities:
            story.append(Paragraph("Detailed Vulnerabilities", styles['Heading2']))
            
            # Group vulnerabilities by severity
            severity_groups = {}
            for vuln in vulnerabilities:
                severity = vuln.severity
                if severity not in severity_groups:
                    severity_groups[severity] = []
                severity_groups[severity].append(vuln)
            
            # Process each severity level
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity in severity_groups:
                    story.append(Paragraph(f"{severity.title()} Severity Issues", styles['Heading3']))
                    
                    for i, vuln in enumerate(severity_groups[severity][:10]):  # Limit to first 10 per severity
                        vuln_text = f"""
                        <b>Issue {i+1}:</b> {vuln.vulnerability}<br/>
                        <b>File:</b> {vuln.file_path}<br/>
                        <b>Line:</b> {vuln.line_no}<br/>
                        <b>Tool:</b> {vuln.tool_name}<br/>
                        <b>Recommendation:</b> {vuln.recommendation or 'No specific recommendation available'}<br/>
                        """
                        story.append(Paragraph(vuln_text, styles['Normal']))
                        story.append(Spacer(1, 10))
                    
                    if len(severity_groups[severity]) > 10:
                        story.append(Paragraph(f"... and {len(severity_groups[severity]) - 10} more {severity} severity issues", styles['Normal']))
                    
                    story.append(Spacer(1, 15))
        
        # Recommendations
        story.append(Paragraph("Security Recommendations", styles['Heading2']))
        recommendations = [
            "1. Address all Critical and High severity vulnerabilities immediately",
            "2. Review and fix Medium severity issues within 30 days",
            "3. Consider Low severity issues for future improvements",
            "4. Implement secure coding practices and training",
            "5. Set up automated security scanning in CI/CD pipeline",
            "6. Regular security audits and penetration testing",
            "7. Keep dependencies updated and monitor for known vulnerabilities"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, styles['Normal']))
            story.append(Spacer(1, 5))
        
        # Footer
        story.append(Spacer(1, 30))
        footer_text = f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by CyberShield SAST Tool"
        story.append(Paragraph(footer_text, styles['Normal']))
        
        # Build PDF
        doc.build(story)
        logger.info(f"Generated summary report: {filepath}")
        return str(filepath)
    
    def generate_csv_report(self, scan: SASTScan, vulnerabilities: List[SASTResult]) -> str:
        """Generate CSV report with all vulnerabilities"""
        filename = f"sast_detailed_report_{scan.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = self.reports_dir / filename
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'id', 'file_path', 'line_no', 'column_no', 'vulnerability', 
                'severity', 'recommendation', 'tool_name', 'cwe_id', 
                'confidence', 'status', 'detected_at'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for vuln in vulnerabilities:
                writer.writerow({
                    'id': vuln.id,
                    'file_path': vuln.file_path,
                    'line_no': vuln.line_no,
                    'column_no': vuln.column_no,
                    'vulnerability': vuln.vulnerability,
                    'severity': vuln.severity,
                    'recommendation': vuln.recommendation,
                    'tool_name': vuln.tool_name,
                    'cwe_id': vuln.cwe_id,
                    'confidence': vuln.confidence,
                    'status': vuln.status,
                    'detected_at': vuln.detected_at.isoformat()
                })
        
        logger.info(f"Generated CSV report: {filepath}")
        return str(filepath)
    
    def generate_excel_report(self, scan: SASTScan, project: Project, 
                            vulnerabilities: List[SASTResult], 
                            summary: ScanSummaryResponse) -> str:
        """Generate Excel report with multiple sheets"""
        filename = f"sast_excel_report_{scan.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        filepath = self.reports_dir / filename
        
        with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
            # Summary sheet
            summary_data = {
                'Metric': [
                    'Project Name', 'Scan ID', 'Scan Type', 'Triggered By',
                    'Scan Date', 'Scan Status', 'Total Files Scanned',
                    'Total Vulnerabilities', 'Critical', 'High', 'Medium', 'Low', 'Info',
                    'Scan Duration (seconds)'
                ],
                'Value': [
                    project.name, scan.id, scan.scan_type, scan.triggered_by,
                    scan.start_time.strftime("%Y-%m-%d %H:%M:%S"), scan.status,
                    scan.scanned_files, summary.total_vulnerabilities,
                    summary.critical_count, summary.high_count,
                    summary.medium_count, summary.low_count, summary.info_count,
                    f"{summary.scan_duration:.2f}" if summary.scan_duration else "N/A"
                ]
            }
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            # Vulnerabilities sheet
            if vulnerabilities:
                vuln_data = []
                for vuln in vulnerabilities:
                    vuln_data.append({
                        'ID': vuln.id,
                        'File Path': vuln.file_path,
                        'Line Number': vuln.line_no,
                        'Column Number': vuln.column_no,
                        'Vulnerability': vuln.vulnerability,
                        'Severity': vuln.severity,
                        'Recommendation': vuln.recommendation,
                        'Tool': vuln.tool_name,
                        'CWE ID': vuln.cwe_id,
                        'Confidence': vuln.confidence,
                        'Status': vuln.status,
                        'Detected At': vuln.detected_at.strftime("%Y-%m-%d %H:%M:%S")
                    })
                
                vuln_df = pd.DataFrame(vuln_data)
                vuln_df.to_excel(writer, sheet_name='Vulnerabilities', index=False)
            
            # Severity breakdown sheet
            severity_data = {
                'Severity': ['Critical', 'High', 'Medium', 'Low', 'Info'],
                'Count': [
                    summary.critical_count, summary.high_count,
                    summary.medium_count, summary.low_count, summary.info_count
                ],
                'Percentage': [
                    f"{(summary.critical_count/summary.total_vulnerabilities*100):.1f}%" if summary.total_vulnerabilities > 0 else "0%",
                    f"{(summary.high_count/summary.total_vulnerabilities*100):.1f}%" if summary.total_vulnerabilities > 0 else "0%",
                    f"{(summary.medium_count/summary.total_vulnerabilities*100):.1f}%" if summary.total_vulnerabilities > 0 else "0%",
                    f"{(summary.low_count/summary.total_vulnerabilities*100):.1f}%" if summary.total_vulnerabilities > 0 else "0%",
                    f"{(summary.info_count/summary.total_vulnerabilities*100):.1f}%" if summary.total_vulnerabilities > 0 else "0%"
                ]
            }
            severity_df = pd.DataFrame(severity_data)
            severity_df.to_excel(writer, sheet_name='Severity Breakdown', index=False)
        
        logger.info(f"Generated Excel report: {filepath}")
        return str(filepath)
    
    def generate_json_report(self, scan: SASTScan, project: Project, 
                           vulnerabilities: List[SASTResult], 
                           summary: ScanSummaryResponse) -> str:
        """Generate JSON report with all data"""
        filename = f"sast_json_report_{scan.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.reports_dir / filename
        
        report_data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "report_type": "sast_scan",
                "version": "1.0"
            },
            "project": {
                "id": project.id,
                "name": project.name,
                "repo_url": project.repo_url,
                "description": project.description
            },
            "scan": {
                "id": scan.id,
                "scan_type": scan.scan_type,
                "triggered_by": scan.triggered_by,
                "start_time": scan.start_time.isoformat(),
                "end_time": scan.end_time.isoformat() if scan.end_time else None,
                "status": scan.status,
                "scanned_files": scan.scanned_files,
                "total_files": scan.total_files
            },
            "summary": {
                "total_vulnerabilities": summary.total_vulnerabilities,
                "critical_count": summary.critical_count,
                "high_count": summary.high_count,
                "medium_count": summary.medium_count,
                "low_count": summary.low_count,
                "info_count": summary.info_count,
                "scan_duration": summary.scan_duration
            },
            "vulnerabilities": [
                {
                    "id": vuln.id,
                    "file_path": vuln.file_path,
                    "line_no": vuln.line_no,
                    "column_no": vuln.column_no,
                    "vulnerability": vuln.vulnerability,
                    "severity": vuln.severity,
                    "recommendation": vuln.recommendation,
                    "tool_name": vuln.tool_name,
                    "cwe_id": vuln.cwe_id,
                    "confidence": vuln.confidence,
                    "status": vuln.status,
                    "detected_at": vuln.detected_at.isoformat()
                }
                for vuln in vulnerabilities
            ]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Generated JSON report: {filepath}")
        return str(filepath)
    
    def cleanup_old_reports(self, days: int = 30):
        """Clean up reports older than specified days"""
        cutoff_date = datetime.now().timestamp() - (days * 24 * 60 * 60)
        
        for file_path in self.reports_dir.glob("*"):
            if file_path.is_file():
                if file_path.stat().st_mtime < cutoff_date:
                    file_path.unlink()
                    logger.info(f"Cleaned up old report: {file_path}") 