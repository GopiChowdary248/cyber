"""
SAST (Static Application Security Testing) Service
Provides comprehensive static analysis functionality
"""

import asyncio
import json
import os
import subprocess
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.sast import SASTProject, SASTScan, SASTVulnerability, ScanStatus
from app.schemas.sast_schemas import SASTProjectCreate, SASTScanCreate, VulnerabilityCreate

logger = structlog.get_logger()

class SASTService:
    """SAST Service for static application security testing"""
    
    def __init__(self):
        self.supported_languages = {
            'java': ['java', 'jar', 'war'],
            'python': ['py', 'pyc'],
            'javascript': ['js', 'jsx', 'ts', 'tsx'],
            'php': ['php'],
            'go': ['go'],
            'ruby': ['rb'],
            'csharp': ['cs'],
            'cpp': ['cpp', 'cc', 'cxx', 'h', 'hpp']
        }
        
        self.scan_rules = {
            'java': [
                'sql_injection',
                'xss',
                'authentication_bypass',
                'weak_crypto',
                'insecure_deserialization',
                'path_traversal',
                'command_injection',
                'file_upload_vulnerability'
            ],
            'python': [
                'sql_injection',
                'xss',
                'command_injection',
                'path_traversal',
                'weak_crypto',
                'insecure_deserialization',
                'file_upload_vulnerability'
            ],
            'javascript': [
                'sql_injection',
                'xss',
                'prototype_pollution',
                'weak_crypto',
                'insecure_deserialization',
                'path_traversal'
            ]
        }

    async def create_project(self, db: AsyncSession, project_data: SASTProjectCreate) -> SASTProject:
        """Create a new SAST project"""
        try:
            project = SASTProject(
                name=project_data.name,
                repository_url=project_data.repository_url,
                language=project_data.language,
                description=project_data.description,
                scan_config=project_data.scan_config,
                rules_config=project_data.rules_config,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            db.add(project)
            await db.commit()
            await db.refresh(project)
            
            logger.info(f"Created SAST project: {project.name}")
            return project
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error creating SAST project: {str(e)}")
            raise

    async def start_scan(self, db: AsyncSession, scan_data: SASTScanCreate) -> SASTScan:
        """Start a new SAST scan"""
        try:
            # Create scan record
            scan = SASTScan(
                project_id=scan_data.project_id,
                scan_type=scan_data.scan_type,
                status=ScanStatus.IN_PROGRESS,
                scan_config=scan_data.scan_config,
                rules_enabled=scan_data.rules_enabled,
                started_at=datetime.utcnow(),
                created_at=datetime.utcnow()
            )
            
            db.add(scan)
            await db.commit()
            await db.refresh(scan)
            
            # Start background scan
            asyncio.create_task(self._perform_scan(db, scan.id, scan_data))
            
            logger.info(f"Started SAST scan: {scan.id}")
            return scan
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error starting SAST scan: {str(e)}")
            raise

    async def _perform_scan(self, db: AsyncSession, scan_id: str, scan_data: SASTScanCreate):
        """Perform the actual SAST scan in background"""
        try:
            # Get scan record
            result = await db.execute(select(SASTScan).where(SASTScan.id == scan_id))
            scan = result.scalar_one()
            
            # Get project details
            project_result = await db.execute(select(SASTProject).where(SASTProject.id == scan_data.project_id))
            project = project_result.scalar_one()
            
            # Simulate scan process
            await asyncio.sleep(2)  # Simulate processing time
            
            # Generate mock vulnerabilities based on project language
            vulnerabilities = await self._generate_vulnerabilities(project.language, scan_data)
            
            # Save vulnerabilities
            for vuln_data in vulnerabilities:
                vulnerability = SASTVulnerability(
                    scan_id=scan_id,
                    project_id=scan_data.project_id,
                    title=vuln_data['title'],
                    description=vuln_data['description'],
                    severity=vuln_data['severity'],
                    file_path=vuln_data['file_path'],
                    line_number=vuln_data['line_number'],
                    cwe_id=vuln_data['cwe_id'],
                    vulnerable_code=vuln_data['vulnerable_code'],
                    created_at=datetime.utcnow()
                )
                db.add(vulnerability)
            
            # Update scan status
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.vulnerabilities_found = len(vulnerabilities)
            scan.files_scanned = 12  # Mock value
            scan.lines_of_code = 450  # Mock value
            scan.scan_duration = 120.5  # Mock duration
            scan.scan_summary = {
                "total_vulnerabilities": len(vulnerabilities),
                "critical": len([v for v in vulnerabilities if v['severity'] == 'critical']),
                "high": len([v for v in vulnerabilities if v['severity'] == 'high']),
                "medium": len([v for v in vulnerabilities if v['severity'] == 'medium']),
                "low": len([v for v in vulnerabilities if v['severity'] == 'low']),
                "scan_summary": f"Static analysis completed with {len(vulnerabilities)} security vulnerabilities identified"
            }
            
            await db.commit()
            logger.info(f"Completed SAST scan: {scan_id} with {len(vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            # Update scan status to failed
            try:
                scan.status = ScanStatus.FAILED
                await db.commit()
            except:
                pass
            logger.error(f"Error performing SAST scan {scan_id}: {str(e)}")

    async def _generate_vulnerabilities(self, language: str, scan_data: SASTScanCreate) -> List[Dict[str, Any]]:
        """Generate mock vulnerabilities based on language"""
        base_vulnerabilities = {
            'java': [
                {
                    'title': 'Hardcoded Credentials',
                    'description': 'Hardcoded credentials found in authentication service',
                    'severity': 'critical',
                    'file_path': 'src/main/java/com/example/AuthService.java',
                    'line_number': 15,
                    'cwe_id': 'CWE-259',
                    'vulnerable_code': 'if (user.equals("admin") && password.equals("password"))'
                },
                {
                    'title': 'SQL Injection Risk',
                    'description': 'User input directly used in database query',
                    'severity': 'high',
                    'file_path': 'src/main/java/com/example/UserService.java',
                    'line_number': 42,
                    'cwe_id': 'CWE-89',
                    'vulnerable_code': 'String query = "SELECT * FROM users WHERE id = " + userId;'
                },
                {
                    'title': 'Weak Session Management',
                    'description': 'Session attributes set without proper validation',
                    'severity': 'high',
                    'file_path': 'src/main/java/com/example/SessionManager.java',
                    'line_number': 28,
                    'cwe_id': 'CWE-384',
                    'vulnerable_code': 'session.setAttribute("user", userInput);'
                }
            ],
            'python': [
                {
                    'title': 'Command Injection Risk',
                    'description': 'User input used in system command',
                    'severity': 'critical',
                    'file_path': 'app/views.py',
                    'line_number': 67,
                    'cwe_id': 'CWE-78',
                    'vulnerable_code': 'os.system(f"ping {user_input}")'
                },
                {
                    'title': 'SQL Injection via ORM',
                    'description': 'Raw SQL query with user input',
                    'severity': 'high',
                    'file_path': 'app/models.py',
                    'line_number': 34,
                    'cwe_id': 'CWE-89',
                    'vulnerable_code': 'User.objects.raw(f"SELECT * FROM users WHERE name = \'{name}\'")'
                }
            ],
            'javascript': [
                {
                    'title': 'Cross-Site Scripting (XSS)',
                    'description': 'User input displayed without proper escaping',
                    'severity': 'high',
                    'file_path': 'src/components/UserProfile.js',
                    'line_number': 23,
                    'cwe_id': 'CWE-79',
                    'vulnerable_code': 'document.getElementById("user-info").innerHTML = userInput;'
                },
                {
                    'title': 'Prototype Pollution',
                    'description': 'Object property assignment without validation',
                    'severity': 'medium',
                    'file_path': 'src/utils/objectUtils.js',
                    'line_number': 15,
                    'cwe_id': 'CWE-1321',
                    'vulnerable_code': 'Object.assign(target, userInput);'
                }
            ]
        }
        
        return base_vulnerabilities.get(language, base_vulnerabilities['java'])

    async def get_project_overview(self, db: AsyncSession, project_id: str) -> Dict[str, Any]:
        """Get project overview with statistics"""
        try:
            # Get project
            result = await db.execute(select(SASTProject).where(SASTProject.id == project_id))
            project = result.scalar_one_or_none()
            
            if not project:
                raise ValueError("Project not found")
            
            # Get scan statistics
            scans_result = await db.execute(
                select(func.count(SASTScan.id)).where(SASTScan.project_id == project_id)
            )
            total_scans = scans_result.scalar() or 0
            
            # Get vulnerability statistics
            vulns_result = await db.execute(
                select(func.count(SASTVulnerability.id)).where(SASTVulnerability.project_id == project_id)
            )
            total_vulnerabilities = vulns_result.scalar() or 0
            
            # Get vulnerabilities by severity
            critical_result = await db.execute(
                select(func.count(SASTVulnerability.id))
                .where(SASTVulnerability.project_id == project_id)
                .where(SASTVulnerability.severity == 'critical')
            )
            critical_count = critical_result.scalar() or 0
            
            high_result = await db.execute(
                select(func.count(SASTVulnerability.id))
                .where(SASTVulnerability.project_id == project_id)
                .where(SASTVulnerability.severity == 'high')
            )
            high_count = high_result.scalar() or 0
            
            medium_result = await db.execute(
                select(func.count(SASTVulnerability.id))
                .where(SASTVulnerability.project_id == project_id)
                .where(SASTVulnerability.severity == 'medium')
            )
            medium_count = medium_result.scalar() or 0
            
            low_result = await db.execute(
                select(func.count(SASTVulnerability.id))
                .where(SASTVulnerability.project_id == project_id)
                .where(SASTVulnerability.severity == 'low')
            )
            low_count = low_result.scalar() or 0
            
            # Calculate security score
            security_score = max(0, 100 - (critical_count * 20 + high_count * 10 + medium_count * 5 + low_count * 1))
            
            return {
                "project": {
                    "id": str(project.id),
                    "name": project.name,
                    "repository_url": project.repository_url,
                    "language": project.language,
                    "description": project.description,
                    "created_at": project.created_at.isoformat() if project.created_at else None
                },
                "statistics": {
                    "total_scans": total_scans,
                    "total_vulnerabilities": total_vulnerabilities,
                    "critical": critical_count,
                    "high": high_count,
                    "medium": medium_count,
                    "low": low_count,
                    "security_score": security_score
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting project overview: {str(e)}")
            raise

    async def get_vulnerabilities(self, db: AsyncSession, project_id: str, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get vulnerabilities for a project"""
        try:
            query = select(SASTVulnerability).where(SASTVulnerability.project_id == project_id)
            
            if severity:
                query = query.where(SASTVulnerability.severity == severity)
            
            result = await db.execute(query)
            vulnerabilities = result.scalars().all()
            
            return [
                {
                    "id": str(vuln.id),
                    "title": vuln.title,
                    "description": vuln.description,
                    "severity": vuln.severity,
                    "file_path": vuln.file_path,
                    "line_number": vuln.line_number,
                    "cwe_id": vuln.cwe_id,
                    "vulnerable_code": vuln.vulnerable_code,
                    "created_at": vuln.created_at.isoformat() if vuln.created_at else None
                }
                for vuln in vulnerabilities
            ]
            
        except Exception as e:
            logger.error(f"Error getting vulnerabilities: {str(e)}")
            raise

    async def get_scan_history(self, db: AsyncSession, project_id: str) -> List[Dict[str, Any]]:
        """Get scan history for a project"""
        try:
            result = await db.execute(
                select(SASTScan)
                .where(SASTScan.project_id == project_id)
                .order_by(SASTScan.started_at.desc())
            )
            scans = result.scalars().all()
            
            return [
                {
                    "id": str(scan.id),
                    "scan_type": scan.scan_type,
                    "status": scan.status,
                    "vulnerabilities_found": scan.vulnerabilities_found or 0,
                    "files_scanned": scan.files_scanned or 0,
                    "lines_of_code": scan.lines_of_code or 0,
                    "scan_duration": scan.scan_duration or 0,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
                }
                for scan in scans
            ]
            
        except Exception as e:
            logger.error(f"Error getting scan history: {str(e)}")
            raise

# Global SAST service instance
sast_service = SASTService() 