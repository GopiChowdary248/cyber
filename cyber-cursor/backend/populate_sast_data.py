#!/usr/bin/env python3
"""
Populate SAST database with sample data for testing
"""

import asyncio
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import random

from app.core.database import AsyncSessionLocal
from app.models.sast import (
    SASTProject, SASTScan, SASTIssue, SASTSecurityHotspot, SASTCodeCoverage,
    SASTDuplication, SASTQualityGate, SASTProjectConfiguration, SASTRule,
    ScanStatus, IssueSeverity, IssueType, IssueStatus, SecurityHotspotStatus,
    QualityGateStatus, Rating
)
from app.models.user import User

async def create_sample_sast_data():
    """Create sample SAST data for testing"""
    async with AsyncSessionLocal() as db:
        try:
            # Get or create a user
            user_result = await db.execute(select(User).limit(1))
            user = user_result.scalar_one_or_none()
            
            if not user:
                print("No user found. Please create a user first.")
                return
            
            # Create sample projects
            projects_data = [
                {
                    "name": "Web Application Security",
                    "key": "web-app-sec",
                    "language": "JavaScript",
                    "repository_url": "https://github.com/example/web-app",
                    "branch": "main",
                    "quality_gate": QualityGateStatus.PASSED,
                    "maintainability_rating": Rating.A,
                    "security_rating": Rating.B,
                    "reliability_rating": Rating.A,
                    "vulnerability_count": 5,
                    "bug_count": 3,
                    "code_smell_count": 12,
                    "security_hotspot_count": 8,
                    "lines_of_code": 15000,
                    "coverage": 85.5,
                    "technical_debt": 120,
                    "debt_ratio": 2.1
                },
                {
                    "name": "API Security Scanner",
                    "key": "api-scanner",
                    "language": "Python",
                    "repository_url": "https://github.com/example/api-scanner",
                    "branch": "develop",
                    "quality_gate": QualityGateStatus.WARNING,
                    "maintainability_rating": Rating.B,
                    "security_rating": Rating.C,
                    "reliability_rating": Rating.B,
                    "vulnerability_count": 8,
                    "bug_count": 5,
                    "code_smell_count": 18,
                    "security_hotspot_count": 12,
                    "lines_of_code": 25000,
                    "coverage": 72.3,
                    "technical_debt": 240,
                    "debt_ratio": 3.8
                },
                {
                    "name": "Mobile App Security",
                    "key": "mobile-app-sec",
                    "language": "Java",
                    "repository_url": "https://github.com/example/mobile-app",
                    "branch": "main",
                    "quality_gate": QualityGateStatus.FAILED,
                    "maintainability_rating": Rating.C,
                    "security_rating": Rating.D,
                    "reliability_rating": Rating.C,
                    "vulnerability_count": 15,
                    "bug_count": 10,
                    "code_smell_count": 25,
                    "security_hotspot_count": 20,
                    "lines_of_code": 35000,
                    "coverage": 65.8,
                    "technical_debt": 480,
                    "debt_ratio": 5.2
                }
            ]
            
            projects = []
            for project_data in projects_data:
                project = SASTProject(
                    **project_data,
                    created_by=user.id,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                    last_analysis=datetime.utcnow() - timedelta(hours=random.randint(1, 24))
                )
                db.add(project)
                await db.flush()
                projects.append(project)
            
            # Create sample scans
            for project in projects:
                for i in range(3):  # 3 scans per project
                    scan = SASTScan(
                        project_id=project.id,
                        scan_type="full",
                        branch=project.branch,
                        status=ScanStatus.COMPLETED,
                        progress=100.0,
                        total_files=random.randint(50, 200),
                        scanned_files=random.randint(50, 200),
                        issues_found=random.randint(5, 25),
                        vulnerabilities_found=random.randint(2, 10),
                        bugs_found=random.randint(1, 8),
                        code_smells_found=random.randint(10, 30),
                        security_hotspots_found=random.randint(5, 15),
                        lines_of_code=project.lines_of_code,
                        lines_of_comment=project.lines_of_code // 4,
                        duplicated_lines=random.randint(100, 500),
                        duplicated_blocks=random.randint(10, 50),
                        coverage=project.coverage + random.uniform(-5, 5),
                        uncovered_lines=project.lines_of_code // 10,
                        uncovered_conditions=project.lines_of_code // 20,
                        technical_debt=project.technical_debt + random.randint(-30, 30),
                        debt_ratio=project.debt_ratio + random.uniform(-0.5, 0.5),
                        started_by=user.id,
                        started_at=datetime.utcnow() - timedelta(days=random.randint(1, 30)),
                        completed_at=datetime.utcnow() - timedelta(days=random.randint(1, 30), hours=random.randint(1, 6)),
                        duration=random.randint(300, 1800)
                    )
                    db.add(scan)
                    await db.flush()
                    
                    # Create sample duplications for this scan
                    languages = ["JavaScript", "Python", "Java", "TypeScript", "C++"]
                    for j in range(random.randint(3, 8)):
                        dup = SASTDuplication(
                            project_id=project.id,
                            scan_id=scan.id,
                            file_path=f"src/components/file_{j}.{languages[j % len(languages)].lower()}",
                            duplicated_lines=random.randint(20, 100),
                            duplicated_blocks=random.randint(1, 5),
                            duplication_density=random.uniform(1.0, 8.0),
                            language=languages[j % len(languages)],
                            last_modified=datetime.utcnow() - timedelta(days=random.randint(1, 30)),
                            created_at=datetime.utcnow(),
                            updated_at=datetime.utcnow()
                        )
                        db.add(dup)
            
            # Create sample issues
            issue_types = [IssueType.BUG, IssueType.VULNERABILITY, IssueType.CODE_SMELL]
            severities = [IssueSeverity.BLOCKER, IssueSeverity.CRITICAL, IssueSeverity.MAJOR, IssueSeverity.MINOR, IssueSeverity.INFO]
            
            for project in projects:
                for i in range(random.randint(10, 30)):
                    issue = SASTIssue(
                        project_id=project.id,
                        rule_id=f"rule_{i:03d}",
                        rule_name=f"Security Rule {i}",
                        rule_category="Security",
                        message=f"Potential security vulnerability found in line {random.randint(1, 100)}",
                        description=f"This is a sample security issue description for issue {i}",
                        file_path=f"src/main/file_{i}.{project.language.lower()}",
                        line_number=random.randint(1, 100),
                        start_line=random.randint(1, 100),
                        end_line=random.randint(1, 100),
                        severity=random.choice(severities),
                        type=random.choice(issue_types),
                        status=IssueStatus.OPEN,
                        assignee=f"user{random.randint(1, 5)}",
                        author=f"developer{random.randint(1, 3)}",
                        effort=random.randint(30, 240),
                        debt=random.randint(30, 240),
                        cwe_id=f"CWE-{random.randint(1, 999):03d}",
                        cvss_score=random.uniform(1.0, 10.0),
                        owasp_category=f"A{random.randint(1, 10):02d}:2021",
                        tags=["security", "vulnerability"],
                        created_at=datetime.utcnow() - timedelta(days=random.randint(1, 30)),
                        updated_at=datetime.utcnow() - timedelta(days=random.randint(1, 30))
                    )
                    db.add(issue)
            
            # Create sample security hotspots
            hotspot_statuses = [SecurityHotspotStatus.TO_REVIEW, SecurityHotspotStatus.REVIEWED, SecurityHotspotStatus.FIXED]
            
            for project in projects:
                for i in range(random.randint(5, 15)):
                    hotspot = SASTSecurityHotspot(
                        project_id=project.id,
                        rule_id=f"hotspot_{i:03d}",
                        rule_name=f"Security Hotspot {i}",
                        message=f"Security hotspot detected in line {random.randint(1, 100)}",
                        description=f"This is a sample security hotspot description for hotspot {i}",
                        file_path=f"src/security/file_{i}.{project.language.lower()}",
                        line_number=random.randint(1, 100),
                        start_line=random.randint(1, 100),
                        end_line=random.randint(1, 100),
                        status=random.choice(hotspot_statuses),
                        cwe_id=f"CWE-{random.randint(1, 999):03d}",
                        cvss_score=random.uniform(1.0, 10.0),
                        owasp_category=f"A{random.randint(1, 10):02d}:2021",
                        tags=["security", "hotspot"],
                        reviewed_by=f"reviewer{random.randint(1, 3)}" if random.choice([True, False]) else None,
                        reviewed_at=datetime.utcnow() - timedelta(days=random.randint(1, 30)) if random.choice([True, False]) else None,
                        created_at=datetime.utcnow() - timedelta(days=random.randint(1, 30)),
                        updated_at=datetime.utcnow() - timedelta(days=random.randint(1, 30))
                    )
                    db.add(hotspot)
            
            # Create sample quality gates
            for project in projects:
                quality_gate = SASTQualityGate(
                    project_id=project.id,
                    max_blocker_issues=0,
                    max_critical_issues=5,
                    max_major_issues=20,
                    max_minor_issues=100,
                    max_info_issues=500,
                    min_coverage=80.0,
                    min_branch_coverage=80.0,
                    max_debt_ratio=5.0,
                    max_technical_debt=1440,
                    max_duplicated_lines=1000,
                    max_duplicated_blocks=100,
                    min_maintainability_rating=Rating.C,
                    min_security_rating=Rating.C,
                    min_reliability_rating=Rating.C,
                    status=project.quality_gate,
                    last_evaluation=datetime.utcnow(),
                    evaluation_results={"status": project.quality_gate.value},
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                db.add(quality_gate)
            
            await db.commit()
            print(f"Successfully created sample SAST data:")
            print(f"- {len(projects)} projects")
            print(f"- {len(projects) * 3} scans")
            print(f"- {len(projects) * 20} issues")
            print(f"- {len(projects) * 10} security hotspots")
            print(f"- {len(projects)} quality gates")
            
        except Exception as e:
            await db.rollback()
            print(f"Error creating sample data: {e}")
            raise

if __name__ == "__main__":
    asyncio.run(create_sample_sast_data()) 