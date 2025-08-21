#!/usr/bin/env python3
"""
Test script for SAST endpoints with real data
"""

import asyncio
import json
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

# Import models
from app.models.sast import (
    SASTProject, SASTScan, SASTIssue, SASTSecurityHotspot, 
    SASTCodeCoverage, SASTQualityGate, SASTBaseline, BaselineType,
    SASTIssueComment, SASTFileChange, SASTBackgroundJob, SASTSavedFilter
)
from app.database import Base, engine

def create_sync_session():
    """Create a synchronous database session"""
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal()

def populate_sample_data():
    """Populate database with sample SAST data"""
    session = create_sync_session()
    
    try:
        # Create sample project
        project = SASTProject(
            name="Sample Web Application",
            key="sample-web-app",
            language="python",
            repository_url="https://github.com/example/sample-web-app",
            branch="main",
            quality_gate="PASSED",
            maintainability_rating="A",
            security_rating="B",
            reliability_rating="A",
            vulnerability_count=5,
            bug_count=12,
            code_smell_count=25,
            security_hotspot_count=8,
            lines_of_code=15000,
            lines_of_comment=3000,
            duplicated_lines=500,
            duplicated_blocks=15,
            coverage=85.5,
            uncovered_lines=2250,
            uncovered_conditions=150,
            technical_debt=480,  # 8 hours
            debt_ratio=2.1,
            created_by=1,
            created_at=datetime.now() - timedelta(days=30),
            updated_at=datetime.now(),
            last_analysis=datetime.now()
        )
        session.add(project)
        session.flush()
        
        # Create sample scan
        scan = SASTScan(
            project_id=project.id,
            scan_type="full",
            branch="main",
            status="COMPLETED",
            is_incremental=False,
            progress=100.0,
            total_files=150,
            scanned_files=150,
            issues_found=42,
            vulnerabilities_found=5,
            bugs_found=12,
            code_smells_found=25,
            security_hotspots_found=8,
            lines_of_code=15000,
            lines_of_comment=3000,
            duplicated_lines=500,
            duplicated_blocks=15,
            coverage=85.5,
            uncovered_lines=2250,
            uncovered_conditions=150,
            technical_debt=480,
            debt_ratio=2.1,
            started_by=1,
            started_at=datetime.now() - timedelta(hours=2),
            completed_at=datetime.now() - timedelta(hours=1),
            duration=3600  # 1 hour
        )
        session.add(scan)
        session.flush()
        
        # Create sample issues
        issues = [
            SASTIssue(
                project_id=project.id,
                scan_id=scan.id,
                rule_id="python:S1481",
                rule_name="Unused local variables should be removed",
                rule_category="Code Smells",
                message="Remove this unused 'i' variable.",
                description="Local variables should not be declared and then left unused.",
                file_path="src/utils/helper.py",
                line_number=42,
                start_line=42,
                end_line=42,
                severity="MINOR",
                type="CODE_SMELL",
                status="OPEN",
                effort=5,
                debt=5,
                cwe_id="CWE-563",
                tags=["unused", "variable"],
                created_at=datetime.now() - timedelta(hours=1)
            ),
            SASTIssue(
                project_id=project.id,
                scan_id=scan.id,
                rule_id="python:S2068",
                rule_name="Credentials should not be hard-coded",
                rule_category="Vulnerabilities",
                message="Make sure this is not a hard-coded credential.",
                description="It's recommended to use a more secure way to store credentials.",
                file_path="src/config/database.py",
                line_number=15,
                start_line=15,
                end_line=15,
                severity="CRITICAL",
                type="VULNERABILITY",
                status="OPEN",
                effort=30,
                debt=30,
                cwe_id="CWE-259",
                cvss_score=9.8,
                owasp_category="A02:2021 - Cryptographic Failures",
                tags=["hardcoded", "credentials", "security"],
                created_at=datetime.now() - timedelta(hours=1)
            )
        ]
        session.add_all(issues)
        session.flush()
        
        # Create sample security hotspots
        hotspots = [
            SASTSecurityHotspot(
                project_id=project.id,
                scan_id=scan.id,
                rule_id="python:S5146",
                rule_name="HTTP requests should not be open to forging attacks",
                rule_category="Security Hotspots",
                message="Make sure this HTTP request is not vulnerable to forging attacks.",
                description="HTTP requests can be forged by malicious users.",
                file_path="src/api/endpoints.py",
                line_number=78,
                start_line=78,
                end_line=78,
                status="TO_REVIEW",
                cwe_id="CWE-345",
                cvss_score=7.5,
                owasp_category="A01:2021 - Broken Access Control",
                tags=["http", "forging", "security"],
                risk_level="HIGH",
                probability=0.7,
                impact=0.8,
                risk_score=0.56,
                review_priority=8,
                created_at=datetime.now() - timedelta(hours=1)
            )
        ]
        session.add_all(hotspots)
        session.flush()
        
        # Create sample code coverage
        coverage = SASTCodeCoverage(
            project_id=project.id,
            scan_id=scan.id,
            file_path="src/main.py",
            lines_to_cover=100,
            uncovered_lines=15,
            covered_lines=85,
            line_coverage=85.0,
            conditions_to_cover=20,
            uncovered_conditions=3,
            covered_conditions=17,
            branch_coverage=85.0,
            overall_coverage=85.0,
            detailed_coverage={
                "lines": {
                    "1": {"covered": True, "hits": 1},
                    "2": {"covered": True, "hits": 1},
                    "15": {"covered": False, "hits": 0},
                    "42": {"covered": True, "hits": 5},
                    "100": {"covered": True, "hits": 1}
                }
            }
        )
        session.add(coverage)
        session.flush()
        
        # Create sample quality gate
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
            min_maintainability_rating="C",
            min_security_rating="C",
            min_reliability_rating="C",
            status="PASSED",
            last_evaluation=datetime.now(),
            evaluation_results={
                "coverage": {"status": "PASSED", "value": 85.0, "threshold": 80.0},
                "critical_issues": {"status": "PASSED", "value": 1, "threshold": 5},
                "security_rating": {"status": "PASSED", "value": "B", "threshold": "C"}
            }
        )
        session.add(quality_gate)
        session.flush()
        
        # Create sample baseline
        baseline = SASTBaseline(
            project_id=project.id,
            baseline_type=BaselineType.DATE,
            value=(datetime.now() - timedelta(days=7)).isoformat(),
            created_at=datetime.now() - timedelta(days=7)
        )
        session.add(baseline)
        session.flush()
        
        # Create sample file changes
        file_changes = [
            SASTFileChange(
                project_id=project.id,
                scan_id=scan.id,
                file_path="src/utils/helper.py",
                change_type="modified",
                old_hash="abc123",
                new_hash="def456",
                lines_added=5,
                lines_removed=2,
                commit_hash="commit123",
                commit_message="Fix unused variable issue",
                author="developer@example.com"
            )
        ]
        session.add_all(file_changes)
        session.flush()
        
        # Create sample background job
        background_job = SASTBackgroundJob(
            project_id=project.id,
            job_type="scan",
            status="completed",
            priority=5,
            parameters={"scan_type": "full", "branch": "main"},
            result={"issues_found": 42, "duration": 3600},
            progress=100.0,
            current_step="completed",
            total_steps=5,
            started_at=datetime.now() - timedelta(hours=2),
            completed_at=datetime.now() - timedelta(hours=1)
        )
        session.add(background_job)
        session.flush()
        
        # Create sample saved filter
        saved_filter = SASTSavedFilter(
            user_id=1,
            project_id=project.id,
            name="High Priority Issues",
            description="Filter for high and critical priority issues",
            filter_type="issues",
            filter_criteria={
                "severity": ["CRITICAL", "HIGH"],
                "status": ["OPEN", "CONFIRMED"],
                "type": ["VULNERABILITY", "BUG"]
            }
        )
        session.add(saved_filter)
        session.flush()
        
        # Create sample issue comment
        comment = SASTIssueComment(
            issue_id=issues[1].id,  # The critical vulnerability
            author="security-reviewer@example.com",
            message="This is a critical security issue that needs immediate attention. Please fix by removing hardcoded credentials and implementing proper configuration management.",
            created_at=datetime.now() - timedelta(minutes=30)
        )
        session.add(comment)
        session.flush()
        
        session.commit()
        print(f"✅ Successfully created sample SAST data:")
        print(f"   - Project: {project.name} (ID: {project.id})")
        print(f"   - Scan: {scan.id}")
        print(f"   - Issues: {len(issues)}")
        print(f"   - Security Hotspots: {len(hotspots)}")
        print(f"   - Code Coverage: {coverage.id}")
        print(f"   - Quality Gate: {quality_gate.id}")
        print(f"   - Baseline: {baseline.id}")
        print(f"   - File Changes: {len(file_changes)}")
        print(f"   - Background Job: {background_job.id}")
        print(f"   - Saved Filter: {saved_filter.id}")
        print(f"   - Issue Comment: {comment.id}")
        
        return project.id
        
    except Exception as e:
        session.rollback()
        print(f"❌ Error creating sample data: {e}")
        raise
    finally:
        session.close()

def test_endpoints():
    """Test the SAST endpoints"""
    print("\n🧪 Testing SAST endpoints...")
    
    # Test project retrieval
    session = create_sync_session()
    try:
        project = session.query(SASTProject).first()
        if project:
            print(f"✅ Project retrieved: {project.name}")
            print(f"   - Quality Gate: {project.quality_gate}")
            print(f"   - Security Rating: {project.security_rating}")
            print(f"   - Coverage: {project.coverage}%")
            print(f"   - Issues: {project.vulnerability_count + project.bug_count + project.code_smell_count}")
        else:
            print("❌ No projects found")
            
        # Test scan retrieval
        scan = session.query(SASTScan).first()
        if scan:
            print(f"✅ Scan retrieved: {scan.scan_type} scan")
            print(f"   - Status: {scan.status}")
            print(f"   - Progress: {scan.progress}%")
            print(f"   - Issues found: {scan.issues_found}")
        else:
            print("❌ No scans found")
            
        # Test issues retrieval
        issues = session.query(SASTIssue).all()
        print(f"✅ Issues retrieved: {len(issues)}")
        for issue in issues:
            print(f"   - {issue.severity} {issue.type}: {issue.message[:50]}...")
            
        # Test security hotspots
        hotspots = session.query(SASTSecurityHotspot).all()
        print(f"✅ Security hotspots retrieved: {len(hotspots)}")
        for hotspot in hotspots:
            print(f"   - {hotspot.risk_level} risk: {hotspot.message[:50]}...")
            
        # Test code coverage
        coverage = session.query(SASTCodeCoverage).first()
        if coverage:
            print(f"✅ Code coverage retrieved: {coverage.overall_coverage}%")
            print(f"   - File: {coverage.file_path}")
            print(f"   - Lines: {coverage.covered_lines}/{coverage.lines_to_cover}")
            
        # Test quality gate
        quality_gate = session.query(SASTQualityGate).first()
        if quality_gate:
            print(f"✅ Quality gate retrieved: {quality_gate.status}")
            print(f"   - Max critical issues: {quality_gate.max_critical_issues}")
            print(f"   - Min coverage: {quality_gate.min_coverage}%")
            
        # Test baseline
        baseline = session.query(SASTBaseline).first()
        if baseline:
            print(f"✅ Baseline retrieved: {baseline.baseline_type}")
            print(f"   - Value: {baseline.value}")
            
        # Test file changes
        file_changes = session.query(SASTFileChange).all()
        print(f"✅ File changes retrieved: {len(file_changes)}")
        for change in file_changes:
            print(f"   - {change.change_type}: {change.file_path}")
            
        # Test background jobs
        background_jobs = session.query(SASTBackgroundJob).all()
        print(f"✅ Background jobs retrieved: {len(background_jobs)}")
        for job in background_jobs:
            print(f"   - {job.job_type}: {job.status}")
            
        # Test saved filters
        saved_filters = session.query(SASTSavedFilter).all()
        print(f"✅ Saved filters retrieved: {len(saved_filters)}")
        for filter_item in saved_filters:
            print(f"   - {filter_item.name}: {filter_item.filter_type}")
            
        # Test issue comments
        comments = session.query(SASTIssueComment).all()
        print(f"✅ Issue comments retrieved: {len(comments)}")
        for comment in comments:
            print(f"   - {comment.author}: {comment.message[:50]}...")
            
    except Exception as e:
        print(f"❌ Error testing endpoints: {e}")
        raise
    finally:
        session.close()

if __name__ == "__main__":
    print("🚀 Starting SAST endpoint testing...")
    
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created/verified")
    
    # Populate sample data
    project_id = populate_sample_data()
    
    # Test endpoints
    test_endpoints()
    
    print(f"\n🎉 SAST endpoint testing completed successfully!")
    print(f"Project ID for testing: {project_id}")
    print(f"\nYou can now test the SAST API endpoints:")
    print(f"  - GET /api/v1/sast/projects")
    print(f"  - GET /api/v1/sast/projects/{project_id}")
    print(f"  - GET /api/v1/sast/projects/{project_id}/scans")
    print(f"  - GET /api/v1/sast/projects/{project_id}/issues")
    print(f"  - GET /api/v1/sast/projects/{project_id}/security-hotspots")
    print(f"  - GET /api/v1/sast/projects/{project_id}/code-coverage")
    print(f"  - GET /api/v1/sast/projects/{project_id}/quality-gate")
    print(f"  - GET /api/v1/sast/projects/{project_id}/baseline")
    print(f"  - GET /api/v1/sast/projects/{project_id}/file-changes")
    print(f"  - GET /api/v1/sast/projects/{project_id}/background-jobs")
    print(f"  - GET /api/v1/sast/saved-filters")
    print(f"  - GET /api/v1/sast/issues/{project_id}/comments") 