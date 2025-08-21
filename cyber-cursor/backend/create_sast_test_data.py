#!/usr/bin/env python3
"""
Script to create sample SAST data for testing
"""

import asyncio
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from app.models.sast import SASTProject, SASTScan, SASTIssue
from app.models.user import User
from app.core.database import Base

# Database URL - using SQLite for testing
DATABASE_URL = "sqlite+aiosqlite:///./cybershield.db"

async def create_test_data():
    """Create sample SAST data"""
    
    # Create async engine
    engine = create_async_engine(DATABASE_URL, echo=True)
    
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Create session
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session() as session:
        try:
            # Create test user
            test_user = User(
                email="test@example.com",
                username="testuser",
                full_name="Test User",
                hashed_password="hashed_password_here",
                role="admin",
                is_active=True,
                is_verified=True
            )
            session.add(test_user)
            await session.commit()
            await session.refresh(test_user)
            
            print(f"Created test user: {test_user.username}")
            
            # Create test SAST project
            test_project = SASTProject(
                name="Test Web Application",
                description="A sample web application for SAST testing",
                repository_url="https://github.com/example/test-web-app",
                language="python",
                framework="django",
                created_by=test_user.id
            )
            session.add(test_project)
            await session.commit()
            await session.refresh(test_project)
            
            print(f"Created test project: {test_project.name}")
            
            # Create test SAST scan
            test_scan = SASTScan(
                project_id=test_project.id,
                scan_type="full",
                status="completed",
                started_at=datetime.utcnow() - timedelta(hours=2),
                completed_at=datetime.utcnow() - timedelta(hours=1),
                total_files=150,
                scanned_files=150,
                total_lines=5000,
                scanned_lines=5000
            )
            session.add(test_scan)
            await session.commit()
            await session.refresh(test_scan)
            
            print(f"Created test scan: {test_scan.id}")
            
            # Create test SAST issues
            issue_types = [
                {
                    "type": "BUG",
                    "severity": "MAJOR",
                    "title": "Potential null pointer dereference",
                    "description": "Variable 'user_input' might be null when accessed",
                    "rule_id": "S2259",
                    "line": 45,
                    "file_path": "src/views/user_profile.py"
                },
                {
                    "type": "VULNERABILITY",
                    "severity": "CRITICAL",
                    "title": "SQL injection vulnerability",
                    "description": "User input is directly concatenated into SQL query",
                    "rule_id": "S3649",
                    "line": 123,
                    "file_path": "src/database/queries.py"
                }
            ]
            
            for issue_data in issue_types:
                issue = SASTIssue(
                    scan_id=test_scan.id,
                    project_id=test_project.id,
                    type=issue_data["type"],
                    severity=issue_data["severity"],
                    title=issue_data["title"],
                    description=issue_data["description"],
                    rule_id=issue_data["rule_id"],
                    line=issue_data["line"],
                    file_path=issue_data["file_path"],
                    status="OPEN",
                    resolution="UNRESOLVED"
                )
                session.add(issue)
            
            await session.commit()
            print(f"Created {len(issue_types)} test issues")
            print("Test data created successfully!")
            
        except Exception as e:
            print(f"Error creating test data: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()
    
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(create_test_data())
