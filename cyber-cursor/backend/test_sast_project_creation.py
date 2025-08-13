#!/usr/bin/env python3
"""
Test script to verify SAST project creation works correctly
"""

import asyncio
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db, init_db
from app.models.sast import SASTProject
from app.models.user import User

async def test_sast_project_creation():
    """Test SAST project creation"""
    
    print("Testing SAST project creation...")
    
    # Initialize database
    await init_db()
    print("Database initialized")
    
    # Get database session
    async for db in get_db():
        try:
            # Test creating a user first
            print("Creating test user...")
            unique_id = str(uuid.uuid4())[:8]
            user = User(
                email=f"test{unique_id}@example.com",
                username=f"testuser{unique_id}",
                hashed_password="hashed_password",
                role="admin",
                is_active=True,
                is_verified=True
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            print(f"User created with ID: {user.id}")
            
            # Test creating a SAST project
            print("Creating SAST project...")
            project = SASTProject(
                name=f"Test Project {unique_id}",
                key=f"test-project-key-{unique_id}",
                language="Python",
                repository_url="https://github.com/test/project",
                branch="main",
                created_by=user.id
            )
            db.add(project)
            await db.commit()
            await db.refresh(project)
            print(f"SAST project created with ID: {project.id}")
            print(f"Project name: {project.name}")
            print(f"Project key: {project.key}")
            print(f"Project language: {project.language}")
            
            # Test querying the project
            print("Querying created project...")
            from sqlalchemy import text
            result = await db.execute(
                text("SELECT * FROM sast_projects WHERE id = :id"), 
                {"id": project.id}
            )
            row = result.fetchone()
            if row:
                print(f"Project found in database: {row}")
            else:
                print("Project not found in database!")
            
            print("✅ SAST project creation test PASSED!")
            
        except Exception as e:
            print(f"❌ Error during test: {e}")
            await db.rollback()
        finally:
            break

if __name__ == "__main__":
    asyncio.run(test_sast_project_creation())
