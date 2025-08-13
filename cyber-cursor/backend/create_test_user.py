#!/usr/bin/env python3
"""
Create a test user for SAST testing
"""

import asyncio
import sys
import os
from datetime import datetime

# Add the backend directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.core.security import get_password_hash

async def create_test_user():
    """Create a test user for SAST testing"""
    
    async with AsyncSessionLocal() as db:
        try:
            # Check if user already exists
            from sqlalchemy import select
            result = await db.execute(select(User).where(User.email == "sast@cybershield.com"))
            existing_user = result.scalar_one_or_none()
            
            if existing_user:
                print(f"User {existing_user.email} already exists")
                return existing_user
            
            # Create new user
            hashed_password = get_password_hash("sastpass123")
            
            user = User(
                email="sast@cybershield.com",
                username="sastuser",
                full_name="SAST Test User",
                hashed_password=hashed_password,
                role="user",
                department="Security",
                is_active=True,
                is_verified=True,
                created_at=datetime.now()
            )
            
            db.add(user)
            await db.commit()
            await db.refresh(user)
            
            print(f"Created user: {user.email} (Role: {user.role})")
            return user
            
        except Exception as e:
            print(f"Error creating user: {e}")
            await db.rollback()
            raise

if __name__ == "__main__":
    asyncio.run(create_test_user())
