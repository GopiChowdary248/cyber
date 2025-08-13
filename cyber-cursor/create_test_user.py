#!/usr/bin/env python3
"""
Script to create a test user for CyberShield
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the backend directory to the Python path
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.core.security import get_password_hash
from datetime import datetime

async def create_test_user():
    """Create a test user in the database"""
    
    # Test user data
    user_data = {
        "username": "admin",
        "email": "admin@cybershield.com",
        "full_name": "CyberShield Administrator",
        "hashed_password": get_password_hash("admin123"),
        "role": "admin",
        "is_active": True,
        "is_verified": True,
        "is_superuser": True,
        "department": "IT Security",
        "phone": "+1234567890"
    }
    
    async with AsyncSessionLocal() as db:
        try:
            # Check if user already exists
            existing_user = await User.get_by_email(db, user_data["email"])
            if existing_user:
                print("✅ Admin user already exists!")
                print(f"Username: {existing_user.username}")
                print(f"Email: {existing_user.email}")
                print(f"Role: {existing_user.role}")
                return
            
            # Create new user
            user = User(**user_data)
            db.add(user)
            await db.commit()
            await db.refresh(user)
            
            print("✅ Admin user created successfully!")
            print(f"Username: {user.username}")
            print(f"Email: {user.email}")
            print(f"Role: {user.role}")
            print("Password: admin123")
            
        except Exception as e:
            print(f"❌ Error creating admin user: {e}")
            await db.rollback()

if __name__ == "__main__":
    print("Creating test user for CyberShield...")
    asyncio.run(create_test_user())
