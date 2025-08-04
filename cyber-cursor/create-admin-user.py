#!/usr/bin/env python3
"""
Script to create an admin user for CyberShield
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the backend directory to the Python path
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

from app.core.database import AsyncSessionLocal
from app.models.iam import IAMUser
from app.core.security import get_password_hash
from datetime import datetime

async def create_admin_user():
    """Create an admin user in the database"""
    
    # Admin user data
    admin_data = {
        "username": "admin",
        "email": "admin@cybershield.com",
        "full_name": "CyberShield Administrator",
        "password_hash": get_password_hash("admin123"),
        "role": "admin",
        "is_active": True,
        "is_verified": True,
        "department": "IT Security",
        "phone": "+1234567890",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    async with AsyncSessionLocal() as db:
        try:
            # Check if admin user already exists
            existing_user = await IAMUser.get_by_email(db, admin_data["email"])
            if existing_user:
                print("Admin user already exists!")
                return
            
            # Create new admin user
            admin_user = IAMUser(**admin_data)
            db.add(admin_user)
            await db.commit()
            await db.refresh(admin_user)
            
            print("✅ Admin user created successfully!")
            print(f"Username: {admin_user.username}")
            print(f"Email: {admin_user.email}")
            print(f"Role: {admin_user.role}")
            print("Password: admin123")
            
        except Exception as e:
            print(f"❌ Error creating admin user: {e}")
            await db.rollback()

if __name__ == "__main__":
    print("Creating admin user for CyberShield...")
    asyncio.run(create_admin_user()) 