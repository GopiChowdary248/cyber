#!/usr/bin/env python3
"""
Test authentication step by step
"""

import asyncio
import sys
import os

# Add the backend directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.core.security import get_password_hash, verify_password

async def test_auth():
    """Test authentication step by step"""
    
    async with AsyncSessionLocal() as db:
        try:
            print("🔍 Testing database connection...")
            
            # Test 1: Check if we can query users
            from sqlalchemy import select
            result = await db.execute(select(User))
            users = result.scalars().all()
            print(f"✅ Found {len(users)} users in database")
            
            for user in users:
                print(f"   - {user.email} (role: {user.role})")
            
            # Test 2: Try to get user by email
            print("\n🔍 Testing get_by_email...")
            test_user = await User.get_by_email(db, "sast@cybershield.com")
            if test_user:
                print(f"✅ User found: {test_user.email}")
                print(f"   - Username: {test_user.username}")
                print(f"   - Role: {test_user.role}")
                print(f"   - Hashed password: {test_user.hashed_password[:20]}...")
                
                # Test 3: Test password verification
                print("\n🔍 Testing password verification...")
                is_valid = verify_password("sastpass123", test_user.hashed_password)
                print(f"✅ Password verification: {is_valid}")
                
            else:
                print("❌ User not found")
                
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_auth())
