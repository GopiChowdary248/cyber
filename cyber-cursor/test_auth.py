#!/usr/bin/env python3
"""
Script to test authentication directly
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
from app.core.security import get_password_hash, verify_password
from sqlalchemy import text

async def test_auth():
    """Test authentication directly"""
    
    try:
        async with AsyncSessionLocal() as db:
            print("🔍 Testing authentication...")
            
            # Test 1: Check if user exists
            print("\n1. Checking if admin user exists...")
            result = await db.execute(text("SELECT * FROM users WHERE email = 'admin@cybershield.com'"))
            user_row = result.fetchone()
            
            if user_row:
                print(f"✅ User found: {user_row}")
            else:
                print("❌ User not found")
                return
            
            # Test 2: Try to get user by email using the model
            print("\n2. Testing User.get_by_email...")
            try:
                user = await User.get_by_email(db, "admin@cybershield.com")
                if user:
                    print(f"✅ User model query successful: {user.username}, {user.email}")
                else:
                    print("❌ User model query failed")
            except Exception as e:
                print(f"❌ Error in User.get_by_email: {e}")
            
            # Test 3: Try to get user by username using the model
            print("\n3. Testing User.get_by_username...")
            try:
                user = await User.get_by_username(db, "admin")
                if user:
                    print(f"✅ Username query successful: {user.username}, {user.email}")
                else:
                    print("❌ Username query failed")
            except Exception as e:
                print(f"❌ Error in User.get_by_username: {e}")
            
            # Test 4: Test password verification
            print("\n4. Testing password verification...")
            try:
                if user_row:
                    # Get the hashed password from the row
                    hashed_password = user_row[4]  # Index 4 is hashed_password
                    is_valid = verify_password("admin123", hashed_password)
                    if is_valid:
                        print("✅ Password verification successful")
                    else:
                        print("❌ Password verification failed")
            except Exception as e:
                print(f"❌ Error in password verification: {e}")
                
    except Exception as e:
        print(f"❌ Error in test: {e}")

if __name__ == "__main__":
    print("Testing authentication system...")
    asyncio.run(test_auth())
