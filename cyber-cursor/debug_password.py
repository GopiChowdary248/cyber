#!/usr/bin/env python3
"""
Script to debug password hashing and verification
"""

import asyncio
import asyncpg
import sys
import os
from pathlib import Path

# Add the backend directory to the Python path
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

from app.core.security import get_password_hash, verify_password

async def debug_password():
    """Debug password hashing and verification"""
    
    print("🔍 Debugging Password Hashing and Verification")
    print("=" * 60)
    
    # Test password
    test_password = "admin123"
    
    # Hash the password
    print(f"1. Hashing password: '{test_password}'")
    hashed_password = get_password_hash(test_password)
    print(f"   Hashed password: {hashed_password}")
    
    # Verify the password
    print(f"\n2. Verifying password: '{test_password}'")
    is_valid = verify_password(test_password, hashed_password)
    print(f"   Verification result: {is_valid}")
    
    # Test with wrong password
    wrong_password = "wrong123"
    print(f"\n3. Testing wrong password: '{wrong_password}'")
    is_valid_wrong = verify_password(wrong_password, hashed_password)
    print(f"   Verification result: {is_valid_wrong}")
    
    # Check database
    print(f"\n4. Checking database for admin user...")
    try:
        conn = await asyncpg.connect(
            host='localhost',
            port=5432,
            user='cybershield_user',
            password='cybershield_password',
            database='cybershield'
        )
        
        # Get admin user
        admin_user = await conn.fetchrow(
            "SELECT id, email, username, hashed_password, role FROM users WHERE email = $1",
            'admin@cybershield.com'
        )
        
        if admin_user:
            print(f"   ✅ Admin user found in database")
            print(f"   ID: {admin_user['id']}")
            print(f"   Email: {admin_user['email']}")
            print(f"   Username: {admin_user['username']}")
            print(f"   Role: {admin_user['role']}")
            print(f"   Stored hash: {admin_user['hashed_password']}")
            
            # Test verification with stored hash
            print(f"\n5. Testing verification with stored hash...")
            stored_hash = admin_user['hashed_password']
            is_valid_stored = verify_password(test_password, stored_hash)
            print(f"   Verification with stored hash: {is_valid_stored}")
            
            # Generate new hash for comparison
            new_hash = get_password_hash(test_password)
            print(f"   New hash: {new_hash}")
            print(f"   Verification with new hash: {verify_password(test_password, new_hash)}")
            
        else:
            print(f"   ❌ Admin user not found in database")
            
        await conn.close()
        
    except Exception as e:
        print(f"   ❌ Database error: {e}")

if __name__ == "__main__":
    asyncio.run(debug_password())
