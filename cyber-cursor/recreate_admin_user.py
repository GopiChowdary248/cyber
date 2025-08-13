#!/usr/bin/env python3
"""
Script to recreate the admin user with a fresh password hash
"""

import asyncio
import asyncpg
import sys
import os
from pathlib import Path

# Add the backend directory to the Python path
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

from app.core.security import get_password_hash

async def recreate_admin_user():
    """Recreate admin user with fresh password hash"""
    
    print("🔄 Recreating Admin User with Fresh Password Hash")
    print("=" * 60)
    
    DB_CONFIG = {
        'host': 'localhost',
        'port': 5432,
        'user': 'cybershield_user',
        'password': 'cybershield_password',
        'database': 'cybershield'
    }
    
    try:
        print("🔌 Connecting to PostgreSQL...")
        conn = await asyncpg.connect(**DB_CONFIG)
        print("✅ Connected to PostgreSQL successfully!")
        
        # Delete existing admin user
        print("\n🗑️ Deleting existing admin user...")
        await conn.execute(
            "DELETE FROM users WHERE email = $1",
            'admin@cybershield.com'
        )
        print("✅ Existing admin user deleted")
        
        # Create new admin user with fresh hash
        print("\n👤 Creating new admin user...")
        password = "admin123"
        hashed_password = get_password_hash(password)
        
        print(f"   Password: {password}")
        print(f"   Hash: {hashed_password}")
        
        await conn.execute("""
            INSERT INTO users (
                email, username, full_name, hashed_password, role,
                is_active, is_verified, is_superuser, department
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9
            )
        """, 
        'admin@cybershield.com', 'admin', 'CyberShield Administrator',
        hashed_password, 'admin', True, True, True, 'IT Security'
        )
        
        print("✅ New admin user created successfully!")
        
        # Verify the user was created
        print("\n🔍 Verifying new admin user...")
        admin_user = await conn.fetchrow(
            "SELECT id, email, username, hashed_password, role FROM users WHERE email = $1",
            'admin@cybershield.com'
        )
        
        if admin_user:
            print(f"   ✅ Admin user verified in database")
            print(f"   ID: {admin_user['id']}")
            print(f"   Email: {admin_user['email']}")
            print(f"   Username: {admin_user['username']}")
            print(f"   Role: {admin_user['role']}")
            print(f"   New Hash: {admin_user['hashed_password']}")
        else:
            print(f"   ❌ Admin user not found after creation")
            
        await conn.close()
        return True

    except Exception as e:
        print(f"❌ Error recreating admin user: {e}")
        return False

async def main():
    """Main function"""
    print("🚀 Recreating Admin User for CyberShield...")
    
    if await recreate_admin_user():
        print("\n🎉 Admin user recreation completed!")
        print("You can now test the login with:")
        print("   Email: admin@cybershield.com")
        print("   Password: admin123")
    else:
        print("\n❌ Admin user recreation failed!")

if __name__ == "__main__":
    asyncio.run(main())
