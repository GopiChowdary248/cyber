#!/usr/bin/env python3
"""
Script to create essential database tables for CyberShield
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the backend directory to the Python path
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

from app.core.database import engine, Base
from app.models.user import User
from app.models.auth import TokenBlacklist
from sqlalchemy import text

async def create_tables():
    """Create essential database tables"""
    
    try:
        # Create all tables
        async with engine.begin() as conn:
            # Create users table
            await conn.execute(text("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    full_name VARCHAR(100),
                    hashed_password VARCHAR(255) NOT NULL,
                    role VARCHAR(50) DEFAULT 'user',
                    is_active BOOLEAN DEFAULT 1,
                    is_verified BOOLEAN DEFAULT 0,
                    is_superuser BOOLEAN DEFAULT 0,
                    last_login DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    department VARCHAR(100),
                    phone VARCHAR(20),
                    avatar_url VARCHAR(255),
                    two_factor_enabled BOOLEAN DEFAULT 0,
                    two_factor_secret VARCHAR(255),
                    preferences TEXT
                )
            """))
            
            # Create token_blacklist table
            await conn.execute(text("""
                CREATE TABLE IF NOT EXISTS token_blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token VARCHAR(500) UNIQUE NOT NULL,
                    blacklisted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME
                )
            """))
            
            # Create indexes
            await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_users_email ON users(email)"))
            await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_users_username ON users(username)"))
            await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_users_id ON users(id)"))
            
            print("✅ Database tables created successfully!")
            
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        return False
    
    return True

async def create_admin_user():
    """Create an admin user for testing"""
    
    try:
        from app.core.database import AsyncSessionLocal
        from app.core.security import get_password_hash
        
        async with AsyncSessionLocal() as db:
            # Check if admin user already exists
            result = await db.execute(text("SELECT id FROM users WHERE email = 'admin@cybershield.com'"))
            existing_user = result.fetchone()
            
            if existing_user:
                print("✅ Admin user already exists!")
                return True
            
            # Create admin user
            hashed_password = get_password_hash("admin123")
            
            await db.execute(text("""
                INSERT INTO users (
                    email, username, full_name, hashed_password, role, 
                    is_active, is_verified, is_superuser, department
                ) VALUES (
                    'admin@cybershield.com', 'admin', 'CyberShield Administrator',
                    :password, 'admin', 1, 1, 1, 'IT Security'
                )
            """), {"password": hashed_password})
            
            await db.commit()
            print("✅ Admin user created successfully!")
            print("Email: admin@cybershield.com")
            print("Password: admin123")
            return True
            
    except Exception as e:
        print(f"❌ Error creating admin user: {e}")
        return False

async def main():
    """Main function"""
    print("Creating essential database tables for CyberShield...")
    
    # Create tables
    if await create_tables():
        # Create admin user
        await create_admin_user()
        print("\n🎉 Database setup completed!")
        print("You can now test the authentication system.")
    else:
        print("\n❌ Database setup failed!")

if __name__ == "__main__":
    asyncio.run(main())
