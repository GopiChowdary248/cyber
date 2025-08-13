#!/usr/bin/env python3
"""
Script to create essential database tables for CyberShield in PostgreSQL
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

async def create_tables():
    """Create essential database tables in PostgreSQL"""
    
    # PostgreSQL connection parameters
    DB_CONFIG = {
        'host': 'localhost',
        'port': 5432,
        'user': 'cybershield_user',
        'password': 'cybershield_password',
        'database': 'cybershield'
    }
    
    try:
        # Connect to PostgreSQL
        print("🔌 Connecting to PostgreSQL...")
        conn = await asyncpg.connect(**DB_CONFIG)
        print("✅ Connected to PostgreSQL successfully!")
        
        # Create users table
        print("\n📋 Creating users table...")
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(100) UNIQUE NOT NULL,
                username VARCHAR(50) UNIQUE NOT NULL,
                full_name VARCHAR(100),
                hashed_password VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'user',
                is_active BOOLEAN DEFAULT true,
                is_verified BOOLEAN DEFAULT false,
                is_superuser BOOLEAN DEFAULT false,
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                department VARCHAR(100),
                phone VARCHAR(20),
                avatar_url VARCHAR(255),
                two_factor_enabled BOOLEAN DEFAULT false,
                two_factor_secret VARCHAR(255),
                preferences TEXT
            )
        """)
        print("✅ Users table created successfully!")

        # Create token_blacklist table
        print("\n📋 Creating token_blacklist table...")
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS token_blacklist (
                id SERIAL PRIMARY KEY,
                token VARCHAR(500) UNIQUE NOT NULL,
                blacklisted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
        """)
        print("✅ Token blacklist table created successfully!")

        # Create indexes
        print("\n📋 Creating indexes...")
        await conn.execute("CREATE INDEX IF NOT EXISTS ix_users_email ON users(email)")
        await conn.execute("CREATE INDEX IF NOT EXISTS ix_users_username ON users(username)")
        await conn.execute("CREATE INDEX IF NOT EXISTS ix_users_id ON users(id)")
        print("✅ Indexes created successfully!")

        await conn.close()
        return True

    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        return False

async def create_admin_user():
    """Create an admin user for testing"""
    
    DB_CONFIG = {
        'host': 'localhost',
        'port': 5432,
        'user': 'cybershield_user',
        'password': 'cybershield_password',
        'database': 'cybershield'
    }
    
    try:
        print("\n👤 Creating admin user...")
        conn = await asyncpg.connect(**DB_CONFIG)
        
        # Check if admin user already exists
        existing_user = await conn.fetchrow(
            "SELECT id FROM users WHERE email = $1", 
            'admin@cybershield.com'
        )
        
        if existing_user:
            print("✅ Admin user already exists!")
            await conn.close()
            return True

        # Create admin user
        hashed_password = get_password_hash("admin123")
        
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
        
        await conn.close()
        print("✅ Admin user created successfully!")
        print("📧 Email: admin@cybershield.com")
        print("🔑 Password: admin123")
        return True

    except Exception as e:
        print(f"❌ Error creating admin user: {e}")
        return False

async def main():
    """Main function"""
    print("🚀 Setting up PostgreSQL database for CyberShield...")
    print("=" * 60)

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
