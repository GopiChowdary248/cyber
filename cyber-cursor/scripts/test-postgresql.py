#!/usr/bin/env python3
"""
PostgreSQL Connection Test Script for CyberShield
This script tests the database connection and basic operations
"""

import asyncio
import asyncpg
import os
from datetime import datetime

async def test_postgresql_connection():
    """Test PostgreSQL connection and basic operations"""
    
    # Connection parameters
    config = {
        'user': 'cybershield_user',
        'password': 'cybershield_password',
        'database': 'cybershield',
        'host': 'localhost',
        'port': 5432
    }
    
    print("🔍 Testing PostgreSQL Connection for CyberShield...")
    print(f"📡 Connecting to: {config['host']}:{config['port']}")
    print(f"🗄️  Database: {config['database']}")
    print(f"👤 User: {config['user']}")
    print("-" * 50)
    
    try:
        # Test connection
        print("1️⃣  Testing basic connection...")
        conn = await asyncpg.connect(**config)
        print("✅ Connection successful!")
        
        # Test version
        print("\n2️⃣  Testing PostgreSQL version...")
        version = await conn.fetchval("SELECT version();")
        print(f"✅ PostgreSQL version: {version.split(',')[0]}")
        
        # Test custom types
        print("\n3️⃣  Testing custom types...")
        try:
            enum_types = await conn.fetch("""
                SELECT typname FROM pg_type 
                WHERE typtype = 'e' 
                AND typname IN ('scan_status', 'issue_severity', 'issue_type', 'issue_status')
                ORDER BY typname;
            """)
            
            if enum_types:
                print("✅ Custom enum types found:")
                for row in enum_types:
                    print(f"   - {row['typname']}")
            else:
                print("⚠️  No custom enum types found (this is normal for fresh installations)")
        except Exception as e:
            print(f"⚠️  Could not check custom types: {e}")
        
        # Test basic operations
        print("\n4️⃣  Testing basic operations...")
        
        # Create a test table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS connection_test (
                id SERIAL PRIMARY KEY,
                test_name VARCHAR(100),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(20) DEFAULT 'success'
            );
        """)
        print("✅ Test table created/verified")
        
        # Insert test data
        await conn.execute("""
            INSERT INTO connection_test (test_name, status) 
            VALUES ($1, $2)
        """, "postgresql_connection_test", "success")
        print("✅ Test data inserted")
        
        # Query test data
        result = await conn.fetch("""
            SELECT * FROM connection_test 
            WHERE test_name = $1 
            ORDER BY timestamp DESC 
            LIMIT 1
        """, "postgresql_connection_test")
        
        if result:
            row = result[0]
            print(f"✅ Test data retrieved: ID={row['id']}, Time={row['timestamp']}")
        
        # Clean up test table
        await conn.execute("DROP TABLE IF EXISTS connection_test;")
        print("✅ Test table cleaned up")
        
        # Test connection pool
        print("\n5️⃣  Testing connection pool...")
        pool = await asyncpg.create_pool(**config, min_size=2, max_size=5)
        
        async with pool.acquire() as conn2:
            result = await conn2.fetchval("SELECT 42 as answer")
            print(f"✅ Pool connection test: {result}")
        
        await pool.close()
        print("✅ Connection pool test successful")
        
        # Close main connection
        await conn.close()
        print("\n🎉 All PostgreSQL tests passed successfully!")
        
        return True
        
    except asyncpg.InvalidPasswordError:
        print("❌ Authentication failed: Invalid password")
        print("💡 Check your database credentials")
        return False
        
    except asyncpg.InvalidAuthorizationSpecificationError:
        print("❌ Authentication failed: Invalid user or database")
        print("💡 Check your database name and username")
        return False
        
    except asyncpg.ConnectionDoesNotExistError:
        print("❌ Connection failed: Database does not exist")
        print("💡 Create the database first: CREATE DATABASE cybershield;")
        return False
        
    except asyncpg.ConnectionError as e:
        print(f"❌ Connection failed: {e}")
        print("💡 Check if PostgreSQL is running and accessible")
        return False
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        print("💡 Check the error details above")
        return False

async def test_cybershield_schema():
    """Test if CyberShield schema is properly set up"""
    
    print("\n🔍 Testing CyberShield Schema...")
    print("-" * 50)
    
    try:
        conn = await asyncpg.connect(
            user='cybershield_user',
            password='cybershield_password',
            database='cybershield',
            host='localhost',
            port=5432
        )
        
        # Check for SAST tables
        tables = await conn.fetch("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name LIKE '%sast%'
            ORDER BY table_name;
        """)
        
        if tables:
            print("✅ SAST tables found:")
            for table in tables:
                print(f"   - {table['table_name']}")
        else:
            print("⚠️  No SAST tables found")
            print("💡 Run database migrations to create tables")
        
        # Check for user tables
        user_tables = await conn.fetch("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name LIKE '%user%'
            ORDER BY table_name;
        """)
        
        if user_tables:
            print("✅ User tables found:")
            for table in user_tables:
                print(f"   - {table['table_name']}")
        
        await conn.close()
        
    except Exception as e:
        print(f"⚠️  Could not test schema: {e}")

def main():
    """Main function"""
    print("🚀 CyberShield PostgreSQL Connection Test")
    print("=" * 60)
    
    # Check if required packages are installed
    try:
        import asyncpg
    except ImportError:
        print("❌ asyncpg package not found")
        print("💡 Install it with: pip install asyncpg")
        return
    
    # Run tests
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        # Test basic connection
        success = loop.run_until_complete(test_postgresql_connection())
        
        if success:
            # Test schema if basic connection works
            loop.run_until_complete(test_cybershield_schema())
            
            print("\n🎯 Next Steps:")
            print("1. Start your CyberShield backend application")
            print("2. Test the SAST project creation endpoint")
            print("3. Check application logs for any remaining issues")
        else:
            print("\n❌ Connection test failed")
            print("💡 Check the PostgreSQL setup guide for troubleshooting")
            
    finally:
        loop.close()

if __name__ == "__main__":
    main()
