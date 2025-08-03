#!/usr/bin/env python3
"""
SAST Database Setup Script
Initializes the SAST module database tables and populates with initial data.
"""

import asyncio
import asyncpg
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

# Add the backend directory to the Python path
backend_dir = Path(__file__).parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.core.config import settings

def parse_database_url(database_url: str):
    """Parse database URL to extract connection parameters"""
    parsed = urlparse(database_url)
    
    # Handle asyncpg format: postgresql+asyncpg://user:pass@host:port/db
    if '+asyncpg' in parsed.scheme:
        scheme = parsed.scheme.replace('+asyncpg', '')
    else:
        scheme = parsed.scheme
    
    # Use localhost instead of Docker service names when running outside Docker
    hostname = parsed.hostname
    if hostname in ['postgres', 'redis']:
        hostname = 'localhost'
    
    return {
        'host': hostname,
        'port': parsed.port or 5432,
        'user': parsed.username,
        'password': parsed.password,
        'database': parsed.path.lstrip('/')
    }

async def setup_sast_database():
    """Initialize SAST database tables and data"""
    
    try:
        print("🔧 Setting up SAST database...")
        
        # Parse database URL
        db_config = parse_database_url(settings.database.DATABASE_URL)
        print(f"📊 Connecting to database: {db_config['host']}:{db_config['port']}/{db_config['database']}")
        
        # Connect to database
        conn = await asyncpg.connect(**db_config)
        
        # Read and execute the SQL schema
        schema_file = Path(__file__).parent / "init-sast-db.sql"
        
        if not schema_file.exists():
            print(f"❌ Schema file not found: {schema_file}")
            return False
        
        print(f"📄 Reading schema file: {schema_file}")
        with open(schema_file, 'r') as f:
            sql_script = f.read()
        
        # Execute the schema
        print("🔨 Executing database schema...")
        await conn.execute(sql_script)
        
        # Verify tables were created
        tables = await conn.fetch("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name LIKE 'sast_%'
            ORDER BY table_name
        """)
        
        print(f"✅ SAST tables created: {[t['table_name'] for t in tables]}")
        
        # Verify data was inserted
        projects_count = await conn.fetchval("SELECT COUNT(*) FROM sast_projects")
        rules_count = await conn.fetchval("SELECT COUNT(*) FROM sast_rules")
        
        print(f"✅ Initial data inserted:")
        print(f"   - Projects: {projects_count}")
        print(f"   - Rules: {rules_count}")
        
        # Test the overview stats view
        stats = await conn.fetchrow("SELECT * FROM sast_overview_stats")
        if stats:
            print(f"✅ Overview stats view working:")
            print(f"   - Total projects: {stats['total_projects']}")
            print(f"   - Total rules: {rules_count}")
        
        await conn.close()
        
        print("🎉 SAST database setup completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error setting up SAST database: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_sast_connection():
    """Test SAST database connection and basic operations"""
    
    try:
        print("🔍 Testing SAST database connection...")
        
        # Parse database URL
        db_config = parse_database_url(settings.database.DATABASE_URL)
        
        conn = await asyncpg.connect(**db_config)
        
        # Test basic queries
        projects = await conn.fetch("SELECT name, language FROM sast_projects LIMIT 3")
        rules = await conn.fetch("SELECT name, severity FROM sast_rules WHERE language = 'python' LIMIT 3")
        
        print(f"✅ Connection successful!")
        print(f"   - Sample projects: {[p['name'] for p in projects]}")
        print(f"   - Python rules: {[r['name'] for r in rules]}")
        
        await conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Connection test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Main function"""
    print("🚀 SAST Database Setup and Test")
    print("=" * 50)
    
    # Setup database
    setup_success = await setup_sast_database()
    
    if setup_success:
        print("\n" + "=" * 50)
        
        # Test connection
        test_success = await test_sast_connection()
        
        if test_success:
            print("\n🎉 All SAST database operations completed successfully!")
            print("\n📋 Next steps:")
            print("   1. Restart the backend application")
            print("   2. Test SAST API endpoints")
            print("   3. Verify frontend integration")
        else:
            print("\n⚠️  Setup completed but connection test failed")
            sys.exit(1)
    else:
        print("\n❌ SAST database setup failed")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 