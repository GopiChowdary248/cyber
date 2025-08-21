#!/usr/bin/env python3
"""
Script to run CSPM database migration and verify table creation
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from app.core.database import get_db_url, engine
from sqlalchemy import text
from alembic import command
from alembic.config import Config

async def verify_tables():
    """Verify that all CSPM tables were created successfully"""
    async with engine.begin() as conn:
        # List of expected CSPM tables
        expected_tables = [
            'asset_relationships',
            'policy_evaluation_results', 
            'compliance_controls',
            'compliance_mappings',
            'integration_webhooks',
            'scan_templates',
            'remediation_playbooks',
            'remediation_executions',
            'risk_assessments'
        ]
        
        # Check if tables exist
        for table_name in expected_tables:
            result = await conn.execute(text(f"""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = '{table_name}'
                );
            """))
            exists = result.scalar()
            
            if exists:
                print(f"✅ Table '{table_name}' exists")
            else:
                print(f"❌ Table '{table_name}' missing")
                return False
        
        return True

def run_migration():
    """Run the Alembic migration"""
    try:
        # Get the alembic.ini path
        alembic_cfg = Config(backend_dir / "alembic.ini")
        
        print("🔄 Running CSPM database migration...")
        command.upgrade(alembic_cfg, "001")
        print("✅ Migration completed successfully!")
        
        return True
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False

async def main():
    """Main function to run migration and verification"""
    print("🚀 Starting CSPM Database Migration Process")
    print("=" * 50)
    
    # Run migration
    if not run_migration():
        print("❌ Migration failed. Exiting.")
        sys.exit(1)
    
    # Verify tables
    print("\n🔍 Verifying table creation...")
    if await verify_tables():
        print("\n🎉 All CSPM tables created successfully!")
        print("\n📋 Next steps:")
        print("1. Test API endpoints with Postman")
        print("2. Verify frontend integration")
        print("3. Test mobile app functionality")
    else:
        print("\n❌ Some tables are missing. Check migration logs.")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
