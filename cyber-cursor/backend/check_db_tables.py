#!/usr/bin/env python3
"""
Check existing SAST tables in the database
"""

import asyncio
from sqlalchemy import text
from app.core.database import engine

async def check_sast_tables():
    """Check what SAST tables exist in the database"""
    async with engine.begin() as conn:
        # Check for SAST tables
        result = await conn.execute(text("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name LIKE 'sast_%'
            ORDER BY table_name
        """))
        
        tables = [row[0] for row in result]
        print("Existing SAST tables:")
        for table in tables:
            print(f"  - {table}")
        
        # Check for enum types
        result = await conn.execute(text("""
            SELECT typname 
            FROM pg_type 
            WHERE typname LIKE '%sast%' OR typname IN ('issueseverity', 'issuetype', 'issuestatus', 'rating', 'qualitygatestatus', 'scanstatus', 'securityhotspotstatus')
            ORDER BY typname
        """))
        
        enums = [row[0] for row in result]
        print("\nExisting enum types:")
        for enum in enums:
            print(f"  - {enum}")

if __name__ == "__main__":
    asyncio.run(check_sast_tables()) 