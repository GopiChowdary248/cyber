#!/usr/bin/env python3
"""
Script to check database schema
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the backend directory to the Python path
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

from app.core.database import AsyncSessionLocal, engine
from sqlalchemy import text

async def check_database_schema():
    """Check what tables exist in the database"""
    
    try:
        async with engine.begin() as conn:
            # Get list of tables
            result = await conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
            tables = result.fetchall()
            
            print("📋 Database tables found:")
            for table in tables:
                print(f"  - {table[0]}")
            
            if not tables:
                print("❌ No tables found in database")
            else:
                print(f"\n✅ Total tables: {len(tables)}")
                
    except Exception as e:
        print(f"❌ Error checking database schema: {e}")

if __name__ == "__main__":
    print("Checking database schema...")
    asyncio.run(check_database_schema())
