#!/usr/bin/env python3
"""
Simple script to create RASP database tables
"""

import asyncio
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import engine, Base
from app.models.rasp import *

async def create_rasp_tables():
    """Create all RASP tables"""
    try:
        async with engine.begin() as conn:
            # Create all tables
            await conn.run_sync(Base.metadata.create_all)
            print("✅ RASP tables created successfully!")
            
            # List created tables
            inspector = await conn.run_sync(lambda sync_conn: sync_conn.dialect.inspector(sync_conn))
            tables = await conn.run_sync(lambda sync_conn: inspector.get_table_names())
            
            rasp_tables = [table for table in tables if table.startswith('rasp_')]
            print(f"📋 Created RASP tables: {', '.join(rasp_tables)}")
            
    except Exception as e:
        print(f"❌ Error creating RASP tables: {e}")
        raise

if __name__ == "__main__":
    print("🚀 Creating RASP database tables...")
    asyncio.run(create_rasp_tables())
