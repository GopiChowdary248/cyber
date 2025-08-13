#!/usr/bin/env python3
"""
Check if SAST tables exist in the database
"""

import asyncio
from sqlalchemy import text
from app.core.database import AsyncSessionLocal
from app.models.sast import SASTProject

async def check_sast_tables():
    """Check if SAST tables exist"""
    try:
        async with AsyncSessionLocal() as db:
            # Check if SAST tables exist (PostgreSQL syntax)
            result = await db.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name LIKE '%sast%'
            """))
            tables = result.fetchall()
            print('SAST tables found:', [t[0] for t in tables])
            
            # Try to query SASTProject table
            try:
                result = await db.execute(text('SELECT COUNT(*) FROM sast_projects'))
                count = result.scalar()
                print(f'SAST projects count: {count}')
            except Exception as e:
                print(f'Error querying sast_projects table: {e}')
                
    except Exception as e:
        print(f'Error checking database: {e}')

if __name__ == "__main__":
    asyncio.run(check_sast_tables())
