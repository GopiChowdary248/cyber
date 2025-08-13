#!/usr/bin/env python3
"""
Test database connection script
"""

import asyncio
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

async def test_db_connection():
    """Test database connection"""
    try:
        from app.core.database import engine
        
        print("✅ Database engine imported successfully")
        print(f"Database URL: {os.getenv('DATABASE_URL', 'Not set')}")
        
        # Test connection
        async with engine.begin() as conn:
            from sqlalchemy import text
            result = await conn.execute(text("SELECT 1 as test"))
            row = result.fetchone()
            print(f"✅ Database connection successful: {row[0]}")
            
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("🔍 Testing database connection...")
    asyncio.run(test_db_connection())
