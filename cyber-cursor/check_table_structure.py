#!/usr/bin/env python3
"""
Script to check the exact structure of the users table
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the backend directory to the Python path
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

from app.core.database import engine
from sqlalchemy import text

async def check_table_structure():
    """Check the structure of the users table"""
    
    try:
        async with engine.begin() as conn:
            # Get table info
            result = await conn.execute(text("PRAGMA table_info(users)"))
            columns = result.fetchall()
            
            print("📋 Users table structure:")
            print("cid | name | type | notnull | dflt_value | pk")
            print("-" * 60)
            for col in columns:
                cid = col[0] or 0
                name = col[1] or ""
                col_type = col[2] or ""
                notnull = col[3] or 0
                dflt_value = col[4] or ""
                pk = col[5] or 0
                print(f"{cid:3} | {name:20} | {col_type:15} | {notnull:7} | {dflt_value:11} | {pk}")
            
            print(f"\n✅ Total columns: {len(columns)}")
            
            # Check if specific columns exist
            column_names = [col[1] for col in columns if col[1]]
            required_columns = [
                'id', 'email', 'username', 'full_name', 'hashed_password',
                'role', 'is_active', 'is_verified', 'is_superuser',
                'last_login', 'created_at', 'updated_at', 'department',
                'phone', 'avatar_url', 'two_factor_enabled', 'two_factor_secret', 'preferences'
            ]
            
            print("\n🔍 Checking required columns:")
            for col in required_columns:
                if col in column_names:
                    print(f"✅ {col}")
                else:
                    print(f"❌ {col} - MISSING!")
                    
    except Exception as e:
        print(f"❌ Error checking table structure: {e}")

if __name__ == "__main__":
    print("Checking users table structure...")
    asyncio.run(check_table_structure())
