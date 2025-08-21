#!/usr/bin/env python3
"""
Debug script to test auth functions
"""

import asyncio
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_auth():
    """Test auth functions step by step"""
    try:
        print("Testing imports...")
        from app.core.security import create_access_token
        from app.core.database import get_db
        from app.api.v1.endpoints.auth import authenticate_user
        print("✓ All imports successful")
        
        print("\nTesting create_access_token...")
        token = create_access_token({"sub": "test"})
        print(f"✓ Token created: {token[:20]}...")
        
        print("\nTesting database connection...")
        async for db in get_db():
            print("✓ Database session created")
            break
        
        print("\nTesting authenticate_user...")
        user = await authenticate_user(db, "testuser", "testpass")
        print(f"✓ User authenticated: {user}")
        
        print("\nAll tests passed!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_auth())
