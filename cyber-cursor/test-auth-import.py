#!/usr/bin/env python3
"""
Test script to check auth router import
"""

import sys
import os

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

def test_auth_import():
    """Test importing the auth router"""
    try:
        print("Testing auth router import...")
        from app.api.v1.endpoints.auth import router as auth_router
        print("✅ Auth router imported successfully!")
        print(f"Router: {auth_router}")
        print(f"Router routes: {auth_router.routes}")
        return True
    except Exception as e:
        print(f"❌ Auth router import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_security_import():
    """Test importing security module"""
    try:
        print("\nTesting security module import...")
        from app.core.security import create_access_token, get_current_active_user
        print("✅ Security module imported successfully!")
        return True
    except Exception as e:
        print(f"❌ Security module import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_user_model_import():
    """Test importing user model"""
    try:
        print("\nTesting user model import...")
        from app.models.user import User
        print("✅ User model imported successfully!")
        return True
    except Exception as e:
        print(f"❌ User model import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_auth_schemas_import():
    """Test importing auth schemas"""
    try:
        print("\nTesting auth schemas import...")
        from app.schemas.auth import Token, UserCreate, User
        print("✅ Auth schemas imported successfully!")
        return True
    except Exception as e:
        print(f"❌ Auth schemas import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🔍 Testing auth router dependencies...")
    
    success = True
    success &= test_security_import()
    success &= test_user_model_import()
    success &= test_auth_schemas_import()
    success &= test_auth_import()
    
    if success:
        print("\n🎉 All imports successful!")
    else:
        print("\n❌ Some imports failed!") 