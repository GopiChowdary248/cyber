#!/usr/bin/env python3
"""
Test script to verify authentication is working correctly
"""
import asyncio
import sys
import os

# Add the backend directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.security import authenticate_user, verify_password
from app.core.database import get_db
from app.models.user import User

async def test_authentication():
    """Test the authentication system"""
    print("Testing authentication system...")
    
    try:
        # Get database session
        async for db in get_db():
            print("✓ Database connection successful")
            
            # Test user lookup
            admin_user = await User.get_by_email(db, "admin@cybershield.com")
            if admin_user:
                print(f"✓ Admin user found: {admin_user.username}")
                print(f"  Email: {admin_user.email}")
                print(f"  Role: {admin_user.role}")
                print(f"  Is active: {admin_user.is_active}")
                print(f"  Password hash: {admin_user.hashed_password[:20]}...")
            else:
                print("✗ Admin user not found")
                return False
            
            # Test password verification
            test_password = "admin123"  # Default password
            if verify_password(test_password, admin_user.hashed_password):
                print("✓ Password verification successful")
            else:
                print("✗ Password verification failed")
                print("  This might be the issue - password hash doesn't match")
                return False
            
            # Test full authentication
            authenticated_user = await authenticate_user(db, "admin@cybershield.com", test_password)
            if authenticated_user:
                print("✓ Full authentication successful")
                print(f"  User ID: {authenticated_user.id}")
                print(f"  Permissions: {authenticated_user.permissions}")
                return True
            else:
                print("✗ Full authentication failed")
                return False
            break  # Only process first session
                
    except Exception as e:
        print(f"✗ Error during authentication test: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_redis_connection():
    """Test Redis connection"""
    print("\nTesting Redis connection...")
    
    try:
        import redis
        redis_client = redis.Redis(
            host='localhost',
            port=6380,
            password='redis_password',
            db=0,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5
        )
        
        # Test connection
        response = redis_client.ping()
        if response:
            print("✓ Redis connection successful")
            return True
        else:
            print("✗ Redis ping failed")
            return False
            
    except Exception as e:
        print(f"✗ Redis connection failed: {e}")
        return False

async def main():
    """Main test function"""
    print("CyberShield Authentication Test")
    print("=" * 40)
    
    # Test Redis
    redis_ok = await test_redis_connection()
    
    # Test authentication
    auth_ok = await test_authentication()
    
    print("\n" + "=" * 40)
    if redis_ok and auth_ok:
        print("✓ All tests passed! Authentication should work now.")
        print("\nTry logging in with:")
        print("  Email: admin@cybershield.com")
        print("  Password: admin123")
    else:
        print("✗ Some tests failed. Check the errors above.")
    
    return redis_ok and auth_ok

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
