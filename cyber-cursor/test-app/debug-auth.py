#!/usr/bin/env python3
"""
Debug Authentication Script
Tests the authentication process step by step to identify issues
"""

import asyncio
import asyncpg
import requests
import json
from datetime import datetime

class AuthDebugger:
    def __init__(self):
        self.api_url = "http://localhost:8000"
        self.db_url = "postgresql://cybershield_user:cybershield_password@localhost:5432/cybershield"
        
    async def test_database_connection(self):
        """Test direct database connection"""
        print("🔍 Testing database connection...")
        try:
            conn = await asyncpg.connect(self.db_url)
            print("✅ Database connection successful")
            
            # Check if users table exists
            result = await conn.fetch("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_name = 'users'
            """)
            
            if result:
                print("✅ Users table exists")
                
                # Check users in the table
                users = await conn.fetch("SELECT id, email, username, role, is_active FROM users")
                print(f"✅ Found {len(users)} users in database:")
                for user in users:
                    print(f"   - ID: {user['id']}, Email: {user['email']}, Role: {user['role']}, Active: {user['is_active']}")
            else:
                print("❌ Users table does not exist")
                
            await conn.close()
            return True
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return False
    
    def test_health_endpoint(self):
        """Test health endpoint"""
        print("\n🔍 Testing health endpoint...")
        try:
            response = requests.get(f"{self.api_url}/health", timeout=10)
            print(f"✅ Health endpoint: Status {response.status_code}")
            print(f"   Response: {response.json()}")
            return True
        except Exception as e:
            print(f"❌ Health endpoint failed: {e}")
            return False
    
    def test_login_endpoint(self):
        """Test login endpoint"""
        print("\n🔍 Testing login endpoint...")
        try:
            # Test with admin credentials
            response = requests.post(
                f"{self.api_url}/api/v1/auth/login",
                data={
                    "username": "admin@cybershield.com",
                    "password": "password"
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10
            )
            
            print(f"✅ Login endpoint: Status {response.status_code}")
            print(f"   Response: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"   Token: {data.get('access_token', 'No token')[:20]}...")
                return True
            else:
                print(f"❌ Login failed with status {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Login endpoint failed: {e}")
            return False
    
    def test_backend_logs(self):
        """Check backend logs for errors"""
        print("\n🔍 Checking backend logs...")
        try:
            import subprocess
            result = subprocess.run(
                ["docker", "logs", "cybershield-backend", "--tail", "5"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                print("✅ Backend logs retrieved:")
                print(result.stdout)
            else:
                print(f"❌ Failed to get backend logs: {result.stderr}")
                
        except Exception as e:
            print(f"❌ Could not check backend logs: {e}")
    
    async def run_full_debug(self):
        """Run complete authentication debug"""
        print("🚀 Starting Authentication Debug\n")
        print("=" * 50)
        
        # Test database
        db_ok = await self.test_database_connection()
        
        # Test health endpoint
        health_ok = self.test_health_endpoint()
        
        # Test login endpoint
        login_ok = self.test_login_endpoint()
        
        # Check logs
        self.test_backend_logs()
        
        print("\n" + "=" * 50)
        print("📊 Debug Summary:")
        print(f"   Database: {'✅ OK' if db_ok else '❌ FAILED'}")
        print(f"   Health Endpoint: {'✅ OK' if health_ok else '❌ FAILED'}")
        print(f"   Login Endpoint: {'✅ OK' if login_ok else '❌ FAILED'}")
        
        if not login_ok:
            print("\n🔧 Recommendations:")
            print("   1. Check backend logs for specific error messages")
            print("   2. Verify database users exist and passwords are correct")
            print("   3. Check authentication function implementation")
            print("   4. Verify database session management")

async def main():
    debugger = AuthDebugger()
    await debugger.run_full_debug()

if __name__ == "__main__":
    asyncio.run(main()) 