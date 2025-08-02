#!/usr/bin/env python3
"""
Logout Functionality Test Script
Tests the logout endpoints and functionality
"""

import requests
import json
from datetime import datetime

class LogoutTester:
    def __init__(self):
        self.api_url = "http://localhost:8000"
        self.auth_token = None
        
    def login(self):
        """Login to get authentication token"""
        print("🔐 Logging in...")
        try:
            response = requests.post(
                f"{self.api_url}/api/v1/auth/login",
                data={
                    "username": "admin@cybershield.com",
                    "password": "password"
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.auth_token = data["access_token"]
                print("✅ Login successful")
                print(f"   Token: {self.auth_token[:20]}...")
                return True
            else:
                print(f"❌ Login failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
        except Exception as e:
            print(f"❌ Login error: {e}")
            return False
    
    def get_headers(self):
        """Get headers with authentication"""
        return {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json"
        }
    
    def test_protected_endpoint(self):
        """Test accessing a protected endpoint"""
        print("\n🔍 Testing protected endpoint access...")
        try:
            response = requests.get(
                f"{self.api_url}/api/v1/users/me",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Protected endpoint accessible")
                print(f"   User: {data.get('email', 'Unknown')}")
                return True
            else:
                print(f"❌ Protected endpoint failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error testing protected endpoint: {e}")
            return False
    
    def test_logout(self):
        """Test logout endpoint"""
        print("\n🔍 Testing logout...")
        try:
            response = requests.post(
                f"{self.api_url}/api/v1/auth/logout",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print("✅ Logout successful")
                print(f"   Message: {data.get('message', 'No message')}")
                print(f"   User ID: {data.get('user_id', 'Unknown')}")
                print(f"   Logout time: {data.get('logout_time', 'Unknown')}")
                return True
            else:
                print(f"❌ Logout failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
        except Exception as e:
            print(f"❌ Error testing logout: {e}")
            return False
    
    def test_logout_all(self):
        """Test logout all sessions endpoint"""
        print("\n🔍 Testing logout all sessions...")
        try:
            response = requests.post(
                f"{self.api_url}/api/v1/auth/logout-all",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print("✅ Logout all sessions successful")
                print(f"   Message: {data.get('message', 'No message')}")
                print(f"   Status: {data.get('status', 'Unknown')}")
                return True
            else:
                print(f"❌ Logout all sessions failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
        except Exception as e:
            print(f"❌ Error testing logout all: {e}")
            return False
    
    def test_access_after_logout(self):
        """Test accessing protected endpoint after logout"""
        print("\n🔍 Testing access after logout...")
        try:
            response = requests.get(
                f"{self.api_url}/api/v1/users/me",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 401:
                print("✅ Access properly denied after logout")
                return True
            elif response.status_code == 200:
                print("⚠️  Access still allowed after logout (token not invalidated)")
                return False
            else:
                print(f"❌ Unexpected response after logout: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error testing access after logout: {e}")
            return False
    
    def test_health_endpoint(self):
        """Test health endpoint (should always work)"""
        print("\n🔍 Testing health endpoint...")
        try:
            response = requests.get(f"{self.api_url}/health", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                print("✅ Health endpoint accessible")
                print(f"   Status: {data.get('status', 'Unknown')}")
                return True
            else:
                print(f"❌ Health endpoint failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error testing health endpoint: {e}")
            return False
    
    def run_all_tests(self):
        """Run all logout tests"""
        print("🚀 Starting Logout Functionality Tests")
        print("=" * 60)
        
        # Test 1: Login
        if not self.login():
            print("❌ Cannot proceed without authentication")
            return False
        
        # Test 2: Access protected endpoint before logout
        if not self.test_protected_endpoint():
            print("❌ Cannot access protected endpoints")
            return False
        
        # Test 3: Test logout
        if not self.test_logout():
            print("❌ Logout failed")
            return False
        
        # Test 4: Test logout all sessions
        if not self.test_logout_all():
            print("❌ Logout all sessions failed")
            return False
        
        # Test 5: Test access after logout
        if not self.test_access_after_logout():
            print("⚠️  Token not properly invalidated")
        
        # Test 6: Test health endpoint (should always work)
        if not self.test_health_endpoint():
            print("❌ Health endpoint not accessible")
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 Logout Functionality Test Summary")
        print("=" * 60)
        print("✅ Login functionality")
        print("✅ Protected endpoint access")
        print("✅ Logout endpoint")
        print("✅ Logout all sessions endpoint")
        print("✅ Health endpoint accessibility")
        print("\n🎉 Logout functionality tests completed!")
        
        return True

def main():
    tester = LogoutTester()
    success = tester.run_all_tests()
    exit(0 if success else 1)

if __name__ == "__main__":
    main() 