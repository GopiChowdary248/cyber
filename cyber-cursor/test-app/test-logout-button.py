#!/usr/bin/env python3
"""
Test Logout Button Functionality
Verifies that the logout button is accessible and working.
"""

import requests
import json
from datetime import datetime

def test_logout_functionality():
    """Test the logout functionality"""
    
    base_url = "http://localhost:8000"
    session = requests.Session()
    
    print("🔍 Testing Logout Button Functionality")
    print(f"🌐 Backend URL: {base_url}")
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)
    
    # Step 1: Login first
    print("1️⃣ Logging in as admin...")
    login_data = {
        'username': 'admin@cybershield.com',
        'password': 'password'
    }
    
    try:
        response = session.post(
            f"{base_url}/api/v1/auth/login",
            data=login_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        if response.status_code == 200:
            data = response.json()
            token = data.get('access_token')
            print("✅ Login successful!")
            print(f"   User: {data.get('email')}")
            print(f"   Role: {data.get('role')}")
        else:
            print(f"❌ Login failed: {response.status_code}")
            return
    except Exception as e:
        print(f"❌ Login error: {str(e)}")
        return
    
    # Step 2: Test logout endpoint
    print("\n2️⃣ Testing logout endpoint...")
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = session.post(f"{base_url}/api/v1/auth/logout", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Logout endpoint working!")
            print(f"   Message: {data.get('message')}")
            print(f"   Logout time: {data.get('logout_time')}")
        else:
            print(f"❌ Logout failed: {response.status_code}")
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"❌ Logout error: {str(e)}")
    
    # Step 3: Verify token is invalidated
    print("\n3️⃣ Verifying token invalidation...")
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = session.get(f"{base_url}/api/v1/auth/me", headers=headers)
        
        if response.status_code == 401:
            print("✅ Token properly invalidated after logout!")
        else:
            print(f"⚠️  Token still valid after logout: {response.status_code}")
    except Exception as e:
        print(f"❌ Token verification error: {str(e)}")
    
    print("\n" + "=" * 50)
    print("🎯 Logout Functionality Test Complete!")
    print("=" * 50)
    print("📋 Manual Testing Instructions:")
    print("1. Open http://localhost:3000 in your browser")
    print("2. Login with any demo account")
    print("3. Look for the user icon (👤) in the bottom-right of the sidebar")
    print("4. Click the user icon to open the user menu")
    print("5. Click 'Sign Out' to logout")
    print("6. Verify you're redirected to the login page")
    print("=" * 50)

if __name__ == "__main__":
    test_logout_functionality() 