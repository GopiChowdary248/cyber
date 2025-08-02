#!/usr/bin/env python3
"""
Test Navigation Visibility
Verifies that the navigation sidebar is hidden before login and only shows after authentication.
"""

import requests
import json
from datetime import datetime

def test_navigation_visibility():
    """Test that navigation is properly hidden/shown based on authentication"""
    
    frontend_url = "http://localhost:3000"
    backend_url = "http://localhost:8000"
    
    print("🔍 Testing Navigation Visibility")
    print(f"🌐 Frontend URL: {frontend_url}")
    print(f"🌐 Backend URL: {backend_url}")
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)
    
    # Step 1: Check login page (should not have navigation)
    print("1️⃣ Checking login page...")
    try:
        response = requests.get(f"{frontend_url}/login", timeout=10)
        
        if response.status_code == 200:
            content = response.text.lower()
            
            # Check for navigation elements
            has_navigation = any([
                'enhancednavigation' in content,
                'cyber cursor' in content,
                'security platform' in content,
                'dashboard' in content,
                'application security' in content
            ])
            
            if not has_navigation:
                print("✅ Login page correctly shows NO navigation sidebar")
            else:
                print("❌ Login page incorrectly shows navigation sidebar")
                
        else:
            print(f"❌ Login page not accessible: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error checking login page: {str(e)}")
    
    # Step 2: Test login and check navigation appears
    print("\n2️⃣ Testing login and navigation appearance...")
    try:
        # Login
        login_data = {
            'username': 'admin@cybershield.com',
            'password': 'password'
        }
        
        login_response = requests.post(
            f"{backend_url}/api/v1/auth/login",
            data=login_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        if login_response.status_code == 200:
            data = login_response.json()
            token = data.get('access_token')
            print("✅ Login successful")
            
            # Check dashboard page (should have navigation)
            dashboard_response = requests.get(f"{frontend_url}/dashboard", timeout=10)
            
            if dashboard_response.status_code == 200:
                content = dashboard_response.text.lower()
                
                # Check for navigation elements
                has_navigation = any([
                    'cyber cursor' in content,
                    'security platform' in content,
                    'dashboard' in content,
                    'application security' in content,
                    'cloud security' in content
                ])
                
                if has_navigation:
                    print("✅ Dashboard page correctly shows navigation sidebar")
                else:
                    print("❌ Dashboard page incorrectly shows NO navigation sidebar")
            else:
                print(f"❌ Dashboard page not accessible: {dashboard_response.status_code}")
                
        else:
            print(f"❌ Login failed: {login_response.status_code}")
            
    except Exception as e:
        print(f"❌ Error testing login: {str(e)}")
    
    print("\n" + "=" * 50)
    print("🎯 Navigation Visibility Test Complete!")
    print("=" * 50)
    print("📋 Manual Testing Instructions:")
    print("1. Open http://localhost:3000/login")
    print("2. Verify NO sidebar navigation is visible")
    print("3. Login with any demo account")
    print("4. Verify sidebar navigation appears after login")
    print("5. Logout and verify sidebar disappears")
    print("=" * 50)

if __name__ == "__main__":
    test_navigation_visibility() 