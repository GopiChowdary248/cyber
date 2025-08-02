#!/usr/bin/env python3
"""
Quick Application Test
Comprehensive test of the CyberShield application functionality.
"""

import requests
import json
from datetime import datetime

def test_application():
    """Test the complete application functionality"""
    
    frontend_url = "http://localhost:3000"
    backend_url = "http://localhost:8000"
    
    print("🚀 CyberShield Application Test")
    print("=" * 50)
    print(f"🌐 Frontend: {frontend_url}")
    print(f"🌐 Backend: {backend_url}")
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    
    results = {
        "backend_health": False,
        "authentication": False,
        "login_functionality": False,
        "logout_functionality": False,
        "user_management": False,
        "frontend_access": False,
        "navigation_visibility": False
    }
    
    # Test 1: Backend Health
    print("1️⃣ Testing Backend Health...")
    try:
        response = requests.get(f"{backend_url}/api/v1/health", timeout=10)
        if response.status_code == 200:
            print("✅ Backend is healthy")
            results["backend_health"] = True
        else:
            print(f"❌ Backend health check failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Backend health check error: {str(e)}")
    
    # Test 2: Frontend Access
    print("\n2️⃣ Testing Frontend Access...")
    try:
        response = requests.get(frontend_url, timeout=10)
        if response.status_code == 200:
            print("✅ Frontend is accessible")
            results["frontend_access"] = True
        else:
            print(f"❌ Frontend access failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Frontend access error: {str(e)}")
    
    # Test 3: Authentication System
    print("\n3️⃣ Testing Authentication System...")
    try:
        # Test login
        login_data = {
            'username': 'admin@cybershield.com',
            'password': 'password'
        }
        
        response = requests.post(
            f"{backend_url}/api/v1/auth/login",
            data=login_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        if response.status_code == 200:
            data = response.json()
            token = data.get('access_token')
            print("✅ Login successful")
            results["login_functionality"] = True
            results["authentication"] = True
            
            # Test user profile
            headers = {'Authorization': f'Bearer {token}'}
            profile_response = requests.get(f"{backend_url}/api/v1/users/me", headers=headers)
            
            if profile_response.status_code == 200:
                profile_data = profile_response.json()
                print(f"✅ User profile: {profile_data.get('email')} ({profile_data.get('role')})")
                results["user_management"] = True
            
            # Test logout
            logout_response = requests.post(f"{backend_url}/api/v1/auth/logout", headers=headers)
            if logout_response.status_code == 200:
                print("✅ Logout successful")
                results["logout_functionality"] = True
                
        else:
            print(f"❌ Login failed: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Authentication test error: {str(e)}")
    
    # Test 4: Navigation Visibility (Basic Check)
    print("\n4️⃣ Testing Navigation Visibility...")
    try:
        # Check login page
        response = requests.get(f"{frontend_url}/login", timeout=10)
        if response.status_code == 200:
            content = response.text.lower()
            has_navigation = any([
                'cyber cursor' in content,
                'security platform' in content,
                'dashboard' in content
            ])
            
            if has_navigation:
                print("⚠️  Navigation still shows on login page (needs fix)")
                results["navigation_visibility"] = False
            else:
                print("✅ Navigation properly hidden on login page")
                results["navigation_visibility"] = True
        else:
            print(f"❌ Login page access failed: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Navigation test error: {str(e)}")
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 APPLICATION TEST SUMMARY")
    print("=" * 50)
    
    passed = sum(results.values())
    total = len(results)
    success_rate = (passed / total) * 100
    
    print(f"Total Tests: {total}")
    print(f"Passed: {passed} ✅")
    print(f"Failed: {total - passed} ❌")
    print(f"Success Rate: {success_rate:.1f}%")
    
    print("\n📋 Detailed Results:")
    for test, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {test.replace('_', ' ').title()}: {status}")
    
    print("\n🎯 Overall Status:")
    if success_rate >= 90:
        print("🟢 EXCELLENT - Application is working well!")
    elif success_rate >= 70:
        print("🟡 GOOD - Most functionality working, minor issues")
    elif success_rate >= 50:
        print("🟠 FAIR - Some functionality working, needs attention")
    else:
        print("🔴 POOR - Major issues need to be addressed")
    
    print("\n📝 Recommendations:")
    if not results["navigation_visibility"]:
        print("  - Fix navigation visibility on login page")
    if not results["backend_health"]:
        print("  - Check backend service status")
    if not results["authentication"]:
        print("  - Verify authentication system")
    
    print("\n🔗 Access URLs:")
    print(f"  Frontend: {frontend_url}")
    print(f"  Backend API: {backend_url}/docs")
    print(f"  Health Check: {backend_url}/api/v1/health")
    
    print("=" * 50)
    
    return results

if __name__ == "__main__":
    test_application() 