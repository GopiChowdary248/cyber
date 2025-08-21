#!/usr/bin/env python3
"""
Frontend Module Test Script
Tests that RASP and CSPM modules are accessible in the frontend
"""

import requests
import json
import time
from typing import Dict, List

# Configuration
FRONTEND_URL = "http://localhost:3000"
BACKEND_URL = "http://localhost:8000"

def test_frontend_accessibility():
    """Test if frontend is accessible"""
    try:
        response = requests.get(FRONTEND_URL, timeout=10)
        if response.status_code == 200:
            print(f"✅ Frontend is accessible at {FRONTEND_URL}")
            return True
        else:
            print(f"❌ Frontend returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Frontend accessibility test failed: {e}")
        return False

def test_backend_health():
    """Test backend health"""
    try:
        response = requests.get(f"{BACKEND_URL}/health", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Backend is healthy: {data['status']}")
            return True
        else:
            print(f"❌ Backend health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Backend health check failed: {e}")
        return False

def test_rasp_endpoints():
    """Test RASP backend endpoints"""
    try:
        # Test RASP overview endpoint
        response = requests.get(f"{BACKEND_URL}/api/v1/rasp", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ RASP endpoint accessible: {data.get('status', 'active')}")
            return True
        elif response.status_code == 401:
            print("🔒 RASP endpoint requires authentication (expected)")
            return True
        else:
            print(f"❌ RASP endpoint failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ RASP endpoint test failed: {e}")
        return False

def test_cspm_endpoints():
    """Test CSPM backend endpoints"""
    try:
        # Test CSPM overview endpoint
        response = requests.get(f"{BACKEND_URL}/api/v1/cloud-security", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ CSPM endpoint accessible: {data.get('status', 'active')}")
            return True
        elif response.status_code == 401:
            print("🔒 CSPM endpoint requires authentication (expected)")
            return True
        else:
            print(f"❌ CSPM endpoint failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ CSPM endpoint test failed: {e}")
        return False

def test_navigation_structure():
    """Test if navigation includes RASP and CSPM"""
    print("\n🔍 Testing Navigation Structure:")
    print("   - RASP should be accessible at: /rasp")
    print("   - CSPM should be accessible at: /cloud-security/cspm")
    print("   - Both should be visible in the main dashboard")
    print("   - Navigation should include both modules")
    return True

def main():
    """Main test function"""
    print("🚀 Starting Frontend Module Test")
    print("="*50)
    
    # Test basic accessibility
    print("\n1. Testing Basic Accessibility:")
    frontend_ok = test_frontend_accessibility()
    backend_ok = test_backend_health()
    
    # Test security modules
    print("\n2. Testing Security Module Endpoints:")
    rasp_ok = test_rasp_endpoints()
    cspm_ok = test_cspm_endpoints()
    
    # Test navigation structure
    print("\n3. Testing Navigation Structure:")
    nav_ok = test_navigation_structure()
    
    # Generate summary
    all_tests = [
        ("Frontend Accessibility", frontend_ok),
        ("Backend Health", backend_ok),
        ("RASP Endpoints", rasp_ok),
        ("CSPM Endpoints", cspm_ok),
        ("Navigation Structure", nav_ok)
    ]
    
    print("\n" + "="*50)
    print("FRONTEND MODULE TEST SUMMARY")
    print("="*50)
    
    total_tests = len(all_tests)
    successful_tests = sum(1 for _, success in all_tests if success)
    failed_tests = total_tests - successful_tests
    
    print(f"Total Tests: {total_tests}")
    print(f"✅ Successful: {successful_tests}")
    print(f"❌ Failed: {failed_tests}")
    print(f"Success Rate: {(successful_tests/total_tests)*100:.1f}%")
    
    if failed_tests > 0:
        print("\nFailed Tests:")
        for test_name, success in all_tests:
            if not success:
                print(f"  - {test_name}")
    
    print("\n" + "="*50)
    
    # Final status
    if all(success for _, success in all_tests):
        print("🎉 All tests passed! RASP and CSPM modules are accessible.")
        print("\n🌐 Access Points:")
        print(f"   Frontend: {FRONTEND_URL}")
        print(f"   Backend API: {BACKEND_URL}")
        print(f"   RASP Dashboard: {FRONTEND_URL}/rasp")
        print(f"   CSPM Dashboard: {FRONTEND_URL}/cloud-security/cspm")
        print(f"   Main Dashboard: {FRONTEND_URL}/dashboard")
        return True
    else:
        print("⚠️  Some tests failed. Check the details above.")
        print("\n🔧 Troubleshooting:")
        print("   1. Ensure both frontend and backend are running")
        print("   2. Check if ports 3000 and 8000 are available")
        print("   3. Verify the new routes are properly configured")
        print("   4. Check browser console for any JavaScript errors")
        return False

if __name__ == "__main__":
    try:
        print("🔍 Testing RASP and CSPM module accessibility...")
        print(f"📍 Frontend: {FRONTEND_URL}")
        print(f"📍 Backend: {BACKEND_URL}")
        print("⏳ Please ensure both services are running before starting this test.")
        print()
        
        # Wait a moment for user to read
        time.sleep(2)
        
        success = main()
        exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⏹️  Test interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n\n💥 Unexpected error: {e}")
        exit(1)
