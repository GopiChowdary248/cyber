#!/usr/bin/env python3
"""
Test RASP Routing - Verify that RASP navigation works correctly
"""

import requests
import json

def test_rasp_routing():
    """Test RASP routing and navigation"""
    
    print("🔍 Testing RASP Routing...")
    print("=" * 40)
    
    # Test backend health
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            print("✅ Backend is running")
        else:
            print(f"❌ Backend health check failed: {response.status_code}")
            return
    except Exception as e:
        print(f"❌ Cannot connect to backend: {e}")
        return
    
    # Test RASP endpoints
    print("\n📊 Testing RASP API Endpoints:")
    
    # Test RASP projects endpoint
    try:
        response = requests.get("http://localhost:8000/api/v1/rasp/projects?skip=0&limit=5", timeout=5)
        if response.status_code == 200:
            print("✅ RASP projects endpoint working")
        else:
            print(f"❌ RASP projects endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ RASP projects endpoint error: {e}")
    
    # Test RASP dashboard endpoint
    try:
        response = requests.get("http://localhost:8000/api/v1/rasp/dashboard/overview", timeout=5)
        if response.status_code == 200:
            print("✅ RASP dashboard endpoint working")
        else:
            print(f"❌ RASP dashboard endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ RASP dashboard endpoint error: {e}")
    
    print("\n🎯 RASP Routing Test Complete!")
    print("💡 If all endpoints are working, the RASP page should load correctly")
    print("💡 Check the browser console for any remaining errors")

if __name__ == "__main__":
    test_rasp_routing()
