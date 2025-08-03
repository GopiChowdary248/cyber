#!/usr/bin/env python3
"""
Simple test script to verify auth endpoint
"""

import requests
import json

def test_auth_endpoint():
    """Test the auth endpoint"""
    base_url = "http://localhost:8000"
    
    # Test 1: Check if server is running
    try:
        response = requests.get(f"{base_url}/health")
        print(f"✅ Health check: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return
    
    # Test 2: Check available endpoints
    try:
        response = requests.get(f"{base_url}/openapi.json")
        openapi_data = response.json()
        paths = openapi_data.get("paths", {})
        print(f"\n📋 Available endpoints:")
        for path in paths.keys():
            print(f"  - {path}")
    except Exception as e:
        print(f"❌ OpenAPI check failed: {e}")
    
    # Test 3: Test auth login endpoint
    try:
        login_data = {
            "username": "admin@cybershield.com",
            "password": "password"
        }
        
        response = requests.post(
            f"{base_url}/api/v1/auth/login",
            data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        print(f"\n🔐 Auth login test:")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            print("✅ Auth login successful!")
        else:
            print("❌ Auth login failed!")
            
    except Exception as e:
        print(f"❌ Auth login test failed: {e}")

if __name__ == "__main__":
    test_auth_endpoint() 