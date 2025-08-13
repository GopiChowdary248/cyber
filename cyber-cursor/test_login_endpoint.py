#!/usr/bin/env python3
"""
Script to test the login endpoint directly
"""

import requests
import json

def test_login_endpoint():
    """Test the login endpoint directly"""
    
    # Test credentials
    login_data = {
        "username": "admin@cybershield.com",  # Using email as username
        "password": "admin123"
    }
    
    print("🧪 Testing Login Endpoint...")
    print(f"URL: http://localhost:8000/api/v1/auth/login")
    print(f"Credentials: {login_data['username']} / {login_data['password']}")
    print("-" * 50)
    
    try:
        # Test health endpoint first
        print("1. Testing health endpoint...")
        health_response = requests.get("http://localhost:8000/health", timeout=5)
        if health_response.status_code == 200:
            print("✅ Health endpoint working")
            health_data = health_response.json()
            print(f"   Database: {health_data.get('database', 'unknown')}")
        else:
            print(f"❌ Health endpoint failed: {health_response.status_code}")
            return
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend on port 8000")
        print("   The backend might not be running or there's a port conflict")
        return
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return
    
    try:
        # Test login endpoint
        print("\n2. Testing login endpoint...")
        login_response = requests.post(
            "http://localhost:8000/api/v1/auth/login",
            json=login_data,
            timeout=10
        )
        
        print(f"   Status Code: {login_response.status_code}")
        print(f"   Response Headers: {dict(login_response.headers)}")
        
        if login_response.status_code == 200:
            print("✅ Login successful!")
            response_data = login_response.json()
            print(f"   Access Token: {response_data.get('access_token', 'Not found')[:20]}...")
            print(f"   Token Type: {response_data.get('token_type', 'Not found')}")
            print(f"   User ID: {response_data.get('user_id', 'Not found')}")
        else:
            print("❌ Login failed!")
            try:
                error_data = login_response.json()
                print(f"   Error: {error_data}")
            except:
                print(f"   Response Text: {login_response.text}")
                
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to login endpoint")
    except Exception as e:
        print(f"❌ Login test error: {e}")

if __name__ == "__main__":
    test_login_endpoint()
