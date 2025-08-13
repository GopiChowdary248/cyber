#!/usr/bin/env python3
"""
Script to test the login endpoint with PostgreSQL database
"""

import requests
import json

def test_login_endpoint():
    """Test the login endpoint with PostgreSQL database"""
    
    # Test credentials
    login_data = {
        "username": "admin@cybershield.com",  # Using email as username
        "password": "admin123"
    }
    
    print("🧪 Testing Login Endpoint with PostgreSQL...")
    print(f"URL: http://localhost:8000/api/v1/auth/login")
    print(f"Credentials: {login_data['username']} / {login_data['password']}")
    print("-" * 60)
    
    try:
        # Test health endpoint first
        print("1. Testing health endpoint...")
        health_response = requests.get("http://localhost:8000/health", timeout=5)
        if health_response.status_code == 200:
            print("✅ Health endpoint working")
            health_data = health_response.json()
            print(f"   Database: {health_data.get('database', 'unknown')}")
            print(f"   Status: {health_data.get('status', 'unknown')}")
        else:
            print(f"❌ Health endpoint failed: {health_response.status_code}")
            return
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend on port 8000")
        print("   The backend might not be running")
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
            print(f"   User Role: {response_data.get('user', {}).get('role', 'Not found')}")
            
            # Test protected endpoint with token
            print("\n3. Testing protected endpoint with token...")
            headers = {"Authorization": f"Bearer {response_data.get('access_token')}"}
            protected_response = requests.get(
                "http://localhost:8000/api/v1/users/me",
                headers=headers,
                timeout=10
            )
            
            if protected_response.status_code == 200:
                print("✅ Protected endpoint working!")
                user_data = protected_response.json()
                print(f"   User Email: {user_data.get('email', 'Not found')}")
                print(f"   User Role: {user_data.get('role', 'Not found')}")
            else:
                print(f"❌ Protected endpoint failed: {protected_response.status_code}")
                print(f"   Response: {protected_response.text}")
                
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
