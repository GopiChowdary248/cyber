#!/usr/bin/env python3
"""
Test login endpoint manually
"""

import requests

def test_login():
    url = "http://localhost:8000/api/v1/auth/login"
    
    # Test with form data
    data = {
        "username": "admin@cybershield.com",
        "password": "password"
    }
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        response = requests.post(url, data=data, headers=headers)
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {response.headers}")
        print(f"Response Body: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Token: {result.get('access_token', 'No token')}")
        else:
            print("Login failed")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_login() 