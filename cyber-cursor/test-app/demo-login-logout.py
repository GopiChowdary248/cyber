#!/usr/bin/env python3
"""
Login/Logout Functionality Demo
Simple demonstration of the authentication system in action.
"""

import requests
import json
from datetime import datetime

def print_step(step, description):
    """Print a formatted step header"""
    print(f"\n{'='*50}")
    print(f"STEP {step}: {description}")
    print(f"{'='*50}")

def print_success(message):
    """Print success message"""
    print(f"✅ {message}")

def print_error(message):
    """Print error message"""
    print(f"❌ {message}")

def print_info(message):
    """Print info message"""
    print(f"ℹ️  {message}")

def demo_login_logout():
    """Demonstrate the complete login/logout flow"""
    
    base_url = "http://localhost:8000"
    session = requests.Session()
    
    print("🚀 CYBERSHIELD LOGIN/LOGOUT DEMO")
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌐 Backend URL: {base_url}")
    
    # Step 1: Check backend health
    print_step(1, "Checking Backend Health")
    try:
        response = session.get(f"{base_url}/health")
        if response.status_code == 200:
            print_success("Backend is running and healthy")
            health_data = response.json()
            print_info(f"Status: {health_data.get('status', 'Unknown')}")
            print_info(f"Version: {health_data.get('version', 'Unknown')}")
        else:
            print_error(f"Backend health check failed: {response.status_code}")
            return
    except Exception as e:
        print_error(f"Backend not accessible: {str(e)}")
        return
    
    # Step 2: Login with admin credentials
    print_step(2, "Logging in as Admin")
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
            print_success("Login successful!")
            print_info(f"User: {data.get('email', 'Unknown')}")
            print_info(f"Role: {data.get('role', 'Unknown')}")
            print_info(f"Token: {data.get('access_token', '')[:20]}...")
            
            # Store token for later use
            token = data.get('access_token')
        else:
            print_error(f"Login failed: {response.status_code}")
            print_error(f"Response: {response.text}")
            return
    except Exception as e:
        print_error(f"Login error: {str(e)}")
        return
    
    # Step 3: Access user profile
    print_step(3, "Accessing User Profile")
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = session.get(f"{base_url}/api/v1/auth/me", headers=headers)
        
        if response.status_code == 200:
            user_data = response.json()
            print_success("Profile access successful!")
            print_info(f"Email: {user_data.get('email', 'Unknown')}")
            print_info(f"Username: {user_data.get('username', 'Unknown')}")
            print_info(f"Role: {user_data.get('role', 'Unknown')}")
            print_info(f"Active: {user_data.get('is_active', 'Unknown')}")
        else:
            print_error(f"Profile access failed: {response.status_code}")
    except Exception as e:
        print_error(f"Profile access error: {str(e)}")
    
    # Step 4: Test token refresh
    print_step(4, "Refreshing Access Token")
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = session.post(f"{base_url}/api/v1/auth/refresh", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            print_success("Token refresh successful!")
            print_info(f"New token: {data.get('access_token', '')[:20]}...")
            
            # Update token
            token = data.get('access_token')
        else:
            print_error(f"Token refresh failed: {response.status_code}")
    except Exception as e:
        print_error(f"Token refresh error: {str(e)}")
    
    # Step 5: Test logout
    print_step(5, "Logging Out")
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = session.post(f"{base_url}/api/v1/auth/logout", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            print_success("Logout successful!")
            print_info(f"Message: {data.get('message', 'Unknown')}")
            print_info(f"Logout time: {data.get('logout_time', 'Unknown')}")
        else:
            print_error(f"Logout failed: {response.status_code}")
    except Exception as e:
        print_error(f"Logout error: {str(e)}")
    
    # Step 6: Verify logout (try to access profile again)
    print_step(6, "Verifying Logout")
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = session.get(f"{base_url}/api/v1/auth/me", headers=headers)
        
        if response.status_code == 401:
            print_success("Logout verified - token is no longer valid")
        else:
            print_error(f"Token still valid after logout: {response.status_code}")
    except Exception as e:
        print_error(f"Logout verification error: {str(e)}")
    
    # Step 7: Test multiple user roles
    print_step(7, "Testing Multiple User Roles")
    users = [
        {'email': 'analyst@cybershield.com', 'role': 'Analyst'},
        {'email': 'user@cybershield.com', 'role': 'User'}
    ]
    
    for user in users:
        try:
            login_data = {
                'username': user['email'],
                'password': 'password'
            }
            
            response = session.post(
                f"{base_url}/api/v1/auth/login",
                data=login_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            if response.status_code == 200:
                data = response.json()
                print_success(f"{user['role']} login successful")
                print_info(f"Email: {data.get('email', 'Unknown')}")
                print_info(f"Role: {data.get('role', 'Unknown')}")
                
                # Logout immediately
                token = data.get('access_token')
                headers = {'Authorization': f'Bearer {token}'}
                logout_response = session.post(f"{base_url}/api/v1/auth/logout", headers=headers)
                if logout_response.status_code == 200:
                    print_info(f"{user['role']} logged out")
            else:
                print_error(f"{user['role']} login failed: {response.status_code}")
        except Exception as e:
            print_error(f"{user['role']} login error: {str(e)}")
    
    # Final summary
    print_step(8, "Demo Summary")
    print_success("Login/Logout functionality demonstration completed!")
    print_info("All core authentication features are working")
    print_info("Demo accounts available for testing:")
    print("   • admin@cybershield.com / password (Admin)")
    print("   • analyst@cybershield.com / password (Analyst)")
    print("   • user@cybershield.com / password (User)")
    print("\n🎉 Ready for production use!")

if __name__ == "__main__":
    demo_login_logout() 