#!/usr/bin/env python3
"""
Comprehensive Login/Logout Functionality Test
Tests the complete authentication flow including login, logout, and session management.
"""

import requests
import json
import time
from datetime import datetime

class LoginLogoutTest:
    def __init__(self):
        self.base_url = "http://localhost:8000"
        self.session = requests.Session()
        self.test_results = []
        
    def log_test(self, test_name, status, details=""):
        """Log test results"""
        result = {
            "test": test_name,
            "status": status,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        print(f"[{status.upper()}] {test_name}: {details}")
        
    def test_backend_health(self):
        """Test if backend is running"""
        try:
            response = self.session.get(f"{self.base_url}/health")
            if response.status_code == 200:
                self.log_test("Backend Health Check", "PASS", "Backend is running")
                return True
            else:
                self.log_test("Backend Health Check", "FAIL", f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Backend Health Check", "FAIL", f"Error: {str(e)}")
            return False
    
    def test_login_with_valid_credentials(self):
        """Test login with valid demo credentials"""
        try:
            # Test admin login
            login_data = {
                'username': 'admin@cybershield.com',
                'password': 'password'
            }
            
            response = self.session.post(
                f"{self.base_url}/api/v1/auth/login",
                data=login_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'access_token' in data:
                    self.log_test("Admin Login", "PASS", f"Token received: {data['access_token'][:20]}...")
                    return data['access_token']
                else:
                    self.log_test("Admin Login", "FAIL", "No access token in response")
                    return None
            else:
                self.log_test("Admin Login", "FAIL", f"Status: {response.status_code}, Response: {response.text}")
                return None
        except Exception as e:
            self.log_test("Admin Login", "FAIL", f"Error: {str(e)}")
            return None
    
    def test_login_with_invalid_credentials(self):
        """Test login with invalid credentials"""
        try:
            login_data = {
                'username': 'invalid@example.com',
                'password': 'wrongpassword'
            }
            
            response = self.session.post(
                f"{self.base_url}/api/v1/auth/login",
                data=login_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            if response.status_code == 401:
                self.log_test("Invalid Login", "PASS", "Correctly rejected invalid credentials")
                return True
            else:
                self.log_test("Invalid Login", "FAIL", f"Expected 401, got {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Invalid Login", "FAIL", f"Error: {str(e)}")
            return False
    
    def test_user_profile_access(self, token):
        """Test accessing user profile with valid token"""
        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = self.session.get(f"{self.base_url}/api/v1/auth/me", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                self.log_test("Profile Access", "PASS", f"User: {data.get('email', 'Unknown')}")
                return True
            else:
                self.log_test("Profile Access", "FAIL", f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Profile Access", "FAIL", f"Error: {str(e)}")
            return False
    
    def test_logout(self, token):
        """Test logout functionality"""
        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = self.session.post(f"{self.base_url}/api/v1/auth/logout", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                self.log_test("Logout", "PASS", f"Logout successful: {data.get('message', '')}")
                return True
            else:
                self.log_test("Logout", "FAIL", f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Logout", "FAIL", f"Error: {str(e)}")
            return False
    
    def test_logout_all_sessions(self, token):
        """Test logout from all sessions"""
        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = self.session.post(f"{self.base_url}/api/v1/auth/logout-all", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                self.log_test("Logout All Sessions", "PASS", f"Logout all successful: {data.get('message', '')}")
                return True
            else:
                self.log_test("Logout All Sessions", "FAIL", f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Logout All Sessions", "FAIL", f"Error: {str(e)}")
            return False
    
    def test_token_refresh(self, token):
        """Test token refresh functionality"""
        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = self.session.post(f"{self.base_url}/api/v1/auth/refresh", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if 'access_token' in data:
                    self.log_test("Token Refresh", "PASS", "New token received")
                    return data['access_token']
                else:
                    self.log_test("Token Refresh", "FAIL", "No new token in response")
                    return None
            else:
                self.log_test("Token Refresh", "FAIL", f"Status: {response.status_code}")
                return None
        except Exception as e:
            self.log_test("Token Refresh", "FAIL", f"Error: {str(e)}")
            return None
    
    def test_multiple_user_logins(self):
        """Test login with different user roles"""
        users = [
            {'email': 'admin@cybershield.com', 'password': 'password', 'role': 'admin'},
            {'email': 'analyst@cybershield.com', 'password': 'password', 'role': 'analyst'},
            {'email': 'user@cybershield.com', 'password': 'password', 'role': 'user'}
        ]
        
        for user in users:
            try:
                login_data = {
                    'username': user['email'],
                    'password': user['password']
                }
                
                response = self.session.post(
                    f"{self.base_url}/api/v1/auth/login",
                    data=login_data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('role') == user['role']:
                        self.log_test(f"{user['role'].title()} Login", "PASS", f"Role: {data.get('role')}")
                    else:
                        self.log_test(f"{user['role'].title()} Login", "FAIL", f"Expected role {user['role']}, got {data.get('role')}")
                else:
                    self.log_test(f"{user['role'].title()} Login", "FAIL", f"Status: {response.status_code}")
            except Exception as e:
                self.log_test(f"{user['role'].title()} Login", "FAIL", f"Error: {str(e)}")
    
    def test_session_management(self):
        """Test session management and token validation"""
        try:
            # First login
            token = self.test_login_with_valid_credentials()
            if not token:
                return False
            
            # Test profile access
            if not self.test_user_profile_access(token):
                return False
            
            # Test token refresh
            new_token = self.test_token_refresh(token)
            if not new_token:
                return False
            
            # Test profile access with new token
            if not self.test_user_profile_access(new_token):
                return False
            
            # Test logout
            if not self.test_logout(new_token):
                return False
            
            # Test that token is no longer valid
            headers = {'Authorization': f'Bearer {new_token}'}
            response = self.session.get(f"{self.base_url}/api/v1/auth/me", headers=headers)
            
            if response.status_code == 401:
                self.log_test("Session Invalidation", "PASS", "Token properly invalidated after logout")
            else:
                self.log_test("Session Invalidation", "FAIL", f"Token still valid after logout: {response.status_code}")
            
            return True
        except Exception as e:
            self.log_test("Session Management", "FAIL", f"Error: {str(e)}")
            return False
    
    def run_all_tests(self):
        """Run all authentication tests"""
        print("=" * 60)
        print("LOGIN/LOGOUT FUNCTIONALITY TEST")
        print("=" * 60)
        print(f"Testing against: {self.base_url}")
        print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Test backend health
        if not self.test_backend_health():
            print("\nBackend is not available. Please start the application first.")
            return
        
        # Test invalid login
        self.test_login_with_invalid_credentials()
        
        # Test multiple user logins
        self.test_multiple_user_logins()
        
        # Test complete session management
        self.test_session_management()
        
        # Test logout all sessions
        token = self.test_login_with_valid_credentials()
        if token:
            self.test_logout_all_sessions(token)
        
        # Print summary
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        
        passed = sum(1 for result in self.test_results if result['status'] == 'PASS')
        failed = sum(1 for result in self.test_results if result['status'] == 'FAIL')
        total = len(self.test_results)
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {(passed/total)*100:.1f}%" if total > 0 else "N/A")
        
        if failed > 0:
            print("\nFailed Tests:")
            for result in self.test_results:
                if result['status'] == 'FAIL':
                    print(f"  - {result['test']}: {result['details']}")
        
        # Save results
        with open('login-logout-test-results.json', 'w') as f:
            json.dump({
                'summary': {
                    'total': total,
                    'passed': passed,
                    'failed': failed,
                    'success_rate': (passed/total)*100 if total > 0 else 0
                },
                'results': self.test_results
            }, f, indent=2)
        
        print(f"\nDetailed results saved to: login-logout-test-results.json")

if __name__ == "__main__":
    tester = LoginLogoutTest()
    tester.run_all_tests() 