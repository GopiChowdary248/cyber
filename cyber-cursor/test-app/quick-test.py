#!/usr/bin/env python3
"""
Quick End-to-End Test for CyberShield Platform
Simplified version for faster testing
"""

import requests
import json
import time
from datetime import datetime

class QuickE2ETest:
    def __init__(self):
        self.base_url = "http://localhost:3000"
        self.api_url = "http://localhost:8000"
        self.test_results = []
        self.auth_token = None
        
    def log_test(self, test_name, status, details=""):
        """Log test result"""
        result = {
            "test_name": test_name,
            "status": status,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        
        status_emoji = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️"}
        emoji = status_emoji.get(status, "ℹ️")
        print(f"{emoji} {test_name}: {details}")
    
    def test_application_accessibility(self):
        """Test if the application is accessible"""
        print("\n🔍 Testing Application Accessibility...")
        
        # Test frontend
        try:
            response = requests.get(self.base_url, timeout=10)
            if response.status_code == 200:
                self.log_test("Frontend Accessibility", "PASS", "Frontend is accessible")
            else:
                self.log_test("Frontend Accessibility", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Frontend Accessibility", "FAIL", f"Error: {str(e)}")
        
        # Test backend
        try:
            response = requests.get(f"{self.api_url}/health", timeout=10)
            if response.status_code == 200:
                self.log_test("Backend Health", "PASS", "Backend is healthy")
            else:
                self.log_test("Backend Health", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Backend Health", "FAIL", f"Error: {str(e)}")
        
        # Test API docs
        try:
            response = requests.get(f"{self.api_url}/docs", timeout=10)
            if response.status_code == 200:
                self.log_test("API Documentation", "PASS", "API docs accessible")
            else:
                self.log_test("API Documentation", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("API Documentation", "FAIL", f"Error: {str(e)}")
    
    def test_authentication(self):
        """Test authentication with demo accounts"""
        print("\n🔐 Testing Authentication...")
        
        # Test admin login
        try:
            response = requests.post(
                f"{self.api_url}/api/v1/auth/login",
                data={
                    "username": "admin@cybershield.com",
                    "password": "password"
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                token = data.get("access_token")
                if token:
                    self.auth_token = token
                    self.log_test("Admin Authentication", "PASS", "Admin login successful")
                else:
                    self.log_test("Admin Authentication", "FAIL", "No token received")
            else:
                self.log_test("Admin Authentication", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Admin Authentication", "FAIL", f"Error: {str(e)}")
    
    def test_core_features(self):
        """Test core application features"""
        print("\n⚙️ Testing Core Features...")
        
        if not self.auth_token:
            self.log_test("Core Features", "FAIL", "No authentication token available")
            return
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test dashboard
        try:
            response = requests.get(f"{self.api_url}/api/v1/dashboard/overview", headers=headers, timeout=10)
            if response.status_code == 200:
                self.log_test("Dashboard API", "PASS", "Dashboard data accessible")
            else:
                self.log_test("Dashboard API", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Dashboard API", "FAIL", f"Error: {str(e)}")
        
        # Test security summary
        try:
            response = requests.get(f"{self.api_url}/api/v1/security/summary", headers=headers, timeout=10)
            if response.status_code == 200:
                self.log_test("Security Summary", "PASS", "Security data accessible")
            else:
                self.log_test("Security Summary", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Security Summary", "FAIL", f"Error: {str(e)}")
        
        # Test user data
        try:
            response = requests.get(f"{self.api_url}/api/v1/users", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("User Management", "PASS", f"Found {len(data)} users")
            else:
                self.log_test("User Management", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("User Management", "FAIL", f"Error: {str(e)}")
    
    def test_security_modules(self):
        """Test security modules"""
        print("\n🛡️ Testing Security Modules...")
        
        if not self.auth_token:
            self.log_test("Security Modules", "FAIL", "No authentication token available")
            return
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test SAST
        try:
            response = requests.get(f"{self.api_url}/api/v1/security/sast/results", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("SAST Module", "PASS", f"Found {len(data)} vulnerabilities")
            else:
                self.log_test("SAST Module", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("SAST Module", "FAIL", f"Error: {str(e)}")
        
        # Test DAST
        try:
            response = requests.get(f"{self.api_url}/api/v1/security/dast/results", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("DAST Module", "PASS", f"Found {len(data)} vulnerabilities")
            else:
                self.log_test("DAST Module", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("DAST Module", "FAIL", f"Error: {str(e)}")
        
        # Test RASP
        try:
            response = requests.get(f"{self.api_url}/api/v1/security/rasp/logs", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("RASP Module", "PASS", f"Found {len(data)} incidents")
            else:
                self.log_test("RASP Module", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("RASP Module", "FAIL", f"Error: {str(e)}")
    
    def generate_summary(self):
        """Generate test summary"""
        print("\n📊 Test Summary:")
        print("=" * 40)
        
        total_tests = len(self.test_results)
        passed_tests = len([t for t in self.test_results if t["status"] == "PASS"])
        failed_tests = len([t for t in self.test_results if t["status"] == "FAIL"])
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Success Rate: {success_rate:.1f}%")
        
        if success_rate >= 90:
            print("🎉 Overall Status: PASS")
            return True
        else:
            print("❌ Overall Status: FAIL")
            return False
    
    def run_quick_test(self):
        """Run all quick tests"""
        print("🚀 Quick End-to-End Test for CyberShield")
        print("=" * 50)
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)
        
        self.test_application_accessibility()
        self.test_authentication()
        self.test_core_features()
        self.test_security_modules()
        
        success = self.generate_summary()
        
        print("\n" + "=" * 50)
        print("🎯 Quick Test Complete!")
        print("=" * 50)
        
        return success

def main():
    """Main function"""
    print("🛡️ CyberShield Quick End-to-End Test")
    print("=" * 50)
    
    # Check if application is running
    try:
        response = requests.get("http://localhost:3000", timeout=5)
        print("✅ Application appears to be running")
    except:
        print("❌ Application not accessible. Please start the application first:")
        print("   docker-compose up -d")
        return
    
    # Run quick test
    tester = QuickE2ETest()
    success = tester.run_quick_test()
    
    if success:
        print("✅ Quick test passed! Application is working correctly.")
    else:
        print("❌ Quick test failed. Please check the application.")

if __name__ == "__main__":
    main() 