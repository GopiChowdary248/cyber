#!/usr/bin/env python3
"""
Fixed End-to-End Test for CyberShield Application
This script addresses the authentication and endpoint routing issues found in the codebase.
"""

import requests
import json
import time
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional

class FixedE2ETest:
    def __init__(self):
        self.base_url = "http://localhost:8000"
        self.api_url = f"{self.base_url}/api/v1"
        self.frontend_url = "http://localhost:3000"
        self.test_results = []
        self.access_token = None
        
    def log_test(self, test_name: str, status: str, message: str, details: Optional[Dict] = None):
        """Log test result"""
        result = {
            "test": test_name,
            "status": status,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "details": details or {}
        }
        self.test_results.append(result)
        
        # Print result
        status_icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
        print(f"{status_icon} {test_name}: {message}")
        if details:
            print(f"   Details: {json.dumps(details, indent=2)}")

    def test_docker_containers(self) -> bool:
        """Test if Docker containers are running"""
        try:
            result = subprocess.run(
                ["docker-compose", "ps", "--format", "json"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode != 0:
                self.log_test("Docker Containers", "FAIL", "Failed to check Docker containers")
                return False
            
            containers = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    containers.append(json.loads(line))
            
            running_containers = [c for c in containers if c.get('State') == 'running']
            
            if len(running_containers) >= 5:  # Expect at least 5 services
                self.log_test("Docker Containers", "PASS", f"Found {len(running_containers)} running containers")
                return True
            else:
                self.log_test("Docker Containers", "FAIL", f"Only {len(running_containers)} containers running")
                return False
                
        except Exception as e:
            self.log_test("Docker Containers", "FAIL", f"Error checking containers: {str(e)}")
            return False

    def test_backend_health(self) -> bool:
        """Test backend health endpoint"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("Backend Health", "PASS", "Backend is healthy", data)
                return True
            else:
                self.log_test("Backend Health", "FAIL", f"Backend health check failed: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Backend Health", "FAIL", f"Backend health check error: {str(e)}")
            return False

    def test_frontend_accessibility(self) -> bool:
        """Test frontend accessibility"""
        try:
            response = requests.get(self.frontend_url, timeout=10)
            if response.status_code == 200:
                self.log_test("Frontend Accessibility", "PASS", "Frontend is accessible")
                return True
            else:
                self.log_test("Frontend Accessibility", "FAIL", f"Frontend not accessible: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Frontend Accessibility", "FAIL", f"Frontend accessibility error: {str(e)}")
            return False

    def test_authentication(self) -> bool:
        """Test authentication with correct endpoint and format"""
        try:
            # Test login with form data (OAuth2 format)
            response = requests.post(
                f"{self.api_url}/auth/login",
                data={
                    "username": "admin@cybershield.com",
                    "password": "password"
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get("access_token")
                self.log_test("Authentication", "PASS", "Login successful", {
                    "user_id": data.get("user_id"),
                    "email": data.get("email"),
                    "role": data.get("role")
                })
                return True
            else:
                self.log_test("Authentication", "FAIL", f"Login failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.log_test("Authentication", "FAIL", f"Authentication error: {str(e)}")
            return False

    def test_user_endpoints(self) -> bool:
        """Test user-related endpoints"""
        if not self.access_token:
            self.log_test("User Endpoints", "FAIL", "No access token available")
            return False
            
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            # Test /me endpoint
            response = requests.get(f"{self.api_url}/auth/me", headers=headers, timeout=10)
            if response.status_code == 200:
                user_data = response.json()
                self.log_test("User Profile", "PASS", "User profile retrieved", user_data)
            else:
                self.log_test("User Profile", "FAIL", f"Failed to get user profile: {response.status_code}")
                return False
            
            # Test users list (admin only)
            response = requests.get(f"{self.api_url}/users", headers=headers, timeout=10)
            if response.status_code == 200:
                users_data = response.json()
                self.log_test("Users List", "PASS", f"Retrieved {len(users_data)} users")
            else:
                self.log_test("Users List", "FAIL", f"Failed to get users: {response.status_code}")
            
            return True
            
        except Exception as e:
            self.log_test("User Endpoints", "FAIL", f"User endpoints error: {str(e)}")
            return False

    def test_security_endpoints(self) -> bool:
        """Test security module endpoints with correct paths"""
        if not self.access_token:
            self.log_test("Security Endpoints", "FAIL", "No access token available")
            return False
            
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            # Test security summary (correct path based on API router)
            response = requests.get(f"{self.api_url}/security/audit/report", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("Security Summary", "PASS", "Security summary retrieved", data)
            else:
                self.log_test("Security Summary", "FAIL", f"Security summary failed: {response.status_code}")
            
            # Test SAST endpoints (correct path)
            response = requests.get(f"{self.api_url}/sast/summary", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("SAST Summary", "PASS", "SAST summary retrieved", data)
            else:
                self.log_test("SAST Summary", "FAIL", f"SAST summary failed: {response.status_code}")
            
            # Test SAST projects
            response = requests.get(f"{self.api_url}/sast/projects", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("SAST Projects", "PASS", f"Retrieved {len(data)} SAST projects")
            else:
                self.log_test("SAST Projects", "FAIL", f"SAST projects failed: {response.status_code}")
            
            return True
            
        except Exception as e:
            self.log_test("Security Endpoints", "FAIL", f"Security endpoints error: {str(e)}")
            return False

    def test_dashboard_endpoints(self) -> bool:
        """Test dashboard endpoints"""
        if not self.access_token:
            self.log_test("Dashboard Endpoints", "FAIL", "No access token available")
            return False
            
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            # Test dashboard overview
            response = requests.get(f"{self.api_url}/dashboard/overview", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("Dashboard Overview", "PASS", "Dashboard overview retrieved", data)
            else:
                self.log_test("Dashboard Overview", "FAIL", f"Dashboard overview failed: {response.status_code}")
            
            # Test analytics overview
            response = requests.get(f"{self.api_url}/analytics/overview", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("Analytics Overview", "PASS", "Analytics overview retrieved", data)
            else:
                self.log_test("Analytics Overview", "FAIL", f"Analytics overview failed: {response.status_code}")
            
            return True
            
        except Exception as e:
            self.log_test("Dashboard Endpoints", "FAIL", f"Dashboard endpoints error: {str(e)}")
            return False

    def test_incidents_endpoints(self) -> bool:
        """Test incidents endpoints"""
        if not self.access_token:
            self.log_test("Incidents Endpoints", "FAIL", "No access token available")
            return False
            
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            # Test incidents list
            response = requests.get(f"{self.api_url}/incidents", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("Incidents List", "PASS", f"Retrieved {len(data)} incidents")
            else:
                self.log_test("Incidents List", "FAIL", f"Incidents list failed: {response.status_code}")
            
            return True
            
        except Exception as e:
            self.log_test("Incidents Endpoints", "FAIL", f"Incidents endpoints error: {str(e)}")
            return False

    def test_cloud_security_endpoints(self) -> bool:
        """Test cloud security endpoints"""
        if not self.access_token:
            self.log_test("Cloud Security Endpoints", "FAIL", "No access token available")
            return False
            
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            # Test cloud security overview
            response = requests.get(f"{self.api_url}/cloud-security/overview", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("Cloud Security Overview", "PASS", "Cloud security overview retrieved", data)
            else:
                self.log_test("Cloud Security Overview", "FAIL", f"Cloud security overview failed: {response.status_code}")
            
            return True
            
        except Exception as e:
            self.log_test("Cloud Security Endpoints", "FAIL", f"Cloud security endpoints error: {str(e)}")
            return False

    def test_api_documentation(self) -> bool:
        """Test API documentation accessibility"""
        try:
            # Test OpenAPI docs
            response = requests.get(f"{self.base_url}/docs", timeout=10)
            if response.status_code == 200:
                self.log_test("API Documentation", "PASS", "API documentation accessible")
                return True
            else:
                self.log_test("API Documentation", "FAIL", f"API documentation failed: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("API Documentation", "FAIL", f"API documentation error: {str(e)}")
            return False

    def run_all_tests(self) -> Dict[str, Any]:
        """Run all end-to-end tests"""
        print("🚀 Starting Fixed End-to-End Tests for CyberShield Application")
        print("=" * 60)
        
        # Infrastructure tests
        self.test_docker_containers()
        self.test_backend_health()
        self.test_frontend_accessibility()
        self.test_api_documentation()
        
        # Authentication tests
        auth_success = self.test_authentication()
        
        # Feature tests (only if authentication succeeds)
        if auth_success:
            self.test_user_endpoints()
            self.test_security_endpoints()
            self.test_dashboard_endpoints()
            self.test_incidents_endpoints()
            self.test_cloud_security_endpoints()
        else:
            print("⚠️  Skipping authenticated endpoints due to authentication failure")
        
        # Generate summary
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r["status"] == "PASS"])
        failed_tests = len([r for r in self.test_results if r["status"] == "FAIL"])
        warning_tests = len([r for r in self.test_results if r["status"] == "WARN"])
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        summary = {
            "timestamp": datetime.now().isoformat(),
            "total_tests": total_tests,
            "passed": passed_tests,
            "failed": failed_tests,
            "warnings": warning_tests,
            "success_rate": round(success_rate, 2),
            "overall_status": "PASS" if failed_tests == 0 else "FAIL",
            "results": self.test_results
        }
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Warnings: {warning_tests} ⚠️")
        print(f"Success Rate: {success_rate}%")
        print(f"Overall Status: {summary['overall_status']}")
        
        if failed_tests > 0:
            print("\n❌ Failed Tests:")
            for result in self.test_results:
                if result["status"] == "FAIL":
                    print(f"  - {result['test']}: {result['message']}")
        
        return summary

def main():
    """Main function to run the fixed end-to-end tests"""
    try:
        test_runner = FixedE2ETest()
        summary = test_runner.run_all_tests()
        
        # Save results to file
        with open("fixed-e2e-test-results.json", "w") as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n📄 Results saved to: fixed-e2e-test-results.json")
        
        # Exit with appropriate code
        sys.exit(0 if summary["overall_status"] == "PASS" else 1)
        
    except KeyboardInterrupt:
        print("\n⚠️  Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test execution failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 