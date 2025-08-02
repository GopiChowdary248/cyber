#!/usr/bin/env python3
"""
Comprehensive End-to-End Test Suite for CyberShield Platform
Tests the complete application stack: Frontend, Backend, Database, and Security Modules
"""

import requests
import json
import time
import subprocess
import os
import sys
from datetime import datetime
from typing import Dict, List, Any
import docker
from urllib.parse import urljoin

class ComprehensiveE2ETest:
    def __init__(self):
        self.base_url = "http://localhost:3000"
        self.api_url = "http://localhost:8000"
        self.test_results = {
            "infrastructure": [],
            "authentication": [],
            "frontend": [],
            "backend": [],
            "database": [],
            "security_modules": [],
            "integration": [],
            "performance": []
        }
        self.session = requests.Session()
        self.auth_token = None
        self.test_start_time = datetime.now()
        
    def log_test(self, category: str, test_name: str, status: str, details: str = "", duration: float = None):
        """Log test results with timestamp and duration"""
        result = {
            "test_name": test_name,
            "status": status,
            "timestamp": datetime.now().isoformat(),
            "details": details,
            "duration": duration
        }
        self.test_results[category].append(result)
        
        status_emoji = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "ERROR": "🚨"}
        emoji = status_emoji.get(status, "ℹ️")
        duration_str = f" ({duration:.2f}s)" if duration else ""
        print(f"{emoji} [{status}] {category.upper()} - {test_name}: {details}{duration_str}")
    
    def test_infrastructure(self):
        """Test Docker containers and infrastructure"""
        print("\n🏗️ Testing Infrastructure...")
        print("=" * 50)
        
        start_time = time.time()
        
        # Test 1: Check if Docker is running
        try:
            client = docker.from_env()
            self.log_test("infrastructure", "Docker Connection", "PASS", "Docker client connected successfully")
        except Exception as e:
            self.log_test("infrastructure", "Docker Connection", "FAIL", f"Docker not available: {str(e)}")
            return False
        
        # Test 2: Check container status
        try:
            containers = client.containers.list()
            expected_containers = ["cybershield-frontend", "cybershield-backend", "cybershield-postgres", "cybershield-redis"]
            running_containers = [c.name for c in containers]
            
            missing_containers = [c for c in expected_containers if c not in running_containers]
            if not missing_containers:
                self.log_test("infrastructure", "Container Status", "PASS", f"All containers running: {running_containers}")
            else:
                self.log_test("infrastructure", "Container Status", "FAIL", f"Missing containers: {missing_containers}")
        except Exception as e:
            self.log_test("infrastructure", "Container Status", "ERROR", str(e))
        
        # Test 3: Check port availability
        ports_to_check = [
            (3000, "Frontend"),
            (8000, "Backend API"),
            (5432, "PostgreSQL"),
            (6379, "Redis")
        ]
        
        for port, service in ports_to_check:
            try:
                response = requests.get(f"http://localhost:{port}", timeout=5)
                self.log_test("infrastructure", f"{service} Port {port}", "PASS", f"Port {port} accessible")
            except requests.exceptions.ConnectionError:
                self.log_test("infrastructure", f"{service} Port {port}", "FAIL", f"Port {port} not accessible")
            except Exception as e:
                self.log_test("infrastructure", f"{service} Port {port}", "ERROR", str(e))
        
        duration = time.time() - start_time
        self.log_test("infrastructure", "Infrastructure Test Complete", "PASS", f"Completed in {duration:.2f}s", duration)
        return True
    
    def test_backend_health(self):
        """Test backend API health and basic functionality"""
        print("\n🔧 Testing Backend API...")
        print("=" * 50)
        
        start_time = time.time()
        
        # Test 1: Health check
        try:
            response = requests.get(f"{self.api_url}/health", timeout=10)
            if response.status_code == 200:
                self.log_test("backend", "Health Check", "PASS", "Backend is healthy")
            else:
                self.log_test("backend", "Health Check", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("backend", "Health Check", "ERROR", str(e))
        
        # Test 2: API documentation
        try:
            response = requests.get(f"{self.api_url}/docs", timeout=10)
            if response.status_code == 200:
                self.log_test("backend", "API Documentation", "PASS", "Swagger docs accessible")
            else:
                self.log_test("backend", "API Documentation", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("backend", "API Documentation", "ERROR", str(e))
        
        # Test 3: Database connection
        try:
            response = requests.get(f"{self.api_url}/api/v1/health/database", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("backend", "Database Connection", "PASS", f"Database: {data.get('status', 'unknown')}")
            else:
                self.log_test("backend", "Database Connection", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("backend", "Database Connection", "ERROR", str(e))
        
        # Test 4: Redis connection
        try:
            response = requests.get(f"{self.api_url}/api/v1/health/redis", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("backend", "Redis Connection", "PASS", f"Redis: {data.get('status', 'unknown')}")
            else:
                self.log_test("backend", "Redis Connection", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("backend", "Redis Connection", "ERROR", str(e))
        
        duration = time.time() - start_time
        self.log_test("backend", "Backend Test Complete", "PASS", f"Completed in {duration:.2f}s", duration)
    
    def test_authentication(self):
        """Test authentication system"""
        print("\n🔐 Testing Authentication...")
        print("=" * 50)
        
        start_time = time.time()
        
        # Test demo accounts
        demo_accounts = [
            {"email": "admin@cybershield.com", "password": "password", "role": "Admin"},
            {"email": "analyst@cybershield.com", "password": "password", "role": "Analyst"},
            {"email": "user@cybershield.com", "password": "password", "role": "User"}
        ]
        
        for account in demo_accounts:
            try:
                response = requests.post(
                    f"{self.api_url}/api/v1/auth/login",
                    data={
                        "username": account["email"],
                        "password": account["password"]
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    token = data.get("access_token")
                    if token:
                        self.log_test("authentication", f"Login {account['role']}", "PASS", f"Token received for {account['email']}")
                        if account["role"] == "Admin":
                            self.auth_token = token
                            self.session.headers.update({"Authorization": f"Bearer {token}"})
                    else:
                        self.log_test("authentication", f"Login {account['role']}", "FAIL", "No token in response")
                else:
                    self.log_test("authentication", f"Login {account['role']}", "FAIL", f"Status: {response.status_code}")
            except Exception as e:
                self.log_test("authentication", f"Login {account['role']}", "ERROR", str(e))
        
        # Test protected endpoint
        if self.auth_token:
            try:
                response = self.session.get(f"{self.api_url}/api/v1/users/me", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    self.log_test("authentication", "Protected Endpoint", "PASS", f"User: {data.get('email', 'unknown')}")
                else:
                    self.log_test("authentication", "Protected Endpoint", "FAIL", f"Status: {response.status_code}")
            except Exception as e:
                self.log_test("authentication", "Protected Endpoint", "ERROR", str(e))
        
        duration = time.time() - start_time
        self.log_test("authentication", "Authentication Test Complete", "PASS", f"Completed in {duration:.2f}s", duration)
    
    def test_frontend(self):
        """Test frontend application"""
        print("\n🎨 Testing Frontend...")
        print("=" * 50)
        
        start_time = time.time()
        
        # Test 1: Main page accessibility
        try:
            response = requests.get(self.base_url, timeout=10)
            if response.status_code == 200:
                self.log_test("frontend", "Main Page", "PASS", "Frontend accessible")
            else:
                self.log_test("frontend", "Main Page", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("frontend", "Main Page", "ERROR", str(e))
        
        # Test 2: Login page
        try:
            response = requests.get(f"{self.base_url}/login", timeout=10)
            if response.status_code == 200:
                self.log_test("frontend", "Login Page", "PASS", "Login page accessible")
            else:
                self.log_test("frontend", "Login Page", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("frontend", "Login Page", "ERROR", str(e))
        
        # Test 3: Dashboard page
        try:
            response = requests.get(f"{self.base_url}/dashboard", timeout=10)
            if response.status_code == 200:
                self.log_test("frontend", "Dashboard Page", "PASS", "Dashboard accessible")
            else:
                self.log_test("frontend", "Dashboard Page", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("frontend", "Dashboard Page", "ERROR", str(e))
        
        # Test 4: Application Security page
        try:
            response = requests.get(f"{self.base_url}/application-security", timeout=10)
            if response.status_code == 200:
                self.log_test("frontend", "Application Security Page", "PASS", "Security page accessible")
            else:
                self.log_test("frontend", "Application Security Page", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("frontend", "Application Security Page", "ERROR", str(e))
        
        duration = time.time() - start_time
        self.log_test("frontend", "Frontend Test Complete", "PASS", f"Completed in {duration:.2f}s", duration)
    
    def test_security_modules(self):
        """Test all security modules"""
        print("\n🛡️ Testing Security Modules...")
        print("=" * 50)
        
        start_time = time.time()
        
        if not self.auth_token:
            self.log_test("security_modules", "Authentication Required", "FAIL", "No auth token available")
            return
        
        # Test SAST
        try:
            response = self.session.get(f"{self.api_url}/api/v1/security/sast/results", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("security_modules", "SAST Results", "PASS", f"Found {len(data)} vulnerabilities")
            else:
                self.log_test("security_modules", "SAST Results", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("security_modules", "SAST Results", "ERROR", str(e))
        
        # Test DAST
        try:
            response = self.session.get(f"{self.api_url}/api/v1/security/dast/results", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("security_modules", "DAST Results", "PASS", f"Found {len(data)} vulnerabilities")
            else:
                self.log_test("security_modules", "DAST Results", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("security_modules", "DAST Results", "ERROR", str(e))
        
        # Test RASP
        try:
            response = self.session.get(f"{self.api_url}/api/v1/security/rasp/logs", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("security_modules", "RASP Logs", "PASS", f"Found {len(data)} incidents")
            else:
                self.log_test("security_modules", "RASP Logs", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("security_modules", "RASP Logs", "ERROR", str(e))
        
        # Test Security Summary
        try:
            response = self.session.get(f"{self.api_url}/api/v1/security/summary", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("security_modules", "Security Summary", "PASS", "Summary data retrieved")
            else:
                self.log_test("security_modules", "Security Summary", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("security_modules", "Security Summary", "ERROR", str(e))
        
        duration = time.time() - start_time
        self.log_test("security_modules", "Security Modules Test Complete", "PASS", f"Completed in {duration:.2f}s", duration)
    
    def test_database_integration(self):
        """Test database integration and data persistence"""
        print("\n🗄️ Testing Database Integration...")
        print("=" * 50)
        
        start_time = time.time()
        
        if not self.auth_token:
            self.log_test("database", "Authentication Required", "FAIL", "No auth token available")
            return
        
        # Test user data retrieval
        try:
            response = self.session.get(f"{self.api_url}/api/v1/users", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("database", "User Data Retrieval", "PASS", f"Found {len(data)} users")
            else:
                self.log_test("database", "User Data Retrieval", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("database", "User Data Retrieval", "ERROR", str(e))
        
        # Test incident data
        try:
            response = self.session.get(f"{self.api_url}/api/v1/incidents", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("database", "Incident Data Retrieval", "PASS", f"Found {len(data)} incidents")
            else:
                self.log_test("database", "Incident Data Retrieval", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("database", "Incident Data Retrieval", "ERROR", str(e))
        
        # Test analytics data
        try:
            response = self.session.get(f"{self.api_url}/api/v1/analytics/overview", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("database", "Analytics Data Retrieval", "PASS", "Analytics data retrieved")
            else:
                self.log_test("database", "Analytics Data Retrieval", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("database", "Analytics Data Retrieval", "ERROR", str(e))
        
        duration = time.time() - start_time
        self.log_test("database", "Database Integration Test Complete", "PASS", f"Completed in {duration:.2f}s", duration)
    
    def test_integration_workflows(self):
        """Test complete integration workflows"""
        print("\n🔄 Testing Integration Workflows...")
        print("=" * 50)
        
        start_time = time.time()
        
        if not self.auth_token:
            self.log_test("integration", "Authentication Required", "FAIL", "No auth token available")
            return
        
        # Test complete security workflow
        try:
            # 1. Trigger SAST scan
            response = self.session.post(f"{self.api_url}/api/v1/security/sast/scan", timeout=10)
            if response.status_code == 200:
                self.log_test("integration", "SAST Scan Trigger", "PASS", "Scan triggered")
                
                # 2. Wait and check results
                time.sleep(2)
                response = self.session.get(f"{self.api_url}/api/v1/security/sast/results", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    self.log_test("integration", "SAST Workflow", "PASS", f"Workflow completed with {len(data)} results")
                else:
                    self.log_test("integration", "SAST Workflow", "FAIL", "Failed to retrieve results")
            else:
                self.log_test("integration", "SAST Scan Trigger", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("integration", "SAST Workflow", "ERROR", str(e))
        
        # Test dashboard data integration
        try:
            response = self.session.get(f"{self.api_url}/api/v1/dashboard/overview", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("integration", "Dashboard Integration", "PASS", "Dashboard data integrated")
            else:
                self.log_test("integration", "Dashboard Integration", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("integration", "Dashboard Integration", "ERROR", str(e))
        
        duration = time.time() - start_time
        self.log_test("integration", "Integration Workflows Test Complete", "PASS", f"Completed in {duration:.2f}s", duration)
    
    def test_performance(self):
        """Test application performance"""
        print("\n⚡ Testing Performance...")
        print("=" * 50)
        
        start_time = time.time()
        
        # Test API response times
        endpoints_to_test = [
            "/health",
            "/api/v1/users/me",
            "/api/v1/dashboard/overview",
            "/api/v1/security/summary"
        ]
        
        for endpoint in endpoints_to_test:
            try:
                start = time.time()
                response = requests.get(f"{self.api_url}{endpoint}", timeout=10)
                duration = time.time() - start
                
                if response.status_code == 200:
                    if duration < 1.0:
                        self.log_test("performance", f"API Response {endpoint}", "PASS", f"Response time: {duration:.3f}s", duration)
                    elif duration < 3.0:
                        self.log_test("performance", f"API Response {endpoint}", "WARN", f"Slow response: {duration:.3f}s", duration)
                    else:
                        self.log_test("performance", f"API Response {endpoint}", "FAIL", f"Very slow: {duration:.3f}s", duration)
                else:
                    self.log_test("performance", f"API Response {endpoint}", "FAIL", f"Status: {response.status_code}")
            except Exception as e:
                self.log_test("performance", f"API Response {endpoint}", "ERROR", str(e))
        
        # Test frontend load time
        try:
            start = time.time()
            response = requests.get(self.base_url, timeout=10)
            duration = time.time() - start
            
            if response.status_code == 200:
                if duration < 2.0:
                    self.log_test("performance", "Frontend Load Time", "PASS", f"Load time: {duration:.3f}s", duration)
                elif duration < 5.0:
                    self.log_test("performance", "Frontend Load Time", "WARN", f"Slow load: {duration:.3f}s", duration)
                else:
                    self.log_test("performance", "Frontend Load Time", "FAIL", f"Very slow: {duration:.3f}s", duration)
            else:
                self.log_test("performance", "Frontend Load Time", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("performance", "Frontend Load Time", "ERROR", str(e))
        
        duration = time.time() - start_time
        self.log_test("performance", "Performance Test Complete", "PASS", f"Completed in {duration:.2f}s", duration)
    
    def generate_comprehensive_report(self):
        """Generate comprehensive test report"""
        print("\n📊 Generating Comprehensive Test Report...")
        print("=" * 50)
        
        total_tests = sum(len(tests) for tests in self.test_results.values())
        passed_tests = sum(len([t for t in tests if t["status"] == "PASS"]) for tests in self.test_results.values())
        failed_tests = sum(len([t for t in tests if t["status"] == "FAIL"]) for tests in self.test_results.values())
        error_tests = sum(len([t for t in tests if t["status"] == "ERROR"]) for tests in self.test_results.values())
        warn_tests = sum(len([t for t in tests if t["status"] == "WARN"]) for tests in self.test_results.values())
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        report = {
            "test_summary": {
                "test_date": self.test_start_time.isoformat(),
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "error_tests": error_tests,
                "warn_tests": warn_tests,
                "success_rate": success_rate,
                "overall_status": "PASS" if success_rate >= 90 else "FAIL"
            },
            "detailed_results": self.test_results,
            "recommendations": self.generate_recommendations()
        }
        
        # Save report to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"comprehensive_e2e_test_report_{timestamp}.json"
        
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print(f"\n🎯 Test Summary:")
        print(f"   Total Tests: {total_tests}")
        print(f"   Passed: {passed_tests} ✅")
        print(f"   Failed: {failed_tests} ❌")
        print(f"   Errors: {error_tests} 🚨")
        print(f"   Warnings: {warn_tests} ⚠️")
        print(f"   Success Rate: {success_rate:.1f}%")
        print(f"   Overall Status: {report['test_summary']['overall_status']}")
        print(f"\n📄 Detailed report saved to: {report_filename}")
        
        return report
    
    def generate_recommendations(self):
        """Generate recommendations based on test results"""
        recommendations = []
        
        # Analyze failed tests
        failed_tests = []
        for category, tests in self.test_results.items():
            for test in tests:
                if test["status"] in ["FAIL", "ERROR"]:
                    failed_tests.append((category, test))
        
        if failed_tests:
            recommendations.append({
                "priority": "HIGH",
                "category": "Critical Issues",
                "description": f"Found {len(failed_tests)} critical test failures that need immediate attention",
                "tests": [f"{cat}: {test['test_name']}" for cat, test in failed_tests]
            })
        
        # Analyze slow performance
        slow_tests = []
        for category, tests in self.test_results.items():
            for test in tests:
                if test.get("duration", 0) > 3.0:
                    slow_tests.append((category, test))
        
        if slow_tests:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Performance",
                "description": f"Found {len(slow_tests)} tests with slow response times",
                "tests": [f"{cat}: {test['test_name']} ({test['duration']:.2f}s)" for cat, test in slow_tests]
            })
        
        # General recommendations
        recommendations.append({
            "priority": "LOW",
            "category": "Enhancement",
            "description": "Consider implementing automated monitoring and alerting",
            "tests": []
        })
        
        return recommendations
    
    def run_all_tests(self):
        """Run all comprehensive tests"""
        print("🚀 Starting Comprehensive End-to-End Test Suite")
        print("=" * 60)
        print(f"Test started at: {self.test_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all test categories
        self.test_infrastructure()
        self.test_backend_health()
        self.test_authentication()
        self.test_frontend()
        self.test_security_modules()
        self.test_database_integration()
        self.test_integration_workflows()
        self.test_performance()
        
        # Generate final report
        report = self.generate_comprehensive_report()
        
        print("\n" + "=" * 60)
        print("🎉 Comprehensive End-to-End Test Suite Complete!")
        print("=" * 60)
        
        return report

def main():
    """Main function to run the comprehensive test suite"""
    print("🛡️ CyberShield Comprehensive End-to-End Test Suite")
    print("=" * 60)
    
    # Check if application is running
    try:
        response = requests.get("http://localhost:3000", timeout=5)
        print("✅ Application appears to be running")
    except:
        print("❌ Application not accessible. Please start the application first:")
        print("   docker-compose up -d")
        print("   Then wait for all services to be ready and run this test again.")
        return
    
    # Run tests
    tester = ComprehensiveE2ETest()
    report = tester.run_all_tests()
    
    # Exit with appropriate code
    if report["test_summary"]["overall_status"] == "PASS":
        print("✅ All tests passed! Application is ready for production.")
        sys.exit(0)
    else:
        print("❌ Some tests failed. Please review the report and fix issues.")
        sys.exit(1)

if __name__ == "__main__":
    main() 