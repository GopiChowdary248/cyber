#!/usr/bin/env python3
"""
SAST Tool End-to-End Test Script

This script performs comprehensive testing of the SAST tool implementation:
1. Database connectivity and model creation
2. SAST scanner functionality
3. AI recommendation engine
4. API endpoints
5. DevSecOps integration
6. Frontend integration
"""

import requests
import json
import time
import os
import sys
from datetime import datetime
from typing import Dict, List, Any

# Test configuration
BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api/v1"
FRONTEND_URL = "http://localhost:3000"

class SASTEndToEndTester:
    def __init__(self):
        self.test_results = []
        self.auth_token = None
        self.session = requests.Session()
        
    def log_test(self, test_name: str, status: str, details: str = ""):
        """Log test results"""
        result = {
            "test": test_name,
            "status": status,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        print(f"[{status.upper()}] {test_name}: {details}")
        
    def authenticate(self):
        """Authenticate with the API"""
        try:
            # Mock authentication - in real scenario, you'd use actual credentials
            auth_data = {
                "username": "admin",
                "password": "admin123"
            }
            response = self.session.post(f"{API_BASE}/auth/login", data=auth_data)
            
            if response.status_code == 200:
                self.auth_token = response.json().get("access_token")
                self.session.headers.update({"Authorization": f"Bearer {self.auth_token}"})
                self.log_test("Authentication", "PASS", "Successfully authenticated")
                return True
            else:
                self.log_test("Authentication", "FAIL", f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Authentication", "ERROR", str(e))
            return False
    
    def test_health_check(self):
        """Test API health check"""
        try:
            response = self.session.get(f"{BASE_URL}/health")
            if response.status_code == 200:
                health_data = response.json()
                self.log_test("Health Check", "PASS", f"Status: {health_data.get('status')}")
                return True
            else:
                self.log_test("Health Check", "FAIL", f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Health Check", "ERROR", str(e))
            return False
    
    def test_sast_api_endpoints(self):
        """Test SAST API endpoints"""
        endpoints = [
            ("GET", "/sast/scans", "Get SAST Scans"),
            ("GET", "/sast/summary", "Get SAST Summary"),
            ("POST", "/sast/scan", "Trigger SAST Scan"),
        ]
        
        for method, endpoint, description in endpoints:
            try:
                if method == "GET":
                    response = self.session.get(f"{API_BASE}{endpoint}")
                else:
                    response = self.session.post(f"{API_BASE}{endpoint}")
                
                if response.status_code in [200, 201, 202]:
                    self.log_test(f"SAST API - {description}", "PASS", f"Status: {response.status_code}")
                else:
                    self.log_test(f"SAST API - {description}", "FAIL", f"Status: {response.status_code}")
            except Exception as e:
                self.log_test(f"SAST API - {description}", "ERROR", str(e))
    
    def test_sast_scan_trigger(self):
        """Test triggering a SAST scan"""
        try:
            scan_data = {
                "project_path": "/tmp/test-project",
                "scan_type": "full",
                "languages": ["python", "javascript"]
            }
            
            response = self.session.post(f"{API_BASE}/sast/scan", json=scan_data)
            
            if response.status_code in [200, 201, 202]:
                scan_result = response.json()
                scan_id = scan_result.get("scan_id")
                self.log_test("SAST Scan Trigger", "PASS", f"Scan ID: {scan_id}")
                
                # Wait a bit and check scan status
                time.sleep(2)
                status_response = self.session.get(f"{API_BASE}/sast/scans/{scan_id}")
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    self.log_test("SAST Scan Status", "PASS", f"Status: {status_data.get('status')}")
                else:
                    self.log_test("SAST Scan Status", "FAIL", f"Status: {status_response.status_code}")
                    
                return scan_id
            else:
                self.log_test("SAST Scan Trigger", "FAIL", f"Status: {response.status_code}")
                return None
        except Exception as e:
            self.log_test("SAST Scan Trigger", "ERROR", str(e))
            return None
    
    def test_sast_vulnerabilities(self):
        """Test SAST vulnerability retrieval"""
        try:
            response = self.session.get(f"{API_BASE}/sast/scans")
            
            if response.status_code == 200:
                scans = response.json()
                if scans:
                    scan_id = scans[0].get("id")
                    
                    # Get vulnerabilities for the first scan
                    vuln_response = self.session.get(f"{API_BASE}/sast/scans/{scan_id}/vulnerabilities")
                    if vuln_response.status_code == 200:
                        vulnerabilities = vuln_response.json()
                        self.log_test("SAST Vulnerabilities", "PASS", f"Found {len(vulnerabilities)} vulnerabilities")
                    else:
                        self.log_test("SAST Vulnerabilities", "FAIL", f"Status: {vuln_response.status_code}")
                else:
                    self.log_test("SAST Vulnerabilities", "SKIP", "No scans available")
            else:
                self.log_test("SAST Vulnerabilities", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("SAST Vulnerabilities", "ERROR", str(e))
    
    def test_ai_recommendations(self):
        """Test AI recommendation engine"""
        try:
            # Test getting recommendations for a vulnerability
            response = self.session.get(f"{API_BASE}/sast/vulnerabilities/1/recommendations")
            
            if response.status_code == 200:
                recommendations = response.json()
                self.log_test("AI Recommendations", "PASS", f"Generated {len(recommendations)} recommendations")
            else:
                self.log_test("AI Recommendations", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("AI Recommendations", "ERROR", str(e))
    
    def test_devsecops_integration(self):
        """Test DevSecOps integration endpoints"""
        try:
            # Test webhook endpoint
            webhook_data = {
                "event": "push",
                "repository": "test-repo",
                "branch": "main",
                "commit": "abc123"
            }
            
            response = self.session.post(f"{API_BASE}/sast/webhook/github", json=webhook_data)
            
            if response.status_code in [200, 201, 202]:
                self.log_test("DevSecOps Webhook", "PASS", "Webhook processed successfully")
            else:
                self.log_test("DevSecOps Webhook", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("DevSecOps Webhook", "ERROR", str(e))
    
    def test_frontend_integration(self):
        """Test frontend integration"""
        try:
            # Test if frontend is accessible
            response = self.session.get(FRONTEND_URL)
            
            if response.status_code == 200:
                self.log_test("Frontend Accessibility", "PASS", "Frontend is accessible")
                
                # Test SAST dashboard page
                sast_response = self.session.get(f"{FRONTEND_URL}/sast")
                if sast_response.status_code == 200:
                    self.log_test("SAST Dashboard", "PASS", "SAST dashboard is accessible")
                else:
                    self.log_test("SAST Dashboard", "FAIL", f"Status: {sast_response.status_code}")
            else:
                self.log_test("Frontend Accessibility", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Frontend Integration", "ERROR", str(e))
    
    def test_database_integration(self):
        """Test database integration"""
        try:
            # Test if scan results are persisted
            response = self.session.get(f"{API_BASE}/sast/scans")
            
            if response.status_code == 200:
                scans = response.json()
                self.log_test("Database Integration", "PASS", f"Retrieved {len(scans)} scans from database")
            else:
                self.log_test("Database Integration", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Database Integration", "ERROR", str(e))
    
    def generate_report(self):
        """Generate comprehensive test report"""
        report = {
            "test_suite": "SAST Tool End-to-End Test",
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_tests": len(self.test_results),
                "passed": len([r for r in self.test_results if r["status"] == "PASS"]),
                "failed": len([r for r in self.test_results if r["status"] == "FAIL"]),
                "errors": len([r for r in self.test_results if r["status"] == "ERROR"]),
                "skipped": len([r for r in self.test_results if r["status"] == "SKIP"])
            },
            "results": self.test_results
        }
        
        # Save report to file
        report_file = "sast-e2e-test-report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📊 Test Report Summary:")
        print(f"   Total Tests: {report['summary']['total_tests']}")
        print(f"   Passed: {report['summary']['passed']}")
        print(f"   Failed: {report['summary']['failed']}")
        print(f"   Errors: {report['summary']['errors']}")
        print(f"   Skipped: {report['summary']['skipped']}")
        print(f"\n📄 Detailed report saved to: {report_file}")
        
        return report
    
    def run_all_tests(self):
        """Run all tests"""
        print("🚀 Starting SAST Tool End-to-End Tests...")
        print("=" * 60)
        
        # Run tests in sequence
        tests = [
            ("Health Check", self.test_health_check),
            ("Authentication", self.authenticate),
            ("SAST API Endpoints", self.test_sast_api_endpoints),
            ("SAST Scan Trigger", self.test_sast_scan_trigger),
            ("SAST Vulnerabilities", self.test_sast_vulnerabilities),
            ("AI Recommendations", self.test_ai_recommendations),
            ("DevSecOps Integration", self.test_devsecops_integration),
            ("Frontend Integration", self.test_frontend_integration),
            ("Database Integration", self.test_database_integration),
        ]
        
        for test_name, test_func in tests:
            print(f"\n🔍 Running: {test_name}")
            print("-" * 40)
            test_func()
        
        # Generate report
        print("\n" + "=" * 60)
        report = self.generate_report()
        
        # Final status
        if report["summary"]["failed"] == 0 and report["summary"]["errors"] == 0:
            print("✅ All tests completed successfully!")
            return True
        else:
            print("❌ Some tests failed. Check the report for details.")
            return False

def main():
    """Main function"""
    tester = SASTEndToEndTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 