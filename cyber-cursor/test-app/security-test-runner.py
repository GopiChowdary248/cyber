#!/usr/bin/env python3
"""
Comprehensive Security Test Runner
Tests all Application Security features: SAST, DAST, and RASP
"""

import requests
import json
import time
import subprocess
import os
from datetime import datetime

class SecurityTestRunner:
    def __init__(self):
        self.cybershield_api = "http://localhost:8000"
        self.vulnerable_app = "http://localhost:5000"
        self.auth_token = "mock_admin_token_123"
        self.headers = {"Authorization": f"Bearer {self.auth_token}"}
        self.test_results = {
            "sast": [],
            "dast": [],
            "rasp": [],
            "summary": {}
        }
    
    def log_test(self, test_type, test_name, status, details=""):
        """Log test results"""
        result = {
            "test_name": test_name,
            "status": status,
            "timestamp": datetime.now().isoformat(),
            "details": details
        }
        self.test_results[test_type].append(result)
        print(f"[{status.upper()}] {test_type.upper()} - {test_name}: {details}")
    
    def test_sast_functionality(self):
        """Test Static Application Security Testing"""
        print("\n🔍 Testing SAST Functionality...")
        print("=" * 50)
        
        # Test 1: Trigger SAST scan
        try:
            response = requests.post(
                f"{self.cybershield_api}/api/v1/security/sast/scan",
                headers=self.headers
            )
            if response.status_code == 200:
                self.log_test("sast", "SAST Scan Trigger", "PASS", "Scan triggered successfully")
            else:
                self.log_test("sast", "SAST Scan Trigger", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("sast", "SAST Scan Trigger", "ERROR", str(e))
        
        # Test 2: Get SAST results
        try:
            response = requests.get(
                f"{self.cybershield_api}/api/v1/security/sast/results",
                headers=self.headers
            )
            if response.status_code == 200:
                results = response.json()
                vulnerability_count = len(results)
                self.log_test("sast", "SAST Results Retrieval", "PASS", f"Found {vulnerability_count} vulnerabilities")
                
                # Analyze vulnerability types
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for vuln in results:
                    severity = vuln.get("severity", "unknown").lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                self.log_test("sast", "SAST Vulnerability Analysis", "PASS", 
                            f"Critical: {severity_counts['critical']}, High: {severity_counts['high']}, "
                            f"Medium: {severity_counts['medium']}, Low: {severity_counts['low']}")
            else:
                self.log_test("sast", "SAST Results Retrieval", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("sast", "SAST Results Retrieval", "ERROR", str(e))
        
        # Test 3: Validate SAST vulnerability details
        try:
            response = requests.get(
                f"{self.cybershield_api}/api/v1/security/sast/results",
                headers=self.headers
            )
            if response.status_code == 200:
                results = response.json()
                if results:
                    vuln = results[0]
                    required_fields = ["file_name", "severity", "description", "recommendation"]
                    missing_fields = [field for field in required_fields if field not in vuln]
                    
                    if not missing_fields:
                        self.log_test("sast", "SAST Vulnerability Details", "PASS", "All required fields present")
                    else:
                        self.log_test("sast", "SAST Vulnerability Details", "FAIL", f"Missing fields: {missing_fields}")
                else:
                    self.log_test("sast", "SAST Vulnerability Details", "WARN", "No vulnerabilities found")
        except Exception as e:
            self.log_test("sast", "SAST Vulnerability Details", "ERROR", str(e))
    
    def test_dast_functionality(self):
        """Test Dynamic Application Security Testing"""
        print("\n🔍 Testing DAST Functionality...")
        print("=" * 50)
        
        # Test 1: Trigger DAST scan
        try:
            response = requests.post(
                f"{self.cybershield_api}/api/v1/security/dast/scan",
                headers=self.headers
            )
            if response.status_code == 200:
                self.log_test("dast", "DAST Scan Trigger", "PASS", "Scan triggered successfully")
            else:
                self.log_test("dast", "DAST Scan Trigger", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("dast", "DAST Scan Trigger", "ERROR", str(e))
        
        # Test 2: Get DAST results
        try:
            response = requests.get(
                f"{self.cybershield_api}/api/v1/security/dast/results",
                headers=self.headers
            )
            if response.status_code == 200:
                results = response.json()
                vulnerability_count = len(results)
                self.log_test("dast", "DAST Results Retrieval", "PASS", f"Found {vulnerability_count} vulnerabilities")
                
                # Analyze vulnerability types
                vuln_types = {}
                for vuln in results:
                    vuln_type = vuln.get("vulnerability_type", "unknown")
                    vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
                
                self.log_test("dast", "DAST Vulnerability Types", "PASS", 
                            f"Types found: {list(vuln_types.keys())}")
            else:
                self.log_test("dast", "DAST Results Retrieval", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("dast", "DAST Results Retrieval", "ERROR", str(e))
        
        # Test 3: Validate DAST vulnerability details
        try:
            response = requests.get(
                f"{self.cybershield_api}/api/v1/security/dast/results",
                headers=self.headers
            )
            if response.status_code == 200:
                results = response.json()
                if results:
                    vuln = results[0]
                    required_fields = ["url", "severity", "vulnerability_type", "recommendation", "cwe_id"]
                    missing_fields = [field for field in required_fields if field not in vuln]
                    
                    if not missing_fields:
                        self.log_test("dast", "DAST Vulnerability Details", "PASS", "All required fields present")
                    else:
                        self.log_test("dast", "DAST Vulnerability Details", "FAIL", f"Missing fields: {missing_fields}")
                else:
                    self.log_test("dast", "DAST Vulnerability Details", "WARN", "No vulnerabilities found")
        except Exception as e:
            self.log_test("dast", "DAST Vulnerability Details", "ERROR", str(e))
    
    def test_rasp_functionality(self):
        """Test Runtime Application Self-Protection"""
        print("\n🔍 Testing RASP Functionality...")
        print("=" * 50)
        
        # Test 1: Get RASP logs
        try:
            response = requests.get(
                f"{self.cybershield_api}/api/v1/security/rasp/logs",
                headers=self.headers
            )
            if response.status_code == 200:
                logs = response.json()
                incident_count = len(logs)
                self.log_test("rasp", "RASP Logs Retrieval", "PASS", f"Found {incident_count} incidents")
                
                # Analyze incident types
                incident_types = {}
                blocked_count = 0
                for log in logs:
                    incident_type = log.get("incident_type", "unknown")
                    incident_types[incident_type] = incident_types.get(incident_type, 0) + 1
                    if log.get("blocked", False):
                        blocked_count += 1
                
                self.log_test("rasp", "RASP Incident Analysis", "PASS", 
                            f"Types: {list(incident_types.keys())}, Blocked: {blocked_count}")
            else:
                self.log_test("rasp", "RASP Logs Retrieval", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("rasp", "RASP Logs Retrieval", "ERROR", str(e))
        
        # Test 2: Get RASP status
        try:
            response = requests.get(
                f"{self.cybershield_api}/api/v1/security/rasp/status",
                headers=self.headers
            )
            if response.status_code == 200:
                status = response.json()
                if status.get("protection_enabled", False):
                    self.log_test("rasp", "RASP Protection Status", "PASS", "Protection is active")
                else:
                    self.log_test("rasp", "RASP Protection Status", "WARN", "Protection is not active")
            else:
                self.log_test("rasp", "RASP Protection Status", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("rasp", "RASP Protection Status", "ERROR", str(e))
        
        # Test 3: Validate RASP log details
        try:
            response = requests.get(
                f"{self.cybershield_api}/api/v1/security/rasp/logs",
                headers=self.headers
            )
            if response.status_code == 200:
                logs = response.json()
                if logs:
                    log = logs[0]
                    required_fields = ["incident_type", "status", "description", "blocked", "timestamp"]
                    missing_fields = [field for field in required_fields if field not in log]
                    
                    if not missing_fields:
                        self.log_test("rasp", "RASP Log Details", "PASS", "All required fields present")
                    else:
                        self.log_test("rasp", "RASP Log Details", "FAIL", f"Missing fields: {missing_fields}")
                else:
                    self.log_test("rasp", "RASP Log Details", "WARN", "No incidents found")
        except Exception as e:
            self.log_test("rasp", "RASP Log Details", "ERROR", str(e))
    
    def test_security_summary(self):
        """Test Security Summary functionality"""
        print("\n🔍 Testing Security Summary...")
        print("=" * 50)
        
        try:
            response = requests.get(
                f"{self.cybershield_api}/api/v1/security/summary",
                headers=self.headers
            )
            if response.status_code == 200:
                summary = response.json()
                self.log_test("summary", "Security Summary Retrieval", "PASS", "Summary retrieved successfully")
                
                # Validate summary structure
                required_fields = [
                    "sast_critical", "sast_high", "sast_medium", "sast_low",
                    "dast_critical", "dast_high", "dast_medium", "dast_low",
                    "rasp_blocked", "rasp_incidents"
                ]
                missing_fields = [field for field in required_fields if field not in summary]
                
                if not missing_fields:
                    self.log_test("summary", "Security Summary Structure", "PASS", "All required fields present")
                    
                    # Calculate totals
                    total_sast = summary["sast_critical"] + summary["sast_high"] + summary["sast_medium"] + summary["sast_low"]
                    total_dast = summary["dast_critical"] + summary["dast_high"] + summary["dast_medium"] + summary["dast_low"]
                    
                    self.log_test("summary", "Security Summary Totals", "PASS", 
                                f"SAST: {total_sast}, DAST: {total_dast}, RASP: {summary['rasp_incidents']}")
                else:
                    self.log_test("summary", "Security Summary Structure", "FAIL", f"Missing fields: {missing_fields}")
            else:
                self.log_test("summary", "Security Summary Retrieval", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("summary", "Security Summary Retrieval", "ERROR", str(e))
    
    def test_frontend_integration(self):
        """Test Frontend Integration"""
        print("\n🔍 Testing Frontend Integration...")
        print("=" * 50)
        
        # Test Application Security page accessibility
        try:
            response = requests.get("http://localhost:3000/application-security")
            if response.status_code == 200:
                self.log_test("frontend", "Application Security Page", "PASS", "Page accessible")
            else:
                self.log_test("frontend", "Application Security Page", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("frontend", "Application Security Page", "ERROR", str(e))
        
        # Test main application accessibility
        try:
            response = requests.get("http://localhost:3000")
            if response.status_code == 200:
                self.log_test("frontend", "Main Application", "PASS", "Application accessible")
            else:
                self.log_test("frontend", "Main Application", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("frontend", "Main Application", "ERROR", str(e))
    
    def generate_test_report(self):
        """Generate comprehensive test report"""
        print("\n📊 Generating Test Report...")
        print("=" * 50)
        
        # Calculate test statistics
        total_tests = 0
        passed_tests = 0
        failed_tests = 0
        error_tests = 0
        
        for test_type in ["sast", "dast", "rasp", "frontend"]:
            if test_type in self.test_results:
                for test in self.test_results[test_type]:
                    total_tests += 1
                    if test["status"] == "PASS":
                        passed_tests += 1
                    elif test["status"] == "FAIL":
                        failed_tests += 1
                    elif test["status"] == "ERROR":
                        error_tests += 1
        
        # Generate summary
        self.test_results["summary"] = {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "error_tests": error_tests,
            "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            "timestamp": datetime.now().isoformat()
        }
        
        # Print summary
        print(f"📈 Test Summary:")
        print(f"   Total Tests: {total_tests}")
        print(f"   Passed: {passed_tests}")
        print(f"   Failed: {failed_tests}")
        print(f"   Errors: {error_tests}")
        print(f"   Success Rate: {self.test_results['summary']['success_rate']:.1f}%")
        
        # Save report to file
        report_file = f"security_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(self.test_results, f, indent=2)
        
        print(f"📄 Test report saved to: {report_file}")
        
        return self.test_results
    
    def run_all_tests(self):
        """Run all security tests"""
        print("🚀 Starting Comprehensive Security Testing...")
        print("=" * 60)
        
        self.test_sast_functionality()
        self.test_dast_functionality()
        self.test_rasp_functionality()
        self.test_security_summary()
        self.test_frontend_integration()
        
        print("\n" + "=" * 60)
        print("✅ All tests completed!")
        
        return self.generate_test_report()

if __name__ == "__main__":
    runner = SecurityTestRunner()
    results = runner.run_all_tests() 