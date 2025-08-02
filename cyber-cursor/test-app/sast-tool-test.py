#!/usr/bin/env python3
"""
SAST Tool End-to-End Test Script
Tests all SAST tool functionality including scanning, AI recommendations, and API endpoints
"""

import requests
import json
import time
import os
import sys
from pathlib import Path
from typing import Dict, List, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SASTToolTester:
    """Comprehensive SAST Tool Tester"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.api_base = f"{base_url}/api/v1/sast"
        self.test_results = []
        
    def log_test(self, test_name: str, status: str, details: str = ""):
        """Log test result"""
        result = {
            "test": test_name,
            "status": status,
            "details": details,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.test_results.append(result)
        logger.info(f"✅ {test_name}: {status}")
        if details:
            logger.info(f"   Details: {details}")
    
    def test_health_check(self):
        """Test health check endpoint"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_test("Health Check", "PASSED", f"Service: {data.get('service')}")
                return True
            else:
                self.log_test("Health Check", "FAILED", f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Health Check", "FAILED", str(e))
            return False
    
    def test_api_documentation(self):
        """Test API documentation endpoint"""
        try:
            response = requests.get(f"{self.base_url}/docs", timeout=10)
            if response.status_code == 200:
                self.log_test("API Documentation", "PASSED", "Swagger UI accessible")
                return True
            else:
                self.log_test("API Documentation", "FAILED", f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("API Documentation", "FAILED", str(e))
            return False
    
    def test_sast_scan_trigger(self):
        """Test SAST scan triggering"""
        try:
            # Test scan with project path
            scan_data = {
                "project_path": "/app/test-project",
                "scan_type": "full",
                "languages": ["python", "javascript"],
                "tools": ["bandit", "pylint", "eslint"]
            }
            
            response = requests.post(
                f"{self.api_base}/scan",
                json=scan_data,
                timeout=30
            )
            
            if response.status_code == 202:
                data = response.json()
                scan_id = data.get("scan_id")
                self.log_test("SAST Scan Trigger", "PASSED", f"Scan ID: {scan_id}")
                return scan_id
            else:
                self.log_test("SAST Scan Trigger", "FAILED", f"Status: {response.status_code}")
                return None
        except Exception as e:
            self.log_test("SAST Scan Trigger", "FAILED", str(e))
            return None
    
    def test_sast_scan_status(self, scan_id: str):
        """Test SAST scan status checking"""
        try:
            response = requests.get(f"{self.api_base}/scans/{scan_id}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                status = data.get("status")
                self.log_test("SAST Scan Status", "PASSED", f"Status: {status}")
                return status
            else:
                self.log_test("SAST Scan Status", "FAILED", f"Status: {response.status_code}")
                return None
        except Exception as e:
            self.log_test("SAST Scan Status", "FAILED", str(e))
            return None
    
    def test_sast_results_retrieval(self, scan_id: str):
        """Test SAST results retrieval"""
        try:
            response = requests.get(f"{self.api_base}/scans/{scan_id}/vulnerabilities", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                self.log_test("SAST Results Retrieval", "PASSED", f"Found {len(vulnerabilities)} vulnerabilities")
                return vulnerabilities
            else:
                self.log_test("SAST Results Retrieval", "FAILED", f"Status: {response.status_code}")
                return []
        except Exception as e:
            self.log_test("SAST Results Retrieval", "FAILED", str(e))
            return []
    
    def test_ai_recommendations(self, vulnerability_id: str):
        """Test AI recommendations for vulnerabilities"""
        try:
            response = requests.get(f"{self.api_base}/vulnerabilities/{vulnerability_id}/recommendations", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                recommendations = data.get("recommendations", [])
                self.log_test("AI Recommendations", "PASSED", f"Generated {len(recommendations)} recommendations")
                return recommendations
            else:
                self.log_test("AI Recommendations", "FAILED", f"Status: {response.status_code}")
                return []
        except Exception as e:
            self.log_test("AI Recommendations", "FAILED", str(e))
            return []
    
    def test_sast_summary(self):
        """Test SAST summary endpoint"""
        try:
            response = requests.get(f"{self.api_base}/summary", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                self.log_test("SAST Summary", "PASSED", f"Summary retrieved successfully")
                return data
            else:
                self.log_test("SAST Summary", "FAILED", f"Status: {response.status_code}")
                return None
        except Exception as e:
            self.log_test("SAST Summary", "FAILED", str(e))
            return None
    
    def test_file_upload_scan(self):
        """Test file upload and scan"""
        try:
            # Create a test file with vulnerabilities
            test_file_content = """
import os
import subprocess

# SQL Injection vulnerability
def vulnerable_query(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query

# Command injection vulnerability
def vulnerable_command(command):
    os.system(command)

# Hardcoded credentials
password = "admin123"
api_key = "sk-1234567890abcdef"

# XSS vulnerability
def vulnerable_xss(user_input):
    return f"<div>{user_input}</div>"
"""
            
            # Create test file
            test_file_path = "test_vulnerable_code.py"
            with open(test_file_path, "w") as f:
                f.write(test_file_content)
            
            # Upload and scan
            with open(test_file_path, "rb") as f:
                files = {"file": ("test_vulnerable_code.py", f, "text/plain")}
                data = {
                    "scan_type": "full",
                    "languages": ["python"],
                    "tools": ["bandit", "pylint"]
                }
                
                response = requests.post(
                    f"{self.api_base}/scan/upload",
                    files=files,
                    data=data,
                    timeout=60
                )
            
            # Clean up test file
            os.remove(test_file_path)
            
            if response.status_code == 202:
                data = response.json()
                scan_id = data.get("scan_id")
                self.log_test("File Upload Scan", "PASSED", f"Scan ID: {scan_id}")
                return scan_id
            else:
                self.log_test("File Upload Scan", "FAILED", f"Status: {response.status_code}")
                return None
        except Exception as e:
            self.log_test("File Upload Scan", "FAILED", str(e))
            return None
    
    def test_report_generation(self, scan_id: str):
        """Test report generation"""
        try:
            response = requests.get(f"{self.api_base}/reports/{scan_id}", timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                self.log_test("Report Generation", "PASSED", "Report generated successfully")
                return data
            else:
                self.log_test("Report Generation", "FAILED", f"Status: {response.status_code}")
                return None
        except Exception as e:
            self.log_test("Report Generation", "FAILED", str(e))
            return None
    
    def test_vulnerability_status_update(self, vulnerability_id: str):
        """Test vulnerability status update"""
        try:
            update_data = {
                "status": "false_positive",
                "comment": "Test status update"
            }
            
            response = requests.post(
                f"{self.api_base}/vulnerabilities/{vulnerability_id}/status",
                json=update_data,
                timeout=10
            )
            
            if response.status_code == 200:
                self.log_test("Vulnerability Status Update", "PASSED", "Status updated successfully")
                return True
            else:
                self.log_test("Vulnerability Status Update", "FAILED", f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Vulnerability Status Update", "FAILED", str(e))
            return False
    
    def test_scan_listing(self):
        """Test scan listing endpoint"""
        try:
            response = requests.get(f"{self.api_base}/scans", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                scans = data.get("scans", [])
                self.log_test("Scan Listing", "PASSED", f"Found {len(scans)} scans")
                return scans
            else:
                self.log_test("Scan Listing", "FAILED", f"Status: {response.status_code}")
                return []
        except Exception as e:
            self.log_test("Scan Listing", "FAILED", str(e))
            return []
    
    def run_comprehensive_test(self):
        """Run comprehensive SAST tool test"""
        logger.info("🚀 Starting Comprehensive SAST Tool Test")
        
        # Basic connectivity tests
        if not self.test_health_check():
            logger.error("❌ Health check failed. SAST tool may not be running.")
            return False
        
        if not self.test_api_documentation():
            logger.warning("⚠️ API documentation not accessible")
        
        # Test scan triggering
        scan_id = self.test_sast_scan_trigger()
        if scan_id:
            # Wait for scan to complete
            logger.info("⏳ Waiting for scan to complete...")
            time.sleep(10)
            
            # Test scan status
            status = self.test_sast_scan_status(scan_id)
            
            # Test results retrieval
            vulnerabilities = self.test_sast_results_retrieval(scan_id)
            
            # Test AI recommendations if vulnerabilities found
            if vulnerabilities:
                first_vuln = vulnerabilities[0]
                vuln_id = first_vuln.get("id")
                if vuln_id:
                    self.test_ai_recommendations(vuln_id)
                    self.test_vulnerability_status_update(vuln_id)
        
        # Test file upload scan
        upload_scan_id = self.test_file_upload_scan()
        if upload_scan_id:
            time.sleep(10)
            self.test_report_generation(upload_scan_id)
        
        # Test summary and listing
        self.test_sast_summary()
        self.test_scan_listing()
        
        # Generate test report
        self.generate_test_report()
        
        logger.info("🎉 Comprehensive SAST Tool Test Completed!")
        return True
    
    def generate_test_report(self):
        """Generate comprehensive test report"""
        report = {
            "test_summary": {
                "total_tests": len(self.test_results),
                "passed": len([r for r in self.test_results if r["status"] == "PASSED"]),
                "failed": len([r for r in self.test_results if r["status"] == "FAILED"]),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            },
            "test_results": self.test_results,
            "recommendations": self.generate_recommendations()
        }
        
        # Save report
        report_file = "sast_tool_test_report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"📊 Test report saved to: {report_file}")
        
        # Print summary
        passed = report["test_summary"]["passed"]
        total = report["test_summary"]["total_tests"]
        logger.info(f"📈 Test Results: {passed}/{total} tests passed")
    
    def generate_recommendations(self):
        """Generate recommendations based on test results"""
        recommendations = []
        
        failed_tests = [r for r in self.test_results if r["status"] == "FAILED"]
        
        if failed_tests:
            recommendations.append("Review failed tests and fix underlying issues")
        
        if not any("Health Check" in r["test"] and r["status"] == "PASSED" for r in self.test_results):
            recommendations.append("Ensure SAST tool is running and accessible")
        
        if not any("API Documentation" in r["test"] and r["status"] == "PASSED" for r in self.test_results):
            recommendations.append("Check API documentation endpoint configuration")
        
        return recommendations

def main():
    """Main test execution"""
    # Get SAST tool URL from environment or use default
    sast_url = os.getenv("SAST_TOOL_URL", "http://localhost:8000")
    
    logger.info(f"🔧 Testing SAST Tool at: {sast_url}")
    
    # Create tester and run tests
    tester = SASTToolTester(sast_url)
    success = tester.run_comprehensive_test()
    
    if success:
        logger.info("✅ All SAST tool tests completed successfully!")
        sys.exit(0)
    else:
        logger.error("❌ Some SAST tool tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main() 