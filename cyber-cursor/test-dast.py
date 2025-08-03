#!/usr/bin/env python3
"""
DAST Test Script
Comprehensive test script to demonstrate and validate DAST functionality
"""

import asyncio
import json
import sys
import time
from datetime import datetime
from typing import Dict, Any

# Import DAST components
from backend.app.services.dast_service import DASTService
from backend.app.services.dast_scanner import DASTScanner
from backend.app.services.dast_payloads import DASTPayloadLibrary
from backend.app.core.database import get_db
from backend.app.models.dast import DASTProject, DASTScan, DASTVulnerability

class DASTTester:
    """Comprehensive DAST testing class"""
    
    def __init__(self):
        self.test_results = []
        self.start_time = time.time()
    
    def log_test(self, test_name: str, status: str, message: str, details: Any = None):
        """Log test results"""
        result = {
            "test_name": test_name,
            "status": status,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "details": details
        }
        self.test_results.append(result)
        
        # Print result
        status_icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
        print(f"{status_icon} {test_name}: {message}")
        if details:
            print(f"   Details: {details}")
    
    async def test_payload_library(self):
        """Test the payload library functionality"""
        print("\n🔍 Testing Payload Library...")
        
        try:
            # Test SQL injection payloads
            sqli_payloads = DASTPayloadLibrary.get_sql_injection_payloads()
            if len(sqli_payloads) >= 5:
                self.log_test("Payload Library - SQL Injection", "PASS", f"Found {len(sqli_payloads)} SQL injection payloads")
            else:
                self.log_test("Payload Library - SQL Injection", "FAIL", f"Expected at least 5 payloads, found {len(sqli_payloads)}")
            
            # Test XSS payloads
            xss_payloads = DASTPayloadLibrary.get_xss_payloads()
            if len(xss_payloads) >= 5:
                self.log_test("Payload Library - XSS", "PASS", f"Found {len(xss_payloads)} XSS payloads")
            else:
                self.log_test("Payload Library - XSS", "FAIL", f"Expected at least 5 payloads, found {len(xss_payloads)}")
            
            # Test command injection payloads
            cmdi_payloads = DASTPayloadLibrary.get_command_injection_payloads()
            if len(cmdi_payloads) >= 4:
                self.log_test("Payload Library - Command Injection", "PASS", f"Found {len(cmdi_payloads)} command injection payloads")
            else:
                self.log_test("Payload Library - Command Injection", "FAIL", f"Expected at least 4 payloads, found {len(cmdi_payloads)}")
            
            # Test path traversal payloads
            lfi_payloads = DASTPayloadLibrary.get_path_traversal_payloads()
            if len(lfi_payloads) >= 4:
                self.log_test("Payload Library - Path Traversal", "PASS", f"Found {len(lfi_payloads)} path traversal payloads")
            else:
                self.log_test("Payload Library - Path Traversal", "FAIL", f"Expected at least 4 payloads, found {len(lfi_payloads)}")
            
            # Test SSRF payloads
            ssrf_payloads = DASTPayloadLibrary.get_ssrf_payloads()
            if len(ssrf_payloads) >= 4:
                self.log_test("Payload Library - SSRF", "PASS", f"Found {len(ssrf_payloads)} SSRF payloads")
            else:
                self.log_test("Payload Library - SSRF", "FAIL", f"Expected at least 4 payloads, found {len(ssrf_payloads)}")
            
            # Test all payloads
            all_payloads = DASTPayloadLibrary.get_all_payloads()
            if len(all_payloads) >= 30:
                self.log_test("Payload Library - Total", "PASS", f"Found {len(all_payloads)} total payloads")
            else:
                self.log_test("Payload Library - Total", "FAIL", f"Expected at least 30 payloads, found {len(all_payloads)}")
            
            # Test OWASP Top 10 payloads
            owasp_payloads = DASTPayloadLibrary.get_owasp_top_10_payloads()
            if len(owasp_payloads) >= 20:
                self.log_test("Payload Library - OWASP Top 10", "PASS", f"Found {len(owasp_payloads)} OWASP Top 10 payloads")
            else:
                self.log_test("Payload Library - OWASP Top 10", "FAIL", f"Expected at least 20 payloads, found {len(owasp_payloads)}")
            
        except Exception as e:
            self.log_test("Payload Library", "ERROR", f"Exception occurred: {str(e)}")
    
    async def test_dast_service(self):
        """Test the DAST service functionality"""
        print("\n🔍 Testing DAST Service...")
        
        try:
            # Get database session
            db = await get_db().__anext__()
            service = DASTService(db)
            
            # Test overview
            try:
                overview = await service.get_dast_overview()
                if overview and "overview" in overview:
                    self.log_test("DAST Service - Overview", "PASS", "Successfully retrieved DAST overview")
                else:
                    self.log_test("DAST Service - Overview", "FAIL", "Failed to retrieve DAST overview")
            except Exception as e:
                self.log_test("DAST Service - Overview", "ERROR", f"Exception: {str(e)}")
            
            # Test project creation
            try:
                project_data = {
                    "name": "Test Project",
                    "target_url": "https://httpbin.org",
                    "description": "Test project for DAST validation",
                    "auth_type": "none"
                }
                project_id = await service.create_project(project_data)
                if project_id:
                    self.log_test("DAST Service - Project Creation", "PASS", f"Created project with ID: {project_id}")
                    
                    # Test project overview
                    try:
                        project_overview = await service.get_project_overview(project_id)
                        if project_overview and "project" in project_overview:
                            self.log_test("DAST Service - Project Overview", "PASS", "Successfully retrieved project overview")
                        else:
                            self.log_test("DAST Service - Project Overview", "FAIL", "Failed to retrieve project overview")
                    except Exception as e:
                        self.log_test("DAST Service - Project Overview", "ERROR", f"Exception: {str(e)}")
                    
                    # Test scan creation
                    try:
                        scan_id = await service.create_scan(project_id, {"scan_type": "passive"})
                        if scan_id:
                            self.log_test("DAST Service - Scan Creation", "PASS", f"Created scan with ID: {scan_id}")
                            
                            # Test scan status
                            try:
                                scan_status = await service.get_scan_status(scan_id)
                                if scan_status and "id" in scan_status:
                                    self.log_test("DAST Service - Scan Status", "PASS", f"Retrieved scan status: {scan_status['status']}")
                                else:
                                    self.log_test("DAST Service - Scan Status", "FAIL", "Failed to retrieve scan status")
                            except Exception as e:
                                self.log_test("DAST Service - Scan Status", "ERROR", f"Exception: {str(e)}")
                        else:
                            self.log_test("DAST Service - Scan Creation", "FAIL", "Failed to create scan")
                    except Exception as e:
                        self.log_test("DAST Service - Scan Creation", "ERROR", f"Exception: {str(e)}")
                else:
                    self.log_test("DAST Service - Project Creation", "FAIL", "Failed to create project")
            except Exception as e:
                self.log_test("DAST Service - Project Creation", "ERROR", f"Exception: {str(e)}")
            
            # Test payload management
            try:
                payloads = await service.get_payloads()
                if payloads and len(payloads) > 0:
                    self.log_test("DAST Service - Payload Management", "PASS", f"Retrieved {len(payloads)} payloads")
                else:
                    self.log_test("DAST Service - Payload Management", "FAIL", "Failed to retrieve payloads")
            except Exception as e:
                self.log_test("DAST Service - Payload Management", "ERROR", f"Exception: {str(e)}")
            
            # Test vulnerability filtering
            try:
                vulns = await service.get_vulnerabilities(severity="critical")
                self.log_test("DAST Service - Vulnerability Filtering", "PASS", f"Retrieved {len(vulns)} critical vulnerabilities")
            except Exception as e:
                self.log_test("DAST Service - Vulnerability Filtering", "ERROR", f"Exception: {str(e)}")
            
        except Exception as e:
            self.log_test("DAST Service", "ERROR", f"Service test failed: {str(e)}")
    
    async def test_dast_scanner(self):
        """Test the DAST scanner functionality"""
        print("\n🔍 Testing DAST Scanner...")
        
        try:
            # Get database session
            db = await get_db().__anext__()
            
            # Test scanner initialization
            try:
                scanner = DASTScanner(db)
                self.log_test("DAST Scanner - Initialization", "PASS", "Scanner initialized successfully")
                
                # Test URL extraction
                test_html = """
                <html>
                <head><title>Test Page</title></head>
                <body>
                    <a href="https://example.com/page1">Link 1</a>
                    <a href="/page2">Link 2</a>
                    <img src="/image.jpg" />
                    <form action="/submit" method="POST">
                        <input name="username" />
                        <input name="password" type="password" />
                    </form>
                </body>
                </html>
                """
                
                urls = scanner._extract_urls(test_html, "https://example.com")
                if len(urls) >= 2:
                    self.log_test("DAST Scanner - URL Extraction", "PASS", f"Extracted {len(urls)} URLs")
                else:
                    self.log_test("DAST Scanner - URL Extraction", "FAIL", f"Expected at least 2 URLs, found {len(urls)}")
                
                # Test form extraction
                forms = scanner._extract_forms(test_html, "https://example.com")
                if len(forms) >= 1:
                    self.log_test("DAST Scanner - Form Extraction", "PASS", f"Extracted {len(forms)} forms")
                else:
                    self.log_test("DAST Scanner - Form Extraction", "FAIL", f"Expected at least 1 form, found {len(forms)}")
                
                # Test vulnerability analysis
                test_response = type('Response', (), {
                    'status': 200,
                    'method': 'GET',
                    'headers': {'Content-Type': 'text/html'}
                })()
                
                test_content = "Error in your SQL syntax near 'OR 1=1'"
                test_payload = type('Payload', (), {
                    'vuln_type': 'sqli',
                    'payload': "' OR 1=1 --",
                    'severity': 'critical'
                })()
                
                is_vulnerable = scanner._analyze_response_for_vulnerability(
                    test_response, test_content, test_payload, 1.0
                )
                if is_vulnerable:
                    self.log_test("DAST Scanner - Vulnerability Analysis", "PASS", "Correctly detected SQL injection vulnerability")
                else:
                    self.log_test("DAST Scanner - Vulnerability Analysis", "FAIL", "Failed to detect SQL injection vulnerability")
                
            except Exception as e:
                self.log_test("DAST Scanner - Initialization", "ERROR", f"Exception: {str(e)}")
            
        except Exception as e:
            self.log_test("DAST Scanner", "ERROR", f"Scanner test failed: {str(e)}")
    
    async def test_integration(self):
        """Test end-to-end integration"""
        print("\n🔍 Testing End-to-End Integration...")
        
        try:
            # Get database session
            db = await get_db().__anext__()
            service = DASTService(db)
            
            # Create test project
            project_data = {
                "name": "Integration Test Project",
                "target_url": "https://httpbin.org",
                "description": "Integration test project",
                "auth_type": "none"
            }
            
            project_id = await service.create_project(project_data)
            if not project_id:
                self.log_test("Integration - Project Creation", "FAIL", "Failed to create test project")
                return
            
            # Create test scan
            scan_id = await service.create_scan(project_id, {
                "scan_type": "passive",
                "max_urls": 10,
                "max_depth": 2
            })
            
            if not scan_id:
                self.log_test("Integration - Scan Creation", "FAIL", "Failed to create test scan")
                return
            
            # Simulate scan completion (in real scenario, this would be done by the scanner)
            scan = await DASTScan.get_by_id(db, scan_id)
            if scan:
                scan.status = "completed"
                scan.vulnerabilities_found = 2
                scan.urls_scanned = 5
                scan.scan_duration = 30.5
                await db.commit()
                
                # Create test vulnerabilities
                vuln1 = DASTVulnerability(
                    scan_id=scan_id,
                    project_id=project_id,
                    title="Missing Security Headers",
                    description="Application missing important security headers",
                    severity="medium",
                    url="https://httpbin.org",
                    http_method="GET",
                    vuln_type="security_headers",
                    cwe_id="CWE-693",
                    owasp_category="A05:2021-Security Misconfiguration"
                )
                
                vuln2 = DASTVulnerability(
                    scan_id=scan_id,
                    project_id=project_id,
                    title="Information Disclosure",
                    description="Server information exposed in headers",
                    severity="low",
                    url="https://httpbin.org",
                    http_method="GET",
                    vuln_type="information_disclosure",
                    cwe_id="CWE-200",
                    owasp_category="A01:2021-Broken Access Control"
                )
                
                db.add(vuln1)
                db.add(vuln2)
                await db.commit()
                
                # Test vulnerability retrieval
                vulns = await service.get_scan_vulnerabilities(scan_id)
                if len(vulns['vulnerabilities']) == 2:
                    self.log_test("Integration - Vulnerability Retrieval", "PASS", f"Retrieved {len(vulns['vulnerabilities'])} vulnerabilities")
                else:
                    self.log_test("Integration - Vulnerability Retrieval", "FAIL", f"Expected 2 vulnerabilities, found {len(vulns['vulnerabilities'])}")
                
                # Test report generation
                try:
                    report = await service.generate_report(scan_id, "json")
                    if report and "report_id" in report:
                        self.log_test("Integration - Report Generation", "PASS", f"Generated report: {report['report_id']}")
                    else:
                        self.log_test("Integration - Report Generation", "FAIL", "Failed to generate report")
                except Exception as e:
                    self.log_test("Integration - Report Generation", "ERROR", f"Exception: {str(e)}")
                
            else:
                self.log_test("Integration - Scan Update", "FAIL", "Failed to update scan status")
            
        except Exception as e:
            self.log_test("Integration", "ERROR", f"Integration test failed: {str(e)}")
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*60)
        print("DAST TEST SUMMARY")
        print("="*60)
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r["status"] == "PASS"])
        failed_tests = len([r for r in self.test_results if r["status"] == "FAIL"])
        error_tests = len([r for r in self.test_results if r["status"] == "ERROR"])
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Errors: {error_tests} ⚠️")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        duration = time.time() - self.start_time
        print(f"Test Duration: {duration:.2f} seconds")
        
        if failed_tests > 0 or error_tests > 0:
            print("\nFailed/Error Tests:")
            for result in self.test_results:
                if result["status"] in ["FAIL", "ERROR"]:
                    print(f"  - {result['test_name']}: {result['message']}")
        
        # Save results to file
        with open("dast-test-results.json", "w") as f:
            json.dump({
                "summary": {
                    "total_tests": total_tests,
                    "passed_tests": passed_tests,
                    "failed_tests": failed_tests,
                    "error_tests": error_tests,
                    "success_rate": (passed_tests/total_tests)*100,
                    "duration": duration
                },
                "results": self.test_results
            }, f, indent=2)
        
        print(f"\nDetailed results saved to: dast-test-results.json")
        
        return passed_tests == total_tests

async def main():
    """Main test function"""
    print("🚀 Starting DAST Implementation Tests")
    print("="*60)
    
    tester = DASTTester()
    
    # Run all tests
    await tester.test_payload_library()
    await tester.test_dast_service()
    await tester.test_dast_scanner()
    await tester.test_integration()
    
    # Print summary
    success = tester.print_summary()
    
    if success:
        print("\n🎉 All tests passed! DAST implementation is working correctly.")
        sys.exit(0)
    else:
        print("\n⚠️  Some tests failed. Please review the results above.")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 