#!/usr/bin/env python3
"""
End-to-End SAST Tool Testing Script
Tests the complete SAST workflow from scan initiation to report generation
"""

import os
import sys
import json
import time
import requests
import zipfile
import tempfile
from pathlib import Path
from typing import Dict, List, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SASTE2ETest:
    """End-to-End SAST Testing Framework"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.api_base = f"{base_url}/api/v1"
        self.test_results = {
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'test_details': []
        }
        
        # Test project path
        self.test_project_path = Path(__file__).parent
        self.project_name = "vulnerable-app-test"
        
    def log_test(self, test_name: str, status: str, details: str = ""):
        """Log test results"""
        self.test_results['total_tests'] += 1
        if status == 'PASS':
            self.test_results['passed_tests'] += 1
            logger.info(f"✅ {test_name}: PASS")
        else:
            self.test_results['failed_tests'] += 1
            logger.error(f"❌ {test_name}: FAIL - {details}")
        
        self.test_results['test_details'].append({
            'test_name': test_name,
            'status': status,
            'details': details,
            'timestamp': time.time()
        })
    
    def test_api_connectivity(self) -> bool:
        """Test if SAST API is accessible"""
        try:
            response = requests.get(f"{self.api_base}/sast/summary", timeout=10)
            if response.status_code == 200:
                self.log_test("API Connectivity", "PASS")
                return True
            else:
                self.log_test("API Connectivity", "FAIL", f"Status code: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("API Connectivity", "FAIL", f"Connection error: {str(e)}")
            return False
    
    def test_project_scan_trigger(self) -> str:
        """Test triggering a SAST scan for the test project"""
        try:
            scan_data = {
                "project_path": str(self.test_project_path),
                "project_name": self.project_name,
                "scan_config": {
                    "languages": ["python"],
                    "tools": ["bandit", "pylint", "semgrep"],
                    "severity_threshold": "low"
                }
            }
            
            response = requests.post(
                f"{self.api_base}/sast/scan",
                json=scan_data,
                timeout=30
            )
            
            if response.status_code == 202:
                result = response.json()
                scan_id = result.get('scan_id')
                self.log_test("Project Scan Trigger", "PASS", f"Scan ID: {scan_id}")
                return scan_id
            else:
                self.log_test("Project Scan Trigger", "FAIL", f"Status: {response.status_code}, Response: {response.text}")
                return None
                
        except Exception as e:
            self.log_test("Project Scan Trigger", "FAIL", f"Error: {str(e)}")
            return None
    
    def test_upload_scan_trigger(self) -> str:
        """Test triggering a SAST scan via file upload"""
        try:
            # Create a zip file of the test project
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp_file:
                with zipfile.ZipFile(tmp_file.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for file_path in self.test_project_path.rglob('*.py'):
                        zipf.write(file_path, file_path.name)
                
                # Upload and scan
                with open(tmp_file.name, 'rb') as f:
                    files = {'file': ('test-project.zip', f, 'application/zip')}
                    data = {
                        'project_name': f"{self.project_name}-upload",
                        'scan_config': json.dumps({
                            "languages": ["python"],
                            "tools": ["bandit", "pylint", "semgrep"]
                        })
                    }
                    
                    response = requests.post(
                        f"{self.api_base}/sast/scan/upload",
                        files=files,
                        data=data,
                        timeout=60
                    )
                
                # Clean up
                os.unlink(tmp_file.name)
                
                if response.status_code == 202:
                    result = response.json()
                    scan_id = result.get('scan_id')
                    self.log_test("Upload Scan Trigger", "PASS", f"Scan ID: {scan_id}")
                    return scan_id
                else:
                    self.log_test("Upload Scan Trigger", "FAIL", f"Status: {response.status_code}, Response: {response.text}")
                    return None
                    
        except Exception as e:
            self.log_test("Upload Scan Trigger", "FAIL", f"Error: {str(e)}")
            return None
    
    def wait_for_scan_completion(self, scan_id: str, timeout: int = 300) -> bool:
        """Wait for scan to complete and verify status"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = requests.get(f"{self.api_base}/sast/scans/{scan_id}")
                if response.status_code == 200:
                    scan_data = response.json()
                    status = scan_data.get('status')
                    
                    if status == 'completed':
                        self.log_test("Scan Completion", "PASS", f"Scan completed in {time.time() - start_time:.2f}s")
                        return True
                    elif status == 'failed':
                        self.log_test("Scan Completion", "FAIL", "Scan failed")
                        return False
                    elif status in ['pending', 'running']:
                        logger.info(f"Scan status: {status}, waiting...")
                        time.sleep(10)
                    else:
                        logger.warning(f"Unknown scan status: {status}")
                        time.sleep(10)
                else:
                    logger.warning(f"Failed to get scan status: {response.status_code}")
                    time.sleep(10)
                    
            except Exception as e:
                logger.warning(f"Error checking scan status: {e}")
                time.sleep(10)
        
        self.log_test("Scan Completion", "FAIL", "Scan timeout")
        return False
    
    def test_vulnerability_detection(self, scan_id: str) -> bool:
        """Test if vulnerabilities are detected and stored"""
        try:
            response = requests.get(f"{self.api_base}/sast/scans/{scan_id}/vulnerabilities")
            
            if response.status_code == 200:
                vulnerabilities = response.json()
                vuln_count = len(vulnerabilities.get('vulnerabilities', []))
                
                if vuln_count > 0:
                    self.log_test("Vulnerability Detection", "PASS", f"Found {vuln_count} vulnerabilities")
                    
                    # Log some sample vulnerabilities
                    for vuln in vulnerabilities.get('vulnerabilities', [])[:5]:
                        logger.info(f"  - {vuln.get('vulnerability_type')} ({vuln.get('severity')}) in {vuln.get('file_name')}")
                    
                    return True
                else:
                    self.log_test("Vulnerability Detection", "FAIL", "No vulnerabilities detected")
                    return False
            else:
                self.log_test("Vulnerability Detection", "FAIL", f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Vulnerability Detection", "FAIL", f"Error: {str(e)}")
            return False
    
    def test_ai_recommendations(self, scan_id: str) -> bool:
        """Test AI-powered recommendations generation"""
        try:
            # Get vulnerabilities first
            response = requests.get(f"{self.api_base}/sast/scans/{scan_id}/vulnerabilities")
            if response.status_code != 200:
                self.log_test("AI Recommendations", "FAIL", "Could not fetch vulnerabilities")
                return False
            
            vulnerabilities = response.json().get('vulnerabilities', [])
            if not vulnerabilities:
                self.log_test("AI Recommendations", "SKIP", "No vulnerabilities to generate recommendations for")
                return True
            
            # Test recommendation for first vulnerability
            vuln_id = vulnerabilities[0].get('id')
            response = requests.get(f"{self.api_base}/sast/vulnerabilities/{vuln_id}/recommendations")
            
            if response.status_code == 200:
                recommendations = response.json()
                if recommendations.get('recommendations'):
                    self.log_test("AI Recommendations", "PASS", f"Generated {len(recommendations['recommendations'])} recommendations")
                    return True
                else:
                    self.log_test("AI Recommendations", "FAIL", "No recommendations generated")
                    return False
            else:
                self.log_test("AI Recommendations", "FAIL", f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("AI Recommendations", "FAIL", f"Error: {str(e)}")
            return False
    
    def test_scan_summary(self) -> bool:
        """Test scan summary and statistics"""
        try:
            response = requests.get(f"{self.api_base}/sast/summary")
            
            if response.status_code == 200:
                summary = response.json()
                
                # Verify summary structure
                required_fields = ['total_scans', 'total_vulnerabilities', 'severity_breakdown', 'recent_scans']
                if all(field in summary for field in required_fields):
                    self.log_test("Scan Summary", "PASS", f"Total scans: {summary.get('total_scans')}, Total vulns: {summary.get('total_vulnerabilities')}")
                    return True
                else:
                    self.log_test("Scan Summary", "FAIL", "Missing required fields")
                    return False
            else:
                self.log_test("Scan Summary", "FAIL", f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Scan Summary", "FAIL", f"Error: {str(e)}")
            return False
    
    def test_report_generation(self, scan_id: str) -> bool:
        """Test report generation in different formats"""
        try:
            # Test JSON report
            response = requests.get(f"{self.api_base}/sast/reports/{scan_id}?format=json")
            if response.status_code == 200:
                report_data = response.json()
                if 'scan_info' in report_data and 'vulnerabilities' in report_data:
                    self.log_test("JSON Report Generation", "PASS")
                else:
                    self.log_test("JSON Report Generation", "FAIL", "Invalid report structure")
                    return False
            else:
                self.log_test("JSON Report Generation", "FAIL", f"Status: {response.status_code}")
                return False
            
            # Test CSV report
            response = requests.get(f"{self.api_base}/sast/reports/{scan_id}?format=csv")
            if response.status_code == 200:
                csv_content = response.text
                if csv_content and 'vulnerability_type' in csv_content:
                    self.log_test("CSV Report Generation", "PASS")
                else:
                    self.log_test("CSV Report Generation", "FAIL", "Invalid CSV content")
                    return False
            else:
                self.log_test("CSV Report Generation", "FAIL", f"Status: {response.status_code}")
                return False
            
            return True
            
        except Exception as e:
            self.log_test("Report Generation", "FAIL", f"Error: {str(e)}")
            return False
    
    def test_scan_history(self) -> bool:
        """Test scan history retrieval"""
        try:
            response = requests.get(f"{self.api_base}/sast/scans")
            
            if response.status_code == 200:
                scans = response.json()
                if 'scans' in scans and len(scans['scans']) > 0:
                    self.log_test("Scan History", "PASS", f"Found {len(scans['scans'])} scans")
                    return True
                else:
                    self.log_test("Scan History", "FAIL", "No scans found")
                    return False
            else:
                self.log_test("Scan History", "FAIL", f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Scan History", "FAIL", f"Error: {str(e)}")
            return False
    
    def test_vulnerability_status_update(self, scan_id: str) -> bool:
        """Test vulnerability status update functionality"""
        try:
            # Get a vulnerability first
            response = requests.get(f"{self.api_base}/sast/scans/{scan_id}/vulnerabilities")
            if response.status_code != 200:
                self.log_test("Vulnerability Status Update", "FAIL", "Could not fetch vulnerabilities")
                return False
            
            vulnerabilities = response.json().get('vulnerabilities', [])
            if not vulnerabilities:
                self.log_test("Vulnerability Status Update", "SKIP", "No vulnerabilities to update")
                return True
            
            vuln_id = vulnerabilities[0].get('id')
            
            # Update status
            update_data = {
                "status": "false_positive",
                "notes": "Test status update"
            }
            
            response = requests.post(
                f"{self.api_base}/sast/vulnerabilities/{vuln_id}/status",
                json=update_data
            )
            
            if response.status_code == 200:
                self.log_test("Vulnerability Status Update", "PASS")
                return True
            else:
                self.log_test("Vulnerability Status Update", "FAIL", f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Vulnerability Status Update", "FAIL", f"Error: {str(e)}")
            return False
    
    def run_complete_test_suite(self) -> Dict[str, Any]:
        """Run the complete SAST E2E test suite"""
        logger.info("🚀 Starting SAST End-to-End Test Suite")
        logger.info("=" * 60)
        
        # Test 1: API Connectivity
        if not self.test_api_connectivity():
            logger.error("❌ API not accessible. Please ensure the SAST backend is running.")
            return self.test_results
        
        # Test 2: Project Scan
        scan_id = self.test_project_scan_trigger()
        if scan_id:
            # Test 3: Wait for scan completion
            if self.wait_for_scan_completion(scan_id):
                # Test 4: Vulnerability detection
                self.test_vulnerability_detection(scan_id)
                
                # Test 5: AI recommendations
                self.test_ai_recommendations(scan_id)
                
                # Test 6: Report generation
                self.test_report_generation(scan_id)
                
                # Test 7: Vulnerability status update
                self.test_vulnerability_status_update(scan_id)
        
        # Test 8: Upload scan
        upload_scan_id = self.test_upload_scan_trigger()
        if upload_scan_id:
            self.wait_for_scan_completion(upload_scan_id)
            self.test_vulnerability_detection(upload_scan_id)
        
        # Test 9: Scan summary
        self.test_scan_summary()
        
        # Test 10: Scan history
        self.test_scan_history()
        
        # Generate final report
        self.generate_test_report()
        
        return self.test_results
    
    def generate_test_report(self):
        """Generate comprehensive test report"""
        logger.info("=" * 60)
        logger.info("📊 SAST E2E Test Results Summary")
        logger.info("=" * 60)
        
        total = self.test_results['total_tests']
        passed = self.test_results['passed_tests']
        failed = self.test_results['failed_tests']
        
        logger.info(f"Total Tests: {total}")
        logger.info(f"Passed: {passed}")
        logger.info(f"Failed: {failed}")
        logger.info(f"Success Rate: {(passed/total*100):.1f}%" if total > 0 else "N/A")
        
        if failed > 0:
            logger.info("\n❌ Failed Tests:")
            for test in self.test_results['test_details']:
                if test['status'] == 'FAIL':
                    logger.info(f"  - {test['test_name']}: {test['details']}")
        
        # Save detailed report
        report_file = "sast_e2e_test_report.json"
        with open(report_file, 'w') as f:
            json.dump(self.test_results, f, indent=2, default=str)
        
        logger.info(f"\n📄 Detailed report saved to: {report_file}")
        
        if failed == 0:
            logger.info("🎉 All SAST E2E tests passed successfully!")
        else:
            logger.warning(f"⚠️  {failed} test(s) failed. Please review the details above.")

def main():
    """Main test execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='SAST End-to-End Test Suite')
    parser.add_argument('--base-url', default='http://localhost:8000', 
                       help='Base URL of the SAST API')
    parser.add_argument('--timeout', type=int, default=300,
                       help='Scan completion timeout in seconds')
    
    args = parser.parse_args()
    
    # Create and run test suite
    tester = SASTE2ETest(args.base_url)
    results = tester.run_complete_test_suite()
    
    # Exit with appropriate code
    sys.exit(0 if results['failed_tests'] == 0 else 1)

if __name__ == "__main__":
    main() 