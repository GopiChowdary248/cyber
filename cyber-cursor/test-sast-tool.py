#!/usr/bin/env python3
"""
Comprehensive Test Script for CyberShield SAST Tool
Tests all SAST functionality including:
- Project management
- Code scanning
- Vulnerability analysis
- Report generation
- API endpoints
"""

import requests
import json
import time
import os
import zipfile
import tempfile
import shutil
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SASTToolTester:
    """Comprehensive SAST Tool Tester"""
    
    def __init__(self):
        self.base_url = "http://localhost:8000"
        self.session = requests.Session()
        self.project_id = None
        self.scan_id = None
        self.test_results = {
            "passed": 0,
            "failed": 0,
            "errors": []
        }
        
        # Test credentials
        self.username = "admin@cybershield.com"
        self.password = "admin123"
        
        # Authenticate
        self.authenticate()
    
    def authenticate(self):
        """Authenticate with the API"""
        try:
            response = self.session.post(f"{self.base_url}/api/v1/auth/login", json={
                "email": self.username,
                "password": self.password
            })
            
            if response.status_code == 200:
                token = response.json().get("access_token")
                self.session.headers.update({"Authorization": f"Bearer {token}"})
                logger.info("✅ Authentication successful")
            else:
                logger.error(f"❌ Authentication failed: {response.status_code}")
                raise Exception("Authentication failed")
                
        except Exception as e:
            logger.error(f"❌ Authentication error: {str(e)}")
            raise
    
    def log_test(self, test_name: str, status: str, message: str):
        """Log test result"""
        if status == "PASSED":
            self.test_results["passed"] += 1
            logger.info(f"✅ {test_name}: {message}")
        else:
            self.test_results["failed"] += 1
            self.test_results["errors"].append(f"{test_name}: {message}")
            logger.error(f"❌ {test_name}: {message}")
    
    def test_health_check(self):
        """Test API health check"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/health")
            if response.status_code == 200:
                self.log_test("Health Check", "PASSED", "API is healthy")
            else:
                self.log_test("Health Check", "FAILED", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Health Check", "FAILED", str(e))
    
    def test_create_project(self):
        """Test project creation"""
        try:
            project_data = {
                "name": "Test Project for SAST",
                "description": "A test project for SAST tool validation",
                "repo_url": "https://github.com/test/sample-project.git",
                "language": "python",
                "framework": "flask"
            }
            
            response = self.session.post(f"{self.base_url}/api/v1/sast/projects", json=project_data)
            
            if response.status_code == 200:
                project = response.json()
                self.project_id = project["id"]
                self.log_test("Create Project", "PASSED", f"Project created with ID: {self.project_id}")
            else:
                self.log_test("Create Project", "FAILED", f"Status: {response.status_code}")
                
        except Exception as e:
            self.log_test("Create Project", "FAILED", str(e))
    
    def test_get_project(self):
        """Test getting project details"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/sast/projects/{self.project_id}")
            
            if response.status_code == 200:
                project = response.json()
                if project["name"] == "Test Project for SAST":
                    self.log_test("Get Project", "PASSED", "Project retrieved successfully")
                else:
                    self.log_test("Get Project", "FAILED", "Project data mismatch")
            else:
                self.log_test("Get Project", "FAILED", f"Status: {response.status_code}")
                
        except Exception as e:
            self.log_test("Get Project", "FAILED", str(e))
    
    def create_test_vulnerable_code(self):
        """Create a test vulnerable Python file"""
        vulnerable_code = '''
import os
import subprocess
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return 'Hello World!'

@app.route('/execute')
def execute_command():
    command = request.args.get('cmd')
    # Vulnerable: command injection
    result = subprocess.check_output(command, shell=True)
    return result

@app.route('/query')
def query_database():
    user_input = request.args.get('user')
    # Vulnerable: SQL injection
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    return cursor.fetchall()

@app.route('/file')
def read_file():
    filename = request.args.get('file')
    # Vulnerable: path traversal
    with open(filename, 'r') as f:
        return f.read()

if __name__ == '__main__':
    # Vulnerable: debug mode in production
    app.run(debug=True, host='0.0.0.0')
'''
        
        # Create temporary directory
        temp_dir = tempfile.mkdtemp()
        test_file = os.path.join(temp_dir, "vulnerable_app.py")
        
        with open(test_file, 'w') as f:
            f.write(vulnerable_code)
        
        # Create ZIP file
        zip_path = os.path.join(temp_dir, "test_project.zip")
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            zipf.write(test_file, "vulnerable_app.py")
        
        return zip_path, temp_dir
    
    def test_upload_and_scan(self):
        """Test file upload and scan"""
        try:
            zip_path, temp_dir = self.create_test_vulnerable_code()
            
            with open(zip_path, 'rb') as f:
                files = {'file': ('test_project.zip', f, 'application/zip')}
                data = {
                    'project_name': 'Vulnerable Test Project',
                    'project_description': 'A vulnerable application for SAST testing',
                    'scan_config': json.dumps({
                        'tools_enabled': ['bandit', 'pylint', 'semgrep'],
                        'severity_threshold': 'low',
                        'scan_type': 'full'
                    })
                }
                
                response = self.session.post(
                    f"{self.base_url}/api/v1/sast/scan/upload",
                    files=files,
                    data=data
                )
            
            # Cleanup
            shutil.rmtree(temp_dir)
            
            if response.status_code == 200:
                scan_data = response.json()
                self.scan_id = scan_data["id"]
                self.log_test("Upload and Scan", "PASSED", f"Scan started with ID: {self.scan_id}")
            else:
                self.log_test("Upload and Scan", "FAILED", f"Status: {response.status_code}")
                
        except Exception as e:
            self.log_test("Upload and Scan", "FAILED", str(e))
    
    def test_scan_progress(self):
        """Test scan progress monitoring"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/sast/scans/{self.scan_id}/progress")
            
            if response.status_code == 200:
                progress = response.json()
                self.log_test("Scan Progress", "PASSED", f"Status: {progress['status']}")
            else:
                self.log_test("Scan Progress", "FAILED", f"Status: {response.status_code}")
                
        except Exception as e:
            self.log_test("Scan Progress", "FAILED", str(e))
    
    def test_wait_for_scan_completion(self):
        """Wait for scan to complete"""
        max_wait_time = 300  # 5 minutes
        start_time = time.time()
        
        while time.time() - start_time < max_wait_time:
            try:
                response = self.session.get(f"{self.base_url}/api/v1/sast/scans/{self.scan_id}/progress")
                
                if response.status_code == 200:
                    progress = response.json()
                    if progress['status'] == 'completed':
                        self.log_test("Scan Completion", "PASSED", "Scan completed successfully")
                        return
                    elif progress['status'] == 'failed':
                        self.log_test("Scan Completion", "FAILED", "Scan failed")
                        return
                    
                    logger.info(f"Scan status: {progress['status']}, Progress: {progress.get('progress_percentage', 0)}%")
                    time.sleep(10)  # Wait 10 seconds before checking again
                else:
                    self.log_test("Scan Completion", "FAILED", f"Status: {response.status_code}")
                    return
                    
            except Exception as e:
                self.log_test("Scan Completion", "FAILED", str(e))
                return
        
        self.log_test("Scan Completion", "FAILED", "Scan timeout")
    
    def test_get_scan_details(self):
        """Test getting scan details"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/sast/scans/{self.scan_id}")
            
            if response.status_code == 200:
                scan = response.json()
                self.log_test("Get Scan Details", "PASSED", f"Scan retrieved: {scan['status']}")
            else:
                self.log_test("Get Scan Details", "FAILED", f"Status: {response.status_code}")
                
        except Exception as e:
            self.log_test("Get Scan Details", "FAILED", str(e))
    
    def test_get_vulnerabilities(self):
        """Test getting vulnerabilities"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/sast/scans/{self.scan_id}/vulnerabilities")
            
            if response.status_code == 200:
                vulnerabilities = response.json()
                self.log_test("Get Vulnerabilities", "PASSED", f"Found {len(vulnerabilities)} vulnerabilities")
                
                # Validate vulnerability structure
                if vulnerabilities:
                    vuln = vulnerabilities[0]
                    required_fields = ['id', 'scan_id', 'file_path', 'vulnerability', 'severity', 'tool_name']
                    missing_fields = [field for field in required_fields if field not in vuln]
                    
                    if not missing_fields:
                        self.log_test("Vulnerability Structure", "PASSED", "All required fields present")
                    else:
                        self.log_test("Vulnerability Structure", "FAILED", f"Missing fields: {missing_fields}")
                else:
                    self.log_test("Vulnerability Structure", "WARN", "No vulnerabilities found")
            else:
                self.log_test("Get Vulnerabilities", "FAILED", f"Status: {response.status_code}")
                
        except Exception as e:
            self.log_test("Get Vulnerabilities", "FAILED", str(e))
    
    def test_get_scan_summary(self):
        """Test getting scan summary"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/sast/scans/{self.scan_id}/summary")
            
            if response.status_code == 200:
                summary = response.json()
                self.log_test("Get Scan Summary", "PASSED", "Summary retrieved successfully")
                
                # Validate summary structure
                required_fields = ['scan_id', 'project_name', 'total_vulnerabilities', 'critical_count', 'high_count', 'medium_count', 'low_count']
                missing_fields = [field for field in required_fields if field not in summary]
                
                if not missing_fields:
                    self.log_test("Summary Structure", "PASSED", "All required fields present")
                else:
                    self.log_test("Summary Structure", "FAILED", f"Missing fields: {missing_fields}")
            else:
                self.log_test("Get Scan Summary", "FAILED", f"Status: {response.status_code}")
                
        except Exception as e:
            self.log_test("Get Scan Summary", "FAILED", str(e))
    
    def test_generate_report(self):
        """Test report generation"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/sast/scans/{self.scan_id}/reports/json")
            
            if response.status_code == 200:
                self.log_test("Generate Report", "PASSED", "JSON report generated successfully")
            else:
                self.log_test("Generate Report", "FAILED", f"Status: {response.status_code}")
                
        except Exception as e:
            self.log_test("Generate Report", "FAILED", str(e))
    
    def test_get_project_summary(self):
        """Test getting project summary"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/sast/projects/{self.project_id}/summary")
            
            if response.status_code == 200:
                summary = response.json()
                self.log_test("Get Project Summary", "PASSED", "Project summary retrieved")
            else:
                self.log_test("Get Project Summary", "FAILED", f"Status: {response.status_code}")
                
        except Exception as e:
            self.log_test("Get Project Summary", "FAILED", str(e))
    
    def test_get_overall_summary(self):
        """Test getting overall SAST summary"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/sast/summary")
            
            if response.status_code == 200:
                summary = response.json()
                self.log_test("Get Overall Summary", "PASSED", "Overall summary retrieved")
            else:
                self.log_test("Get Overall Summary", "FAILED", f"Status: {response.status_code}")
                
        except Exception as e:
            self.log_test("Get Overall Summary", "FAILED", str(e))
    
    def test_update_vulnerability_status(self):
        """Test updating vulnerability status"""
        try:
            # First get vulnerabilities
            response = self.session.get(f"{self.base_url}/api/v1/sast/scans/{self.scan_id}/vulnerabilities")
            
            if response.status_code == 200:
                vulnerabilities = response.json()
                
                if vulnerabilities:
                    vuln_id = vulnerabilities[0]["id"]
                    
                    # Update status
                    update_response = self.session.put(
                        f"{self.base_url}/api/v1/sast/vulnerabilities/{vuln_id}/status",
                        data={"status": "in_progress"}
                    )
                    
                    if update_response.status_code == 200:
                        self.log_test("Update Vulnerability Status", "PASSED", "Status updated successfully")
                    else:
                        self.log_test("Update Vulnerability Status", "FAILED", f"Status: {update_response.status_code}")
                else:
                    self.log_test("Update Vulnerability Status", "WARN", "No vulnerabilities to update")
            else:
                self.log_test("Update Vulnerability Status", "FAILED", f"Status: {response.status_code}")
                
        except Exception as e:
            self.log_test("Update Vulnerability Status", "FAILED", str(e))
    
    def test_delete_project(self):
        """Test project deletion"""
        try:
            response = self.session.delete(f"{self.base_url}/api/v1/sast/projects/{self.project_id}")
            
            if response.status_code == 200:
                self.log_test("Delete Project", "PASSED", "Project deleted successfully")
            else:
                self.log_test("Delete Project", "FAILED", f"Status: {response.status_code}")
                
        except Exception as e:
            self.log_test("Delete Project", "FAILED", str(e))
    
    def run_all_tests(self):
        """Run all SAST tool tests"""
        logger.info("🚀 Starting Comprehensive SAST Tool Test")
        
        # Health check
        self.test_health_check()
        
        # Project management tests
        self.test_create_project()
        self.test_get_project()
        
        # Scan tests
        self.test_upload_and_scan()
        self.test_scan_progress()
        self.test_wait_for_scan_completion()
        self.test_get_scan_details()
        
        # Results tests
        self.test_get_vulnerabilities()
        self.test_get_scan_summary()
        self.test_generate_report()
        
        # Summary tests
        self.test_get_project_summary()
        self.test_get_overall_summary()
        
        # Management tests
        self.test_update_vulnerability_status()
        self.test_delete_project()
        
        # Print results
        self.print_results()
    
    def print_results(self):
        """Print test results summary"""
        logger.info("\n" + "="*50)
        logger.info("SAST TOOL TEST SUMMARY")
        logger.info("="*50)
        logger.info(f"✅ Passed: {self.test_results['passed']}")
        logger.info(f"❌ Failed: {self.test_results['failed']}")
        logger.info(f"📊 Success Rate: {(self.test_results['passed'] / (self.test_results['passed'] + self.test_results['failed'])) * 100:.1f}%")
        
        if self.test_results['errors']:
            logger.info("\n❌ Errors:")
            for error in self.test_results['errors']:
                logger.info(f"  - {error}")
        
        logger.info("="*50)

def main():
    """Main test function"""
    try:
        logger.info("Starting SAST Tool Comprehensive Testing...")
        
        tester = SASTToolTester()
        tester.run_all_tests()
        
    except Exception as e:
        logger.error(f"Test execution failed: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 