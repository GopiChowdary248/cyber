#!/usr/bin/env python3
"""
Comprehensive Backend Testing Script
Tests all backend components and identifies issues
"""

import asyncio
import aiohttp
import json
import sys
import os
import subprocess
import time
import requests
from typing import Dict, List, Any
import traceback

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

class BackendTester:
    def __init__(self):
        self.base_url = "http://localhost:8000"
        self.results = {
            "server_status": False,
            "endpoints": {},
            "errors": [],
            "warnings": []
        }
        
    def log(self, message: str, level: str = "INFO"):
        """Log messages with timestamp"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
        
    def test_server_startup(self) -> bool:
        """Test if the server can start properly"""
        self.log("Testing server startup...")
        
        try:
            # Try to start the server
            process = subprocess.Popen(
                ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"],
                cwd="backend",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait a bit for startup
            time.sleep(5)
            
            # Check if process is still running
            if process.poll() is None:
                self.log("Server started successfully", "SUCCESS")
                process.terminate()
                return True
            else:
                stdout, stderr = process.communicate()
                self.log(f"Server failed to start. STDOUT: {stdout}", "ERROR")
                self.log(f"Server failed to start. STDERR: {stderr}", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Error testing server startup: {e}", "ERROR")
            return False
    
    def test_health_endpoint(self) -> bool:
        """Test the health endpoint"""
        self.log("Testing health endpoint...")
        
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log(f"Health endpoint working: {data}", "SUCCESS")
                self.results["endpoints"]["/health"] = {
                    "status": "working",
                    "response": data
                }
                return True
            else:
                self.log(f"Health endpoint failed with status {response.status_code}", "ERROR")
                self.results["endpoints"]["/health"] = {
                    "status": "failed",
                    "status_code": response.status_code
                }
                return False
                
        except requests.exceptions.ConnectionError:
            self.log("Cannot connect to server - server may not be running", "ERROR")
            return False
        except Exception as e:
            self.log(f"Error testing health endpoint: {e}", "ERROR")
            return False
    
    def test_auth_endpoints(self) -> Dict[str, bool]:
        """Test authentication endpoints"""
        self.log("Testing authentication endpoints...")
        
        auth_results = {}
        
        # Test login endpoint
        try:
            login_data = {
                "username": "admin@cybershield.com",
                "password": "password",
                "device_info": {"type": "web"}
            }
            
            response = requests.post(
                f"{self.base_url}/api/v1/auth/login",
                json=login_data,
                timeout=10
            )
            
            if response.status_code in [200, 401]:  # 401 is expected for invalid credentials
                self.log(f"Login endpoint responding: {response.status_code}", "SUCCESS")
                auth_results["/api/v1/auth/login"] = True
            else:
                self.log(f"Login endpoint failed: {response.status_code}", "ERROR")
                auth_results["/api/v1/auth/login"] = False
                
        except Exception as e:
            self.log(f"Error testing login endpoint: {e}", "ERROR")
            auth_results["/api/v1/auth/login"] = False
        
        # Test OAuth login endpoint
        try:
            oauth_data = {
                "username": "admin@cybershield.com",
                "password": "password"
            }
            
            response = requests.post(
                f"{self.base_url}/api/v1/auth/login/oauth",
                data=oauth_data,
                timeout=10
            )
            
            if response.status_code in [200, 401]:
                self.log(f"OAuth login endpoint responding: {response.status_code}", "SUCCESS")
                auth_results["/api/v1/auth/login/oauth"] = True
            else:
                self.log(f"OAuth login endpoint failed: {response.status_code}", "ERROR")
                auth_results["/api/v1/auth/login/oauth"] = False
                
        except Exception as e:
            self.log(f"Error testing OAuth login endpoint: {e}", "ERROR")
            auth_results["/api/v1/auth/login/oauth"] = False
        
        self.results["endpoints"]["auth"] = auth_results
        return auth_results
    
    def test_iam_endpoints(self) -> Dict[str, bool]:
        """Test IAM endpoints"""
        self.log("Testing IAM endpoints...")
        
        iam_results = {}
        
        # Test IAM login endpoint
        try:
            login_data = {
                "username": "admin@cybershield.com",
                "password": "password",
                "device_info": {"type": "web"}
            }
            
            response = requests.post(
                f"{self.base_url}/api/v1/iam/auth/login",
                json=login_data,
                timeout=10
            )
            
            if response.status_code in [200, 401]:
                self.log(f"IAM login endpoint responding: {response.status_code}", "SUCCESS")
                iam_results["/api/v1/iam/auth/login"] = True
            else:
                self.log(f"IAM login endpoint failed: {response.status_code}", "ERROR")
                iam_results["/api/v1/iam/auth/login"] = False
                
        except Exception as e:
            self.log(f"Error testing IAM login endpoint: {e}", "ERROR")
            iam_results["/api/v1/iam/auth/login"] = False
        
        # Test IAM health endpoint
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/iam/health",
                timeout=10
            )
            
            if response.status_code == 200:
                self.log("IAM health endpoint working", "SUCCESS")
                iam_results["/api/v1/iam/health"] = True
            else:
                self.log(f"IAM health endpoint failed: {response.status_code}", "ERROR")
                iam_results["/api/v1/iam/health"] = False
                
        except Exception as e:
            self.log(f"Error testing IAM health endpoint: {e}", "ERROR")
            iam_results["/api/v1/iam/health"] = False
        
        self.results["endpoints"]["iam"] = iam_results
        return iam_results
    
    def test_api_documentation(self) -> bool:
        """Test API documentation endpoints"""
        self.log("Testing API documentation...")
        
        try:
            # Test OpenAPI docs
            response = requests.get(f"{self.base_url}/docs", timeout=10)
            if response.status_code == 200:
                self.log("API documentation (docs) accessible", "SUCCESS")
                self.results["endpoints"]["/docs"] = {"status": "working"}
                return True
            else:
                self.log(f"API documentation failed: {response.status_code}", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Error testing API documentation: {e}", "ERROR")
            return False
    
    def test_database_connection(self) -> bool:
        """Test database connection"""
        self.log("Testing database connection...")
        
        try:
            # Import database module
            sys.path.append("backend")
            from app.core.database import check_db_connection
            
            if check_db_connection():
                self.log("Database connection successful", "SUCCESS")
                return True
            else:
                self.log("Database connection failed", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Error testing database connection: {e}", "ERROR")
            return False
    
    def check_import_issues(self) -> List[str]:
        """Check for import issues in the backend"""
        self.log("Checking for import issues...")
        
        issues = []
        
        # Test importing main modules
        modules_to_test = [
            "app.core.config",
            "app.core.database", 
            "app.core.security",
            "app.models.iam",
            "app.schemas.iam",
            "app.services.iam_service",
            "app.api.v1.endpoints.auth",
            "app.api.v1.endpoints.iam"
        ]
        
        for module in modules_to_test:
            try:
                __import__(module)
                self.log(f"Module {module} imports successfully", "SUCCESS")
            except Exception as e:
                self.log(f"Module {module} import failed: {e}", "ERROR")
                issues.append(f"{module}: {e}")
        
        return issues
    
    def run_comprehensive_test(self):
        """Run all tests"""
        self.log("Starting comprehensive backend testing...")
        
        # Check import issues first
        import_issues = self.check_import_issues()
        if import_issues:
            self.results["errors"].extend(import_issues)
        
        # Test database connection
        db_ok = self.test_database_connection()
        
        # Test server startup
        server_ok = self.test_server_startup()
        self.results["server_status"] = server_ok
        
        if server_ok:
            # Test endpoints
            health_ok = self.test_health_endpoint()
            auth_results = self.test_auth_endpoints()
            iam_results = self.test_iam_endpoints()
            docs_ok = self.test_api_documentation()
        
        # Generate summary
        self.generate_summary()
        
        return self.results
    
    def generate_summary(self):
        """Generate test summary"""
        self.log("=" * 50)
        self.log("BACKEND TESTING SUMMARY")
        self.log("=" * 50)
        
        # Server status
        if self.results["server_status"]:
            self.log("✓ Server startup: SUCCESS", "SUCCESS")
        else:
            self.log("✗ Server startup: FAILED", "ERROR")
        
        # Endpoint status
        self.log("\nEndpoint Status:")
        for endpoint, status in self.results["endpoints"].items():
            if isinstance(status, dict) and status.get("status") == "working":
                self.log(f"✓ {endpoint}: WORKING", "SUCCESS")
            elif isinstance(status, dict):
                self.log(f"✗ {endpoint}: FAILED", "ERROR")
            else:
                self.log(f"? {endpoint}: UNKNOWN", "WARNING")
        
        # Errors
        if self.results["errors"]:
            self.log("\nErrors Found:")
            for error in self.results["errors"]:
                self.log(f"✗ {error}", "ERROR")
        
        # Warnings
        if self.results["warnings"]:
            self.log("\nWarnings:")
            for warning in self.results["warnings"]:
                self.log(f"! {warning}", "WARNING")
        
        self.log("=" * 50)

def main():
    """Main function"""
    tester = BackendTester()
    results = tester.run_comprehensive_test()
    
    # Save results to file
    with open("backend_test_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\nResults saved to backend_test_results.json")
    
    # Return exit code based on results
    if results["errors"]:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main() 