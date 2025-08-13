#!/usr/bin/env python3
"""
Endpoint Integration Test Script
Tests the integration between frontend services and backend endpoints
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Any
import sys
import os

# Configuration
BASE_URL = "http://localhost:8000"
API_VERSION = "v1"
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json"
}

# Test endpoints to verify
ENDPOINTS = {
    "auth": {
        "login": f"/api/{API_VERSION}/auth/login",
        "register": f"/api/{API_VERSION}/auth/register",
        "refresh": f"/api/{API_VERSION}/auth/refresh",
        "logout": f"/api/{API_VERSION}/auth/logout"
    },
    "sast": {
        "projects": f"/api/{API_VERSION}/sast/projects",
        "scans": f"/api/{API_VERSION}/sast/scans",
        "vulnerabilities": f"/api/{API_VERSION}/sast/vulnerabilities",
        "metrics": f"/api/{API_VERSION}/sast/metrics"
    },
    "dast": {
        "projects": f"/api/{API_VERSION}/dast/projects",
        "scans": f"/api/{API_VERSION}/dast/scans",
        "reports": f"/api/{API_VERSION}/dast/reports"
    },
    "rasp": {
        "status": f"/api/{API_VERSION}/rasp/status",
        "alerts": f"/api/{API_VERSION}/rasp/alerts",
        "config": f"/api/{API_VERSION}/rasp/config"
    },
    "cloud_security": {
        "status": f"/api/{API_VERSION}/cloud-security/status",
        "providers": f"/api/{API_VERSION}/cloud-security/providers",
        "compliance": f"/api/{API_VERSION}/cloud-security/compliance"
    },
    "endpoint_security": {
        "status": f"/api/{API_VERSION}/endpoint-antivirus-edr/status",
        "threats": f"/api/{API_VERSION}/endpoint-antivirus-edr/threats",
        "quarantine": f"/api/{API_VERSION}/endpoint-antivirus-edr/quarantine"
    },
    "device_control": {
        "devices": f"/api/{API_VERSION}/device-control/devices",
        "policies": f"/api/{API_VERSION}/device-control/policies",
        "logs": f"/api/{API_VERSION}/device-control/logs"
    },
    "network_security": {
        "status": f"/api/{API_VERSION}/network-security/status",
        "threats": f"/api/{API_VERSION}/network-security/threats",
        "traffic": f"/api/{API_VERSION}/network-security/traffic"
    },
    "iam": {
        "users": f"/api/{API_VERSION}/iam/users",
        "roles": f"/api/{API_VERSION}/iam/roles",
        "permissions": f"/api/{API_VERSION}/iam/permissions"
    },
    "data_protection": {
        "status": f"/api/{API_VERSION}/data-protection/status",
        "policies": f"/api/{API_VERSION}/data-protection/policies",
        "compliance": f"/api/{API_VERSION}/data-protection/compliance"
    },
    "threat_intelligence": {
        "indicators": f"/api/{API_VERSION}/threat-intelligence/indicators",
        "threats": f"/api/{API_VERSION}/threat-intelligence/threats",
        "feeds": f"/api/{API_VERSION}/threat-intelligence/feeds"
    }
}

class EndpointIntegrationTester:
    def __init__(self):
        self.results = {}
        self.auth_token = None
        self.test_start_time = datetime.now()
        
    def log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
        
    def test_health_check(self) -> bool:
        """Test basic health check endpoint"""
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=10)
            if response.status_code == 200:
                self.log("✅ Health check passed", "SUCCESS")
                return True
            else:
                self.log(f"❌ Health check failed: {response.status_code}", "ERROR")
                return False
        except requests.exceptions.RequestException as e:
            self.log(f"❌ Health check error: {e}", "ERROR")
            return False
    
    def test_auth_endpoints(self) -> Dict[str, Any]:
        """Test authentication endpoints"""
        self.log("Testing authentication endpoints...")
        auth_results = {}
        
        # Test registration
        try:
            register_data = {
                "email": "test@example.com",
                "password": "testpassword123",
                "full_name": "Test User"
            }
            response = requests.post(
                f"{BASE_URL}{ENDPOINTS['auth']['register']}", 
                json=register_data, 
                headers=HEADERS,
                timeout=10
            )
            if response.status_code in [200, 201, 409]:  # 409 = user already exists
                auth_results['register'] = "PASS"
                self.log("✅ Registration endpoint working", "SUCCESS")
            else:
                auth_results['register'] = f"FAIL: {response.status_code}"
                self.log(f"❌ Registration failed: {response.status_code}", "ERROR")
        except Exception as e:
            auth_results['register'] = f"ERROR: {str(e)}"
            self.log(f"❌ Registration error: {e}", "ERROR")
        
        # Test login
        try:
            login_data = {
                "email": "test@example.com",
                "password": "testpassword123"
            }
            response = requests.post(
                f"{BASE_URL}{ENDPOINTS['auth']['login']}", 
                json=login_data, 
                headers=HEADERS,
                timeout=10
            )
            if response.status_code == 200:
                auth_results['login'] = "PASS"
                self.log("✅ Login endpoint working", "SUCCESS")
                # Extract token for other tests
                try:
                    token_data = response.json()
                    if 'access_token' in token_data:
                        self.auth_token = token_data['access_token']
                        HEADERS['Authorization'] = f"Bearer {self.auth_token}"
                        self.log("✅ Authentication token obtained", "SUCCESS")
                except:
                    pass
            else:
                auth_results['login'] = f"FAIL: {response.status_code}"
                self.log(f"❌ Login failed: {response.status_code}", "ERROR")
        except Exception as e:
            auth_results['login'] = f"ERROR: {str(e)}"
            self.log(f"❌ Login error: {e}", "ERROR")
        
        return auth_results
    
    def test_module_endpoints(self, module_name: str, module_endpoints: Dict[str, str]) -> Dict[str, Any]:
        """Test endpoints for a specific module"""
        self.log(f"Testing {module_name} endpoints...")
        module_results = {}
        
        for endpoint_name, endpoint_path in module_endpoints.items():
            try:
                # Use GET method for most endpoints
                response = requests.get(
                    f"{BASE_URL}{endpoint_path}", 
                    headers=HEADERS,
                    timeout=10
                )
                
                if response.status_code in [200, 201, 204]:
                    module_results[endpoint_name] = "PASS"
                    self.log(f"✅ {module_name}.{endpoint_name}: PASS", "SUCCESS")
                elif response.status_code == 401:
                    module_results[endpoint_name] = "AUTH_REQUIRED"
                    self.log(f"⚠️ {module_name}.{endpoint_name}: Authentication required", "WARNING")
                elif response.status_code == 404:
                    module_results[endpoint_name] = "NOT_FOUND"
                    self.log(f"⚠️ {module_name}.{endpoint_name}: Endpoint not found", "WARNING")
                else:
                    module_results[endpoint_name] = f"FAIL: {response.status_code}"
                    self.log(f"❌ {module_name}.{endpoint_name}: {response.status_code}", "ERROR")
                    
            except requests.exceptions.RequestException as e:
                module_results[endpoint_name] = f"ERROR: {str(e)}"
                self.log(f"❌ {module_name}.{endpoint_name}: {e}", "ERROR")
            except Exception as e:
                module_results[endpoint_name] = f"ERROR: {str(e)}"
                self.log(f"❌ {module_name}.{endpoint_name}: {e}", "ERROR")
        
        return module_results
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all endpoint integration tests"""
        self.log("🚀 Starting Endpoint Integration Tests", "INFO")
        self.log(f"Base URL: {BASE_URL}", "INFO")
        self.log(f"Test started at: {self.test_start_time}", "INFO")
        
        # Test health check first
        if not self.test_health_check():
            self.log("❌ Health check failed. Stopping tests.", "ERROR")
            return {"status": "FAILED", "reason": "Health check failed"}
        
        # Test authentication
        auth_results = self.test_auth_endpoints()
        self.results['auth'] = auth_results
        
        # Test all module endpoints
        for module_name, module_endpoints in ENDPOINTS.items():
            if module_name != 'auth':  # Skip auth as it's already tested
                module_results = self.test_module_endpoints(module_name, module_endpoints)
                self.results[module_name] = module_results
        
        return self.results
    
    def generate_report(self) -> str:
        """Generate a comprehensive test report"""
        test_end_time = datetime.now()
        test_duration = test_end_time - self.test_start_time
        
        report = []
        report.append("=" * 80)
        report.append("ENDPOINT INTEGRATION TEST REPORT")
        report.append("=" * 80)
        report.append(f"Test Start Time: {self.test_start_time}")
        report.append(f"Test End Time: {test_end_time}")
        report.append(f"Test Duration: {test_duration}")
        report.append("")
        
        # Summary statistics
        total_endpoints = 0
        passed_endpoints = 0
        failed_endpoints = 0
        auth_required_endpoints = 0
        not_found_endpoints = 0
        error_endpoints = 0
        
        for module_name, module_results in self.results.items():
            if module_name == 'auth':
                continue
                
            report.append(f"📋 {module_name.upper()} MODULE")
            report.append("-" * 40)
            
            for endpoint_name, result in module_results.items():
                total_endpoints += 1
                if result == "PASS":
                    passed_endpoints += 1
                    report.append(f"✅ {endpoint_name}: PASS")
                elif result == "AUTH_REQUIRED":
                    auth_required_endpoints += 1
                    report.append(f"⚠️ {endpoint_name}: Authentication Required")
                elif result == "NOT_FOUND":
                    not_found_endpoints += 1
                    report.append(f"⚠️ {endpoint_name}: Not Found")
                elif result.startswith("FAIL"):
                    failed_endpoints += 1
                    report.append(f"❌ {endpoint_name}: {result}")
                else:
                    error_endpoints += 1
                    report.append(f"❌ {endpoint_name}: {result}")
            
            report.append("")
        
        # Overall summary
        report.append("=" * 80)
        report.append("OVERALL SUMMARY")
        report.append("=" * 80)
        report.append(f"Total Endpoints Tested: {total_endpoints}")
        report.append(f"✅ Passed: {passed_endpoints}")
        report.append(f"⚠️ Auth Required: {auth_required_endpoints}")
        report.append(f"⚠️ Not Found: {not_found_endpoints}")
        report.append(f"❌ Failed: {failed_endpoints}")
        report.append(f"❌ Errors: {error_endpoints}")
        
        # Calculate success rate
        if total_endpoints > 0:
            success_rate = (passed_endpoints / total_endpoints) * 100
            report.append(f"Success Rate: {success_rate:.1f}%")
            
            if success_rate >= 90:
                overall_status = "🟢 EXCELLENT"
            elif success_rate >= 80:
                overall_status = "🟡 GOOD"
            elif success_rate >= 70:
                overall_status = "🟠 FAIR"
            else:
                overall_status = "🔴 POOR"
            
            report.append(f"Overall Status: {overall_status}")
        
        report.append("")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def save_results(self, filename: str = None):
        """Save test results to file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"endpoint_integration_results_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            self.log(f"Results saved to: {filename}", "INFO")
        except Exception as e:
            self.log(f"Error saving results: {e}", "ERROR")

def main():
    """Main function to run the integration tests"""
    print("🔍 CyberShield Endpoint Integration Tester")
    print("=" * 50)
    
    # Check if backend is accessible
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code != 200:
            print(f"❌ Backend health check failed: {response.status_code}")
            print("Please ensure the backend server is running on http://localhost:8000")
            sys.exit(1)
    except requests.exceptions.RequestException:
        print("❌ Cannot connect to backend server")
        print("Please ensure the backend server is running on http://localhost:8000")
        sys.exit(1)
    
    # Run tests
    tester = EndpointIntegrationTester()
    results = tester.run_all_tests()
    
    # Generate and display report
    report = tester.generate_report()
    print("\n" + report)
    
    # Save results
    tester.save_results()
    
    # Exit with appropriate code
    if 'status' in results and results['status'] == 'FAILED':
        sys.exit(1)
    else:
        # Check if we have any successful endpoints
        total_passed = sum(1 for module in results.values() 
                          if isinstance(module, dict) 
                          for result in module.values() 
                          if result == "PASS")
        
        if total_passed > 0:
            print(f"\n✅ Integration test completed with {total_passed} successful endpoints")
            sys.exit(0)
        else:
            print("\n❌ No endpoints passed the integration test")
            sys.exit(1)

if __name__ == "__main__":
    main()
