#!/usr/bin/env python3
"""
Comprehensive Backend Endpoint Testing Script
Tests all backend endpoints and reports results
"""

import requests
import json
import time
from datetime import datetime

# Test configuration
BASE_URL = "http://localhost:8000"
TEST_USER = "admin@cybershield.com"
TEST_PASSWORD = "password"

# Test results
results = {
    "timestamp": datetime.now().isoformat(),
    "overall_status": "unknown",
    "endpoints": {},
    "summary": {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "errors": 0
    }
}

def log_result(endpoint, status, details="", error=""):
    """Log test result"""
    results["endpoints"][endpoint] = {
        "status": status,
        "details": details,
        "error": error,
        "timestamp": datetime.now().isoformat()
    }
    
    results["summary"]["total"] += 1
    if status == "PASS":
        results["summary"]["passed"] += 1
    elif status == "FAIL":
        results["summary"]["failed"] += 1
    else:
        results["summary"]["errors"] += 1
    
    print(f"[{status}] {endpoint}: {details}")
    if error:
        print(f"  Error: {error}")

def test_basic_endpoints():
    """Test basic endpoints that don't require authentication"""
    print("\n=== Testing Basic Endpoints ===")
    
    # Test root endpoint
    try:
        response = requests.get(f"{BASE_URL}/")
        if response.status_code == 200:
            log_result("GET /", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /", "ERROR", error=str(e))
    
    # Test health endpoint
    try:
        response = requests.get(f"{BASE_URL}/health")
        if response.status_code == 200:
            log_result("GET /health", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /health", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /health", "ERROR", error=str(e))
    
    # Test API health endpoint
    try:
        response = requests.get(f"{BASE_URL}/api/v1/health")
        if response.status_code == 200:
            log_result("GET /api/v1/health", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /api/v1/health", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /api/v1/health", "ERROR", error=str(e))
    
    # Test docs endpoint
    try:
        response = requests.get(f"{BASE_URL}/docs")
        if response.status_code == 200:
            log_result("GET /docs", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /docs", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /docs", "ERROR", error=str(e))

def test_authentication_endpoints():
    """Test authentication endpoints"""
    print("\n=== Testing Authentication Endpoints ===")
    
    # Test OAuth login endpoint
    try:
        response = requests.post(f"{BASE_URL}/api/v1/auth/login/oauth", 
                               data={"username": TEST_USER, "password": TEST_PASSWORD})
        if response.status_code == 200:
            data = response.json()
            if "access_token" in data:
                log_result("POST /api/v1/auth/login/oauth", "PASS", f"Status: {response.status_code}, Token received")
                return data["access_token"]
            else:
                log_result("POST /api/v1/auth/login/oauth", "FAIL", "No access token in response")
        else:
            log_result("POST /api/v1/auth/login/oauth", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("POST /api/v1/auth/login/oauth", "ERROR", error=str(e))
    
    return None

def test_protected_endpoints(access_token):
    """Test protected endpoints that require authentication"""
    print("\n=== Testing Protected Endpoints ===")
    
    if not access_token:
        log_result("Protected endpoints", "FAIL", "No access token available")
        return
    
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Test protected route
    try:
        response = requests.get(f"{BASE_URL}/protected", headers=headers)
        if response.status_code == 200:
            log_result("GET /protected", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /protected", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /protected", "ERROR", error=str(e))
    
    # Test user info endpoint
    try:
        response = requests.get(f"{BASE_URL}/api/v1/auth/me", headers=headers)
        if response.status_code == 200:
            log_result("GET /api/v1/auth/me", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /api/v1/auth/me", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /api/v1/auth/me", "ERROR", error=str(e))

def test_iam_endpoints(access_token):
    """Test IAM endpoints"""
    print("\n=== Testing IAM Endpoints ===")
    
    if not access_token:
        log_result("IAM endpoints", "FAIL", "No access token available")
        return
    
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Test IAM health endpoint
    try:
        response = requests.get(f"{BASE_URL}/api/v1/iam/health", headers=headers)
        if response.status_code == 200:
            log_result("GET /api/v1/iam/health", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /api/v1/iam/health", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /api/v1/iam/health", "ERROR", error=str(e))
    
    # Test IAM dashboard stats
    try:
        response = requests.get(f"{BASE_URL}/api/v1/iam/dashboard/stats", headers=headers)
        if response.status_code == 200:
            log_result("GET /api/v1/iam/dashboard/stats", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /api/v1/iam/dashboard/stats", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /api/v1/iam/dashboard/stats", "ERROR", error=str(e))

def test_rasp_endpoints():
    """Test RASP endpoints"""
    print("\n=== Testing RASP Endpoints ===")
    
    # Test RASP overview endpoint
    try:
        response = requests.get(f"{BASE_URL}/api/rasp/dashboard/overview")
        if response.status_code == 200:
            log_result("GET /api/rasp/dashboard/overview", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /api/rasp/dashboard/overview", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /api/rasp/dashboard/overview", "ERROR", error=str(e))
    
    # Test RASP agents endpoint
    try:
        response = requests.get(f"{BASE_URL}/api/rasp/agents")
        if response.status_code == 200:
            log_result("GET /api/rasp/agents", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /api/rasp/agents", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /api/rasp/agents", "ERROR", error=str(e))

def test_dast_endpoints():
    """Test DAST endpoints"""
    print("\n=== Testing DAST Endpoints ===")
    
    # Test DAST test endpoint
    try:
        response = requests.get(f"{BASE_URL}/dast/test")
        if response.status_code == 200:
            log_result("GET /dast/test", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /dast/test", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /dast/test", "ERROR", error=str(e))
    
    # Test DAST overview endpoint
    try:
        response = requests.get(f"{BASE_URL}/dast/overview")
        if response.status_code == 200:
            log_result("GET /dast/overview", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /dast/overview", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /dast/overview", "ERROR", error=str(e))

def test_sast_endpoints():
    """Test SAST endpoints"""
    print("\n=== Testing SAST Endpoints ===")
    
    # Test SAST dashboard endpoint
    try:
        response = requests.get(f"{BASE_URL}/api/v1/sast/dashboard")
        if response.status_code == 200:
            log_result("GET /api/v1/sast/dashboard", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /api/v1/sast/dashboard", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /api/v1/sast/dashboard", "ERROR", error=str(e))
    
    # Test SAST overview endpoint
    try:
        response = requests.get(f"{BASE_URL}/api/v1/sast/overview")
        if response.status_code == 200:
            log_result("GET /api/v1/sast/overview", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /api/v1/sast/overview", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /api/v1/sast/overview", "ERROR", error=str(e))

def test_cloud_security_endpoints():
    """Test Cloud Security endpoints"""
    print("\n=== Testing Cloud Security Endpoints ===")
    
    # Test cloud security overview endpoint
    try:
        response = requests.get(f"{BASE_URL}/api/v1/cloud-security/api/v1/cloud-security/dashboard/overview")
        if response.status_code == 200:
            log_result("GET /api/v1/cloud-security/dashboard/overview", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /api/v1/cloud-security/dashboard/overview", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /api/v1/cloud-security/dashboard/overview", "ERROR", error=str(e))

def test_device_control_endpoints():
    """Test Device Control endpoints"""
    print("\n=== Testing Device Control Endpoints ===")
    
    # Test device control summary endpoint
    try:
        response = requests.get(f"{BASE_URL}/api/v1/device-control/summary")
        if response.status_code == 200:
            log_result("GET /api/v1/device-control/summary", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /api/v1/device-control/summary", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /api/v1/device-control/summary", "ERROR", error=str(e))
    
    # Test device control health endpoint
    try:
        response = requests.get(f"{BASE_URL}/api/v1/device-control/health")
        if response.status_code == 200:
            log_result("GET /api/v1/device-control/health", "PASS", f"Status: {response.status_code}")
        else:
            log_result("GET /api/v1/device-control/health", "FAIL", f"Status: {response.status_code}")
    except Exception as e:
        log_result("GET /api/v1/device-control/health", "ERROR", error=str(e))

def generate_summary():
    """Generate test summary"""
    print("\n=== Test Summary ===")
    
    total = results["summary"]["total"]
    passed = results["summary"]["passed"]
    failed = results["summary"]["failed"]
    errors = results["summary"]["errors"]
    
    print(f"Total Endpoints Tested: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Errors: {errors}")
    
    success_rate = (passed / total * 100) if total > 0 else 0
    print(f"Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 80:
        results["overall_status"] = "PASS"
        print("Overall Status: PASS")
    elif success_rate >= 60:
        results["overall_status"] = "PARTIAL"
        print("Overall Status: PARTIAL")
    else:
        results["overall_status"] = "FAIL"
        print("Overall Status: FAIL")

def main():
    """Main test function"""
    print("CyberShield Backend Endpoint Testing")
    print("=" * 50)
    
    # Test basic endpoints
    test_basic_endpoints()
    
    # Test authentication and get token
    access_token = test_authentication_endpoints()
    
    # Test protected endpoints
    test_protected_endpoints(access_token)
    
    # Test IAM endpoints
    test_iam_endpoints(access_token)
    
    # Test other module endpoints
    test_rasp_endpoints()
    test_dast_endpoints()
    test_sast_endpoints()
    test_cloud_security_endpoints()
    test_device_control_endpoints()
    
    # Generate summary
    generate_summary()
    
    # Save results
    with open("endpoint_test_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nTest results saved to: endpoint_test_results.json")
    
    return results["overall_status"] == "PASS"

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1) 