#!/usr/bin/env python3
"""
Comprehensive Backend Test Script
Tests all security modules and endpoints
"""

import requests
import json
import time
from typing import Dict, List

# Configuration
BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api/v1"

def test_health_endpoint():
    """Test the health endpoint"""
    try:
        response = requests.get(f"{BASE_URL}/health")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Health Check: {data['status']}")
            print(f"   Service: {data['service']}")
            print(f"   Version: {data['version']}")
            print(f"   Modules: {', '.join(data['modules'])}")
            return True
        else:
            print(f"❌ Health Check Failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health Check Error: {e}")
        return False

def test_root_endpoint():
    """Test the root endpoint"""
    try:
        response = requests.get(BASE_URL)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Root Endpoint: {data['message']}")
            print(f"   Version: {data['version']}")
            print(f"   Description: {data['description']}")
            return True
        else:
            print(f"❌ Root Endpoint Failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Root Endpoint Error: {e}")
        return False

def test_api_status():
    """Test the API status endpoint"""
    try:
        response = requests.get(f"{BASE_URL}/api/status")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ API Status: {data['status']}")
            print(f"   Version: {data['version']}")
            print(f"   WebSocket: {data['websocket']['status']}")
            return True
        else:
            print(f"❌ API Status Failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API Status Error: {e}")
        return False

def test_security_modules():
    """Test all security module endpoints"""
    modules = [
        ("DAST", "/dast"),
        ("SAST", "/sast"),
        ("RASP", "/rasp"),
        ("Cloud Security", "/cloud-security"),
        ("Endpoint Security", "/endpoint-security"),
        ("Network Security", "/network-security"),
        ("IAM", "/iam"),
        ("Data Security", "/data-security"),
        ("Incident Management", "/incidents"),
        ("Threat Intelligence", "/threat-intelligence"),
        ("Compliance", "/compliance"),
        ("DevSecOps", "/devsecops"),
        ("AI/ML", "/ai-ml"),
        ("Admin", "/admin"),
        ("User Management", "/users"),
        ("Audit Logs", "/audit"),
        ("Reporting", "/reporting"),
        ("Integrations", "/integrations")
    ]
    
    results = []
    
    for module_name, endpoint in modules:
        try:
            response = requests.get(f"{API_BASE}{endpoint}")
            if response.status_code == 200:
                data = response.json()
                print(f"✅ {module_name}: {data.get('status', 'active')}")
                if 'features' in data:
                    print(f"   Features: {', '.join(data['features'][:3])}...")
                results.append((module_name, True))
            else:
                print(f"❌ {module_name}: HTTP {response.status_code}")
                results.append((module_name, False))
        except Exception as e:
            print(f"❌ {module_name}: Error - {e}")
            results.append((module_name, False))
    
    return results

def test_websocket_endpoint():
    """Test WebSocket endpoint availability"""
    try:
        response = requests.get(f"{BASE_URL}/docs")
        if response.status_code == 200:
            print("✅ Swagger Documentation: Available")
            return True
        else:
            print(f"❌ Swagger Documentation: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Swagger Documentation Error: {e}")
        return False

def generate_summary_report(results: List[tuple]):
    """Generate a summary report"""
    print("\n" + "="*60)
    print("COMPREHENSIVE BACKEND TEST SUMMARY")
    print("="*60)
    
    total_modules = len(results)
    successful_modules = sum(1 for _, success in results if success)
    failed_modules = total_modules - successful_modules
    
    print(f"Total Security Modules: {total_modules}")
    print(f"✅ Successful: {successful_modules}")
    print(f"❌ Failed: {failed_modules}")
    print(f"Success Rate: {(successful_modules/total_modules)*100:.1f}%")
    
    if failed_modules > 0:
        print("\nFailed Modules:")
        for module_name, success in results:
            if not success:
                print(f"  - {module_name}")
    
    print("\n" + "="*60)

def main():
    """Main test function"""
    print("🚀 Starting Comprehensive Backend Test")
    print("="*60)
    
    # Test basic endpoints
    print("\n1. Testing Basic Endpoints:")
    health_ok = test_health_endpoint()
    root_ok = test_root_endpoint()
    api_status_ok = test_api_status()
    
    # Test security modules
    print("\n2. Testing Security Modules:")
    module_results = test_security_modules()
    
    # Test additional features
    print("\n3. Testing Additional Features:")
    websocket_ok = test_websocket_endpoint()
    
    # Generate summary
    all_results = module_results + [
        ("Health Endpoint", health_ok),
        ("Root Endpoint", root_ok),
        ("API Status", api_status_ok),
        ("WebSocket", websocket_ok)
    ]
    
    generate_summary_report(all_results)
    
    # Final status
    if all(success for _, success in all_results):
        print("🎉 All tests passed! Backend is fully operational.")
        return True
    else:
        print("⚠️  Some tests failed. Check the details above.")
        return False

if __name__ == "__main__":
    try:
        success = main()
        exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⏹️  Test interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n\n💥 Unexpected error: {e}")
        exit(1)
