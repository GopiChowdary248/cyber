#!/usr/bin/env python3
"""
Backend Connection Test Script
Tests the connection to the CyberShield backend and verifies all endpoints
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
        response = requests.get(f"{BASE_URL}/health", timeout=10)
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
        response = requests.get(BASE_URL, timeout=10)
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
        response = requests.get(f"{BASE_URL}/api/status", timeout=10)
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
        ("AI/ML", "/ai-ml"),
        ("DevSecOps", "/devsecops"),
        ("Compliance", "/compliance"),
        ("Network Security", "/network-security"),
        ("Data Security", "/data-security"),
        ("IAM Security", "/users/management"),
        ("Incident Management", "/incidents"),
        ("Threat Intelligence", "/threat-intelligence"),
        ("Admin", "/admin"),
        ("User Management", "/users/profiles"),
        ("Audit Logs", "/audit"),
        ("Reporting", "/reporting"),
        ("Integrations", "/integrations")
    ]
    
    results = []
    
    for module_name, endpoint in modules:
        try:
            response = requests.get(f"{API_BASE}{endpoint}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                print(f"✅ {module_name}: {data.get('status', 'active')}")
                if 'features' in data:
                    print(f"   Features: {', '.join(data['features'][:3])}...")
                results.append((module_name, True))
            elif response.status_code == 401:
                print(f"🔒 {module_name}: Authentication required (expected)")
                results.append((module_name, True))
            else:
                print(f"❌ {module_name}: HTTP {response.status_code}")
                results.append((module_name, False))
        except Exception as e:
            print(f"❌ {module_name}: Error - {e}")
            results.append((module_name, False))
    
    return results

def test_swagger_documentation():
    """Test Swagger documentation availability"""
    try:
        response = requests.get(f"{BASE_URL}/docs", timeout=10)
        if response.status_code == 200:
            print("✅ Swagger Documentation: Available")
            return True
        else:
            print(f"❌ Swagger Documentation: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Swagger Documentation Error: {e}")
        return False

def test_openapi_spec():
    """Test OpenAPI specification availability"""
    try:
        response = requests.get(f"{BASE_URL}/openapi.json", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ OpenAPI Specification: Available")
            print(f"   Title: {data.get('info', {}).get('title', 'Unknown')}")
            print(f"   Version: {data.get('info', {}).get('version', 'Unknown')}")
            print(f"   Endpoints: {len(data.get('paths', {}))}")
            return True
        else:
            print(f"❌ OpenAPI Specification: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ OpenAPI Specification Error: {e}")
        return False

def test_websocket_endpoint():
    """Test WebSocket endpoint availability"""
    try:
        response = requests.get(f"{BASE_URL}/ws", timeout=10)
        if response.status_code in [200, 101, 426]:  # 101 = switching protocols, 426 = upgrade required
            print("✅ WebSocket Endpoint: Available")
            return True
        else:
            print(f"❌ WebSocket Endpoint: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ WebSocket Endpoint Error: {e}")
        return False

def generate_summary_report(results: List[tuple]):
    """Generate a summary report"""
    print("\n" + "="*60)
    print("BACKEND CONNECTION TEST SUMMARY")
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
    print("🚀 Starting Backend Connection Test")
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
    swagger_ok = test_swagger_documentation()
    openapi_ok = test_openapi_spec()
    websocket_ok = test_websocket_endpoint()
    
    # Generate summary
    all_results = module_results + [
        ("Health Endpoint", health_ok),
        ("Root Endpoint", root_ok),
        ("API Status", api_status_ok),
        ("Swagger Documentation", swagger_ok),
        ("OpenAPI Specification", openapi_ok),
        ("WebSocket Endpoint", websocket_ok)
    ]
    
    generate_summary_report(all_results)
    
    # Final status
    if all(success for _, success in all_results):
        print("🎉 All tests passed! Backend is fully operational.")
        print("\n🌐 Access Points:")
        print(f"   Frontend: http://localhost:3000")
        print(f"   Backend API: {BASE_URL}")
        print(f"   API Documentation: {BASE_URL}/docs")
        print(f"   Health Check: {BASE_URL}/health")
        return True
    else:
        print("⚠️  Some tests failed. Check the details above.")
        print("\n🔧 Troubleshooting:")
        print("   1. Ensure the backend is running (python main.py)")
        print("   2. Check if port 8000 is available")
        print("   3. Verify PostgreSQL is running")
        print("   4. Check backend logs for errors")
        return False

if __name__ == "__main__":
    try:
        print("🔍 Testing connection to CyberShield Backend...")
        print(f"📍 Target: {BASE_URL}")
        print("⏳ Please ensure the backend is running before starting this test.")
        print()
        
        # Wait a moment for user to read
        time.sleep(2)
        
        success = main()
        exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⏹️  Test interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n\n💥 Unexpected error: {e}")
        exit(1)
