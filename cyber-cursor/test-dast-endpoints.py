#!/usr/bin/env python3
"""
Test script for DAST endpoints
"""

import requests
import json

BASE_URL = "http://localhost:8000"

def test_dast_endpoints():
    """Test DAST endpoints"""
    
    print("Testing DAST endpoints...")
    
    # Test 1: Check if DAST overview endpoint exists (should return 401 due to auth)
    try:
        response = requests.get(f"{BASE_URL}/api/v1/dast/overview")
        print(f"DAST Overview Status: {response.status_code}")
        if response.status_code == 401:
            print("✅ DAST endpoint exists but requires authentication")
        elif response.status_code == 200:
            print("✅ DAST endpoint working")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"❌ Unexpected status: {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"❌ Error testing DAST overview: {e}")
    
    # Test 2: Check if DAST projects endpoint exists
    try:
        response = requests.get(f"{BASE_URL}/api/v1/dast/projects")
        print(f"DAST Projects Status: {response.status_code}")
        if response.status_code == 401:
            print("✅ DAST projects endpoint exists but requires authentication")
        else:
            print(f"❌ Unexpected status: {response.status_code}")
    except Exception as e:
        print(f"❌ Error testing DAST projects: {e}")
    
    # Test 3: Check if DAST scans endpoint exists
    try:
        response = requests.get(f"{BASE_URL}/api/v1/dast/scans")
        print(f"DAST Scans Status: {response.status_code}")
        if response.status_code == 401:
            print("✅ DAST scans endpoint exists but requires authentication")
        else:
            print(f"❌ Unexpected status: {response.status_code}")
    except Exception as e:
        print(f"❌ Error testing DAST scans: {e}")
    
    # Test 4: Check if DAST vulnerabilities endpoint exists
    try:
        response = requests.get(f"{BASE_URL}/api/v1/dast/vulnerabilities")
        print(f"DAST Vulnerabilities Status: {response.status_code}")
        if response.status_code == 401:
            print("✅ DAST vulnerabilities endpoint exists but requires authentication")
        else:
            print(f"❌ Unexpected status: {response.status_code}")
    except Exception as e:
        print(f"❌ Error testing DAST vulnerabilities: {e}")
    
    # Test 5: Check if DAST payloads endpoint exists
    try:
        response = requests.get(f"{BASE_URL}/api/v1/dast/payloads")
        print(f"DAST Payloads Status: {response.status_code}")
        if response.status_code == 401:
            print("✅ DAST payloads endpoint exists but requires authentication")
        else:
            print(f"❌ Unexpected status: {response.status_code}")
    except Exception as e:
        print(f"❌ Error testing DAST payloads: {e}")

def test_openapi_schema():
    """Test if DAST endpoints are in OpenAPI schema"""
    
    print("\nChecking OpenAPI schema for DAST endpoints...")
    
    try:
        response = requests.get(f"{BASE_URL}/openapi.json")
        if response.status_code == 200:
            schema = response.json()
            
            # Check if DAST paths exist
            dast_paths = [path for path in schema.get("paths", {}).keys() if "/api/v1/dast" in path]
            
            if dast_paths:
                print(f"✅ Found {len(dast_paths)} DAST endpoints in OpenAPI schema:")
                for path in dast_paths:
                    print(f"   - {path}")
            else:
                print("❌ No DAST endpoints found in OpenAPI schema")
                
            # Check if DAST tag exists
            dast_tag = any(tag.get("name") == "DAST" for tag in schema.get("tags", []))
            if dast_tag:
                print("✅ DAST tag found in OpenAPI schema")
            else:
                print("❌ DAST tag not found in OpenAPI schema")
                
        else:
            print(f"❌ Failed to get OpenAPI schema: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error checking OpenAPI schema: {e}")

if __name__ == "__main__":
    test_dast_endpoints()
    test_openapi_schema()
    print("\nDAST endpoint testing completed!") 