#!/usr/bin/env python3
"""
Test script to verify RASP endpoints are working correctly
"""

import requests
import json
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api/v1"

def test_endpoint(method, endpoint, data=None, params=None):
    """Test a single endpoint"""
    url = f"{API_BASE}{endpoint}"
    headers = {"Content-Type": "application/json"}
    
    try:
        if method.upper() == "GET":
            response = requests.get(url, params=params, headers=headers)
        elif method.upper() == "POST":
            response = requests.post(url, json=data, headers=headers)
        elif method.upper() == "PUT":
            response = requests.put(url, json=data, headers=headers)
        elif method.upper() == "DELETE":
            response = requests.delete(url, headers=headers)
        else:
            print(f"❌ Unknown method: {method}")
            return False
            
        print(f"{'✅' if response.status_code < 400 else '❌'} {method} {endpoint}")
        print(f"   Status: {response.status_code}")
        
        if response.status_code < 400:
            try:
                response_data = response.json()
                print(f"   Response: {json.dumps(response_data, indent=2)[:200]}...")
            except:
                print(f"   Response: {response.text[:200]}...")
        else:
            print(f"   Error: {response.text}")
            
        print()
        return response.status_code < 400
        
    except requests.exceptions.ConnectionError:
        print(f"❌ {method} {endpoint} - Connection failed (backend not running?)")
        print()
        return False
    except Exception as e:
        print(f"❌ {method} {endpoint} - Error: {str(e)}")
        print()
        return False

def main():
    """Test all RASP endpoints"""
    print("🧪 Testing RASP Endpoints")
    print("=" * 50)
    
    # Test basic endpoints
    test_endpoint("GET", "/rasp/overview")
    test_endpoint("GET", "/rasp/dashboard/overview")
    test_endpoint("GET", "/rasp/metrics", params={
        "since": "2024-01-01T00:00:00",
        "until": "2024-12-31T23:59:59",
        "metric": "attacks"
    })
    
    # Test projects/applications endpoints
    test_endpoint("GET", "/rasp/projects", params={"skip": 0, "limit": 12})
    test_endpoint("GET", "/rasp/apps", params={"page": 1, "size": 20})
    
    # Test scans endpoints
    test_endpoint("GET", "/rasp/scans/recent", params={"limit": 10})
    
    # Test attacks endpoints
    test_endpoint("GET", "/rasp/attacks/recent", params={"limit": 10})
    
    # Test incidents endpoints
    test_endpoint("GET", "/rasp/incidents/recent", params={"limit": 10})
    test_endpoint("GET", "/rasp/incidents", params={"page": 1, "size": 20})
    
    # Test agents endpoints
    test_endpoint("GET", "/rasp/agents", params={"page": 1, "size": 20})
    
    # Test policies endpoints
    test_endpoint("GET", "/rasp/policies")
    
    # Test vulnerabilities endpoints
    test_endpoint("GET", "/rasp/vulnerabilities", params={"page": 1, "size": 20})
    
    # Test traces endpoints
    test_endpoint("GET", "/rasp/traces", params={"page": 1, "size": 20})
    
    # Test integrations endpoints
    test_endpoint("GET", "/rasp/integrations")
    
    print("🎯 Testing completed!")
    print("\n📝 Note: Some endpoints may return 401 (Unauthorized) if authentication is required")
    print("   This is expected behavior for protected endpoints")

if __name__ == "__main__":
    main()
