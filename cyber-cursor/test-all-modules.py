#!/usr/bin/env python3
"""
Comprehensive test script to verify all security module endpoints
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
    """Test all security module endpoints"""
    print("🧪 Testing All Security Module Endpoints")
    print("=" * 60)
    
    # Test RASP endpoints
    print("\n🔵 RASP Module:")
    print("-" * 30)
    test_endpoint("GET", "/rasp/overview")
    test_endpoint("GET", "/rasp/dashboard/overview")
    test_endpoint("GET", "/rasp/projects", params={"skip": 0, "limit": 12})
    test_endpoint("GET", "/rasp/apps", params={"page": 1, "size": 20})
    test_endpoint("GET", "/rasp/scans/recent", params={"limit": 10})
    test_endpoint("GET", "/rasp/attacks/recent", params={"limit": 10})
    test_endpoint("GET", "/rasp/incidents/recent", params={"limit": 10})
    
    # Test SAST endpoints
    print("\n🟣 SAST Module:")
    print("-" * 30)
    test_endpoint("GET", "/sast/projects", params={"page": 1, "size": 20})
    test_endpoint("GET", "/sast/vulnerabilities", params={"page": 1, "size": 20})
    test_endpoint("GET", "/sast/scans", params={"page": 1, "size": 20})
    test_endpoint("GET", "/sast/dashboard")
    test_endpoint("GET", "/sast/hotspots", params={"page": 1, "size": 20})
    test_endpoint("GET", "/sast/quality-gates")
    test_endpoint("GET", "/sast/rule-profiles")
    
    # Test DAST endpoints
    print("\n🟠 DAST Module:")
    print("-" * 30)
    test_endpoint("GET", "/dast/projects", params={"page": 1, "size": 20})
    test_endpoint("GET", "/dast/scans", params={"page": 1, "size": 20})
    test_endpoint("GET", "/dast/vulnerabilities", params={"page": 1, "size": 20})
    test_endpoint("GET", "/dast/dashboard")
    
    # Test CSPM endpoints
    print("\n🟢 CSPM Module:")
    print("-" * 30)
    test_endpoint("GET", "/cspm/overview")
    test_endpoint("GET", "/cspm/compliance")
    test_endpoint("GET", "/cspm/resources")
    test_endpoint("GET", "/cspm/violations", params={"page": 1, "size": 20})
    
    # Test AI/ML endpoints
    print("\n🤖 AI/ML Module:")
    print("-" * 30)
    test_endpoint("GET", "/ai-ml/models")
    test_endpoint("GET", "/ai-ml/predictions")
    test_endpoint("GET", "/ai-ml/anomalies")
    test_endpoint("GET", "/ai-ml/health")
    
    # Test DevSecOps endpoints
    print("\n🔧 DevSecOps Module:")
    print("-" * 30)
    test_endpoint("GET", "/devsecops/pipelines")
    test_endpoint("GET", "/devsecops/containers")
    test_endpoint("GET", "/devsecops/infrastructure")
    test_endpoint("GET", "/devsecops/security-gates")
    
    # Test Compliance endpoints
    print("\n📋 Compliance Module:")
    print("-" * 30)
    test_endpoint("GET", "/compliance/frameworks")
    test_endpoint("GET", "/compliance/audits")
    test_endpoint("GET", "/compliance/controls")
    test_endpoint("GET", "/compliance/dashboard")
    
    # Test Network Security endpoints
    print("\n🌐 Network Security Module:")
    print("-" * 30)
    test_endpoint("GET", "/network-security/traffic")
    test_endpoint("GET", "/network-security/firewall")
    test_endpoint("GET", "/network-security/ids-ips")
    test_endpoint("GET", "/network-security/threats")
    
    # Test Data Security endpoints
    print("\n🔒 Data Security Module:")
    print("-" * 30)
    test_endpoint("GET", "/data-security/classification")
    test_endpoint("GET", "/data-security/encryption")
    test_endpoint("GET", "/data-security/dlp")
    test_endpoint("GET", "/data-security/privacy")
    
    # Test IAM Security endpoints
    print("\n👤 IAM Security Module:")
    print("-" * 30)
    test_endpoint("GET", "/iam-security/users")
    test_endpoint("GET", "/iam-security/roles")
    test_endpoint("GET", "/iam-security/permissions")
    test_endpoint("GET", "/iam-security/access")
    
    # Test Incident Management endpoints
    print("\n🚨 Incident Management Module:")
    print("-" * 30)
    test_endpoint("GET", "/incident-management/incidents")
    test_endpoint("GET", "/incident-management/response")
    test_endpoint("GET", "/incident-management/escalation")
    test_endpoint("GET", "/incident-management/dashboard")
    
    # Test Threat Intelligence endpoints
    print("\n🕵️ Threat Intelligence Module:")
    print("-" * 30)
    test_endpoint("GET", "/threat-intelligence/threats")
    test_endpoint("GET", "/threat-intelligence/indicators")
    test_endpoint("GET", "/threat-intelligence/analysis")
    
    # Test Admin endpoints
    print("\n⚙️ Admin Module:")
    print("-" * 30)
    test_endpoint("GET", "/admin/status")
    test_endpoint("GET", "/admin/config")
    test_endpoint("GET", "/admin/users")
    test_endpoint("GET", "/admin/maintenance")
    
    # Test User Management endpoints
    print("\n👥 User Management Module:")
    print("-" * 30)
    test_endpoint("GET", "/user-management/profiles")
    test_endpoint("GET", "/user-management/preferences")
    test_endpoint("GET", "/user-management/access")
    test_endpoint("GET", "/user-management/onboarding")
    
    # Test Audit Logs endpoints
    print("\n📝 Audit Logs Module:")
    print("-" * 30)
    test_endpoint("GET", "/audit-logs/logs")
    test_endpoint("GET", "/audit-logs/search")
    test_endpoint("GET", "/audit-logs/statistics")
    test_endpoint("GET", "/audit-logs/export")
    
    # Test Reporting endpoints
    print("\n📊 Reporting Module:")
    print("-" * 30)
    test_endpoint("GET", "/reporting/reports")
    test_endpoint("GET", "/reporting/templates")
    test_endpoint("GET", "/reporting/schedules")
    test_endpoint("GET", "/reporting/analytics")
    
    # Test Integrations endpoints
    print("\n🔗 Integrations Module:")
    print("-" * 30)
    test_endpoint("GET", "/integrations/providers")
    test_endpoint("GET", "/integrations/status")
    test_endpoint("GET", "/integrations/webhooks")
    test_endpoint("GET", "/integrations/credentials")
    
    print("\n🎯 Testing completed!")
    print("\n📝 Note: Some endpoints may return 401 (Unauthorized) if authentication is required")
    print("   This is expected behavior for protected endpoints")
    print("\n🔍 Check the results above to identify any missing or broken endpoints")

if __name__ == "__main__":
    main()
