#!/usr/bin/env python3
"""
Cloud Security Module Test Suite
Tests CSPM, CASB, and Cloud-Native Security functionality
"""

import asyncio
import json
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List
import aiohttp
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CloudSecurityTester:
    """Comprehensive testing class for Cloud Security module"""
    
    def __init__(self, api_url: str = "http://localhost:8000"):
        self.api_url = api_url
        self.session = None
        self.auth_token = None
        self.test_results = []
        
    def log_test(self, test_name: str, status: str, message: str, details: Any = None):
        """Log test results"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result = {
            'timestamp': timestamp,
            'test_name': test_name,
            'status': status,
            'message': message,
            'details': details
        }
        self.test_results.append(result)
        
        status_emoji = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
        print(f"{status_emoji} {test_name}: {message}")
        if details:
            print(f"   Details: {details}")
    
    async def setup_session(self):
        """Setup HTTP session and authenticate"""
        try:
            self.session = aiohttp.ClientSession()
            
            # Login to get auth token
            login_data = {
                "username": "admin@cybershield.com",
                "password": "password"
            }
            
            async with self.session.post(
                f"{self.api_url}/api/v1/auth/login",
                data=login_data
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.auth_token = result.get("access_token")
                    self.log_test("Authentication", "PASS", "Successfully authenticated")
                else:
                    self.log_test("Authentication", "FAIL", f"Login failed: {response.status}")
                    raise Exception("Authentication failed")
                    
        except Exception as e:
            self.log_test("Session Setup", "FAIL", f"Failed to setup session: {e}")
            raise
    
    async def test_cspm_functionality(self):
        """Test CSPM (Cloud Security Posture Management) functionality"""
        self.log_test("CSPM Testing", "INFO", "Starting CSPM functionality tests")
        
        # Test 1: Create Cloud Account
        try:
            account_data = {
                "account_id": "test-aws-account-123",
                "name": "Test AWS Production Account",
                "provider": "aws",
                "region": "us-east-1",
                "metadata": {
                    "environment": "production",
                    "team": "infrastructure"
                }
            }
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            async with self.session.post(
                f"{self.api_url}/api/v1/cloud-security/accounts",
                json=account_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    account_id = result["id"]
                    self.log_test("Create Cloud Account", "PASS", f"Created account ID: {account_id}")
                else:
                    self.log_test("Create Cloud Account", "FAIL", f"Failed: {response.status}")
                    return
        except Exception as e:
            self.log_test("Create Cloud Account", "FAIL", f"Exception: {e}")
            return
        
        # Test 2: Create Cloud Asset
        try:
            asset_data = {
                "asset_id": "i-1234567890abcdef0",
                "name": "Web Server Instance",
                "asset_type": "ec2",
                "region": "us-east-1",
                "tags": {"Environment": "Production", "Role": "WebServer"},
                "metadata": {"instance_type": "t3.medium"}
            }
            
            async with self.session.post(
                f"{self.api_url}/api/v1/cloud-security/accounts/{account_id}/assets",
                json=asset_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    asset_id = result["id"]
                    self.log_test("Create Cloud Asset", "PASS", f"Created asset ID: {asset_id}")
                else:
                    self.log_test("Create Cloud Asset", "FAIL", f"Failed: {response.status}")
                    return
        except Exception as e:
            self.log_test("Create Cloud Asset", "FAIL", f"Exception: {e}")
            return
        
        # Test 3: Create Misconfiguration
        try:
            misconfig_data = {
                "rule_id": "S3_BUCKET_PUBLIC_ACCESS",
                "title": "S3 Bucket Publicly Accessible",
                "description": "S3 bucket is configured for public access",
                "severity": "high",
                "category": "storage",
                "compliance_standards": ["cis", "nist"],
                "remediation_steps": "Remove public access and configure bucket policies",
                "auto_remediable": True
            }
            
            async with self.session.post(
                f"{self.api_url}/api/v1/cloud-security/misconfigurations?asset_id={asset_id}",
                json=misconfig_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Create Misconfiguration", "PASS", f"Created misconfiguration ID: {result['id']}")
                else:
                    self.log_test("Create Misconfiguration", "FAIL", f"Failed: {response.status}")
        except Exception as e:
            self.log_test("Create Misconfiguration", "FAIL", f"Exception: {e}")
        
        # Test 4: Get Cloud Accounts
        try:
            async with self.session.get(
                f"{self.api_url}/api/v1/cloud-security/accounts",
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Get Cloud Accounts", "PASS", f"Retrieved {len(result)} accounts")
                else:
                    self.log_test("Get Cloud Accounts", "FAIL", f"Failed: {response.status}")
        except Exception as e:
            self.log_test("Get Cloud Accounts", "FAIL", f"Exception: {e}")
    
    async def test_casb_functionality(self):
        """Test CASB (Cloud Access Security Broker) functionality"""
        self.log_test("CASB Testing", "INFO", "Starting CASB functionality tests")
        
        # Test 1: Create SaaS Application
        try:
            saas_data = {
                "app_name": "Test CRM Application",
                "app_category": "CRM",
                "vendor": "Test Vendor Inc",
                "risk_score": 25.0,
                "status": "discovered",
                "user_count": 50,
                "data_classification": {"pii": True, "pci": False},
                "security_features": {"sso": True, "mfa": True}
            }
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            async with self.session.post(
                f"{self.api_url}/api/v1/cloud-security/saas-applications",
                json=saas_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    app_id = result["id"]
                    self.log_test("Create SaaS Application", "PASS", f"Created app ID: {app_id}")
                else:
                    self.log_test("Create SaaS Application", "FAIL", f"Failed: {response.status}")
                    return
        except Exception as e:
            self.log_test("Create SaaS Application", "FAIL", f"Exception: {e}")
            return
        
        # Test 2: Create User Activity
        try:
            activity_data = {
                "user_id": "test-user-123",
                "activity_type": "login",
                "ip_address": "192.168.1.100",
                "location": "New York, NY",
                "device_info": {"browser": "Chrome", "os": "Windows"},
                "risk_score": 10.0
            }
            
            async with self.session.post(
                f"{self.api_url}/api/v1/cloud-security/user-activities?app_id={app_id}",
                json=activity_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Create User Activity", "PASS", f"Created activity ID: {result['id']}")
                else:
                    self.log_test("Create User Activity", "FAIL", f"Failed: {response.status}")
        except Exception as e:
            self.log_test("Create User Activity", "FAIL", f"Exception: {e}")
        
        # Test 3: Create DLP Incident
        try:
            dlp_data = {
                "user_id": "test-user-456",
                "incident_type": "pii",
                "file_name": "customer_data.csv",
                "file_size": 2048576,
                "action_taken": "blocked",
                "confidence_score": 95.0,
                "details": {
                    "detected_patterns": ["ssn", "credit_card"],
                    "file_type": "csv"
                }
            }
            
            async with self.session.post(
                f"{self.api_url}/api/v1/cloud-security/dlp-incidents?app_id={app_id}",
                json=dlp_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Create DLP Incident", "PASS", f"Created DLP incident ID: {result['id']}")
                else:
                    self.log_test("Create DLP Incident", "FAIL", f"Failed: {response.status}")
        except Exception as e:
            self.log_test("Create DLP Incident", "FAIL", f"Exception: {e}")
        
        # Test 4: Get SaaS Applications
        try:
            async with self.session.get(
                f"{self.api_url}/api/v1/cloud-security/saas-applications",
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Get SaaS Applications", "PASS", f"Retrieved {len(result)} applications")
                else:
                    self.log_test("Get SaaS Applications", "FAIL", f"Failed: {response.status}")
        except Exception as e:
            self.log_test("Get SaaS Applications", "FAIL", f"Exception: {e}")
    
    async def test_cloud_native_security(self):
        """Test Cloud-Native Security functionality"""
        self.log_test("Cloud-Native Security Testing", "INFO", "Starting Cloud-Native Security tests")
        
        # Test 1: Create Cloud Threat
        try:
            threat_data = {
                "threat_id": "threat-test-001",
                "threat_type": "ddos",
                "severity": "high",
                "source_ip": "203.0.113.1",
                "target_resource": "i-1234567890abcdef0",
                "description": "DDoS attack detected on web server",
                "threat_data": {
                    "attack_volume": "10Gbps",
                    "duration": "30min",
                    "attack_type": "volumetric"
                }
            }
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            async with self.session.post(
                f"{self.api_url}/api/v1/cloud-security/threats?account_id=1",
                json=threat_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Create Cloud Threat", "PASS", f"Created threat ID: {result['id']}")
                else:
                    self.log_test("Create Cloud Threat", "FAIL", f"Failed: {response.status}")
        except Exception as e:
            self.log_test("Create Cloud Threat", "FAIL", f"Exception: {e}")
        
        # Test 2: Create IAM Risk
        try:
            iam_risk_data = {
                "entity_id": "arn:aws:iam::123456789012:user/admin",
                "entity_type": "user",
                "risk_type": "over_privileged",
                "severity": "high",
                "permissions": {"permissions": ["*"]},
                "recommendations": {
                    "action": "reduce_permissions",
                    "principle": "least_privilege"
                }
            }
            
            async with self.session.post(
                f"{self.api_url}/api/v1/cloud-security/iam-risks?account_id=1",
                json=iam_risk_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Create IAM Risk", "PASS", f"Created IAM risk ID: {result['id']}")
                else:
                    self.log_test("Create IAM Risk", "FAIL", f"Failed: {response.status}")
        except Exception as e:
            self.log_test("Create IAM Risk", "FAIL", f"Exception: {e}")
        
        # Test 3: Create DDoS Protection
        try:
            ddos_data = {
                "protection_id": "shield-test-001",
                "service": "aws_shield",
                "status": "active",
                "protected_resources": ["i-1234567890abcdef0", "s3-bucket-production-data"],
                "attack_statistics": {
                    "attacks_blocked": 5,
                    "total_volume": "50Gbps"
                }
            }
            
            async with self.session.post(
                f"{self.api_url}/api/v1/cloud-security/ddos-protection?account_id=1",
                json=ddos_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Create DDoS Protection", "PASS", f"Created DDoS protection ID: {result['id']}")
                else:
                    self.log_test("Create DDoS Protection", "FAIL", f"Failed: {response.status}")
        except Exception as e:
            self.log_test("Create DDoS Protection", "FAIL", f"Exception: {e}")
        
        # Test 4: Get Cloud Threats
        try:
            async with self.session.get(
                f"{self.api_url}/api/v1/cloud-security/threats",
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Get Cloud Threats", "PASS", f"Retrieved {len(result)} threats")
                else:
                    self.log_test("Get Cloud Threats", "FAIL", f"Failed: {response.status}")
        except Exception as e:
            self.log_test("Get Cloud Threats", "FAIL", f"Exception: {e}")
    
    async def test_dashboard_analytics(self):
        """Test Dashboard and Analytics functionality"""
        self.log_test("Dashboard Testing", "INFO", "Starting Dashboard and Analytics tests")
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test 1: Get Cloud Security Overview
        try:
            async with self.session.get(
                f"{self.api_url}/api/v1/cloud-security/dashboard/overview",
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Get Security Overview", "PASS", f"Overview retrieved: {result['total_accounts']} accounts")
                else:
                    self.log_test("Get Security Overview", "FAIL", f"Failed: {response.status}")
        except Exception as e:
            self.log_test("Get Security Overview", "FAIL", f"Exception: {e}")
        
        # Test 2: Get Cloud Security Metrics
        try:
            async with self.session.get(
                f"{self.api_url}/api/v1/cloud-security/dashboard/metrics",
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Get Security Metrics", "PASS", "Metrics retrieved successfully")
                else:
                    self.log_test("Get Security Metrics", "FAIL", f"Failed: {response.status}")
        except Exception as e:
            self.log_test("Get Security Metrics", "FAIL", f"Exception: {e}")
    
    async def test_scan_remediation(self):
        """Test Scan and Remediation functionality"""
        self.log_test("Scan/Remediation Testing", "INFO", "Starting Scan and Remediation tests")
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test 1: Initiate Cloud Scan
        try:
            scan_data = {
                "account_id": 1,
                "scan_type": "comprehensive",
                "include_assets": True,
                "include_misconfigurations": True,
                "include_compliance": True
            }
            
            async with self.session.post(
                f"{self.api_url}/api/v1/cloud-security/scan",
                json=scan_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Initiate Cloud Scan", "PASS", "Scan initiated successfully")
                else:
                    self.log_test("Initiate Cloud Scan", "FAIL", f"Failed: {response.status}")
        except Exception as e:
            self.log_test("Initiate Cloud Scan", "FAIL", f"Exception: {e}")
        
        # Test 2: Remediate Misconfiguration
        try:
            remediation_data = {
                "misconfiguration_id": 1,
                "auto_remediate": True,
                "custom_steps": None
            }
            
            async with self.session.post(
                f"{self.api_url}/api/v1/cloud-security/remediate",
                json=remediation_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Remediate Misconfiguration", "PASS", "Remediation initiated")
                else:
                    self.log_test("Remediate Misconfiguration", "FAIL", f"Failed: {response.status}")
        except Exception as e:
            self.log_test("Remediate Misconfiguration", "FAIL", f"Exception: {e}")
    
    async def run_all_tests(self):
        """Run all Cloud Security tests"""
        print("🚀 Starting Cloud Security Module Test Suite")
        print("=" * 60)
        
        try:
            await self.setup_session()
            
            # Run test suites
            await self.test_cspm_functionality()
            await self.test_casb_functionality()
            await self.test_cloud_native_security()
            await self.test_dashboard_analytics()
            await self.test_scan_remediation()
            
            # Summary
            print("\n" + "=" * 60)
            print("📊 Cloud Security Test Summary")
            print("=" * 60)
            
            total_tests = len(self.test_results)
            passed_tests = len([r for r in self.test_results if r['status'] == 'PASS'])
            failed_tests = len([r for r in self.test_results if r['status'] == 'FAIL'])
            info_tests = len([r for r in self.test_results if r['status'] == 'INFO'])
            
            print(f"Total Tests: {total_tests}")
            print(f"✅ Passed: {passed_tests}")
            print(f"❌ Failed: {failed_tests}")
            print(f"ℹ️  Info: {info_tests}")
            
            success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
            print(f"Success Rate: {success_rate:.1f}%")
            
            if failed_tests == 0:
                print("\n🎉 All Cloud Security tests passed successfully!")
            else:
                print(f"\n⚠️  {failed_tests} tests failed. Check the details above.")
            
        except Exception as e:
            self.log_test("Test Suite", "FAIL", f"Test suite failed: {e}")
        finally:
            if self.session:
                await self.session.close()

async def main():
    """Main test runner"""
    tester = CloudSecurityTester()
    await tester.run_all_tests()

if __name__ == "__main__":
    asyncio.run(main()) 