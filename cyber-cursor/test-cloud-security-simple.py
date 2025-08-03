#!/usr/bin/env python3
"""
Simple Cloud Security Module Test Suite
Tests basic CSPM, CASB, and Cloud-Native Security functionality
"""

import asyncio
import json
import sys
from datetime import datetime
import aiohttp
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SimpleCloudSecurityTester:
    """Simple testing class for Cloud Security module"""
    
    def __init__(self, api_url: str = "http://localhost:8000"):
        self.api_url = api_url
        self.session = None
        self.auth_token = None
        self.test_results = []
        
    def log_test(self, test_name: str, status: str, message: str):
        """Log test results"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result = {
            'timestamp': timestamp,
            'test_name': test_name,
            'status': status,
            'message': message
        }
        self.test_results.append(result)
        
        status_emoji = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
        print(f"{status_emoji} {test_name}: {message}")
    
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
    
    async def test_cspm_basic(self):
        """Test basic CSPM functionality"""
        self.log_test("CSPM Basic", "INFO", "Testing basic CSPM functionality")
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test 1: Create Cloud Account
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
        
        try:
            async with self.session.post(
                f"{self.api_url}/api/v1/cloud-security/accounts",
                json=account_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    account_id = result["id"]
                    self.log_test("Create Cloud Account", "PASS", f"Created account ID: {account_id}")
                    
                    # Test 2: Get Cloud Accounts
                    async with self.session.get(
                        f"{self.api_url}/api/v1/cloud-security/accounts",
                        headers=headers
                    ) as get_response:
                        if get_response.status == 200:
                            accounts = await get_response.json()
                            self.log_test("Get Cloud Accounts", "PASS", f"Retrieved {len(accounts)} accounts")
                        else:
                            self.log_test("Get Cloud Accounts", "FAIL", f"Status: {get_response.status}")
                    
                else:
                    self.log_test("Create Cloud Account", "FAIL", f"Status: {response.status}")
        except Exception as e:
            self.log_test("Create Cloud Account", "FAIL", f"Error: {e}")
    
    async def test_casb_basic(self):
        """Test basic CASB functionality"""
        self.log_test("CASB Basic", "INFO", "Testing basic CASB functionality")
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test 1: Create SaaS Application
        app_data = {
            "app_name": "Test SaaS App",
            "app_category": "collaboration",
            "vendor": "test-vendor.com",
            "risk_score": 45.5,
            "status": "discovered",
            "user_count": 25,
            "data_classification": {
                "pii": True,
                "pci": False,
                "phi": False
            },
            "security_features": {
                "sso": True,
                "mfa": True,
                "encryption": True
            }
        }
        
        try:
            async with self.session.post(
                f"{self.api_url}/api/v1/cloud-security/saas-applications",
                json=app_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    app_id = result["id"]
                    self.log_test("Create SaaS App", "PASS", f"Created app ID: {app_id}")
                    
                    # Test 2: Get SaaS Applications
                    async with self.session.get(
                        f"{self.api_url}/api/v1/cloud-security/saas-applications",
                        headers=headers
                    ) as get_response:
                        if get_response.status == 200:
                            apps = await get_response.json()
                            self.log_test("Get SaaS Apps", "PASS", f"Retrieved {len(apps)} applications")
                        else:
                            self.log_test("Get SaaS Apps", "FAIL", f"Status: {get_response.status}")
                    
                else:
                    self.log_test("Create SaaS App", "FAIL", f"Status: {response.status}")
        except Exception as e:
            self.log_test("Create SaaS App", "FAIL", f"Error: {e}")
    
    async def test_cloud_native_basic(self):
        """Test basic Cloud-Native Security functionality"""
        self.log_test("Cloud-Native Basic", "INFO", "Testing basic Cloud-Native Security functionality")
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test 1: Create Cloud Threat
        threat_data = {
            "threat_id": "THREAT-DDOS-123",
            "threat_type": "ddos",
            "severity": "high",
            "source_ip": "203.0.113.1",
            "target_resource": "web-server-01",
            "description": "Detected DDoS attack from suspicious IP",
            "threat_data": {
                "attack_vector": "network",
                "confidence": 95.5,
                "indicators": ["suspicious_ip", "high_traffic"]
            }
        }
        
        try:
            async with self.session.post(
                f"{self.api_url}/api/v1/cloud-security/threats",
                json=threat_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    threat_id = result["id"]
                    self.log_test("Create Cloud Threat", "PASS", f"Created threat ID: {threat_id}")
                    
                    # Test 2: Get Cloud Threats
                    async with self.session.get(
                        f"{self.api_url}/api/v1/cloud-security/threats",
                        headers=headers
                    ) as get_response:
                        if get_response.status == 200:
                            threats = await get_response.json()
                            self.log_test("Get Cloud Threats", "PASS", f"Retrieved {len(threats)} threats")
                        else:
                            self.log_test("Get Cloud Threats", "FAIL", f"Status: {get_response.status}")
                    
                else:
                    self.log_test("Create Cloud Threat", "FAIL", f"Status: {response.status}")
        except Exception as e:
            self.log_test("Create Cloud Threat", "FAIL", f"Error: {e}")
    
    async def test_dashboard_basic(self):
        """Test basic dashboard functionality"""
        self.log_test("Dashboard Basic", "INFO", "Testing basic dashboard functionality")
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test 1: Get Overview Dashboard
        try:
            async with self.session.get(
                f"{self.api_url}/api/v1/cloud-security/dashboard/overview",
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Get Overview Dashboard", "PASS", "Retrieved overview data")
                    self.log_test("Dashboard Info", "INFO", f"Total accounts: {result.get('total_accounts', 0)}")
                    self.log_test("Dashboard Info", "INFO", f"Security score: {result.get('overall_security_score', 0)}")
                else:
                    self.log_test("Get Overview Dashboard", "FAIL", f"Status: {response.status}")
        except Exception as e:
            self.log_test("Get Overview Dashboard", "FAIL", f"Error: {e}")
        
        # Test 2: Get Metrics
        try:
            async with self.session.get(
                f"{self.api_url}/api/v1/cloud-security/dashboard/metrics",
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Get Metrics", "PASS", "Retrieved metrics data")
                else:
                    self.log_test("Get Metrics", "FAIL", f"Status: {response.status}")
        except Exception as e:
            self.log_test("Get Metrics", "FAIL", f"Error: {e}")
    
    async def run_basic_tests(self):
        """Run all basic tests"""
        self.log_test("Basic Testing", "INFO", "Starting basic Cloud Security testing")
        
        try:
            # Setup session and authenticate
            await self.setup_session()
            
            # Run basic tests
            await self.test_cspm_basic()
            await self.test_casb_basic()
            await self.test_cloud_native_basic()
            await self.test_dashboard_basic()
            
            # Generate test summary
            total_tests = len(self.test_results)
            passed_tests = len([r for r in self.test_results if r['status'] == 'PASS'])
            failed_tests = len([r for r in self.test_results if r['status'] == 'FAIL'])
            info_tests = len([r for r in self.test_results if r['status'] == 'INFO'])
            
            self.log_test("Test Summary", "INFO", f"Total tests: {total_tests}")
            self.log_test("Test Summary", "INFO", f"Passed: {passed_tests}")
            self.log_test("Test Summary", "INFO", f"Failed: {failed_tests}")
            self.log_test("Test Summary", "INFO", f"Info: {info_tests}")
            
            success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
            self.log_test("Success Rate", "INFO", f"{success_rate:.1f}%")
            
        except Exception as e:
            self.log_test("Basic Testing", "FAIL", f"Testing failed: {e}")
        finally:
            if self.session:
                await self.session.close()

async def main():
    """Main function to run basic cloud security tests"""
    print("🛡️ Basic Cloud Security Module Testing")
    print("=" * 50)
    
    # Get API URL from command line or use default
    api_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    
    tester = SimpleCloudSecurityTester(api_url)
    await tester.run_basic_tests()
    
    print("\n" + "=" * 50)
    print("🏁 Basic Cloud Security Testing Complete!")

if __name__ == "__main__":
    asyncio.run(main()) 