#!/usr/bin/env python3
"""
Comprehensive Cloud Security Module Test Suite
Tests CSPM, CASB, and Cloud-Native Security functionality with real-world scenarios
"""

import asyncio
import json
import sys
import time
import random
from datetime import datetime, timedelta
from typing import Dict, Any, List
import aiohttp
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ComprehensiveCloudSecurityTester:
    """Comprehensive testing class for Cloud Security module with real-world scenarios"""
    
    def __init__(self, api_url: str = "http://localhost:8000"):
        self.api_url = api_url
        self.session = None
        self.auth_token = None
        self.test_results = []
        self.created_resources = []
        
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
    
    async def test_cspm_comprehensive(self):
        """Test comprehensive CSPM functionality"""
        self.log_test("CSPM Comprehensive", "INFO", "Starting comprehensive CSPM tests")
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test 1: Create Multiple Cloud Accounts
        cloud_accounts = []
        providers = ["aws", "azure", "gcp"]
        
        for i, provider in enumerate(providers):
            account_data = {
                "account_id": f"test-{provider}-account-{i+1}",
                "name": f"Test {provider.upper()} Production Account {i+1}",
                "provider": provider,
                "region": "us-east-1" if provider == "aws" else "eastus" if provider == "azure" else "us-central1",
                "metadata": {
                    "environment": "production",
                    "team": "infrastructure",
                    "cost_center": f"CC-{provider.upper()}-{i+1}"
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
                        cloud_accounts.append(result)
                        self.log_test(f"Create {provider.upper()} Account", "PASS", f"Created account ID: {result['id']}")
                    else:
                        self.log_test(f"Create {provider.upper()} Account", "FAIL", f"Status: {response.status}")
            except Exception as e:
                self.log_test(f"Create {provider.upper()} Account", "FAIL", f"Error: {e}")
        
        # Test 2: Create Cloud Assets for Each Account
        for account in cloud_accounts:
            asset_types = {
                "aws": ["ec2", "s3", "rds", "lambda", "vpc", "iam"],
                "azure": ["vm", "blob", "sql", "app_service", "key_vault"],
                "gcp": ["compute_engine", "cloud_storage", "cloud_sql", "kubernetes"]
            }
            
            provider = account["provider"]
            asset_list = asset_types.get(provider, [])
            
            for asset_type in asset_list[:3]:  # Create 3 assets per account
                asset_data = {
                    "asset_id": f"{provider}-{asset_type}-{random.randint(1000, 9999)}",
                    "name": f"Test {asset_type.upper()} Asset",
                    "asset_type": asset_type,
                    "region": account["region"],
                    "tags": {
                        "Environment": "production",
                        "Team": "infrastructure",
                        "AssetType": asset_type
                    },
                    "metadata": {
                        "created_by": "test-script",
                        "version": "1.0"
                    }
                }
                
                try:
                    async with self.session.post(
                        f"{self.api_url}/api/v1/cloud-security/accounts/{account['id']}/assets",
                        json=asset_data,
                        headers=headers
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            self.log_test(f"Create {asset_type} Asset", "PASS", f"Created asset ID: {result['id']}")
                        else:
                            self.log_test(f"Create {asset_type} Asset", "FAIL", f"Status: {response.status}")
                except Exception as e:
                    self.log_test(f"Create {asset_type} Asset", "FAIL", f"Error: {e}")
        
        # Test 3: Create Misconfigurations
        misconfigurations = []
        for account in cloud_accounts:
            for severity in ["critical", "high", "medium", "low"]:
                misconfig_data = {
                    "rule_id": f"RULE-{account['provider'].upper()}-{severity.upper()}-{random.randint(100, 999)}",
                    "title": f"Test {severity.title()} Misconfiguration",
                    "description": f"This is a test {severity} misconfiguration for {account['provider']}",
                    "severity": severity,
                    "category": "security",
                    "compliance_standards": ["cis", "nist"],
                    "remediation_steps": f"Follow these steps to fix the {severity} misconfiguration",
                    "auto_remediable": severity in ["low", "medium"]
                }
                
                try:
                    async with self.session.post(
                        f"{self.api_url}/api/v1/cloud-security/misconfigurations",
                        json=misconfig_data,
                        headers=headers
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            misconfigurations.append(result)
                            self.log_test(f"Create {severity} Misconfig", "PASS", f"Created misconfig ID: {result['id']}")
                        else:
                            self.log_test(f"Create {severity} Misconfig", "FAIL", f"Status: {response.status}")
                except Exception as e:
                    self.log_test(f"Create {severity} Misconfig", "FAIL", f"Error: {e}")
        
        # Test 4: Generate Compliance Reports
        for account in cloud_accounts:
            for standard in ["cis", "nist", "iso27001"]:
                report_data = {
                    "standard": standard,
                    "score": random.uniform(60, 95),
                    "total_checks": random.randint(50, 200),
                    "passed_checks": random.randint(30, 180),
                    "failed_checks": random.randint(5, 50),
                    "report_data": {
                        "summary": f"Compliance report for {standard.upper()}",
                        "details": {
                            "critical_findings": random.randint(0, 5),
                            "high_findings": random.randint(0, 10),
                            "medium_findings": random.randint(0, 20),
                            "low_findings": random.randint(0, 30)
                        }
                    }
                }
                
                try:
                    async with self.session.post(
                        f"{self.api_url}/api/v1/cloud-security/compliance-reports",
                        json=report_data,
                        headers=headers
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            self.log_test(f"Generate {standard.upper()} Report", "PASS", f"Generated report ID: {result['id']}")
                        else:
                            self.log_test(f"Generate {standard.upper()} Report", "FAIL", f"Status: {response.status}")
                except Exception as e:
                    self.log_test(f"Generate {standard.upper()} Report", "FAIL", f"Error: {e}")
    
    async def test_casb_comprehensive(self):
        """Test comprehensive CASB functionality"""
        self.log_test("CASB Comprehensive", "INFO", "Starting comprehensive CASB tests")
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test 1: Create SaaS Applications
        saas_apps = []
        app_categories = [
            ("Slack", "communication", "slack.com"),
            ("Zoom", "video_conferencing", "zoom.us"),
            ("Dropbox", "file_sharing", "dropbox.com"),
            ("Salesforce", "crm", "salesforce.com"),
            ("GitHub", "development", "github.com"),
            ("Trello", "project_management", "trello.com")
        ]
        
        for app_name, category, vendor in app_categories:
            app_data = {
                "app_name": app_name,
                "app_category": category,
                "vendor": vendor,
                "risk_score": random.uniform(10, 80),
                "status": random.choice(["discovered", "sanctioned", "blocked"]),
                "user_count": random.randint(10, 500),
                "data_classification": {
                    "pii": random.choice([True, False]),
                    "pci": random.choice([True, False]),
                    "phi": random.choice([True, False])
                },
                "security_features": {
                    "sso": random.choice([True, False]),
                    "mfa": random.choice([True, False]),
                    "encryption": random.choice([True, False])
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
                        saas_apps.append(result)
                        self.log_test(f"Create {app_name} App", "PASS", f"Created app ID: {result['id']}")
                    else:
                        self.log_test(f"Create {app_name} App", "FAIL", f"Status: {response.status}")
            except Exception as e:
                self.log_test(f"Create {app_name} App", "FAIL", f"Error: {e}")
        
        # Test 2: Create User Activities
        for app in saas_apps:
            activity_types = ["login", "upload", "download", "share", "admin_action"]
            
            for activity_type in activity_types:
                for _ in range(3):  # Create 3 activities per type
                    activity_data = {
                        "user_id": f"user-{random.randint(1000, 9999)}",
                        "activity_type": activity_type,
                        "ip_address": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                        "location": random.choice(["New York, NY", "San Francisco, CA", "London, UK", "Tokyo, JP"]),
                        "device_info": {
                            "browser": random.choice(["Chrome", "Firefox", "Safari", "Edge"]),
                            "os": random.choice(["Windows", "macOS", "Linux", "iOS", "Android"]),
                            "device_type": random.choice(["desktop", "mobile", "tablet"])
                        },
                        "risk_score": random.uniform(0, 100)
                    }
                    
                    try:
                        async with self.session.post(
                            f"{self.api_url}/api/v1/cloud-security/user-activities",
                            json=activity_data,
                            headers=headers
                        ) as response:
                            if response.status == 200:
                                result = await response.json()
                                self.log_test(f"Create {activity_type} Activity", "PASS", f"Created activity ID: {result['id']}")
                            else:
                                self.log_test(f"Create {activity_type} Activity", "FAIL", f"Status: {response.status}")
                    except Exception as e:
                        self.log_test(f"Create {activity_type} Activity", "FAIL", f"Error: {e}")
        
        # Test 3: Create DLP Incidents
        for app in saas_apps:
            incident_types = ["pii", "pci", "phi", "intellectual_property"]
            
            for incident_type in incident_types:
                incident_data = {
                    "user_id": f"user-{random.randint(1000, 9999)}",
                    "incident_type": incident_type,
                    "file_name": f"sensitive_data_{incident_type}_{random.randint(1000, 9999)}.pdf",
                    "file_size": random.randint(100000, 5000000),
                    "action_taken": random.choice(["blocked", "quarantined", "allowed", "alerted"]),
                    "confidence_score": random.uniform(70, 99),
                    "details": {
                        "detection_method": "ml_analysis",
                        "file_type": "pdf",
                        "risk_level": random.choice(["low", "medium", "high", "critical"])
                    }
                }
                
                try:
                    async with self.session.post(
                        f"{self.api_url}/api/v1/cloud-security/dlp-incidents",
                        json=incident_data,
                        headers=headers
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            self.log_test(f"Create {incident_type} DLP Incident", "PASS", f"Created incident ID: {result['id']}")
                        else:
                            self.log_test(f"Create {incident_type} DLP Incident", "FAIL", f"Status: {response.status}")
                except Exception as e:
                    self.log_test(f"Create {incident_type} DLP Incident", "FAIL", f"Error: {e}")
    
    async def test_cloud_native_security(self):
        """Test comprehensive Cloud-Native Security functionality"""
        self.log_test("Cloud-Native Security", "INFO", "Starting comprehensive Cloud-Native Security tests")
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test 1: Create Cloud Threats
        threat_types = ["ddos", "malware", "unauthorized_access", "data_exfiltration", "insider_threat"]
        
        for threat_type in threat_types:
            threat_data = {
                "threat_id": f"THREAT-{threat_type.upper()}-{random.randint(1000, 9999)}",
                "threat_type": threat_type,
                "severity": random.choice(["critical", "high", "medium", "low"]),
                "source_ip": f"203.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "target_resource": f"resource-{random.randint(1000, 9999)}",
                "description": f"Detected {threat_type} threat from {threat_data['source_ip']}",
                "threat_data": {
                    "attack_vector": random.choice(["network", "application", "social_engineering"]),
                    "confidence": random.uniform(80, 99),
                    "indicators": ["suspicious_ip", "unusual_activity", "data_access_pattern"]
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
                        self.log_test(f"Create {threat_type} Threat", "PASS", f"Created threat ID: {result['id']}")
                    else:
                        self.log_test(f"Create {threat_type} Threat", "FAIL", f"Status: {response.status}")
            except Exception as e:
                self.log_test(f"Create {threat_type} Threat", "FAIL", f"Error: {e}")
        
        # Test 2: Create IAM Risks
        risk_types = ["over_privileged", "unused_permissions", "weak_policies", "orphaned_accounts"]
        entity_types = ["user", "role", "group", "service_account"]
        
        for risk_type in risk_types:
            for entity_type in entity_types:
                risk_data = {
                    "entity_id": f"{entity_type}-{random.randint(1000, 9999)}",
                    "entity_type": entity_type,
                    "risk_type": risk_type,
                    "severity": random.choice(["critical", "high", "medium", "low"]),
                    "permissions": {
                        "admin_access": random.choice([True, False]),
                        "data_access": random.choice([True, False]),
                        "network_access": random.choice([True, False])
                    },
                    "recommendations": {
                        "action": f"Review and update {entity_type} permissions",
                        "priority": random.choice(["immediate", "high", "medium", "low"]),
                        "estimated_effort": f"{random.randint(1, 8)} hours"
                    }
                }
                
                try:
                    async with self.session.post(
                        f"{self.api_url}/api/v1/cloud-security/iam-risks",
                        json=risk_data,
                        headers=headers
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            self.log_test(f"Create {risk_type} IAM Risk", "PASS", f"Created risk ID: {result['id']}")
                        else:
                            self.log_test(f"Create {risk_type} IAM Risk", "FAIL", f"Status: {response.status}")
                except Exception as e:
                    self.log_test(f"Create {risk_type} IAM Risk", "FAIL", f"Error: {e}")
        
        # Test 3: Create DDoS Protection
        ddos_services = ["aws_shield", "azure_ddos", "gcp_armor"]
        
        for service in ddos_services:
            protection_data = {
                "protection_id": f"DDOS-{service.upper()}-{random.randint(1000, 9999)}",
                "service": service,
                "status": random.choice(["active", "inactive", "suspended"]),
                "protected_resources": [
                    f"resource-{random.randint(1000, 9999)}",
                    f"resource-{random.randint(1000, 9999)}",
                    f"resource-{random.randint(1000, 9999)}"
                ],
                "attack_statistics": {
                    "total_attacks": random.randint(0, 50),
                    "blocked_attacks": random.randint(0, 45),
                    "peak_bandwidth": f"{random.randint(1, 100)} Gbps",
                    "attack_types": ["volumetric", "protocol", "application"]
                }
            }
            
            try:
                async with self.session.post(
                    f"{self.api_url}/api/v1/cloud-security/ddos-protection",
                    json=protection_data,
                    headers=headers
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        self.log_test(f"Create {service} DDoS Protection", "PASS", f"Created protection ID: {result['id']}")
                    else:
                        self.log_test(f"Create {service} DDoS Protection", "FAIL", f"Status: {response.status}")
            except Exception as e:
                self.log_test(f"Create {service} DDoS Protection", "FAIL", f"Error: {e}")
    
    async def test_dashboard_analytics(self):
        """Test dashboard and analytics functionality"""
        self.log_test("Dashboard Analytics", "INFO", "Starting dashboard analytics tests")
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test 1: Get Overview Dashboard
        try:
            async with self.session.get(
                f"{self.api_url}/api/v1/cloud-security/dashboard/overview",
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Get Overview Dashboard", "PASS", f"Retrieved overview data")
                    self.log_test("Dashboard Data", "INFO", f"Total accounts: {result.get('total_accounts', 0)}")
                    self.log_test("Dashboard Data", "INFO", f"Total assets: {result.get('total_assets', 0)}")
                    self.log_test("Dashboard Data", "INFO", f"Security score: {result.get('overall_security_score', 0)}")
                else:
                    self.log_test("Get Overview Dashboard", "FAIL", f"Status: {response.status}")
        except Exception as e:
            self.log_test("Get Overview Dashboard", "FAIL", f"Error: {e}")
        
        # Test 2: Get Detailed Metrics
        try:
            async with self.session.get(
                f"{self.api_url}/api/v1/cloud-security/dashboard/metrics",
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Get Detailed Metrics", "PASS", f"Retrieved metrics data")
                    self.log_test("Metrics Data", "INFO", f"Provider distribution: {result.get('provider_distribution', {})}")
                    self.log_test("Metrics Data", "INFO", f"Asset type distribution: {result.get('asset_type_distribution', {})}")
                else:
                    self.log_test("Get Detailed Metrics", "FAIL", f"Status: {response.status}")
        except Exception as e:
            self.log_test("Get Detailed Metrics", "FAIL", f"Error: {e}")
        
        # Test 3: Test Scanning Functionality
        scan_data = {
            "account_id": 1,  # Assuming account ID 1 exists
            "scan_type": "comprehensive",
            "include_assets": True,
            "include_misconfigurations": True,
            "include_compliance": True
        }
        
        try:
            async with self.session.post(
                f"{self.api_url}/api/v1/cloud-security/scan",
                json=scan_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Initiate Cloud Scan", "PASS", f"Scan initiated: {result.get('scan_id', 'N/A')}")
                else:
                    self.log_test("Initiate Cloud Scan", "FAIL", f"Status: {response.status}")
        except Exception as e:
            self.log_test("Initiate Cloud Scan", "FAIL", f"Error: {e}")
    
    async def test_data_retrieval(self):
        """Test data retrieval and filtering"""
        self.log_test("Data Retrieval", "INFO", "Starting data retrieval tests")
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test 1: Get Cloud Accounts with Filtering
        try:
            async with self.session.get(
                f"{self.api_url}/api/v1/cloud-security/accounts?provider=aws",
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Get AWS Accounts", "PASS", f"Retrieved {len(result)} AWS accounts")
                else:
                    self.log_test("Get AWS Accounts", "FAIL", f"Status: {response.status}")
        except Exception as e:
            self.log_test("Get AWS Accounts", "FAIL", f"Error: {e}")
        
        # Test 2: Get Misconfigurations with Severity Filter
        try:
            async with self.session.get(
                f"{self.api_url}/api/v1/cloud-security/misconfigurations?severity=critical",
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Get Critical Misconfigurations", "PASS", f"Retrieved {len(result)} critical misconfigurations")
                else:
                    self.log_test("Get Critical Misconfigurations", "FAIL", f"Status: {response.status}")
        except Exception as e:
            self.log_test("Get Critical Misconfigurations", "FAIL", f"Error: {e}")
        
        # Test 3: Get SaaS Applications with Status Filter
        try:
            async with self.session.get(
                f"{self.api_url}/api/v1/cloud-security/saas-applications?status=sanctioned",
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Get Sanctioned SaaS Apps", "PASS", f"Retrieved {len(result)} sanctioned applications")
                else:
                    self.log_test("Get Sanctioned SaaS Apps", "FAIL", f"Status: {response.status}")
        except Exception as e:
            self.log_test("Get Sanctioned SaaS Apps", "FAIL", f"Error: {e}")
    
    async def run_comprehensive_tests(self):
        """Run all comprehensive tests"""
        self.log_test("Comprehensive Testing", "INFO", "Starting comprehensive Cloud Security testing")
        
        try:
            # Setup session and authenticate
            await self.setup_session()
            
            # Run comprehensive tests
            await self.test_cspm_comprehensive()
            await self.test_casb_comprehensive()
            await self.test_cloud_native_security()
            await self.test_dashboard_analytics()
            await self.test_data_retrieval()
            
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
            
            # Save test results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cloud_security_comprehensive_results_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump({
                    'test_summary': {
                        'total_tests': total_tests,
                        'passed_tests': passed_tests,
                        'failed_tests': failed_tests,
                        'info_tests': info_tests,
                        'success_rate': success_rate
                    },
                    'test_results': self.test_results,
                    'timestamp': datetime.now().isoformat()
                }, f, indent=2)
            
            self.log_test("Results Saved", "INFO", f"Test results saved to {filename}")
            
        except Exception as e:
            self.log_test("Comprehensive Testing", "FAIL", f"Testing failed: {e}")
        finally:
            if self.session:
                await self.session.close()

async def main():
    """Main function to run comprehensive cloud security tests"""
    print("🛡️ Comprehensive Cloud Security Module Testing")
    print("=" * 60)
    
    # Get API URL from command line or use default
    api_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    
    tester = ComprehensiveCloudSecurityTester(api_url)
    await tester.run_comprehensive_tests()
    
    print("\n" + "=" * 60)
    print("🏁 Comprehensive Cloud Security Testing Complete!")

if __name__ == "__main__":
    asyncio.run(main()) 