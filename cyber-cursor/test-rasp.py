#!/usr/bin/env python3
"""
RASP Test Script
Comprehensive test script to demonstrate and validate RASP functionality
"""
import asyncio
import json
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, Any
import aiohttp
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RASPTester:
    """Comprehensive RASP testing class"""
    
    def __init__(self, api_url: str = "http://localhost:8000"):
        self.api_url = api_url
        self.test_results = []
        self.session = None
    
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
        """Setup HTTP session"""
        try:
            self.session = aiohttp.ClientSession()
            self.log_test("Session Setup", "PASS", "HTTP session created successfully")
        except Exception as e:
            self.log_test("Session Setup", "FAIL", f"Failed to create session: {e}")
            raise
    
    async def cleanup_session(self):
        """Cleanup HTTP session"""
        if self.session:
            await self.session.close()
    
    async def test_api_connectivity(self):
        """Test basic API connectivity"""
        try:
            async with self.session.get(f"{self.api_url}/docs") as response:
                if response.status == 200:
                    self.log_test("API Connectivity", "PASS", "API is accessible")
                else:
                    self.log_test("API Connectivity", "FAIL", f"API returned status {response.status}")
        except Exception as e:
            self.log_test("API Connectivity", "FAIL", f"Failed to connect to API: {e}")
    
    async def test_agent_management(self):
        """Test agent management functionality"""
        try:
            # Create agent
            agent_data = {
                "app_name": "Test Web App",
                "language": "python",
                "version": "1.0.0",
                "config": {"monitoring_level": "high"}
            }
            
            async with self.session.post(
                f"{self.api_url}/api/rasp/agents",
                json=agent_data
            ) as response:
                if response.status == 200:
                    agent = await response.json()
                    agent_id = agent['agent_id']
                    self.log_test("Agent Creation", "PASS", f"Agent created with ID: {agent_id}")
                    
                    # Test agent retrieval
                    async with self.session.get(f"{self.api_url}/api/rasp/agents/{agent_id}") as get_response:
                        if get_response.status == 200:
                            retrieved_agent = await get_response.json()
                            if retrieved_agent['app_name'] == agent_data['app_name']:
                                self.log_test("Agent Retrieval", "PASS", "Agent retrieved successfully")
                            else:
                                self.log_test("Agent Retrieval", "FAIL", "Retrieved agent data doesn't match")
                        else:
                            self.log_test("Agent Retrieval", "FAIL", f"Failed to retrieve agent: {get_response.status}")
                    
                    # Test agent heartbeat
                    heartbeat_data = {
                        "status": "active",
                        "telemetry": [
                            {
                                "metric_name": "requests_per_minute",
                                "metric_value": 150
                            }
                        ]
                    }
                    
                    async with self.session.post(
                        f"{self.api_url}/api/rasp/agents/{agent_id}/heartbeat",
                        json=heartbeat_data
                    ) as heartbeat_response:
                        if heartbeat_response.status == 200:
                            self.log_test("Agent Heartbeat", "PASS", "Agent heartbeat updated successfully")
                        else:
                            self.log_test("Agent Heartbeat", "FAIL", f"Failed to update heartbeat: {heartbeat_response.status}")
                    
                    return agent_id
                else:
                    self.log_test("Agent Creation", "FAIL", f"Failed to create agent: {response.status}")
                    return None
        except Exception as e:
            self.log_test("Agent Management", "FAIL", f"Agent management test failed: {e}")
            return None
    
    async def test_rule_management(self):
        """Test rule management functionality"""
        try:
            # Create rule
            rule_data = {
                "vuln_type": "SQLi",
                "language": "python",
                "pattern": ".*SELECT.*FROM.*\\+.*",
                "severity": "critical",
                "auto_block": True,
                "description": "Test SQL injection rule"
            }
            
            async with self.session.post(
                f"{self.api_url}/api/rasp/rules",
                json=rule_data
            ) as response:
                if response.status == 200:
                    rule = await response.json()
                    rule_id = rule['rule_id']
                    self.log_test("Rule Creation", "PASS", f"Rule created with ID: {rule_id}")
                    
                    # Test rule retrieval
                    async with self.session.get(f"{self.api_url}/api/rasp/rules/{rule_id}") as get_response:
                        if get_response.status == 200:
                            retrieved_rule = await get_response.json()
                            if retrieved_rule['vuln_type'] == rule_data['vuln_type']:
                                self.log_test("Rule Retrieval", "PASS", "Rule retrieved successfully")
                            else:
                                self.log_test("Rule Retrieval", "FAIL", "Retrieved rule data doesn't match")
                        else:
                            self.log_test("Rule Retrieval", "FAIL", f"Failed to retrieve rule: {get_response.status}")
                    
                    return rule_id
                else:
                    self.log_test("Rule Creation", "FAIL", f"Failed to create rule: {response.status}")
                    return None
        except Exception as e:
            self.log_test("Rule Management", "FAIL", f"Rule management test failed: {e}")
            return None
    
    async def test_attack_detection(self, agent_id: int):
        """Test attack detection and logging"""
        try:
            # Create attack record
            attack_data = {
                "agent_id": agent_id,
                "source_ip": "192.168.1.100",
                "url": "/api/users",
                "payload": "'; DROP TABLE users; --",
                "vuln_type": "SQLi",
                "severity": "critical",
                "stack_trace": "Traceback (most recent call last):\n  File \"app.py\", line 10, in <module>",
                "blocked": True,
                "context": {"user_id": 123, "session_id": "abc123"},
                "request_data": {"method": "POST", "headers": {"Content-Type": "application/json"}},
                "response_data": {"status_code": 500, "error": "Database error"}
            }
            
            async with self.session.post(
                f"{self.api_url}/api/rasp/attacks",
                json=attack_data
            ) as response:
                if response.status == 200:
                    attack = await response.json()
                    attack_id = attack['attack_id']
                    self.log_test("Attack Detection", "PASS", f"Attack logged with ID: {attack_id}")
                    
                    # Test attack retrieval
                    async with self.session.get(f"{self.api_url}/api/rasp/attacks/{attack_id}") as get_response:
                        if get_response.status == 200:
                            retrieved_attack = await get_response.json()
                            if retrieved_attack['vuln_type'] == attack_data['vuln_type']:
                                self.log_test("Attack Retrieval", "PASS", "Attack retrieved successfully")
                            else:
                                self.log_test("Attack Retrieval", "FAIL", "Retrieved attack data doesn't match")
                        else:
                            self.log_test("Attack Retrieval", "FAIL", f"Failed to retrieve attack: {get_response.status}")
                    
                    return attack_id
                else:
                    self.log_test("Attack Detection", "FAIL", f"Failed to log attack: {response.status}")
                    return None
        except Exception as e:
            self.log_test("Attack Detection", "FAIL", f"Attack detection test failed: {e}")
            return None
    
    async def test_vulnerability_management(self, agent_id: int):
        """Test vulnerability management functionality"""
        try:
            # Create vulnerability (this would typically be done by the agent)
            # For testing, we'll simulate a vulnerability discovery
            vuln_data = {
                "agent_id": agent_id,
                "vuln_type": "SQLi",
                "severity": "high",
                "description": "SQL injection vulnerability in user input",
                "affected_file": "/app/models/user.py",
                "affected_line": 25,
                "affected_method": "get_user_by_id",
                "cwe_id": "CWE-89",
                "owasp_category": "A03:2021-Injection",
                "evidence": {"payload": "'; DROP TABLE users; --", "context": "user_id parameter"},
                "remediation": "Use parameterized queries or ORM methods"
            }
            
            # Note: In a real implementation, vulnerabilities would be created by the agent
            # For testing purposes, we'll just test the retrieval functionality
            async with self.session.get(f"{self.api_url}/api/rasp/vulnerabilities") as response:
                if response.status == 200:
                    vulnerabilities = await response.json()
                    self.log_test("Vulnerability Retrieval", "PASS", f"Retrieved {len(vulnerabilities)} vulnerabilities")
                else:
                    self.log_test("Vulnerability Retrieval", "FAIL", f"Failed to retrieve vulnerabilities: {response.status}")
        except Exception as e:
            self.log_test("Vulnerability Management", "FAIL", f"Vulnerability management test failed: {e}")
    
    async def test_dashboard_functionality(self):
        """Test dashboard and analytics functionality"""
        try:
            # Test dashboard overview
            async with self.session.get(f"{self.api_url}/api/rasp/dashboard/overview") as response:
                if response.status == 200:
                    overview = await response.json()
                    self.log_test("Dashboard Overview", "PASS", "Dashboard overview retrieved successfully", {
                        'total_agents': overview.get('total_agents'),
                        'total_attacks': overview.get('total_attacks'),
                        'total_vulnerabilities': overview.get('total_vulnerabilities')
                    })
                else:
                    self.log_test("Dashboard Overview", "FAIL", f"Failed to get dashboard overview: {response.status}")
            
            # Test attack summary
            async with self.session.get(f"{self.api_url}/api/rasp/dashboard/attack-summary?hours=24") as response:
                if response.status == 200:
                    summary = await response.json()
                    self.log_test("Attack Summary", "PASS", "Attack summary retrieved successfully", {
                        'total_attacks': summary.get('total_attacks'),
                        'blocked_attacks': summary.get('blocked_attacks')
                    })
                else:
                    self.log_test("Attack Summary", "FAIL", f"Failed to get attack summary: {response.status}")
            
            # Test agent status
            async with self.session.get(f"{self.api_url}/api/rasp/dashboard/agent-status") as response:
                if response.status == 200:
                    agent_status = await response.json()
                    self.log_test("Agent Status", "PASS", f"Agent status retrieved for {len(agent_status)} agents")
                else:
                    self.log_test("Agent Status", "FAIL", f"Failed to get agent status: {response.status}")
        except Exception as e:
            self.log_test("Dashboard Functionality", "FAIL", f"Dashboard functionality test failed: {e}")
    
    async def test_webhook_functionality(self):
        """Test webhook processing functionality"""
        try:
            webhook_data = {
                "event_type": "attack_detected",
                "timestamp": datetime.utcnow().isoformat(),
                "source": "test_agent",
                "data": {
                    "agent_id": 1,
                    "source_ip": "192.168.1.101",
                    "url": "/api/test",
                    "payload": "test payload",
                    "vuln_type": "XSS",
                    "severity": "medium",
                    "blocked": False
                }
            }
            
            async with self.session.post(
                f"{self.api_url}/api/rasp/webhook",
                json=webhook_data
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.log_test("Webhook Processing", "PASS", "Webhook processed successfully", result)
                else:
                    self.log_test("Webhook Processing", "FAIL", f"Failed to process webhook: {response.status}")
        except Exception as e:
            self.log_test("Webhook Functionality", "FAIL", f"Webhook functionality test failed: {e}")
    
    async def test_integration_management(self):
        """Test integration management functionality"""
        try:
            # Create SIEM integration
            integration_data = {
                "integration_type": "siem",
                "name": "Test Splunk Integration",
                "config": {
                    "endpoint": "https://splunk.example.com:8088/services/collector",
                    "token": "test_token",
                    "index": "security"
                }
            }
            
            async with self.session.post(
                f"{self.api_url}/api/rasp/integrations",
                json=integration_data
            ) as response:
                if response.status == 200:
                    integration = await response.json()
                    integration_id = integration['integration_id']
                    self.log_test("Integration Creation", "PASS", f"Integration created with ID: {integration_id}")
                    
                    # Test integration retrieval
                    async with self.session.get(f"{self.api_url}/api/rasp/integrations") as get_response:
                        if get_response.status == 200:
                            integrations = await get_response.json()
                            self.log_test("Integration Retrieval", "PASS", f"Retrieved {len(integrations)} integrations")
                        else:
                            self.log_test("Integration Retrieval", "FAIL", f"Failed to retrieve integrations: {get_response.status}")
                else:
                    self.log_test("Integration Creation", "FAIL", f"Failed to create integration: {response.status}")
        except Exception as e:
            self.log_test("Integration Management", "FAIL", f"Integration management test failed: {e}")
    
    async def test_alert_management(self):
        """Test alert management functionality"""
        try:
            # Get alerts
            async with self.session.get(f"{self.api_url}/api/rasp/alerts") as response:
                if response.status == 200:
                    alerts = await response.json()
                    self.log_test("Alert Retrieval", "PASS", f"Retrieved {len(alerts)} alerts")
                    
                    # Test alert update if alerts exist
                    if alerts:
                        alert_id = alerts[0]['alert_id']
                        update_data = {
                            "status": "acknowledged",
                            "acknowledged_by": 1
                        }
                        
                        async with self.session.put(
                            f"{self.api_url}/api/rasp/alerts/{alert_id}",
                            json=update_data
                        ) as update_response:
                            if update_response.status == 200:
                                self.log_test("Alert Update", "PASS", "Alert updated successfully")
                            else:
                                self.log_test("Alert Update", "FAIL", f"Failed to update alert: {update_response.status}")
                    else:
                        self.log_test("Alert Update", "SKIP", "No alerts to update")
                else:
                    self.log_test("Alert Retrieval", "FAIL", f"Failed to retrieve alerts: {response.status}")
        except Exception as e:
            self.log_test("Alert Management", "FAIL", f"Alert management test failed: {e}")
    
    async def run_all_tests(self):
        """Run all RASP tests"""
        print("🚀 Starting RASP Comprehensive Testing")
        print("=" * 50)
        
        try:
            await self.setup_session()
            
            # Test basic connectivity
            await self.test_api_connectivity()
            
            # Test agent management
            agent_id = await self.test_agent_management()
            
            # Test rule management
            rule_id = await self.test_rule_management()
            
            # Test attack detection (if agent was created)
            if agent_id:
                attack_id = await self.test_attack_detection(agent_id)
                await self.test_vulnerability_management(agent_id)
            
            # Test dashboard functionality
            await self.test_dashboard_functionality()
            
            # Test webhook functionality
            await self.test_webhook_functionality()
            
            # Test integration management
            await self.test_integration_management()
            
            # Test alert management
            await self.test_alert_management()
            
        except Exception as e:
            self.log_test("Test Execution", "ERROR", f"Test execution failed: {e}")
        finally:
            await self.cleanup_session()
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 50)
        print("📊 RASP Test Summary")
        print("=" * 50)
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r['status'] == 'PASS'])
        failed_tests = len([r for r in self.test_results if r['status'] == 'FAIL'])
        error_tests = len([r for r in self.test_results if r['status'] == 'ERROR'])
        skipped_tests = len([r for r in self.test_results if r['status'] == 'SKIP'])
        
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"⚠️  Errors: {error_tests}")
        print(f"⏭️  Skipped: {skipped_tests}")
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        print(f"\nSuccess Rate: {success_rate:.1f}%")
        
        if failed_tests > 0 or error_tests > 0:
            print("\n❌ Failed Tests:")
            for result in self.test_results:
                if result['status'] in ['FAIL', 'ERROR']:
                    print(f"  - {result['test_name']}: {result['message']}")
        
        # Save results to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"rasp_test_results_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(self.test_results, f, indent=2, default=str)
        
        print(f"\n📄 Detailed results saved to: {filename}")
        
        return success_rate >= 80  # Return True if success rate is 80% or higher

async def main():
    """Main test function"""
    tester = RASPTester()
    
    try:
        await tester.run_all_tests()
        success = tester.print_summary()
        
        if success:
            print("\n🎉 RASP testing completed successfully!")
            sys.exit(0)
        else:
            print("\n💥 RASP testing completed with failures!")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⏹️  Testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error during testing: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 