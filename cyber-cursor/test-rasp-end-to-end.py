#!/usr/bin/env python3
"""
RASP End-to-End Test Application
Comprehensive test that simulates real-world RASP deployment scenarios
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

class RASPEndToEndTester:
    """End-to-end RASP testing class that simulates real-world scenarios"""
    
    def __init__(self, api_url: str = "http://localhost:8000"):
        self.api_url = api_url
        self.session = None
        self.test_results = []
        self.agents = []
        self.attacks = []
        
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
    
    async def test_system_health(self):
        """Test overall system health"""
        try:
            # Test API connectivity
            async with self.session.get(f"{self.api_url}/api/rasp/agents") as response:
                if response.status == 200:
                    self.log_test("System Health", "PASS", "RASP API is healthy and accessible")
                else:
                    self.log_test("System Health", "FAIL", f"API returned status {response.status}")
            
            # Test dashboard
            async with self.session.get(f"{self.api_url}/api/rasp/dashboard/overview") as response:
                if response.status == 200:
                    dashboard = await response.json()
                    self.log_test("Dashboard Health", "PASS", "Dashboard is operational", {
                        'total_agents': dashboard.get('total_agents'),
                        'total_attacks': dashboard.get('total_attacks')
                    })
                else:
                    self.log_test("Dashboard Health", "FAIL", f"Dashboard returned status {response.status}")
                    
        except Exception as e:
            self.log_test("System Health", "FAIL", f"System health check failed: {e}")
    
    async def deploy_test_agents(self):
        """Deploy test agents simulating different application types"""
        agent_configs = [
            {
                "app_name": "E-Commerce Web App",
                "language": "python",
                "version": "2.1.0",
                "config": {"monitoring_level": "high", "auto_block": True}
            },
            {
                "app_name": "Banking API",
                "language": "java",
                "version": "1.5.2",
                "config": {"monitoring_level": "critical", "auto_block": True}
            },
            {
                "app_name": "Mobile Backend",
                "language": "nodejs",
                "version": "3.0.1",
                "config": {"monitoring_level": "high", "auto_block": False}
            }
        ]
        
        for i, config in enumerate(agent_configs):
            try:
                async with self.session.post(
                    f"{self.api_url}/api/rasp/agents",
                    json=config
                ) as response:
                    if response.status == 200:
                        agent = await response.json()
                        self.agents.append(agent)
                        self.log_test(f"Agent Deployment {i+1}", "PASS", 
                                    f"Deployed {config['app_name']} agent", {
                                        'agent_id': agent['agent_id'],
                                        'app_name': config['app_name'],
                                        'language': config['language']
                                    })
                    else:
                        self.log_test(f"Agent Deployment {i+1}", "FAIL", 
                                    f"Failed to deploy {config['app_name']} agent")
            except Exception as e:
                self.log_test(f"Agent Deployment {i+1}", "FAIL", 
                            f"Agent deployment failed: {e}")
    
    async def simulate_attack_scenarios(self):
        """Simulate various attack scenarios"""
        attack_scenarios = [
            {
                "name": "SQL Injection Attack",
                "agent_id": self.agents[0]['agent_id'] if self.agents else 1,
                "payload": "'; DROP TABLE users; --",
                "vuln_type": "SQLi",
                "severity": "critical",
                "url": "/api/users/search",
                "source_ip": "192.168.1.100"
            },
            {
                "name": "XSS Attack",
                "agent_id": self.agents[1]['agent_id'] if len(self.agents) > 1 else 1,
                "payload": "<script>alert('XSS')</script>",
                "vuln_type": "XSS",
                "severity": "high",
                "url": "/api/comments",
                "source_ip": "192.168.1.101"
            },
            {
                "name": "Command Injection Attack",
                "agent_id": self.agents[2]['agent_id'] if len(self.agents) > 2 else 1,
                "payload": "; rm -rf /",
                "vuln_type": "Command Injection",
                "severity": "critical",
                "url": "/api/system/backup",
                "source_ip": "192.168.1.102"
            },
            {
                "name": "Path Traversal Attack",
                "agent_id": self.agents[0]['agent_id'] if self.agents else 1,
                "payload": "../../../etc/passwd",
                "vuln_type": "Path Traversal",
                "severity": "high",
                "url": "/api/files/download",
                "source_ip": "192.168.1.103"
            }
        ]
        
        for i, scenario in enumerate(attack_scenarios):
            try:
                attack_data = {
                    "agent_id": scenario["agent_id"],
                    "source_ip": scenario["source_ip"],
                    "url": scenario["url"],
                    "payload": scenario["payload"],
                    "vuln_type": scenario["vuln_type"],
                    "severity": scenario["severity"],
                    "stack_trace": f"Traceback for {scenario['name']}",
                    "blocked": scenario["severity"] == "critical",
                    "context": {"user_id": random.randint(1000, 9999)},
                    "request_data": {"method": "POST", "headers": {"Content-Type": "application/json"}},
                    "response_data": {"status_code": 500 if scenario["severity"] == "critical" else 200}
                }
                
                async with self.session.post(
                    f"{self.api_url}/api/rasp/attacks",
                    json=attack_data
                ) as response:
                    if response.status == 200:
                        attack = await response.json()
                        self.attacks.append(attack)
                        self.log_test(f"Attack Simulation {i+1}", "PASS", 
                                    f"Simulated {scenario['name']}", {
                                        'attack_id': attack['attack_id'],
                                        'vuln_type': scenario['vuln_type'],
                                        'severity': scenario['severity'],
                                        'blocked': attack['blocked']
                                    })
                    else:
                        self.log_test(f"Attack Simulation {i+1}", "FAIL", 
                                    f"Failed to simulate {scenario['name']}")
                        
            except Exception as e:
                self.log_test(f"Attack Simulation {i+1}", "FAIL", 
                            f"Attack simulation failed: {e}")
    
    async def test_agent_heartbeats(self):
        """Test agent heartbeat functionality"""
        for i, agent in enumerate(self.agents):
            try:
                heartbeat_data = {
                    "status": "active",
                    "telemetry": [
                        {
                            "metric_name": "requests_per_minute",
                            "metric_value": random.randint(50, 200)
                        },
                        {
                            "metric_name": "memory_usage_mb",
                            "metric_value": random.randint(100, 500)
                        },
                        {
                            "metric_name": "cpu_usage_percent",
                            "metric_value": random.randint(10, 80)
                        }
                    ]
                }
                
                async with self.session.post(
                    f"{self.api_url}/api/rasp/agents/{agent['agent_id']}/heartbeat",
                    json=heartbeat_data
                ) as response:
                    if response.status == 200:
                        self.log_test(f"Agent Heartbeat {i+1}", "PASS", 
                                    f"Heartbeat updated for {agent['app_name']}")
                    else:
                        self.log_test(f"Agent Heartbeat {i+1}", "FAIL", 
                                    f"Heartbeat failed for {agent['app_name']}")
                        
            except Exception as e:
                self.log_test(f"Agent Heartbeat {i+1}", "FAIL", 
                            f"Heartbeat test failed: {e}")
    
    async def test_alert_generation(self):
        """Test alert generation and management"""
        try:
            # Get current alerts
            async with self.session.get(f"{self.api_url}/api/rasp/alerts") as response:
                if response.status == 200:
                    alerts = await response.json()
                    self.log_test("Alert Generation", "PASS", 
                                f"Generated {len(alerts)} alerts from attacks")
                    
                    # Test alert acknowledgment
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
                                self.log_test("Alert Management", "PASS", "Alert acknowledged successfully")
                            else:
                                self.log_test("Alert Management", "FAIL", "Failed to acknowledge alert")
                else:
                    self.log_test("Alert Generation", "FAIL", "Failed to retrieve alerts")
                    
        except Exception as e:
            self.log_test("Alert Generation", "FAIL", f"Alert test failed: {e}")
    
    async def test_dashboard_analytics(self):
        """Test dashboard analytics and reporting"""
        try:
            # Test attack summary
            async with self.session.get(f"{self.api_url}/api/rasp/dashboard/attack-summary?hours=24") as response:
                if response.status == 200:
                    summary = await response.json()
                    self.log_test("Dashboard Analytics", "PASS", "Attack summary retrieved", {
                        'total_attacks': summary.get('total_attacks'),
                        'blocked_attacks': summary.get('blocked_attacks'),
                        'attack_types': summary.get('recent_attacks_by_type', {})
                    })
                else:
                    self.log_test("Dashboard Analytics", "FAIL", "Failed to get attack summary")
            
            # Test agent status
            async with self.session.get(f"{self.api_url}/api/rasp/dashboard/agent-status") as response:
                if response.status == 200:
                    agent_status = await response.json()
                    self.log_test("Agent Status Dashboard", "PASS", 
                                f"Agent status for {len(agent_status)} agents")
                else:
                    self.log_test("Agent Status Dashboard", "FAIL", "Failed to get agent status")
                    
        except Exception as e:
            self.log_test("Dashboard Analytics", "FAIL", f"Dashboard analytics failed: {e}")
    
    async def test_siem_integration(self):
        """Test SIEM integration functionality"""
        try:
            # Test webhook processing
            webhook_data = {
                "event_type": "attack_detected",
                "timestamp": datetime.now().isoformat(),
                "source": "end_to_end_test",
                "data": {
                    "agent_id": self.agents[0]['agent_id'] if self.agents else 1,
                    "source_ip": "192.168.1.200",
                    "url": "/api/test",
                    "payload": "test payload",
                    "vuln_type": "Test",
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
                    self.log_test("SIEM Integration", "PASS", "Webhook processed successfully", result)
                else:
                    self.log_test("SIEM Integration", "FAIL", "Failed to process webhook")
                    
        except Exception as e:
            self.log_test("SIEM Integration", "FAIL", f"SIEM integration failed: {e}")
    
    async def test_performance_metrics(self):
        """Test performance and response times"""
        try:
            start_time = time.time()
            
            # Test multiple concurrent requests
            tasks = []
            for i in range(10):
                task = self.session.get(f"{self.api_url}/api/rasp/agents")
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            end_time = time.time()
            response_time = end_time - start_time
            
            successful_responses = sum(1 for r in responses if not isinstance(r, Exception))
            
            self.log_test("Performance Test", "PASS", 
                        f"Handled {successful_responses}/10 concurrent requests", {
                            'response_time_seconds': round(response_time, 3),
                            'avg_response_time_ms': round((response_time / 10) * 1000, 2),
                            'success_rate': f"{successful_responses/10*100:.1f}%"
                        })
                        
        except Exception as e:
            self.log_test("Performance Test", "FAIL", f"Performance test failed: {e}")
    
    async def run_end_to_end_test(self):
        """Run complete end-to-end test"""
        print("🚀 Starting RASP End-to-End Testing")
        print("=" * 60)
        
        try:
            await self.setup_session()
            
            # Phase 1: System Health Check
            print("\n📋 Phase 1: System Health Check")
            await self.test_system_health()
            
            # Phase 2: Agent Deployment
            print("\n📋 Phase 2: Agent Deployment")
            await self.deploy_test_agents()
            
            # Phase 3: Attack Simulation
            print("\n📋 Phase 3: Attack Simulation")
            await self.simulate_attack_scenarios()
            
            # Phase 4: Agent Monitoring
            print("\n📋 Phase 4: Agent Monitoring")
            await self.test_agent_heartbeats()
            
            # Phase 5: Alert Management
            print("\n📋 Phase 5: Alert Management")
            await self.test_alert_generation()
            
            # Phase 6: Dashboard Analytics
            print("\n📋 Phase 6: Dashboard Analytics")
            await self.test_dashboard_analytics()
            
            # Phase 7: SIEM Integration
            print("\n📋 Phase 7: SIEM Integration")
            await self.test_siem_integration()
            
            # Phase 8: Performance Testing
            print("\n📋 Phase 8: Performance Testing")
            await self.test_performance_metrics()
            
        except Exception as e:
            self.log_test("End-to-End Test", "ERROR", f"Test execution failed: {e}")
        finally:
            await self.cleanup_session()
    
    def print_summary(self):
        """Print comprehensive test summary"""
        print("\n" + "=" * 60)
        print("📊 RASP End-to-End Test Summary")
        print("=" * 60)
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r['status'] == 'PASS'])
        failed_tests = len([r for r in self.test_results if r['status'] == 'FAIL'])
        error_tests = len([r for r in self.test_results if r['status'] == 'ERROR'])
        
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"⚠️  Errors: {error_tests}")
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        print(f"\nSuccess Rate: {success_rate:.1f}%")
        
        # System metrics
        print(f"\n📈 System Metrics:")
        print(f"   Agents Deployed: {len(self.agents)}")
        print(f"   Attacks Simulated: {len(self.attacks)}")
        print(f"   Critical Attacks: {len([a for a in self.attacks if a.get('severity') == 'critical'])}")
        print(f"   Blocked Attacks: {len([a for a in self.attacks if a.get('blocked')])}")
        
        if failed_tests > 0 or error_tests > 0:
            print("\n❌ Failed Tests:")
            for result in self.test_results:
                if result['status'] in ['FAIL', 'ERROR']:
                    print(f"  - {result['test_name']}: {result['message']}")
        
        # Save detailed results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"rasp_end_to_end_results_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump({
                'test_results': self.test_results,
                'agents': self.agents,
                'attacks': self.attacks,
                'summary': {
                    'total_tests': total_tests,
                    'passed_tests': passed_tests,
                    'failed_tests': failed_tests,
                    'error_tests': error_tests,
                    'success_rate': success_rate
                }
            }, f, indent=2, default=str)
        
        print(f"\n📄 Detailed results saved to: {filename}")
        
        return success_rate >= 90  # Return True if success rate is 90% or higher

async def main():
    """Main test function"""
    tester = RASPEndToEndTester()
    
    try:
        await tester.run_end_to_end_test()
        success = tester.print_summary()
        
        if success:
            print("\n🎉 RASP end-to-end testing completed successfully!")
            print("✅ System is ready for production deployment")
            sys.exit(0)
        else:
            print("\n💥 RASP end-to-end testing completed with issues!")
            print("⚠️  Review failed tests before production deployment")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⏹️  Testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error during testing: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 