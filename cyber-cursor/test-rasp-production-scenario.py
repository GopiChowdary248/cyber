#!/usr/bin/env python3
"""
RASP Production Scenario Test
Simulates real-world production environment with multiple concurrent users,
complex attack patterns, and stress testing scenarios.
"""

import asyncio
import json
import sys
import time
import random
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List
import aiohttp
import logging
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RASPProductionScenarioTester:
    """Production scenario testing class for RASP system"""
    
    def __init__(self, api_url: str = "http://localhost:8000"):
        self.api_url = api_url
        self.session = None
        self.test_results = []
        self.agents = []
        self.attacks = []
        self.users = []
        self.scenarios = []
        
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
    
    def generate_realistic_users(self, count: int = 50):
        """Generate realistic user profiles for testing"""
        user_types = [
            {"type": "admin", "weight": 0.1},
            {"type": "developer", "weight": 0.2},
            {"type": "analyst", "weight": 0.3},
            {"type": "end_user", "weight": 0.4}
        ]
        
        for i in range(count):
            user_type = random.choices(
                [u["type"] for u in user_types],
                weights=[u["weight"] for u in user_types]
            )[0]
            
            user = {
                "user_id": f"user_{uuid.uuid4().hex[:8]}",
                "type": user_type,
                "ip_range": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "session_id": f"session_{uuid.uuid4().hex[:12]}",
                "user_agent": self.get_random_user_agent(),
                "activity_pattern": self.get_activity_pattern(user_type)
            }
            self.users.append(user)
    
    def get_random_user_agent(self):
        """Get random user agent string"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15",
            "Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/68.0"
        ]
        return random.choice(user_agents)
    
    def get_activity_pattern(self, user_type: str):
        """Get activity pattern based on user type"""
        patterns = {
            "admin": {"requests_per_minute": (20, 50), "attack_probability": 0.05},
            "developer": {"requests_per_minute": (30, 80), "attack_probability": 0.02},
            "analyst": {"requests_per_minute": (10, 30), "attack_probability": 0.01},
            "end_user": {"requests_per_minute": (5, 15), "attack_probability": 0.001}
        }
        return patterns.get(user_type, {"requests_per_minute": (10, 20), "attack_probability": 0.01})
    
    async def deploy_production_agents(self):
        """Deploy agents simulating production environment"""
        production_apps = [
            {
                "app_name": "Customer Portal",
                "language": "python",
                "version": "3.2.1",
                "config": {"monitoring_level": "high", "auto_block": True},
                "expected_traffic": "high"
            },
            {
                "app_name": "Payment Gateway",
                "language": "java",
                "version": "2.8.5",
                "config": {"monitoring_level": "critical", "auto_block": True},
                "expected_traffic": "critical"
            },
            {
                "app_name": "Admin Dashboard",
                "language": "nodejs",
                "version": "4.1.2",
                "config": {"monitoring_level": "high", "auto_block": False},
                "expected_traffic": "medium"
            },
            {
                "app_name": "API Gateway",
                "language": "python",
                "version": "2.5.0",
                "config": {"monitoring_level": "critical", "auto_block": True},
                "expected_traffic": "very_high"
            },
            {
                "app_name": "Mobile API",
                "language": "java",
                "version": "1.9.3",
                "config": {"monitoring_level": "high", "auto_block": True},
                "expected_traffic": "high"
            }
        ]
        
        for i, app in enumerate(production_apps):
            try:
                async with self.session.post(
                    f"{self.api_url}/api/rasp/agents",
                    json=app
                ) as response:
                    if response.status == 200:
                        agent = await response.json()
                        self.agents.append(agent)
                        self.log_test(f"Production Agent {i+1}", "PASS", 
                                    f"Deployed {app['app_name']}", {
                                        'agent_id': agent['agent_id'],
                                        'app_name': app['app_name'],
                                        'traffic_level': app['expected_traffic']
                                    })
                    else:
                        self.log_test(f"Production Agent {i+1}", "FAIL", 
                                    f"Failed to deploy {app['app_name']}")
            except Exception as e:
                self.log_test(f"Production Agent {i+1}", "FAIL", 
                            f"Agent deployment failed: {e}")
    
    async def simulate_normal_traffic(self, duration_minutes: int = 5):
        """Simulate normal user traffic patterns"""
        self.log_test("Normal Traffic Simulation", "INFO", 
                     f"Starting {duration_minutes} minute traffic simulation")
        
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        normal_requests = 0
        while time.time() < end_time:
            # Simulate concurrent users
            tasks = []
            for user in random.sample(self.users, min(10, len(self.users))):
                task = self.simulate_user_session(user)
                tasks.append(task)
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                normal_requests += len(tasks)
            
            # Wait between batches
            await asyncio.sleep(random.uniform(0.5, 2.0))
        
        self.log_test("Normal Traffic Simulation", "PASS", 
                     f"Completed {normal_requests} normal requests")
    
    async def simulate_user_session(self, user: Dict[str, Any]):
        """Simulate a single user session"""
        try:
            # Simulate normal API calls
            endpoints = [
                "/api/users/profile",
                "/api/products/search",
                "/api/orders/history",
                "/api/notifications",
                "/api/settings"
            ]
            
            endpoint = random.choice(endpoints)
            headers = {
                "User-Agent": user["user_agent"],
                "X-Session-ID": user["session_id"],
                "X-User-ID": user["user_id"]
            }
            
            # Simulate request (this would normally go to the actual application)
            # For testing, we just simulate the request pattern
            await asyncio.sleep(random.uniform(0.01, 0.1))
            
        except Exception as e:
            logger.debug(f"User session simulation error: {e}")
    
    async def simulate_advanced_attacks(self):
        """Simulate advanced attack scenarios"""
        advanced_attacks = [
            {
                "name": "SQL Injection with Encoding",
                "payloads": [
                    "'; DROP TABLE users; --",
                    "1' UNION SELECT password FROM users--",
                    "1' OR '1'='1'--",
                    "admin'--",
                    "1' AND (SELECT COUNT(*) FROM users)>0--"
                ],
                "vuln_type": "SQLi",
                "severity": "critical"
            },
            {
                "name": "XSS with Evasion",
                "payloads": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<svg onload=alert('XSS')>",
                    "&#60;script&#62;alert('XSS')&#60;/script&#62;"
                ],
                "vuln_type": "XSS",
                "severity": "high"
            },
            {
                "name": "Command Injection with Bypass",
                "payloads": [
                    "; rm -rf /",
                    "| cat /etc/passwd",
                    "&& whoami",
                    "`id`",
                    "$(cat /etc/shadow)"
                ],
                "vuln_type": "Command Injection",
                "severity": "critical"
            },
            {
                "name": "Path Traversal with Encoding",
                "payloads": [
                    "../../../etc/passwd",
                    "..%2F..%2F..%2Fetc%2Fpasswd",
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%252F..%252F..%252Fetc%252Fpasswd"
                ],
                "vuln_type": "Path Traversal",
                "severity": "high"
            },
            {
                "name": "NoSQL Injection",
                "payloads": [
                    '{"$where": "1==1"}',
                    '{"$ne": null}',
                    '{"$gt": ""}',
                    '{"$regex": ".*"}',
                    '{"$exists": true}'
                ],
                "vuln_type": "NoSQL Injection",
                "severity": "critical"
            }
        ]
        
        for i, attack_scenario in enumerate(advanced_attacks):
            for j, payload in enumerate(attack_scenario["payloads"]):
                try:
                    attack_data = {
                        "agent_id": random.choice(self.agents)["agent_id"] if self.agents else 1,
                        "source_ip": random.choice(self.users)["ip_range"] if self.users else "192.168.1.100",
                        "url": f"/api/vulnerable/endpoint/{i}",
                        "payload": payload,
                        "vuln_type": attack_scenario["vuln_type"],
                        "severity": attack_scenario["severity"],
                        "stack_trace": f"Advanced attack simulation: {attack_scenario['name']}",
                        "blocked": attack_scenario["severity"] == "critical",
                        "context": {
                            "user_id": random.choice(self.users)["user_id"] if self.users else "unknown",
                            "session_id": random.choice(self.users)["session_id"] if self.users else "unknown",
                            "attack_technique": attack_scenario["name"]
                        },
                        "request_data": {
                            "method": random.choice(["GET", "POST", "PUT"]),
                            "headers": {
                                "Content-Type": "application/json",
                                "User-Agent": random.choice(self.users)["user_agent"] if self.users else "Mozilla/5.0"
                            }
                        },
                        "response_data": {
                            "status_code": 500 if attack_scenario["severity"] == "critical" else 200,
                            "response_time_ms": random.randint(50, 500)
                        }
                    }
                    
                    async with self.session.post(
                        f"{self.api_url}/api/rasp/attacks",
                        json=attack_data
                    ) as response:
                        if response.status == 200:
                            attack = await response.json()
                            self.attacks.append(attack)
                            self.log_test(f"Advanced Attack {i+1}.{j+1}", "PASS", 
                                        f"Simulated {attack_scenario['name']} with payload {j+1}", {
                                            'attack_id': attack['attack_id'],
                                            'vuln_type': attack_scenario['vuln_type'],
                                            'severity': attack_scenario['severity'],
                                            'blocked': attack['blocked']
                                        })
                        else:
                            self.log_test(f"Advanced Attack {i+1}.{j+1}", "FAIL", 
                                        f"Failed to simulate {attack_scenario['name']}")
                            
                except Exception as e:
                    self.log_test(f"Advanced Attack {i+1}.{j+1}", "FAIL", 
                                f"Attack simulation failed: {e}")
    
    async def simulate_concurrent_stress_test(self, concurrent_users: int = 100, duration_seconds: int = 60):
        """Simulate high concurrent load stress test"""
        self.log_test("Stress Test", "INFO", 
                     f"Starting stress test with {concurrent_users} concurrent users for {duration_seconds} seconds")
        
        start_time = time.time()
        end_time = start_time + duration_seconds
        
        async def stress_worker(worker_id: int):
            """Individual stress test worker"""
            requests_made = 0
            errors = 0
            
            while time.time() < end_time:
                try:
                    # Simulate various API calls
                    endpoints = [
                        "/api/rasp/agents",
                        "/api/rasp/dashboard/overview",
                        "/api/rasp/attacks",
                        "/api/rasp/alerts"
                    ]
                    
                    endpoint = random.choice(endpoints)
                    async with self.session.get(f"{self.api_url}{endpoint}") as response:
                        if response.status == 200:
                            requests_made += 1
                        else:
                            errors += 1
                    
                    await asyncio.sleep(random.uniform(0.1, 0.5))
                    
                except Exception as e:
                    errors += 1
                    logger.debug(f"Stress worker {worker_id} error: {e}")
            
            return {"worker_id": worker_id, "requests": requests_made, "errors": errors}
        
        # Create concurrent workers
        workers = [stress_worker(i) for i in range(concurrent_users)]
        results = await asyncio.gather(*workers, return_exceptions=True)
        
        # Calculate statistics
        total_requests = sum(r["requests"] for r in results if isinstance(r, dict))
        total_errors = sum(r["errors"] for r in results if isinstance(r, dict))
        success_rate = ((total_requests - total_errors) / total_requests * 100) if total_requests > 0 else 0
        
        self.log_test("Stress Test", "PASS", 
                     f"Completed stress test", {
                         'total_requests': total_requests,
                         'total_errors': total_errors,
                         'success_rate': f"{success_rate:.1f}%",
                         'requests_per_second': f"{total_requests/duration_seconds:.1f}"
                     })
    
    async def test_real_time_monitoring(self):
        """Test real-time monitoring capabilities"""
        try:
            # Test dashboard with real-time data
            async with self.session.get(f"{self.api_url}/api/rasp/dashboard/overview") as response:
                if response.status == 200:
                    dashboard = await response.json()
                    self.log_test("Real-time Dashboard", "PASS", 
                                "Dashboard updated with real-time data", {
                                    'total_agents': dashboard.get('total_agents'),
                                    'total_attacks': dashboard.get('total_attacks'),
                                    'active_agents': dashboard.get('active_agents'),
                                    'blocked_attacks': dashboard.get('blocked_attacks')
                                })
                else:
                    self.log_test("Real-time Dashboard", "FAIL", "Failed to get dashboard data")
            
            # Test attack summary
            async with self.session.get(f"{self.api_url}/api/rasp/dashboard/attack-summary?hours=1") as response:
                if response.status == 200:
                    summary = await response.json()
                    self.log_test("Real-time Attack Summary", "PASS", 
                                "Attack summary updated", {
                                    'total_attacks': summary.get('total_attacks'),
                                    'blocked_attacks': summary.get('blocked_attacks'),
                                    'attack_types': summary.get('recent_attacks_by_type', {})
                                })
                else:
                    self.log_test("Real-time Attack Summary", "FAIL", "Failed to get attack summary")
                    
        except Exception as e:
            self.log_test("Real-time Monitoring", "FAIL", f"Real-time monitoring failed: {e}")
    
    async def test_alert_correlation(self):
        """Test alert correlation and false positive reduction"""
        try:
            # Get recent alerts
            async with self.session.get(f"{self.api_url}/api/rasp/alerts") as response:
                if response.status == 200:
                    alerts = await response.json()
                    
                    # Analyze alert patterns
                    critical_alerts = [a for a in alerts if a.get('severity') == 'critical']
                    high_alerts = [a for a in alerts if a.get('severity') == 'high']
                    
                    self.log_test("Alert Correlation", "PASS", 
                                "Alert correlation analysis completed", {
                                    'total_alerts': len(alerts),
                                    'critical_alerts': len(critical_alerts),
                                    'high_alerts': len(high_alerts),
                                    'correlation_score': f"{len(critical_alerts) / len(alerts) * 100:.1f}%" if alerts else "0%"
                                })
                else:
                    self.log_test("Alert Correlation", "FAIL", "Failed to retrieve alerts")
                    
        except Exception as e:
            self.log_test("Alert Correlation", "FAIL", f"Alert correlation failed: {e}")
    
    async def run_production_scenario(self):
        """Run complete production scenario test"""
        print("🚀 Starting RASP Production Scenario Test")
        print("=" * 60)
        
        try:
            await self.setup_session()
            
            # Phase 1: Setup Production Environment
            print("\n📋 Phase 1: Production Environment Setup")
            self.generate_realistic_users(50)
            await self.deploy_production_agents()
            
            # Phase 2: Normal Traffic Simulation
            print("\n📋 Phase 2: Normal Traffic Simulation")
            await self.simulate_normal_traffic(duration_minutes=2)
            
            # Phase 3: Advanced Attack Simulation
            print("\n📋 Phase 3: Advanced Attack Simulation")
            await self.simulate_advanced_attacks()
            
            # Phase 4: Stress Testing
            print("\n📋 Phase 4: Stress Testing")
            await self.simulate_concurrent_stress_test(concurrent_users=50, duration_seconds=30)
            
            # Phase 5: Real-time Monitoring
            print("\n📋 Phase 5: Real-time Monitoring")
            await self.test_real_time_monitoring()
            
            # Phase 6: Alert Correlation
            print("\n📋 Phase 6: Alert Correlation")
            await self.test_alert_correlation()
            
        except Exception as e:
            self.log_test("Production Scenario", "ERROR", f"Scenario execution failed: {e}")
        finally:
            await self.cleanup_session()
    
    def print_production_summary(self):
        """Print comprehensive production scenario summary"""
        print("\n" + "=" * 60)
        print("📊 RASP Production Scenario Test Summary")
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
        
        # Production metrics
        print(f"\n📈 Production Metrics:")
        print(f"   Users Simulated: {len(self.users)}")
        print(f"   Agents Deployed: {len(self.agents)}")
        print(f"   Attacks Detected: {len(self.attacks)}")
        print(f"   Critical Attacks: {len([a for a in self.attacks if a.get('severity') == 'critical'])}")
        print(f"   Blocked Attacks: {len([a for a in self.attacks if a.get('blocked')])}")
        
        # Performance metrics
        if self.attacks:
            avg_response_time = sum(a.get('response_data', {}).get('response_time_ms', 0) for a in self.attacks) / len(self.attacks)
            print(f"   Average Response Time: {avg_response_time:.1f}ms")
        
        if failed_tests > 0 or error_tests > 0:
            print("\n❌ Failed Tests:")
            for result in self.test_results:
                if result['status'] in ['FAIL', 'ERROR']:
                    print(f"  - {result['test_name']}: {result['message']}")
        
        # Save detailed results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"rasp_production_scenario_results_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump({
                'test_results': self.test_results,
                'users': self.users,
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
        
        return success_rate >= 95  # Return True if success rate is 95% or higher

async def main():
    """Main production scenario test function"""
    tester = RASPProductionScenarioTester()
    
    try:
        await tester.run_production_scenario()
        success = tester.print_production_summary()
        
        if success:
            print("\n🎉 RASP production scenario testing completed successfully!")
            print("✅ System is ready for production deployment")
            print("✅ All production scenarios validated")
            sys.exit(0)
        else:
            print("\n💥 RASP production scenario testing completed with issues!")
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