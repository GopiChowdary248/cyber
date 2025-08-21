#!/usr/bin/env python3
"""
Comprehensive Platform Testing Script for Cyber Cursor Security Platform
Tests all security modules, endpoints, and functionality
"""

import asyncio
import requests
import json
import time
import sys
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from datetime import datetime

# Add the backend directory to the Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

@dataclass
class TestResult:
    module: str
    endpoint: str
    status: str
    response_time: float
    status_code: int
    error: str = None
    details: Dict[str, Any] = None

class ComprehensivePlatformTester:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.api_base = f"{base_url}/api/v1"
        self.results: List[TestResult] = []
        self.start_time = time.time()
        
    def log(self, message: str, level: str = "INFO"):
        """Log a message with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
    
    async def test_health_endpoints(self) -> List[TestResult]:
        """Test basic health and status endpoints"""
        self.log("🏥 Testing Health and Status Endpoints...")
        
        health_endpoints = [
            ("Health Check", "/health"),
            ("Root Endpoint", "/"),
            ("API Status", "/api/status"),
            ("OpenAPI Schema", "/openapi.json"),
            ("Swagger Docs", "/docs"),
            ("ReDoc", "/redoc")
        ]
        
        results = []
        for name, endpoint in health_endpoints:
            try:
                start_time = time.time()
                response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                response_time = time.time() - start_time
                
                result = TestResult(
                    module="Platform",
                    endpoint=endpoint,
                    status="PASS" if response.status_code == 200 else "FAIL",
                    response_time=response_time,
                    status_code=response.status_code,
                    details={"name": name}
                )
                
                if response.status_code == 200:
                    self.log(f"✅ {name}: {endpoint} - {response.status_code} ({response_time:.3f}s)")
                else:
                    self.log(f"❌ {name}: {endpoint} - {response.status_code} ({response_time:.3f}s)")
                
                results.append(result)
                
            except Exception as e:
                result = TestResult(
                    module="Platform",
                    endpoint=endpoint,
                    status="ERROR",
                    response_time=0,
                    status_code=0,
                    error=str(e),
                    details={"name": name}
                )
                self.log(f"💥 {name}: {endpoint} - ERROR: {e}")
                results.append(result)
        
        return results
    
    async def test_security_modules(self) -> List[TestResult]:
        """Test all security module endpoints"""
        self.log("🔒 Testing Security Module Endpoints...")
        
        security_modules = [
            ("DAST", "/dast"),
            ("SAST", "/sast"),
            ("RASP", "/rasp"),
            ("Cloud Security", "/cloud-security"),
            ("Endpoint Security", "/endpoint-security"),
            ("Network Security", "/network-security"),
            ("IAM", "/iam"),
            ("Data Security", "/data-security"),
            ("Incident Management", "/incidents"),
            ("Threat Intelligence", "/threat-intelligence"),
            ("Compliance", "/compliance"),
            ("DevSecOps", "/devsecops"),
            ("AI/ML", "/ai-ml"),
            ("Admin", "/admin"),
            ("User Management", "/users"),
            ("Audit & Logging", "/audit"),
            ("Reporting & Analytics", "/reporting"),
            ("Integrations", "/integrations")
        ]
        
        results = []
        for module_name, endpoint in security_modules:
            try:
                start_time = time.time()
                response = requests.get(f"{self.api_base}{endpoint}", timeout=10)
                response_time = time.time() - start_time
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        status = "PASS"
                        details = {
                            "module": data.get("module"),
                            "status": data.get("status"),
                            "features_count": len(data.get("features", []))
                        }
                        self.log(f"✅ {module_name}: {endpoint} - {response.status_code} ({response_time:.3f}s)")
                    except json.JSONDecodeError:
                        status = "FAIL"
                        details = {"error": "Invalid JSON response"}
                        self.log(f"⚠️ {module_name}: {endpoint} - Invalid JSON response")
                else:
                    status = "FAIL"
                    details = {"error": f"HTTP {response.status_code}"}
                    self.log(f"❌ {module_name}: {endpoint} - {response.status_code} ({response_time:.3f}s)")
                
                result = TestResult(
                    module=module_name,
                    endpoint=endpoint,
                    status=status,
                    response_time=response_time,
                    status_code=response.status_code,
                    details=details
                )
                
                results.append(result)
                
            except Exception as e:
                result = TestResult(
                    module=module_name,
                    endpoint=endpoint,
                    status="ERROR",
                    response_time=0,
                    status_code=0,
                    error=str(e)
                )
                self.log(f"💥 {module_name}: {endpoint} - ERROR: {e}")
                results.append(result)
        
        return results
    
    async def test_authentication(self) -> List[TestResult]:
        """Test authentication and protected endpoints"""
        self.log("🔐 Testing Authentication and Protected Endpoints...")
        
        # Test protected endpoint without authentication
        try:
            start_time = time.time()
            response = requests.get(f"{self.api_base}/dast/projects", timeout=10)
            response_time = time.time() - start_time
            
            # Should return 401 or 403 for unauthenticated requests
            expected_status = 401 if response.status_code in [401, 403] else "Unexpected"
            
            result = TestResult(
                module="Authentication",
                endpoint="/dast/projects",
                status="PASS" if expected_status == 401 else "FAIL",
                response_time=response_time,
                status_code=response.status_code,
                details={"expected": "401 Unauthorized", "actual": response.status_code}
            )
            
            if expected_status == 401:
                self.log(f"✅ Authentication Test: Protected endpoint correctly requires auth ({response.status_code})")
            else:
                self.log(f"⚠️ Authentication Test: Protected endpoint should require auth but returned {response.status_code}")
            
            return [result]
            
        except Exception as e:
            result = TestResult(
                module="Authentication",
                endpoint="/dast/projects",
                status="ERROR",
                response_time=0,
                status_code=0,
                error=str(e)
            )
            self.log(f"💥 Authentication Test: ERROR: {e}")
            return [result]
    
    async def test_websocket_endpoints(self) -> List[TestResult]:
        """Test WebSocket endpoint availability"""
        self.log("🔌 Testing WebSocket Endpoints...")
        
        try:
            # Test WebSocket endpoint (should return 426 or similar for upgrade required)
            start_time = time.time()
            response = requests.get(f"{self.base_url}/ws", timeout=10)
            response_time = time.time() - start_time
            
            # WebSocket endpoints typically return 426 (Upgrade Required) or 400
            is_websocket_endpoint = response.status_code in [426, 400, 101]
            
            result = TestResult(
                module="WebSocket",
                endpoint="/ws",
                status="PASS" if is_websocket_endpoint else "FAIL",
                response_time=response_time,
                status_code=response.status_code,
                details={"websocket_detected": is_websocket_endpoint}
            )
            
            if is_websocket_endpoint:
                self.log(f"✅ WebSocket Test: Endpoint detected ({response.status_code})")
            else:
                self.log(f"⚠️ WebSocket Test: Endpoint not detected ({response.status_code})")
            
            return [result]
            
        except Exception as e:
            result = TestResult(
                module="WebSocket",
                endpoint="/ws",
                status="ERROR",
                response_time=0,
                status_code=0,
                error=str(e)
            )
            self.log(f"💥 WebSocket Test: ERROR: {e}")
            return [result]
    
    async def test_performance(self) -> List[TestResult]:
        """Test platform performance under load"""
        self.log("⚡ Testing Platform Performance...")
        
        # Test multiple concurrent requests to health endpoint
        start_time = time.time()
        concurrent_requests = 10
        
        try:
            import asyncio
            import aiohttp
            
            async def make_request(session, url):
                async with session.get(url) as response:
                    return await response.text()
            
            async def test_concurrent():
                async with aiohttp.ClientSession() as session:
                    tasks = [make_request(session, f"{self.base_url}/health") for _ in range(concurrent_requests)]
                    await asyncio.gather(*tasks)
            
            # Run concurrent test
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(test_concurrent())
            loop.close()
            
            total_time = time.time() - start_time
            avg_time = total_time / concurrent_requests
            
            result = TestResult(
                module="Performance",
                endpoint="/health (concurrent)",
                status="PASS" if avg_time < 1.0 else "WARNING",
                response_time=avg_time,
                status_code=200,
                details={
                    "concurrent_requests": concurrent_requests,
                    "total_time": total_time,
                    "avg_time_per_request": avg_time
                }
            )
            
            if avg_time < 1.0:
                self.log(f"✅ Performance Test: {concurrent_requests} concurrent requests in {total_time:.3f}s (avg: {avg_time:.3f}s)")
            else:
                self.log(f"⚠️ Performance Test: {concurrent_requests} concurrent requests in {total_time:.3f}s (avg: {avg_time:.3f}s) - Slow")
            
            return [result]
            
        except ImportError:
            self.log("⚠️ Performance Test: aiohttp not available, skipping concurrent test")
            return []
        except Exception as e:
            result = TestResult(
                module="Performance",
                endpoint="/health (concurrent)",
                status="ERROR",
                response_time=0,
                status_code=0,
                error=str(e)
            )
            self.log(f"💥 Performance Test: ERROR: {e}")
            return [result]
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all comprehensive tests"""
        self.log("🚀 Starting Comprehensive Platform Testing...")
        self.log("=" * 60)
        
        all_results = []
        
        # Run all test suites
        test_suites = [
            ("Health Endpoints", self.test_health_endpoints()),
            ("Security Modules", self.test_security_modules()),
            ("Authentication", self.test_authentication()),
            ("WebSocket", self.test_websocket_endpoints()),
            ("Performance", self.test_performance())
        ]
        
        for suite_name, test_coro in test_suites:
            self.log(f"\n📋 Running {suite_name} Tests...")
            try:
                results = await test_coro
                all_results.extend(results)
                self.log(f"✅ {suite_name}: {len(results)} tests completed")
            except Exception as e:
                self.log(f"💥 {suite_name}: Failed to run tests - {e}")
        
        # Calculate summary statistics
        total_tests = len(all_results)
        passed_tests = len([r for r in all_results if r.status == "PASS"])
        failed_tests = len([r for r in all_results if r.status == "FAIL"])
        error_tests = len([r for r in all_results if r.status == "ERROR"])
        warning_tests = len([r for r in all_results if r.status == "WARNING"])
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        # Calculate average response time
        valid_times = [r.response_time for r in all_results if r.response_time > 0]
        avg_response_time = sum(valid_times) / len(valid_times) if valid_times else 0
        
        total_time = time.time() - self.start_time
        
        summary = {
            "total_tests": total_tests,
            "passed": passed_tests,
            "failed": failed_tests,
            "errors": error_tests,
            "warnings": warning_tests,
            "success_rate": success_rate,
            "avg_response_time": avg_response_time,
            "total_test_time": total_time,
            "results": all_results
        }
        
        return summary
    
    def generate_report(self, summary: Dict[str, Any]):
        """Generate a comprehensive test report"""
        self.log("\n" + "=" * 60)
        self.log("📊 COMPREHENSIVE PLATFORM TEST REPORT")
        self.log("=" * 60)
        
        self.log(f"Total Tests: {summary['total_tests']}")
        self.log(f"✅ Passed: {summary['passed']}")
        self.log(f"❌ Failed: {summary['failed']}")
        self.log(f"⚠️ Warnings: {summary['warnings']}")
        self.log(f"💥 Errors: {summary['errors']}")
        self.log(f"Success Rate: {summary['success_rate']:.1f}%")
        self.log(f"Average Response Time: {summary['avg_response_time']:.3f}s")
        self.log(f"Total Test Time: {summary['total_test_time']:.3f}s")
        
        if summary['failed'] > 0 or summary['errors'] > 0:
            self.log("\n🔍 Failed/Error Tests:")
            for result in summary['results']:
                if result.status in ["FAIL", "ERROR"]:
                    self.log(f"  - {result.module}: {result.endpoint} - {result.status}")
                    if result.error:
                        self.log(f"    Error: {result.error}")
        
        # Overall assessment
        if summary['success_rate'] >= 90:
            self.log("\n🎉 EXCELLENT: Platform is performing exceptionally well!")
        elif summary['success_rate'] >= 80:
            self.log("\n✅ GOOD: Platform is performing well with minor issues")
        elif summary['success_rate'] >= 70:
            self.log("\n⚠️ FAIR: Platform has some issues that need attention")
        else:
            self.log("\n❌ POOR: Platform has significant issues that need immediate attention")
        
        self.log("\n" + "=" * 60)

async def main():
    """Main function to run comprehensive platform testing"""
    tester = ComprehensivePlatformTester()
    
    try:
        summary = await tester.run_all_tests()
        tester.generate_report(summary)
        
        # Exit with appropriate code
        if summary['success_rate'] >= 80:
            print("\n🎉 Platform testing completed successfully!")
            sys.exit(0)
        else:
            print("\n⚠️ Platform testing completed with issues")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⏹️ Testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n💥 Unexpected error during testing: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
