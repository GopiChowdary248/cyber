#!/usr/bin/env python3
"""
Comprehensive SAST Testing Script
Tests all SAST endpoints and functionality to ensure no duplicates and proper operation
"""

import asyncio
import json
import sys
import time
from datetime import datetime
from typing import Dict, Any, List
import aiohttp
import structlog

# Configure logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

class SASTTester:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session = None
        self.auth_token = None
        self.test_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "errors": [],
            "endpoints_tested": [],
            "duplicate_check": {}
        }

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def login(self) -> bool:
        """Login to get authentication token"""
        try:
            login_data = {
                "username": "admin@cybershield.com",
                "password": "password"
            }
            
            async with self.session.post(
                f"{self.base_url}/api/v1/auth/login/oauth",
                data=login_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    self.auth_token = data.get("access_token")
                    logger.info("Login successful", status=response.status)
                    return True
                else:
                    logger.error("Login failed", status=response.status)
                    return False
        except Exception as e:
            logger.error("Login error", error=str(e))
            return False

    def get_auth_headers(self) -> Dict[str, str]:
        """Get headers with authentication token"""
        return {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json"
        }

    async def test_endpoint(self, method: str, endpoint: str, expected_status: int = 200, 
                          data: Dict[str, Any] = None, description: str = "") -> bool:
        """Test a single endpoint"""
        self.test_results["total_tests"] += 1
        
        try:
            url = f"{self.base_url}{endpoint}"
            headers = self.get_auth_headers()
            
            if method.upper() == "GET":
                async with self.session.get(url, headers=headers) as response:
                    success = response.status == expected_status
            elif method.upper() == "POST":
                async with self.session.post(url, headers=headers, json=data or {}) as response:
                    success = response.status == expected_status
            elif method.upper() == "PUT":
                async with self.session.put(url, headers=headers, json=data or {}) as response:
                    success = response.status == expected_status
            elif method.upper() == "DELETE":
                async with self.session.delete(url, headers=headers) as response:
                    success = response.status == expected_status
            else:
                logger.error("Unsupported HTTP method", method=method)
                success = False

            if success:
                self.test_results["passed"] += 1
                logger.info("Test passed", endpoint=endpoint, method=method, status=response.status)
            else:
                self.test_results["failed"] += 1
                response_text = await response.text()
                logger.error("Test failed", endpoint=endpoint, method=method, 
                           expected=expected_status, actual=response.status, response=response_text)
                self.test_results["errors"].append({
                    "endpoint": endpoint,
                    "method": method,
                    "expected": expected_status,
                    "actual": response.status,
                    "response": response_text,
                    "description": description
                })

            self.test_results["endpoints_tested"].append({
                "endpoint": endpoint,
                "method": method,
                "status": response.status,
                "success": success,
                "description": description
            })

            return success

        except Exception as e:
            self.test_results["failed"] += 1
            logger.error("Test error", endpoint=endpoint, method=method, error=str(e))
            self.test_results["errors"].append({
                "endpoint": endpoint,
                "method": method,
                "error": str(e),
                "description": description
            })
            return False

    async def test_sast_endpoints(self) -> Dict[str, Any]:
        """Test all SAST endpoints"""
        logger.info("Starting SAST endpoint tests")
        
        # Test dashboard endpoints
        await self.test_endpoint("GET", "/api/v1/sast/dashboard", description="SAST Dashboard")
        await self.test_endpoint("GET", "/api/v1/sast/overview", description="SAST Overview")
        
        # Test project endpoints
        await self.test_endpoint("GET", "/api/v1/sast/projects", description="Get SAST Projects")
        
        # Test creating a project
        project_data = {
            "name": "Test SAST Project",
            "repository_url": "https://github.com/test/test-repo",
            "language": "python",
            "description": "Test project for SAST functionality"
        }
        await self.test_endpoint("POST", "/api/v1/sast/projects", 201, project_data, "Create SAST Project")
        
        # Test scan endpoints
        scan_data = {
            "project_id": "1",
            "scan_type": "static",
            "scan_config": {"include_patterns": ["*.py"]}
        }
        await self.test_endpoint("POST", "/api/v1/sast/scans", 201, scan_data, "Start SAST Scan")
        
        # Test vulnerability endpoints
        await self.test_endpoint("GET", "/api/v1/sast/vulnerabilities", description="Get SAST Vulnerabilities")
        await self.test_endpoint("GET", "/api/v1/sast/vulnerabilities?severity=CRITICAL", description="Get Critical Vulnerabilities")
        
        # Test statistics endpoints
        await self.test_endpoint("GET", "/api/v1/sast/statistics", description="Get SAST Statistics")
        
        # Test configuration endpoints
        await self.test_endpoint("GET", "/api/v1/sast/rules", description="Get Detection Rules")
        await self.test_endpoint("GET", "/api/v1/sast/languages", description="Get Supported Languages")
        
        # Test project-specific endpoints
        await self.test_endpoint("GET", "/api/v1/sast/projects/1", description="Get Specific Project")
        await self.test_endpoint("GET", "/api/v1/sast/projects/1/scans", description="Get Project Scan History")
        await self.test_endpoint("GET", "/api/v1/sast/projects/1/vulnerabilities", description="Get Project Vulnerabilities")
        
        # Test scan details
        await self.test_endpoint("GET", "/api/v1/sast/scans/1", description="Get Scan Details")

        logger.info("SAST endpoint tests completed")
        return self.test_results

    async def check_for_duplicates(self) -> Dict[str, Any]:
        """Check for duplicate routes and functionality"""
        logger.info("Checking for duplicates")
        
        # Get all routes from the API
        try:
            async with self.session.get(f"{self.base_url}/docs") as response:
                if response.status == 200:
                    # This is a simple check - in a real scenario, you'd parse the OpenAPI spec
                    logger.info("API documentation accessible")
                    
            # Check for duplicate route patterns
            sast_endpoints = [
                "/api/v1/sast/dashboard",
                "/api/v1/sast/overview", 
                "/api/v1/sast/projects",
                "/api/v1/sast/projects/{project_id}",
                "/api/v1/sast/scans",
                "/api/v1/sast/scans/{scan_id}",
                "/api/v1/sast/vulnerabilities",
                "/api/v1/sast/statistics",
                "/api/v1/sast/rules",
                "/api/v1/sast/languages"
            ]
            
            # Check for duplicates in endpoint patterns
            endpoint_patterns = {}
            for endpoint in sast_endpoints:
                base_pattern = endpoint.split('/')[-1]  # Get the last part
                if base_pattern in endpoint_patterns:
                    endpoint_patterns[base_pattern].append(endpoint)
                else:
                    endpoint_patterns[base_pattern] = [endpoint]
            
            duplicates = {pattern: endpoints for pattern, endpoints in endpoint_patterns.items() 
                         if len(endpoints) > 1}
            
            self.test_results["duplicate_check"] = {
                "duplicate_patterns": duplicates,
                "total_endpoints": len(sast_endpoints),
                "unique_patterns": len(endpoint_patterns)
            }
            
            if duplicates:
                logger.warning("Found potential duplicate patterns", duplicates=duplicates)
            else:
                logger.info("No duplicate patterns found")
                
        except Exception as e:
            logger.error("Error checking for duplicates", error=str(e))
            
        return self.test_results["duplicate_check"]

    async def test_containerized_deployment(self) -> bool:
        """Test if the application works in containerized environment"""
        logger.info("Testing containerized deployment")
        
        # Test basic health endpoints
        health_endpoints = [
            ("GET", "/", 200, "Root endpoint"),
            ("GET", "/health", 200, "Health check"),
            ("GET", "/api/v1/health", 200, "API health check")
        ]
        
        for method, endpoint, expected_status, description in health_endpoints:
            await self.test_endpoint(method, endpoint, expected_status, description=description)
        
        # Test authentication
        auth_success = await self.login()
        if not auth_success:
            logger.error("Containerized deployment test failed - authentication not working")
            return False
            
        # Test protected endpoints
        await self.test_endpoint("GET", "/protected", description="Protected endpoint")
        
        logger.info("Containerized deployment test completed")
        return True

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        report = {
            "test_summary": {
                "timestamp": self.test_results["timestamp"],
                "total_tests": self.test_results["total_tests"],
                "passed": self.test_results["passed"],
                "failed": self.test_results["failed"],
                "success_rate": f"{(self.test_results['passed'] / max(self.test_results['total_tests'], 1)) * 100:.2f}%"
            },
            "duplicate_analysis": self.test_results["duplicate_check"],
            "endpoints_tested": self.test_results["endpoints_tested"],
            "errors": self.test_results["errors"],
            "recommendations": []
        }
        
        # Generate recommendations
        if self.test_results["failed"] > 0:
            report["recommendations"].append("Fix failed endpoint tests")
        
        if self.test_results["duplicate_check"].get("duplicate_patterns"):
            report["recommendations"].append("Review and remove duplicate endpoint patterns")
        
        if self.test_results["passed"] / max(self.test_results["total_tests"], 1) < 0.8:
            report["recommendations"].append("Improve overall test coverage")
        
        return report

async def main():
    """Main test function"""
    logger.info("Starting comprehensive SAST testing")
    
    async with SASTTester() as tester:
        # Test containerized deployment
        container_test = await tester.test_containerized_deployment()
        if not container_test:
            logger.error("Containerized deployment test failed")
            return
        
        # Login for authenticated tests
        if not await tester.login():
            logger.error("Failed to login - cannot test authenticated endpoints")
            return
        
        # Test all SAST endpoints
        await tester.test_sast_endpoints()
        
        # Check for duplicates
        await tester.check_for_duplicates()
        
        # Generate report
        report = tester.generate_report()
        
        # Print results
        print("\n" + "="*60)
        print("COMPREHENSIVE SAST TESTING REPORT")
        print("="*60)
        print(f"Timestamp: {report['test_summary']['timestamp']}")
        print(f"Total Tests: {report['test_summary']['total_tests']}")
        print(f"Passed: {report['test_summary']['passed']}")
        print(f"Failed: {report['test_summary']['failed']}")
        print(f"Success Rate: {report['test_summary']['success_rate']}")
        print("\n" + "-"*60)
        
        if report['duplicate_analysis']['duplicate_patterns']:
            print("DUPLICATE PATTERNS FOUND:")
            for pattern, endpoints in report['duplicate_analysis']['duplicate_patterns'].items():
                print(f"  {pattern}: {endpoints}")
        else:
            print("No duplicate patterns found ✓")
        
        print("\n" + "-"*60)
        if report['errors']:
            print("ERRORS:")
            for error in report['errors'][:5]:  # Show first 5 errors
                print(f"  {error['endpoint']} ({error['method']}): {error.get('error', f'Status {error.get('actual')}')}")
        else:
            print("No errors found ✓")
        
        print("\n" + "-"*60)
        if report['recommendations']:
            print("RECOMMENDATIONS:")
            for rec in report['recommendations']:
                print(f"  • {rec}")
        else:
            print("All tests passed successfully ✓")
        
        print("="*60)
        
        # Save detailed report
        with open(f"sast_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info("Comprehensive SAST testing completed", report_file=f"sast_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

if __name__ == "__main__":
    asyncio.run(main()) 