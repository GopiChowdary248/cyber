#!/usr/bin/env python3
"""
Enhanced DAST Tool Test Script
Demonstrates comprehensive DAST functionality including scanning, fuzzing, and vulnerability detection
"""

import asyncio
import aiohttp
import json
import time
import sys
import os
from datetime import datetime
from typing import Dict, List, Any

# Add backend to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

try:
    from app.services.dast_core import DASTScanner, ScanTarget
    from app.services.dast_fuzzer import DASTFuzzer, FuzzTarget
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you're running this from the project root directory")
    sys.exit(1)

class EnhancedDASTTester:
    """Comprehensive DAST testing framework"""
    
    def __init__(self):
        self.test_results = []
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def test_dast_scanner(self, target_url: str) -> Dict[str, Any]:
        """Test the core DAST scanner functionality"""
        print(f"\n🔍 Testing DAST Scanner for: {target_url}")
        
        config = {
            "max_depth": 2,
            "scan_type": "full",
            "threads": 5,
            "timeout": 30
        }
        
        try:
            async with DASTScanner(config) as scanner:
                start_time = time.time()
                results = await scanner.scan_target(target_url, config)
                scan_duration = time.time() - start_time
                
                print(f"✅ Scan completed in {scan_duration:.2f} seconds")
                print(f"📊 URLs discovered: {results['statistics']['urls_discovered']}")
                print(f"🔍 Requests made: {results['statistics']['requests_made']}")
                print(f"🚨 Vulnerabilities found: {results['statistics']['vulnerabilities_found']}")
                
                return {
                    "test_type": "dast_scanner",
                    "target_url": target_url,
                    "success": True,
                    "results": results,
                    "duration": scan_duration
                }
                
        except Exception as e:
            print(f"❌ DAST Scanner test failed: {str(e)}")
            return {
                "test_type": "dast_scanner",
                "target_url": target_url,
                "success": False,
                "error": str(e)
            }
    
    async def test_dast_fuzzer(self, target_url: str) -> Dict[str, Any]:
        """Test the DAST fuzzer functionality"""
        print(f"\n🧪 Testing DAST Fuzzer for: {target_url}")
        
        config = {
            "max_mutations": 10,
            "timeout": 30
        }
        
        try:
            fuzzer = DASTFuzzer(config)
            
            # Create a test target
            target = FuzzTarget(
                url=f"{target_url}/search?q=test&id=1",
                method="GET",
                parameters={"q": "test", "id": "1"},
                headers={"User-Agent": "DAST-Tester/1.0"},
                cookies={"session": "test-session"}
            )
            
            start_time = time.time()
            results = await fuzzer.fuzz_target(target, self.session)
            fuzz_duration = time.time() - start_time
            
            print(f"✅ Fuzzing completed in {fuzz_duration:.2f} seconds")
            print(f"🧬 Mutations tested: {len(results)}")
            
            # Count anomalies
            total_anomalies = sum(len(result.anomalies) for result in results)
            print(f"⚠️  Anomalies detected: {total_anomalies}")
            
            return {
                "test_type": "dast_fuzzer",
                "target_url": target_url,
                "success": True,
                "results": {
                    "mutations_tested": len(results),
                    "anomalies_detected": total_anomalies,
                    "fuzz_results": [
                        {
                            "mutation": result.mutation,
                            "response_code": result.response_code,
                            "response_time": result.response_time,
                            "anomalies": result.anomalies
                        }
                        for result in results
                    ]
                },
                "duration": fuzz_duration
            }
            
        except Exception as e:
            print(f"❌ DAST Fuzzer test failed: {str(e)}")
            return {
                "test_type": "dast_fuzzer",
                "target_url": target_url,
                "success": False,
                "error": str(e)
            }
    
    async def test_vulnerability_detection(self, target_url: str) -> Dict[str, Any]:
        """Test specific vulnerability detection capabilities"""
        print(f"\n🎯 Testing Vulnerability Detection for: {target_url}")
        
        vulnerabilities = []
        
        # Test SQL Injection
        sqli_payloads = [
            "' OR 1=1 --",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR '1'='1"
        ]
        
        for payload in sqli_payloads:
            try:
                test_url = f"{target_url}/search?q={payload}"
                async with self.session.get(test_url, timeout=10) as response:
                    content = await response.text()
                    
                    # Check for SQL error patterns
                    sql_errors = [
                        "sql syntax",
                        "mysql_fetch_array",
                        "ora-",
                        "postgresql",
                        "sqlite"
                    ]
                    
                    if any(error in content.lower() for error in sql_errors):
                        vulnerabilities.append({
                            "type": "sql_injection",
                            "payload": payload,
                            "url": test_url,
                            "evidence": "SQL error detected in response"
                        })
                        
            except Exception as e:
                print(f"Warning: SQL injection test failed for {payload}: {str(e)}")
        
        # Test XSS
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        for payload in xss_payloads:
            try:
                test_url = f"{target_url}/search?q={payload}"
                async with self.session.get(test_url, timeout=10) as response:
                    content = await response.text()
                    
                    if payload in content:
                        vulnerabilities.append({
                            "type": "xss",
                            "payload": payload,
                            "url": test_url,
                            "evidence": "XSS payload reflected in response"
                        })
                        
            except Exception as e:
                print(f"Warning: XSS test failed for {payload}: {str(e)}")
        
        print(f"✅ Vulnerability detection completed")
        print(f"🚨 Vulnerabilities found: {len(vulnerabilities)}")
        
        return {
            "test_type": "vulnerability_detection",
            "target_url": target_url,
            "success": True,
            "vulnerabilities": vulnerabilities
        }
    
    async def test_security_headers(self, target_url: str) -> Dict[str, Any]:
        """Test security header analysis"""
        print(f"\n🛡️  Testing Security Headers for: {target_url}")
        
        try:
            async with self.session.get(target_url, timeout=10) as response:
                headers = dict(response.headers)
                
                security_headers = {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "X-XSS-Protection": "1; mode=block",
                    "Strict-Transport-Security": "max-age=31536000",
                    "Content-Security-Policy": "default-src 'self'"
                }
                
                missing_headers = []
                for header, expected_value in security_headers.items():
                    if header not in headers:
                        missing_headers.append(header)
                
                print(f"✅ Security headers analysis completed")
                print(f"⚠️  Missing headers: {len(missing_headers)}")
                
                return {
                    "test_type": "security_headers",
                    "target_url": target_url,
                    "success": True,
                    "headers_analyzed": len(security_headers),
                    "missing_headers": missing_headers,
                    "all_headers": headers
                }
                
        except Exception as e:
            print(f"❌ Security headers test failed: {str(e)}")
            return {
                "test_type": "security_headers",
                "target_url": target_url,
                "success": False,
                "error": str(e)
            }
    
    async def test_api_endpoints(self, target_url: str) -> Dict[str, Any]:
        """Test API endpoint discovery and testing"""
        print(f"\n🔌 Testing API Endpoints for: {target_url}")
        
        api_endpoints = []
        common_api_paths = [
            "/api/",
            "/rest/",
            "/graphql",
            "/swagger",
            "/openapi",
            "/v1/",
            "/v2/",
            "/admin/",
            "/user/",
            "/auth/"
        ]
        
        for path in common_api_paths:
            try:
                test_url = f"{target_url}{path}"
                async with self.session.get(test_url, timeout=10) as response:
                    if response.status != 404:
                        api_endpoints.append({
                            "path": path,
                            "status_code": response.status,
                            "url": test_url
                        })
                        
            except Exception as e:
                print(f"Warning: API endpoint test failed for {path}: {str(e)}")
        
        print(f"✅ API endpoint discovery completed")
        print(f"🔌 API endpoints found: {len(api_endpoints)}")
        
        return {
            "test_type": "api_endpoints",
            "target_url": target_url,
            "success": True,
            "endpoints_found": len(api_endpoints),
            "endpoints": api_endpoints
        }
    
    async def run_comprehensive_test(self, target_url: str) -> Dict[str, Any]:
        """Run all DAST tests comprehensively"""
        print(f"\n🚀 Starting Comprehensive DAST Test for: {target_url}")
        print("=" * 60)
        
        start_time = time.time()
        
        # Run all tests
        tests = [
            self.test_dast_scanner(target_url),
            self.test_dast_fuzzer(target_url),
            self.test_vulnerability_detection(target_url),
            self.test_security_headers(target_url),
            self.test_api_endpoints(target_url)
        ]
        
        results = await asyncio.gather(*tests, return_exceptions=True)
        
        total_duration = time.time() - start_time
        
        # Compile results
        test_summary = {
            "target_url": target_url,
            "timestamp": datetime.now().isoformat(),
            "total_duration": total_duration,
            "tests_run": len(results),
            "tests_passed": sum(1 for r in results if isinstance(r, dict) and r.get("success", False)),
            "tests_failed": sum(1 for r in results if isinstance(r, dict) and not r.get("success", False)),
            "exceptions": sum(1 for r in results if isinstance(r, Exception)),
            "detailed_results": results
        }
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 COMPREHENSIVE DAST TEST SUMMARY")
        print("=" * 60)
        print(f"🎯 Target: {target_url}")
        print(f"⏱️  Total Duration: {total_duration:.2f} seconds")
        print(f"🧪 Tests Run: {test_summary['tests_run']}")
        print(f"✅ Tests Passed: {test_summary['tests_passed']}")
        print(f"❌ Tests Failed: {test_summary['tests_failed']}")
        print(f"💥 Exceptions: {test_summary['exceptions']}")
        
        # Count total vulnerabilities
        total_vulns = 0
        for result in results:
            if isinstance(result, dict) and result.get("success"):
                if "vulnerabilities" in result:
                    total_vulns += len(result["vulnerabilities"])
                elif "results" in result and "vulnerabilities_found" in result["results"]:
                    total_vulns += result["results"]["vulnerabilities_found"]
        
        print(f"🚨 Total Vulnerabilities Found: {total_vulns}")
        
        return test_summary

async def main():
    """Main test function"""
    print("🔒 Enhanced DAST Tool Test Suite")
    print("=" * 50)
    
    # Test targets (replace with actual test URLs)
    test_targets = [
        "http://httpbin.org",  # Safe test target
        "https://jsonplaceholder.typicode.com",  # Another safe test target
    ]
    
    # Add command line argument for custom target
    if len(sys.argv) > 1:
        custom_target = sys.argv[1]
        if custom_target.startswith(('http://', 'https://')):
            test_targets.insert(0, custom_target)
            print(f"🎯 Added custom test target: {custom_target}")
    
    async with EnhancedDASTTester() as tester:
        all_results = []
        
        for target in test_targets:
            try:
                result = await tester.run_comprehensive_test(target)
                all_results.append(result)
                
                # Save individual result
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"dast_test_results_{timestamp}_{target.replace('://', '_').replace('/', '_')}.json"
                
                with open(filename, 'w') as f:
                    json.dump(result, f, indent=2, default=str)
                
                print(f"💾 Results saved to: {filename}")
                
            except Exception as e:
                print(f"❌ Test failed for {target}: {str(e)}")
        
        # Save comprehensive results
        if all_results:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            comprehensive_filename = f"comprehensive_dast_results_{timestamp}.json"
            
            with open(comprehensive_filename, 'w') as f:
                json.dump(all_results, f, indent=2, default=str)
            
            print(f"\n💾 Comprehensive results saved to: {comprehensive_filename}")
            
            # Print final summary
            total_vulns = sum(
                result.get("detailed_results", [])
                for result in all_results
                if isinstance(result, dict)
            )
            
            print(f"\n🎯 FINAL SUMMARY")
            print(f"📊 Total Targets Tested: {len(all_results)}")
            print(f"🚨 Total Vulnerabilities Found: {total_vulns}")
            print(f"⏱️  Total Test Time: {sum(r.get('total_duration', 0) for r in all_results):.2f} seconds")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test suite failed: {str(e)}")
        sys.exit(1) 