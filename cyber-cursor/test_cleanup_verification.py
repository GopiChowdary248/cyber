#!/usr/bin/env python3
"""
Comprehensive Cleanup Verification Test
Verifies that all duplicate files have been removed and the application works properly
"""

import asyncio
import aiohttp
import json
import time
import sys
import os
from datetime import datetime
from typing import Dict, List, Any

class CleanupVerificationTester:
    """Comprehensive cleanup verification framework"""
    
    def __init__(self):
        self.test_results = []
        self.session = None
        self.base_url = "http://localhost:8000"
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def test_backend_health(self) -> Dict[str, Any]:
        """Test backend health endpoint"""
        print(f"\n🏥 Testing Backend Health")
        
        try:
            async with self.session.get(f"{self.base_url}/health") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Backend is healthy: {data.get('status', 'unknown')}")
                    return {
                        "test_type": "backend_health",
                        "success": True,
                        "status": data.get('status'),
                        "timestamp": data.get('timestamp')
                    }
                else:
                    print(f"❌ Backend health check failed: {response.status}")
                    return {
                        "test_type": "backend_health",
                        "success": False,
                        "error": f"HTTP {response.status}"
                    }
        except Exception as e:
            print(f"❌ Backend health test failed: {str(e)}")
            return {
                "test_type": "backend_health",
                "success": False,
                "error": str(e)
            }
    
    async def test_database_connection(self) -> Dict[str, Any]:
        """Test database connection"""
        print(f"\n🗄️  Testing Database Connection")
        
        try:
            async with self.session.get(f"{self.base_url}/health/database") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Database connection successful")
                    return {
                        "test_type": "database_connection",
                        "success": True,
                        "database_status": data.get('database_status')
                    }
                else:
                    print(f"❌ Database connection failed: {response.status}")
                    return {
                        "test_type": "database_connection",
                        "success": False,
                        "error": f"HTTP {response.status}"
                    }
        except Exception as e:
            print(f"❌ Database connection test failed: {str(e)}")
            return {
                "test_type": "database_connection",
                "success": False,
                "error": str(e)
            }
    
    async def test_dast_endpoints(self) -> Dict[str, Any]:
        """Test DAST API endpoints"""
        print(f"\n🔍 Testing DAST Endpoints")
        
        endpoints_to_test = [
            "/dast/scans",
            "/dast/vulnerabilities",
            "/dast/payloads",
            "/dast/reports"
        ]
        
        results = []
        for endpoint in endpoints_to_test:
            try:
                async with self.session.get(f"{self.base_url}{endpoint}") as response:
                    if response.status in [200, 401, 403]:  # 401/403 are expected without auth
                        results.append({
                            "endpoint": endpoint,
                            "status": response.status,
                            "success": True
                        })
                        print(f"✅ {endpoint}: {response.status}")
                    else:
                        results.append({
                            "endpoint": endpoint,
                            "status": response.status,
                            "success": False
                        })
                        print(f"❌ {endpoint}: {response.status}")
            except Exception as e:
                results.append({
                    "endpoint": endpoint,
                    "error": str(e),
                    "success": False
                })
                print(f"❌ {endpoint}: {str(e)}")
        
        return {
            "test_type": "dast_endpoints",
            "success": all(r["success"] for r in results),
            "endpoints_tested": len(endpoints_to_test),
            "endpoints_successful": sum(1 for r in results if r["success"]),
            "results": results
        }
    
    async def test_sast_endpoints(self) -> Dict[str, Any]:
        """Test SAST API endpoints"""
        print(f"\n🔬 Testing SAST Endpoints")
        
        endpoints_to_test = [
            "/sast/projects",
            "/sast/scans",
            "/sast/issues",
            "/sast/security-hotspots"
        ]
        
        results = []
        for endpoint in endpoints_to_test:
            try:
                async with self.session.get(f"{self.base_url}{endpoint}") as response:
                    if response.status in [200, 401, 403]:  # 401/403 are expected without auth
                        results.append({
                            "endpoint": endpoint,
                            "status": response.status,
                            "success": True
                        })
                        print(f"✅ {endpoint}: {response.status}")
                    else:
                        results.append({
                            "endpoint": endpoint,
                            "status": response.status,
                            "success": False
                        })
                        print(f"❌ {endpoint}: {response.status}")
            except Exception as e:
                results.append({
                    "endpoint": endpoint,
                    "error": str(e),
                    "success": False
                })
                print(f"❌ {endpoint}: {str(e)}")
        
        return {
            "test_type": "sast_endpoints",
            "success": all(r["success"] for r in results),
            "endpoints_tested": len(endpoints_to_test),
            "endpoints_successful": sum(1 for r in results if r["success"]),
            "results": results
        }
    
    async def test_authentication_endpoints(self) -> Dict[str, Any]:
        """Test authentication endpoints"""
        print(f"\n🔐 Testing Authentication Endpoints")
        
        endpoints_to_test = [
            "/auth/login",
            "/auth/register",
            "/auth/refresh"
        ]
        
        results = []
        for endpoint in endpoints_to_test:
            try:
                # Test with POST for login/register, GET for refresh
                method = "POST" if endpoint in ["/auth/login", "/auth/register"] else "GET"
                async with self.session.request(method, f"{self.base_url}{endpoint}") as response:
                    if response.status in [200, 401, 422]:  # 422 is expected for invalid data
                        results.append({
                            "endpoint": endpoint,
                            "status": response.status,
                            "success": True
                        })
                        print(f"✅ {endpoint}: {response.status}")
                    else:
                        results.append({
                            "endpoint": endpoint,
                            "status": response.status,
                            "success": False
                        })
                        print(f"❌ {endpoint}: {response.status}")
            except Exception as e:
                results.append({
                    "endpoint": endpoint,
                    "error": str(e),
                    "success": False
                })
                print(f"❌ {endpoint}: {str(e)}")
        
        return {
            "test_type": "authentication_endpoints",
            "success": all(r["success"] for r in results),
            "endpoints_tested": len(endpoints_to_test),
            "endpoints_successful": sum(1 for r in results if r["success"]),
            "results": results
        }
    
    async def test_file_structure(self) -> Dict[str, Any]:
        """Test that duplicate files have been removed"""
        print(f"\n📁 Testing File Structure")
        
        # Check for removed duplicate files
        removed_files = [
            "mobile/src/screens/DASTScreen.tsx",
            "mobile/src/screens/SASTScreen.tsx", 
            "mobile/src/screens/SASTCompleteScreen.tsx",
            "backend/app/services/dast_scanner.py",
            "backend/app/services/dast_service.py",
            "backend/app/services/dast_payloads.py",
            "backend/app/services/sast_service.py",
            "backend/app/services/sast_scanner.py",
            "backend/app/services/sast_reports.py",
            "backend/app/services/sast_database.py",
            "backend/app/services/cloud_security_service.py",
            "backend/app/services/ai_service.py",
            "backend/app/api/v1/endpoints/enhanced_cloud_security.py",
            "backend/app/api/v1/endpoints/endpoint_security.py"
        ]
        
        # Check for required enhanced files
        required_files = [
            "mobile/src/screens/DASTEnhancedScreen.tsx",
            "mobile/src/screens/SASTEnhancedScreen.tsx",
            "backend/app/services/dast_core.py",
            "backend/app/services/dast_fuzzer.py",
            "backend/app/models/dast.py",
            "backend/app/api/v1/endpoints/dast.py"
        ]
        
        results = {
            "removed_files": [],
            "required_files": [],
            "success": True
        }
        
        # Check removed files
        for file_path in removed_files:
            if os.path.exists(file_path):
                results["removed_files"].append({
                    "file": file_path,
                    "status": "still_exists",
                    "success": False
                })
                results["success"] = False
                print(f"❌ {file_path}: Still exists (should be removed)")
            else:
                results["removed_files"].append({
                    "file": file_path,
                    "status": "removed",
                    "success": True
                })
                print(f"✅ {file_path}: Removed")
        
        # Check required files
        for file_path in required_files:
            if os.path.exists(file_path):
                results["required_files"].append({
                    "file": file_path,
                    "status": "exists",
                    "success": True
                })
                print(f"✅ {file_path}: Exists")
            else:
                results["required_files"].append({
                    "file": file_path,
                    "status": "missing",
                    "success": False
                })
                results["success"] = False
                print(f"❌ {file_path}: Missing")
        
        return {
            "test_type": "file_structure",
            "success": results["success"],
            "removed_files_count": len(results["removed_files"]),
            "required_files_count": len(results["required_files"]),
            "removed_files_successful": sum(1 for f in results["removed_files"] if f["success"]),
            "required_files_successful": sum(1 for f in results["required_files"] if f["success"]),
            "details": results
        }
    
    async def test_navigation_configuration(self) -> Dict[str, Any]:
        """Test navigation configuration"""
        print(f"\n🧭 Testing Navigation Configuration")
        
        try:
            # Check if navigation file exists and imports correct screens
            nav_file = "mobile/src/navigation/AppNavigator.tsx"
            
            if not os.path.exists(nav_file):
                return {
                    "test_type": "navigation_configuration",
                    "success": False,
                    "error": "Navigation file not found"
                }
            
            with open(nav_file, 'r') as f:
                content = f.read()
            
            # Check for correct imports
            checks = {
                "DASTEnhancedScreen import": "DASTEnhancedScreen" in content,
                "SASTEnhancedScreen import": "SASTEnhancedScreen" in content,
                "No DASTScreen import": "DASTScreen" not in content,
                "No SASTScreen import": "SASTScreen" not in content,
                "No SASTCompleteScreen import": "SASTCompleteScreen" not in content
            }
            
            all_passed = all(checks.values())
            
            for check, passed in checks.items():
                status = "✅" if passed else "❌"
                print(f"{status} {check}")
            
            return {
                "test_type": "navigation_configuration",
                "success": all_passed,
                "checks": checks,
                "checks_passed": sum(checks.values()),
                "total_checks": len(checks)
            }
            
        except Exception as e:
            print(f"❌ Navigation configuration test failed: {str(e)}")
            return {
                "test_type": "navigation_configuration",
                "success": False,
                "error": str(e)
            }
    
    async def run_comprehensive_verification(self) -> Dict[str, Any]:
        """Run all verification tests"""
        print(f"\n🚀 Starting Comprehensive Cleanup Verification")
        print("=" * 60)
        
        start_time = time.time()
        
        # Run all tests
        tests = [
            self.test_backend_health(),
            self.test_database_connection(),
            self.test_dast_endpoints(),
            self.test_sast_endpoints(),
            self.test_authentication_endpoints(),
            self.test_file_structure(),
            self.test_navigation_configuration()
        ]
        
        results = await asyncio.gather(*tests, return_exceptions=True)
        
        total_duration = time.time() - start_time
        
        # Compile results
        verification_summary = {
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
        print("📊 COMPREHENSIVE CLEANUP VERIFICATION SUMMARY")
        print("=" * 60)
        print(f"⏱️  Total Duration: {total_duration:.2f} seconds")
        print(f"🧪 Tests Run: {verification_summary['tests_run']}")
        print(f"✅ Tests Passed: {verification_summary['tests_passed']}")
        print(f"❌ Tests Failed: {verification_summary['tests_failed']}")
        print(f"💥 Exceptions: {verification_summary['exceptions']}")
        
        # Overall status
        overall_success = verification_summary['tests_passed'] == verification_summary['tests_run']
        status = "✅ SUCCESS" if overall_success else "❌ FAILED"
        print(f"\n🎯 Overall Status: {status}")
        
        if overall_success:
            print("🎉 All cleanup operations completed successfully!")
            print("🔧 The application is ready for deployment.")
        else:
            print("⚠️  Some issues were found during verification.")
            print("🔧 Please review the detailed results and fix any issues.")
        
        return verification_summary

async def main():
    """Main verification function"""
    print("🧹 Cleanup Verification Test Suite")
    print("=" * 50)
    
    async with CleanupVerificationTester() as tester:
        try:
            result = await tester.run_comprehensive_verification()
            
            # Save results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cleanup_verification_results_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            
            print(f"\n💾 Results saved to: {filename}")
            
            # Exit with appropriate code
            overall_success = result['tests_passed'] == result['tests_run']
            sys.exit(0 if overall_success else 1)
            
        except Exception as e:
            print(f"\n❌ Verification failed: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Verification interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Verification suite failed: {str(e)}")
        sys.exit(1) 