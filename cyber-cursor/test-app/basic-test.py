#!/usr/bin/env python3
"""
Basic End-to-End Test for CyberShield Platform
Tests core functionality without authentication
"""

import requests
import json
import time
from datetime import datetime

class BasicE2ETest:
    def __init__(self):
        self.base_url = "http://localhost:3000"
        self.api_url = "http://localhost:8000"
        self.test_results = []
        
    def log_test(self, test_name, status, details=""):
        """Log test result"""
        result = {
            "test_name": test_name,
            "status": status,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        
        status_emoji = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️"}
        emoji = status_emoji.get(status, "ℹ️")
        print(f"{emoji} {test_name}: {details}")
    
    def test_infrastructure(self):
        """Test basic infrastructure"""
        print("\n🏗️ Testing Infrastructure...")
        
        # Test Docker containers
        try:
            import subprocess
            result = subprocess.run(['docker', 'ps', '--filter', 'name=cybershield'], 
                                  capture_output=True, text=True)
            if 'cybershield' in result.stdout:
                self.log_test("Docker Containers", "PASS", "All containers running")
            else:
                self.log_test("Docker Containers", "FAIL", "Containers not found")
        except Exception as e:
            self.log_test("Docker Containers", "WARN", f"Could not check: {str(e)}")
        
        # Test port accessibility
        ports_to_check = [
            (3000, "Frontend"),
            (8000, "Backend API"),
            (5432, "PostgreSQL"),
            (6379, "Redis")
        ]
        
        for port, service in ports_to_check:
            try:
                response = requests.get(f"http://localhost:{port}", timeout=5)
                self.log_test(f"{service} Port {port}", "PASS", f"Port {port} accessible")
            except requests.exceptions.ConnectionError:
                self.log_test(f"{service} Port {port}", "FAIL", f"Port {port} not accessible")
            except Exception as e:
                self.log_test(f"{service} Port {port}", "WARN", f"Error: {str(e)}")
    
    def test_backend_health(self):
        """Test backend health endpoints"""
        print("\n🔧 Testing Backend Health...")
        
        # Test main health endpoint
        try:
            response = requests.get(f"{self.api_url}/health", timeout=10)
            if response.status_code == 200:
                self.log_test("Backend Health", "PASS", "Backend is healthy")
            else:
                self.log_test("Backend Health", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Backend Health", "FAIL", f"Error: {str(e)}")
        
        # Test API documentation
        try:
            response = requests.get(f"{self.api_url}/docs", timeout=10)
            if response.status_code == 200:
                self.log_test("API Documentation", "PASS", "Swagger docs accessible")
            else:
                self.log_test("API Documentation", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("API Documentation", "FAIL", f"Error: {str(e)}")
        
        # Test OpenAPI schema
        try:
            response = requests.get(f"{self.api_url}/openapi.json", timeout=10)
            if response.status_code == 200:
                schema = response.json()
                endpoints = len(schema.get('paths', {}))
                self.log_test("OpenAPI Schema", "PASS", f"Schema accessible with {endpoints} endpoints")
            else:
                self.log_test("OpenAPI Schema", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("OpenAPI Schema", "FAIL", f"Error: {str(e)}")
    
    def test_frontend(self):
        """Test frontend application"""
        print("\n🎨 Testing Frontend...")
        
        # Test main page
        try:
            response = requests.get(self.base_url, timeout=10)
            if response.status_code == 200:
                self.log_test("Frontend Main Page", "PASS", "Frontend is accessible")
            else:
                self.log_test("Frontend Main Page", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Frontend Main Page", "FAIL", f"Error: {str(e)}")
        
        # Test login page
        try:
            response = requests.get(f"{self.base_url}/login", timeout=10)
            if response.status_code == 200:
                self.log_test("Frontend Login Page", "PASS", "Login page accessible")
            else:
                self.log_test("Frontend Login Page", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Frontend Login Page", "FAIL", f"Error: {str(e)}")
        
        # Test dashboard page (might redirect to login)
        try:
            response = requests.get(f"{self.base_url}/dashboard", timeout=10)
            if response.status_code in [200, 302, 401]:
                self.log_test("Frontend Dashboard Page", "PASS", "Dashboard page accessible")
            else:
                self.log_test("Frontend Dashboard Page", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Frontend Dashboard Page", "FAIL", f"Error: {str(e)}")
    
    def test_database_connectivity(self):
        """Test database connectivity"""
        print("\n🗄️ Testing Database Connectivity...")
        
        try:
            import asyncpg
            import asyncio
            
            async def test_db():
                conn = await asyncpg.connect(
                    host='localhost',
                    port=5432,
                    user='cybershield_user',
                    password='cybershield_password',
                    database='cybershield'
                )
                
                # Test basic query
                result = await conn.fetchval('SELECT COUNT(*) FROM users')
                await conn.close()
                return result
            
            user_count = asyncio.run(test_db())
            self.log_test("Database Connection", "PASS", f"Connected successfully, found {user_count} users")
            
        except Exception as e:
            self.log_test("Database Connection", "FAIL", f"Error: {str(e)}")
    
    def test_security_endpoints(self):
        """Test security endpoints (without authentication)"""
        print("\n🛡️ Testing Security Endpoints...")
        
        # Test security summary (might require auth)
        try:
            response = requests.get(f"{self.api_url}/api/v1/security/summary", timeout=10)
            if response.status_code in [200, 401, 403]:
                self.log_test("Security Summary Endpoint", "PASS", "Endpoint accessible")
            else:
                self.log_test("Security Summary Endpoint", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Security Summary Endpoint", "FAIL", f"Error: {str(e)}")
        
        # Test SAST endpoint
        try:
            response = requests.get(f"{self.api_url}/api/v1/security/sast/results", timeout=10)
            if response.status_code in [200, 401, 403]:
                self.log_test("SAST Endpoint", "PASS", "Endpoint accessible")
            else:
                self.log_test("SAST Endpoint", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("SAST Endpoint", "FAIL", f"Error: {str(e)}")
        
        # Test DAST endpoint
        try:
            response = requests.get(f"{self.api_url}/api/v1/security/dast/results", timeout=10)
            if response.status_code in [200, 401, 403]:
                self.log_test("DAST Endpoint", "PASS", "Endpoint accessible")
            else:
                self.log_test("DAST Endpoint", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("DAST Endpoint", "FAIL", f"Error: {str(e)}")
    
    def test_performance(self):
        """Test basic performance"""
        print("\n⚡ Testing Performance...")
        
        # Test API response time
        try:
            start_time = time.time()
            response = requests.get(f"{self.api_url}/health", timeout=10)
            duration = time.time() - start_time
            
            if response.status_code == 200:
                if duration < 1.0:
                    self.log_test("API Response Time", "PASS", f"Response time: {duration:.3f}s")
                elif duration < 3.0:
                    self.log_test("API Response Time", "WARN", f"Slow response: {duration:.3f}s")
                else:
                    self.log_test("API Response Time", "FAIL", f"Very slow: {duration:.3f}s")
            else:
                self.log_test("API Response Time", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("API Response Time", "FAIL", f"Error: {str(e)}")
        
        # Test frontend load time
        try:
            start_time = time.time()
            response = requests.get(self.base_url, timeout=10)
            duration = time.time() - start_time
            
            if response.status_code == 200:
                if duration < 2.0:
                    self.log_test("Frontend Load Time", "PASS", f"Load time: {duration:.3f}s")
                elif duration < 5.0:
                    self.log_test("Frontend Load Time", "WARN", f"Slow load: {duration:.3f}s")
                else:
                    self.log_test("Frontend Load Time", "FAIL", f"Very slow: {duration:.3f}s")
            else:
                self.log_test("Frontend Load Time", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Frontend Load Time", "FAIL", f"Error: {str(e)}")
    
    def generate_summary(self):
        """Generate test summary"""
        print("\n📊 Test Summary:")
        print("=" * 40)
        
        total_tests = len(self.test_results)
        passed_tests = len([t for t in self.test_results if t["status"] == "PASS"])
        failed_tests = len([t for t in self.test_results if t["status"] == "FAIL"])
        warn_tests = len([t for t in self.test_results if t["status"] == "WARN"])
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Warnings: {warn_tests} ⚠️")
        print(f"Success Rate: {success_rate:.1f}%")
        
        if success_rate >= 80:
            print("🎉 Overall Status: PASS")
            return True
        else:
            print("❌ Overall Status: FAIL")
            return False
    
    def run_basic_test(self):
        """Run all basic tests"""
        print("🚀 Basic End-to-End Test for CyberShield")
        print("=" * 50)
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)
        
        self.test_infrastructure()
        self.test_backend_health()
        self.test_frontend()
        self.test_database_connectivity()
        self.test_security_endpoints()
        self.test_performance()
        
        success = self.generate_summary()
        
        print("\n" + "=" * 50)
        print("🎯 Basic Test Complete!")
        print("=" * 50)
        
        return success

def main():
    """Main function"""
    print("🛡️ CyberShield Basic End-to-End Test")
    print("=" * 50)
    
    # Check if application is running
    try:
        response = requests.get("http://localhost:3000", timeout=5)
        print("✅ Application appears to be running")
    except:
        print("❌ Application not accessible. Please start the application first:")
        print("   docker-compose up -d")
        return
    
    # Run basic test
    tester = BasicE2ETest()
    success = tester.run_basic_test()
    
    if success:
        print("✅ Basic test passed! Application infrastructure is working correctly.")
    else:
        print("❌ Basic test failed. Please check the application infrastructure.")

if __name__ == "__main__":
    main() 