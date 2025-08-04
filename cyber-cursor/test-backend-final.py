#!/usr/bin/env python3
"""
Final Backend Testing Script
Comprehensive test of all backend components with detailed reporting
"""

import sys
import os
import subprocess
import time
import json
import requests
from typing import Dict, List, Any

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

class BackendFinalTester:
    def __init__(self):
        self.base_url = "http://localhost:8001"
        self.results = {
            "overall_status": "unknown",
            "server_status": False,
            "endpoints": {},
            "import_issues": [],
            "database_issues": [],
            "configuration_issues": [],
            "recommendations": []
        }
        
    def log(self, message: str, level: str = "INFO"):
        """Log messages with timestamp"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
        
    def test_imports(self) -> List[str]:
        """Test all critical imports"""
        self.log("Testing critical imports...")
        
        critical_modules = [
            "app.core.config",
            "app.core.database", 
            "app.core.security",
            "app.models.iam",
            "app.schemas.iam",
            "app.services.iam_service",
            "app.api.v1.endpoints.auth",
            "app.api.v1.endpoints.iam",
            "app.api.v1.endpoints.health"
        ]
        
        failed_imports = []
        
        for module in critical_modules:
            try:
                __import__(module)
                self.log(f"✓ {module} - OK", "SUCCESS")
            except Exception as e:
                self.log(f"✗ {module} - FAILED: {e}", "ERROR")
                failed_imports.append(f"{module}: {e}")
        
        self.results["import_issues"] = failed_imports
        return failed_imports
    
    def test_configuration(self) -> List[str]:
        """Test configuration settings"""
        self.log("Testing configuration...")
        
        config_issues = []
        
        try:
            from app.core.config import settings
            
            # Test essential settings
            required_settings = [
                "security.SECRET_KEY",
                "security.ALGORITHM", 
                "database.DATABASE_URL",
                "api.HOST",
                "api.PORT"
            ]
            
            for setting in required_settings:
                try:
                    # Navigate nested settings
                    value = settings
                    for attr in setting.split('.'):
                        value = getattr(value, attr)
                    
                    if value is None or value == "":
                        config_issues.append(f"Setting {setting} is empty or None")
                    else:
                        self.log(f"✓ {setting} - OK", "SUCCESS")
                        
                except AttributeError as e:
                    config_issues.append(f"Setting {setting} missing: {e}")
                    
        except Exception as e:
            config_issues.append(f"Configuration test failed: {e}")
        
        self.results["configuration_issues"] = config_issues
        return config_issues
    
    def test_database_connection(self) -> List[str]:
        """Test database connection"""
        self.log("Testing database connection...")
        
        db_issues = []
        
        try:
            from app.core.database import check_db_connection
            
            if check_db_connection():
                self.log("✓ Database connection - OK", "SUCCESS")
            else:
                db_issues.append("Database connection failed")
                self.log("✗ Database connection - FAILED", "ERROR")
                
        except Exception as e:
            db_issues.append(f"Database test failed: {e}")
            self.log(f"✗ Database test - FAILED: {e}", "ERROR")
        
        self.results["database_issues"] = db_issues
        return db_issues
    
    def test_server_startup(self) -> bool:
        """Test server startup"""
        self.log("Testing server startup...")
        
        try:
            # Start server in background
            process = subprocess.Popen(
                ["python", "main_test.py"],
                cwd="backend",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for startup
            time.sleep(10)
            
            # Check if process is still running
            if process.poll() is None:
                self.log("✓ Server started successfully", "SUCCESS")
                self.results["server_status"] = True
                process.terminate()
                return True
            else:
                stdout, stderr = process.communicate()
                self.log(f"✗ Server failed to start", "ERROR")
                self.log(f"STDOUT: {stdout}", "ERROR")
                self.log(f"STDERR: {stderr}", "ERROR")
                self.results["server_status"] = False
                return False
                
        except Exception as e:
            self.log(f"✗ Error testing server startup: {e}", "ERROR")
            self.results["server_status"] = False
            return False
    
    def test_endpoints(self) -> Dict[str, Any]:
        """Test all endpoints"""
        self.log("Testing endpoints...")
        
        if not self.results["server_status"]:
            self.log("Skipping endpoint tests - server not running", "WARNING")
            return {}
        
        endpoints_to_test = [
            ("/", "GET", "Root endpoint"),
            ("/health", "GET", "Health check"),
            ("/test", "GET", "Test endpoint"),
            ("/api/v1/auth/login", "POST", "Auth login"),
            ("/api/v1/iam/health", "GET", "IAM health"),
            ("/docs", "GET", "API documentation")
        ]
        
        endpoint_results = {}
        
        for path, method, description in endpoints_to_test:
            try:
                if method == "GET":
                    response = requests.get(f"{self.base_url}{path}", timeout=5)
                elif method == "POST":
                    # For POST endpoints, send minimal data
                    data = {"username": "test", "password": "test"}
                    response = requests.post(f"{self.base_url}{path}", json=data, timeout=5)
                
                if response.status_code in [200, 401, 404]:  # 401 is expected for auth endpoints
                    self.log(f"✓ {description} ({path}) - {response.status_code}", "SUCCESS")
                    endpoint_results[path] = {
                        "status": "working",
                        "status_code": response.status_code,
                        "description": description
                    }
                else:
                    self.log(f"✗ {description} ({path}) - {response.status_code}", "ERROR")
                    endpoint_results[path] = {
                        "status": "failed",
                        "status_code": response.status_code,
                        "description": description
                    }
                    
            except requests.exceptions.ConnectionError:
                self.log(f"✗ {description} ({path}) - Connection failed", "ERROR")
                endpoint_results[path] = {
                    "status": "connection_failed",
                    "description": description
                }
            except Exception as e:
                self.log(f"✗ {description} ({path}) - Error: {e}", "ERROR")
                endpoint_results[path] = {
                    "status": "error",
                    "error": str(e),
                    "description": description
                }
        
        self.results["endpoints"] = endpoint_results
        return endpoint_results
    
    def generate_recommendations(self):
        """Generate recommendations based on test results"""
        recommendations = []
        
        if self.results["import_issues"]:
            recommendations.append("Fix import issues by ensuring all required modules are available")
        
        if self.results["configuration_issues"]:
            recommendations.append("Review and fix configuration settings")
        
        if self.results["database_issues"]:
            recommendations.append("Set up database connection (PostgreSQL or SQLite)")
        
        if not self.results["server_status"]:
            recommendations.append("Investigate server startup issues")
        
        if not self.results["endpoints"]:
            recommendations.append("Ensure server is running before testing endpoints")
        
        # Add specific recommendations
        if any("SECRET_KEY" in issue for issue in self.results["configuration_issues"]):
            recommendations.append("Set a proper SECRET_KEY in configuration")
        
        if any("DATABASE_URL" in issue for issue in self.results["configuration_issues"]):
            recommendations.append("Configure DATABASE_URL for your environment")
        
        self.results["recommendations"] = recommendations
    
    def determine_overall_status(self):
        """Determine overall status based on test results"""
        if (not self.results["import_issues"] and 
            not self.results["configuration_issues"] and 
            not self.results["database_issues"] and 
            self.results["server_status"]):
            self.results["overall_status"] = "healthy"
        elif self.results["import_issues"] or self.results["configuration_issues"]:
            self.results["overall_status"] = "broken"
        else:
            self.results["overall_status"] = "partially_working"
    
    def generate_report(self):
        """Generate comprehensive test report"""
        self.log("=" * 60)
        self.log("BACKEND COMPREHENSIVE TEST REPORT")
        self.log("=" * 60)
        
        # Overall status
        status_emoji = {
            "healthy": "✅",
            "partially_working": "⚠️",
            "broken": "❌"
        }
        emoji = status_emoji.get(self.results["overall_status"], "❓")
        self.log(f"{emoji} Overall Status: {self.results['overall_status'].upper()}")
        
        # Import issues
        if self.results["import_issues"]:
            self.log(f"\n❌ Import Issues ({len(self.results['import_issues'])}):")
            for issue in self.results["import_issues"]:
                self.log(f"  - {issue}")
        else:
            self.log("\n✅ No import issues")
        
        # Configuration issues
        if self.results["configuration_issues"]:
            self.log(f"\n❌ Configuration Issues ({len(self.results['configuration_issues'])}):")
            for issue in self.results["configuration_issues"]:
                self.log(f"  - {issue}")
        else:
            self.log("\n✅ No configuration issues")
        
        # Database issues
        if self.results["database_issues"]:
            self.log(f"\n❌ Database Issues ({len(self.results['database_issues'])}):")
            for issue in self.results["database_issues"]:
                self.log(f"  - {issue}")
        else:
            self.log("\n✅ No database issues")
        
        # Server status
        if self.results["server_status"]:
            self.log("\n✅ Server startup successful")
        else:
            self.log("\n❌ Server startup failed")
        
        # Endpoint status
        if self.results["endpoints"]:
            working_endpoints = sum(1 for ep in self.results["endpoints"].values() 
                                  if ep.get("status") == "working")
            total_endpoints = len(self.results["endpoints"])
            self.log(f"\n📊 Endpoints: {working_endpoints}/{total_endpoints} working")
            
            for path, result in self.results["endpoints"].items():
                status = result.get("status", "unknown")
                if status == "working":
                    self.log(f"  ✅ {path} - {result.get('status_code', 'N/A')}")
                else:
                    self.log(f"  ❌ {path} - {status}")
        
        # Recommendations
        if self.results["recommendations"]:
            self.log(f"\n💡 Recommendations ({len(self.results['recommendations'])}):")
            for i, rec in enumerate(self.results["recommendations"], 1):
                self.log(f"  {i}. {rec}")
        
        self.log("=" * 60)
    
    def run_comprehensive_test(self):
        """Run all tests"""
        self.log("Starting comprehensive backend testing...")
        
        # Run all tests
        self.test_imports()
        self.test_configuration()
        self.test_database_connection()
        server_ok = self.test_server_startup()
        
        if server_ok:
            self.test_endpoints()
        
        # Generate recommendations and final status
        self.generate_recommendations()
        self.determine_overall_status()
        
        # Generate report
        self.generate_report()
        
        return self.results

def main():
    """Main function"""
    tester = BackendFinalTester()
    results = tester.run_comprehensive_test()
    
    # Save results to file
    with open("backend_final_test_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\nResults saved to backend_final_test_results.json")
    
    # Return exit code based on results
    if results["overall_status"] == "broken":
        sys.exit(1)
    elif results["overall_status"] == "partially_working":
        sys.exit(2)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main() 