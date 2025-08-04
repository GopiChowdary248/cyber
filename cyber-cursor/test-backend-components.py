#!/usr/bin/env python3
"""
Comprehensive Backend Component Testing Script
Tests all backend components and identifies issues
"""

import asyncio
import json
import sys
import traceback
from datetime import datetime
from typing import Dict, Any, List

# Test results storage
test_results = {
    "timestamp": datetime.now().isoformat(),
    "overall_status": "unknown",
    "tests": {},
    "summary": {
        "total_tests": 0,
        "passed": 0,
        "failed": 0,
        "errors": 0
    }
}

def log_test_result(test_name: str, status: str, details: str = "", error: str = ""):
    """Log test result"""
    test_results["tests"][test_name] = {
        "status": status,
        "details": details,
        "error": error,
        "timestamp": datetime.now().isoformat()
    }
    
    if status == "PASS":
        test_results["summary"]["passed"] += 1
    elif status == "FAIL":
        test_results["summary"]["failed"] += 1
    else:
        test_results["summary"]["errors"] += 1
    
    test_results["summary"]["total_tests"] += 1
    
    print(f"[{status}] {test_name}: {details}")
    if error:
        print(f"  Error: {error}")

def test_imports():
    """Test if all required modules can be imported"""
    print("\n=== Testing Module Imports ===")
    
    required_modules = [
        "fastapi",
        "uvicorn", 
        "sqlalchemy",
        "pydantic",
        "pydantic_settings",
        "structlog",
        "requests"
    ]
    
    for module in required_modules:
        try:
            __import__(module)
            log_test_result(f"import_{module}", "PASS", f"Successfully imported {module}")
        except ImportError as e:
            log_test_result(f"import_{module}", "FAIL", f"Failed to import {module}", str(e))

def test_configuration():
    """Test configuration loading"""
    print("\n=== Testing Configuration ===")
    
    try:
        from app.core.config import settings
        log_test_result("config_loading", "PASS", "Configuration loaded successfully")
        
        # Test specific settings
        if hasattr(settings, 'security'):
            log_test_result("config_security", "PASS", "Security settings available")
        else:
            log_test_result("config_security", "FAIL", "Security settings missing")
            
        if hasattr(settings, 'database'):
            log_test_result("config_database", "PASS", "Database settings available")
        else:
            log_test_result("config_database", "FAIL", "Database settings missing")
            
    except Exception as e:
        log_test_result("config_loading", "ERROR", "Configuration loading failed", str(e))

def test_database_connection():
    """Test database connection"""
    print("\n=== Testing Database Connection ===")
    
    try:
        import os
        os.environ["USE_SQLITE"] = "true"
        
        from app.core.database import engine, init_db
        
        # Test async database initialization
        async def test_db():
            try:
                await init_db()
                log_test_result("database_init", "PASS", "Database initialized successfully")
                
                # Test connection
                async with engine.begin() as conn:
                    await conn.execute("SELECT 1")
                log_test_result("database_connection", "PASS", "Database connection successful")
                
            except Exception as e:
                log_test_result("database_init", "ERROR", "Database initialization failed", str(e))
        
        asyncio.run(test_db())
        
    except Exception as e:
        log_test_result("database_setup", "ERROR", "Database setup failed", str(e))

def test_models():
    """Test model imports and basic functionality"""
    print("\n=== Testing Models ===")
    
    try:
        from app.models.user import User
        log_test_result("model_user", "PASS", "User model imported successfully")
    except Exception as e:
        log_test_result("model_user", "ERROR", "User model import failed", str(e))
    
    try:
        from app.models.iam import User as IAMUser
        log_test_result("model_iam_user", "PASS", "IAM User model imported successfully")
    except Exception as e:
        log_test_result("model_iam_user", "ERROR", "IAM User model import failed", str(e))

def test_schemas():
    """Test schema imports"""
    print("\n=== Testing Schemas ===")
    
    try:
        from app.schemas.auth import Token, UserCreate
        log_test_result("schema_auth", "PASS", "Auth schemas imported successfully")
    except Exception as e:
        log_test_result("schema_auth", "ERROR", "Auth schemas import failed", str(e))
    
    try:
        from app.schemas.iam import LoginRequest, TokenResponse
        log_test_result("schema_iam", "PASS", "IAM schemas imported successfully")
    except Exception as e:
        log_test_result("schema_iam", "ERROR", "IAM schemas import failed", str(e))

def test_services():
    """Test service imports"""
    print("\n=== Testing Services ===")
    
    try:
        from app.services.iam_service import iam_service
        log_test_result("service_iam", "PASS", "IAM service imported successfully")
    except Exception as e:
        log_test_result("service_iam", "ERROR", "IAM service import failed", str(e))

def test_endpoints():
    """Test endpoint imports"""
    print("\n=== Testing Endpoints ===")
    
    try:
        from app.api.v1.endpoints.auth import router as auth_router
        log_test_result("endpoint_auth", "PASS", "Auth endpoints imported successfully")
        
        # Check if login route exists
        routes = [route.path for route in auth_router.routes]
        if "/login" in routes:
            log_test_result("endpoint_login", "PASS", "Login endpoint found")
        else:
            log_test_result("endpoint_login", "FAIL", "Login endpoint not found")
            
    except Exception as e:
        log_test_result("endpoint_auth", "ERROR", "Auth endpoints import failed", str(e))
    
    try:
        from app.api.v1.endpoints.iam import router as iam_router
        log_test_result("endpoint_iam", "PASS", "IAM endpoints imported successfully")
    except Exception as e:
        log_test_result("endpoint_iam", "ERROR", "IAM endpoints import failed", str(e))

def test_security():
    """Test security functions"""
    print("\n=== Testing Security ===")
    
    try:
        from app.core.security import create_access_token, verify_password, get_password_hash
        log_test_result("security_functions", "PASS", "Security functions imported successfully")
        
        # Test password hashing
        test_password = "testpassword123"
        hashed = get_password_hash(test_password)
        if verify_password(test_password, hashed):
            log_test_result("password_hashing", "PASS", "Password hashing works correctly")
        else:
            log_test_result("password_hashing", "FAIL", "Password hashing verification failed")
            
    except Exception as e:
        log_test_result("security_functions", "ERROR", "Security functions import failed", str(e))

def test_fastapi_app():
    """Test FastAPI app creation"""
    print("\n=== Testing FastAPI App ===")
    
    try:
        from main import app
        log_test_result("fastapi_app", "PASS", "FastAPI app created successfully")
        
        # Check if routes are registered
        routes = [route.path for route in app.routes]
        if "/health" in routes:
            log_test_result("health_endpoint", "PASS", "Health endpoint registered")
        else:
            log_test_result("health_endpoint", "FAIL", "Health endpoint not found")
            
        if "/api/v1/auth/login" in routes:
            log_test_result("login_endpoint", "PASS", "Login endpoint registered")
        else:
            log_test_result("login_endpoint", "FAIL", "Login endpoint not found")
            
    except Exception as e:
        log_test_result("fastapi_app", "ERROR", "FastAPI app creation failed", str(e))

def test_backend_startup():
    """Test if backend can start"""
    print("\n=== Testing Backend Startup ===")
    
    try:
        import subprocess
        import time
        import requests
        
        # Start backend in background
        process = subprocess.Popen(
            ["python", "main.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"USE_SQLITE": "true"}
        )
        
        # Wait for startup
        time.sleep(5)
        
        # Test health endpoint
        try:
            response = requests.get("http://localhost:8000/health", timeout=5)
            if response.status_code == 200:
                log_test_result("backend_startup", "PASS", "Backend started successfully")
                log_test_result("health_endpoint_response", "PASS", f"Health endpoint responded: {response.json()}")
            else:
                log_test_result("backend_startup", "FAIL", f"Health endpoint returned {response.status_code}")
        except requests.exceptions.RequestException as e:
            log_test_result("backend_startup", "FAIL", "Backend not responding", str(e))
        
        # Cleanup
        process.terminate()
        process.wait()
        
    except Exception as e:
        log_test_result("backend_startup", "ERROR", "Backend startup test failed", str(e))

def generate_summary():
    """Generate test summary"""
    print("\n=== Test Summary ===")
    
    total = test_results["summary"]["total_tests"]
    passed = test_results["summary"]["passed"]
    failed = test_results["summary"]["failed"]
    errors = test_results["summary"]["errors"]
    
    print(f"Total Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Errors: {errors}")
    
    success_rate = (passed / total * 100) if total > 0 else 0
    print(f"Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 80:
        test_results["overall_status"] = "PASS"
        print("Overall Status: PASS")
    elif success_rate >= 60:
        test_results["overall_status"] = "PARTIAL"
        print("Overall Status: PARTIAL")
    else:
        test_results["overall_status"] = "FAIL"
        print("Overall Status: FAIL")

def main():
    """Main test function"""
    print("CyberShield Backend Component Testing")
    print("=" * 50)
    
    # Run all tests
    test_imports()
    test_configuration()
    test_database_connection()
    test_models()
    test_schemas()
    test_services()
    test_endpoints()
    test_security()
    test_fastapi_app()
    test_backend_startup()
    
    # Generate summary
    generate_summary()
    
    # Save results
    with open("backend_component_test_results.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest results saved to: backend_component_test_results.json")
    
    return test_results["overall_status"] == "PASS"

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 