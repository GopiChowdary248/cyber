#!/usr/bin/env python3
"""
Simple Backend Startup Test
Tests if the backend can start without errors
"""

import sys
import os
import subprocess
import time
import json

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

def test_imports():
    """Test if all required modules can be imported"""
    print("Testing imports...")
    
    modules_to_test = [
        "app.core.config",
        "app.core.database",
        "app.core.security",
        "app.api.v1.endpoints.auth",
        "app.api.v1.endpoints.iam"
    ]
    
    failed_imports = []
    
    for module in modules_to_test:
        try:
            __import__(module)
            print(f"✓ {module} - OK")
        except Exception as e:
            print(f"✗ {module} - FAILED: {e}")
            failed_imports.append(f"{module}: {e}")
    
    return failed_imports

def test_server_startup():
    """Test if the server can start"""
    print("\nTesting server startup...")
    
    try:
        # Try to start the server with main_complete.py
        process = subprocess.Popen(
            ["python", "-m", "uvicorn", "main_complete:app", "--host", "0.0.0.0", "--port", "8000"],
            cwd="backend",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait for startup
        time.sleep(10)
        
        # Check if process is still running
        if process.poll() is None:
            print("✓ Server started successfully")
            process.terminate()
            return True
        else:
            stdout, stderr = process.communicate()
            print(f"✗ Server failed to start")
            print(f"STDOUT: {stdout}")
            print(f"STDERR: {stderr}")
            return False
            
    except Exception as e:
        print(f"✗ Error testing server startup: {e}")
        return False

def test_endpoints():
    """Test if endpoints are accessible"""
    print("\nTesting endpoints...")
    
    import requests
    
    endpoints_to_test = [
        "http://localhost:8000/",
        "http://localhost:8000/health",
        "http://localhost:8000/docs"
    ]
    
    for endpoint in endpoints_to_test:
        try:
            response = requests.get(endpoint, timeout=5)
            print(f"✓ {endpoint} - {response.status_code}")
        except Exception as e:
            print(f"✗ {endpoint} - FAILED: {e}")

def main():
    """Main test function"""
    print("=" * 50)
    print("BACKEND STARTUP TEST")
    print("=" * 50)
    
    # Test imports
    failed_imports = test_imports()
    
    if failed_imports:
        print(f"\n❌ {len(failed_imports)} import failures detected")
        return False
    
    # Test server startup
    server_ok = test_server_startup()
    
    if server_ok:
        # Test endpoints
        test_endpoints()
        print("\n✅ Backend startup test completed successfully")
        return True
    else:
        print("\n❌ Backend startup test failed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 