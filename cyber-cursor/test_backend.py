#!/usr/bin/env python3
"""
Test script for Cyber Cursor DAST Backend
"""

import requests
import json
import time
from urllib.parse import urljoin

# Configuration
BASE_URL = "http://localhost:8000"
TEST_PROJECT_ID = "test-project-123"

def test_health_endpoint():
    """Test the health endpoint"""
    print("🔍 Testing health endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/health")
        if response.status_code == 200:
            print("✅ Health endpoint working")
            print(f"   Response: {response.json()}")
            return True
        else:
            print(f"❌ Health endpoint failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health endpoint error: {e}")
        return False

def test_root_endpoint():
    """Test the root endpoint"""
    print("🔍 Testing root endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/")
        if response.status_code == 200:
            print("✅ Root endpoint working")
            print(f"   Response: {response.json()}")
            return True
        else:
            print(f"❌ Root endpoint failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Root endpoint error: {e}")
        return False

def test_dast_endpoints():
    """Test DAST-specific endpoints"""
    print("🔍 Testing DAST endpoints...")
    
    # Test project status endpoint
    try:
        url = f"{BASE_URL}/api/v1/dast/projects/{TEST_PROJECT_ID}/status"
        response = requests.get(url)
        if response.status_code == 200:
            print("✅ Project status endpoint working")
            print(f"   Response: {response.json()}")
        else:
            print(f"❌ Project status endpoint failed: {response.status_code}")
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"❌ Project status endpoint error: {e}")
    
    # Test HTTP history endpoint
    try:
        url = f"{BASE_URL}/api/v1/dast/projects/{TEST_PROJECT_ID}/http-history"
        response = requests.get(url)
        if response.status_code == 200:
            print("✅ HTTP history endpoint working")
            print(f"   Response: {response.json()}")
        else:
            print(f"❌ HTTP history endpoint failed: {response.status_code}")
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"❌ HTTP history endpoint error: {e}")
    
    # Test scan profiles endpoint
    try:
        url = f"{BASE_URL}/api/v1/dast/projects/{TEST_PROJECT_ID}/scanner/profiles"
        response = requests.get(url)
        if response.status_code == 200:
            print("✅ Scan profiles endpoint working")
            print(f"   Response: {response.json()}")
        else:
            print(f"❌ Scan profiles endpoint failed: {response.status_code}")
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"❌ Scan profiles endpoint error: {e}")

def test_websocket_endpoint():
    """Test WebSocket endpoint availability"""
    print("🔍 Testing WebSocket endpoint...")
    try:
        # Try to connect to WebSocket endpoint
        import websocket
        
        ws_url = f"ws://localhost:8000/api/v1/dast/projects/{TEST_PROJECT_ID}/ws?token=mock_token"
        
        # Create WebSocket connection
        ws = websocket.create_connection(ws_url, timeout=5)
        
        # Send a test message
        ws.send(json.dumps({"type": "test", "data": "test message"}))
        
        # Receive response
        response = ws.recv()
        print("✅ WebSocket endpoint working")
        print(f"   Response: {response}")
        
        ws.close()
        return True
        
    except ImportError:
        print("⚠️  WebSocket library not installed, skipping WebSocket test")
        return False
    except Exception as e:
        print(f"❌ WebSocket endpoint error: {e}")
        return False

def test_api_documentation():
    """Test API documentation endpoint"""
    print("🔍 Testing API documentation...")
    try:
        response = requests.get(f"{BASE_URL}/docs")
        if response.status_code == 200:
            print("✅ API documentation accessible")
            return True
        else:
            print(f"❌ API documentation failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API documentation error: {e}")
        return False

def main():
    """Main test function"""
    print("🚀 Starting Cyber Cursor DAST Backend Tests")
    print("=" * 50)
    
    # Wait for backend to be ready
    print("⏳ Waiting for backend to be ready...")
    max_attempts = 30
    attempt = 0
    
    while attempt < max_attempts:
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=5)
            if response.status_code == 200:
                print("✅ Backend is ready!")
                break
        except:
            pass
        
        attempt += 1
        print(f"   Attempt {attempt}/{max_attempts}...")
        time.sleep(2)
    
    if attempt >= max_attempts:
        print("❌ Backend failed to start within expected time")
        return
    
    print("\n🧪 Running tests...")
    print("-" * 30)
    
    # Run tests
    tests = [
        test_health_endpoint,
        test_root_endpoint,
        test_dast_endpoints,
        test_websocket_endpoint,
        test_api_documentation
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
        print()
    
    # Summary
    print("=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Backend is working correctly.")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
    
    print("\n🔗 Available endpoints:")
    print(f"   Frontend: http://localhost:3000")
    print(f"   Backend:  {BASE_URL}")
    print(f"   API Docs: {BASE_URL}/docs")
    print(f"   Health:   {BASE_URL}/health")

if __name__ == "__main__":
    main()
