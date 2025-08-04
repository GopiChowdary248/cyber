#!/usr/bin/env python3
"""
Test script for Device Control endpoints
"""

import requests
import json
from datetime import datetime

# Base URL for the API
BASE_URL = "http://localhost:8000"

def test_device_control_endpoints():
    """Test the device control endpoints"""
    
    print("=== Testing Device Control Endpoints ===\n")
    
    # Test 1: Health check
    print("1. Testing health check...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/device-control/health")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {response.json()}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    print()
    
    # Test 2: Get devices (should return empty list initially)
    print("2. Testing get devices...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/device-control/devices")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            devices = response.json()
            print(f"   Found {len(devices)} devices")
            if devices:
                print(f"   First device: {devices[0]}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    print()
    
    # Test 3: Get policies
    print("3. Testing get policies...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/device-control/policies")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            policies = response.json()
            print(f"   Found {len(policies)} policies")
            if policies:
                print(f"   First policy: {policies[0]}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    print()
    
    # Test 4: Get events
    print("4. Testing get events...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/device-control/events")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            events = response.json()
            print(f"   Found {len(events)} events")
            if events:
                print(f"   First event: {events[0]}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    print()
    
    # Test 5: Get summary
    print("5. Testing get summary...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/device-control/summary")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            summary = response.json()
            print(f"   Summary: {summary}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    print("\n=== Testing Antivirus/EDR Endpoints ===\n")
    
    # Test 6: Get endpoint security summary
    print("6. Testing endpoint security summary...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/endpoint-antivirus-edr/summary")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            summary = response.json()
            print(f"   Summary: {summary}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    print()
    
    # Test 7: Get endpoints
    print("7. Testing get endpoints...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/endpoint-antivirus-edr/endpoints")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            endpoints = response.json()
            print(f"   Found {len(endpoints)} endpoints")
            if endpoints:
                print(f"   First endpoint: {endpoints[0]}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    print("\n=== Test Complete ===")

if __name__ == "__main__":
    test_device_control_endpoints() 