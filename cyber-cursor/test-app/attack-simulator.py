#!/usr/bin/env python3
"""
Attack Simulator for RASP Testing
This script simulates various attacks against the vulnerable application.
"""

import requests
import time
import json
from urllib.parse import quote

class AttackSimulator:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        
    def test_sql_injection(self):
        """Test SQL Injection attacks"""
        print("🔍 Testing SQL Injection attacks...")
        
        payloads = [
            "1' OR '1'='1",
            "1; DROP TABLE users; --",
            "1' UNION SELECT * FROM users --",
            "1' AND 1=1 --",
            "1' AND 1=2 --"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(f"{self.base_url}/search?id={quote(payload)}")
                print(f"  SQL Injection: {payload} -> Status: {response.status_code}")
                time.sleep(0.5)
            except Exception as e:
                print(f"  Error: {e}")
    
    def test_xss_attacks(self):
        """Test Cross-Site Scripting attacks"""
        print("🔍 Testing XSS attacks...")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(f"{self.base_url}/profile?username={quote(payload)}")
                print(f"  XSS: {payload} -> Status: {response.status_code}")
                time.sleep(0.5)
            except Exception as e:
                print(f"  Error: {e}")
    
    def test_command_injection(self):
        """Test Command Injection attacks"""
        print("🔍 Testing Command Injection attacks...")
        
        payloads = [
            "ls",
            "whoami",
            "cat /etc/passwd",
            "pwd",
            "id"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(f"{self.base_url}/command?cmd={quote(payload)}")
                print(f"  Command Injection: {payload} -> Status: {response.status_code}")
                time.sleep(0.5)
            except Exception as e:
                print(f"  Error: {e}")
    
    def test_path_traversal(self):
        """Test Path Traversal attacks"""
        print("🔍 Testing Path Traversal attacks...")
        
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "../../../proc/version"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(f"{self.base_url}/file?file={quote(payload)}")
                print(f"  Path Traversal: {payload} -> Status: {response.status_code}")
                time.sleep(0.5)
            except Exception as e:
                print(f"  Error: {e}")
    
    def test_brute_force(self):
        """Test Brute Force attacks"""
        print("🔍 Testing Brute Force attacks...")
        
        common_passwords = [
            "admin", "password", "123456", "qwerty", "letmein",
            "welcome", "monkey", "dragon", "master", "root"
        ]
        
        for password in common_passwords:
            try:
                data = {"username": "admin", "password": password}
                response = self.session.post(f"{self.base_url}/login", data=data)
                print(f"  Brute Force: admin/{password} -> Status: {response.status_code}")
                time.sleep(0.2)
            except Exception as e:
                print(f"  Error: {e}")
    
    def test_insecure_deserialization(self):
        """Test Insecure Deserialization attacks"""
        print("🔍 Testing Insecure Deserialization attacks...")
        
        # Create a simple pickle payload
        import pickle
        import base64
        
        payloads = [
            base64.b64encode(pickle.dumps({"test": "data"})).decode(),
            base64.b64encode(pickle.dumps(["list", "data"])).decode(),
            base64.b64encode(pickle.dumps(123)).decode()
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(f"{self.base_url}/deserialize?data={quote(payload)}")
                print(f"  Deserialization: {payload[:20]}... -> Status: {response.status_code}")
                time.sleep(0.5)
            except Exception as e:
                print(f"  Error: {e}")
    
    def test_unauthorized_access(self):
        """Test Unauthorized Access attempts"""
        print("🔍 Testing Unauthorized Access attempts...")
        
        endpoints = [
            "/api/admin",
            "/api/users/1",
            "/debug",
            "/api/data"
        ]
        
        for endpoint in endpoints:
            try:
                response = self.session.get(f"{self.base_url}{endpoint}")
                print(f"  Unauthorized Access: {endpoint} -> Status: {response.status_code}")
                time.sleep(0.5)
            except Exception as e:
                print(f"  Error: {e}")
    
    def test_information_disclosure(self):
        """Test Information Disclosure attempts"""
        print("🔍 Testing Information Disclosure attempts...")
        
        try:
            response = self.session.get(f"{self.base_url}/debug")
            print(f"  Information Disclosure: /debug -> Status: {response.status_code}")
            if response.status_code == 200:
                print(f"    Response: {response.text[:100]}...")
        except Exception as e:
            print(f"  Error: {e}")
    
    def run_all_attacks(self):
        """Run all attack simulations"""
        print("🚀 Starting Attack Simulation...")
        print("=" * 50)
        
        self.test_sql_injection()
        print()
        
        self.test_xss_attacks()
        print()
        
        self.test_command_injection()
        print()
        
        self.test_path_traversal()
        print()
        
        self.test_brute_force()
        print()
        
        self.test_insecure_deserialization()
        print()
        
        self.test_unauthorized_access()
        print()
        
        self.test_information_disclosure()
        print()
        
        print("✅ Attack simulation completed!")

if __name__ == "__main__":
    simulator = AttackSimulator()
    simulator.run_all_attacks() 