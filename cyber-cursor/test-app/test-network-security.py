#!/usr/bin/env python3
"""
Network Security Module Test Script
Tests all Network Security endpoints and functionality
"""

import requests
import json
from datetime import datetime
import time

class NetworkSecurityTester:
    def __init__(self):
        self.api_url = "http://localhost:8000"
        self.auth_token = None
        
    def login(self):
        """Login to get authentication token"""
        print("🔐 Logging in...")
        try:
            response = requests.post(
                f"{self.api_url}/api/v1/auth/login",
                data={
                    "username": "admin@cybershield.com",
                    "password": "password"
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.auth_token = data["access_token"]
                print("✅ Login successful")
                return True
            else:
                print(f"❌ Login failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Login error: {e}")
            return False
    
    def get_headers(self):
        """Get headers with authentication"""
        return {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json"
        }
    
    def test_network_devices(self):
        """Test network devices endpoints"""
        print("\n🔍 Testing Network Devices...")
        
        # Get all devices
        try:
            response = requests.get(
                f"{self.api_url}/api/v1/network-security/devices",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Found {data['total']} network devices")
                for device in data['devices']:
                    print(f"   - {device['device_name']} ({device['device_type']}) - {device['status']}")
                return True
            else:
                print(f"❌ Failed to get devices: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error testing devices: {e}")
            return False
    
    def test_firewall_logs(self):
        """Test firewall logs endpoints"""
        print("\n🔍 Testing Firewall Logs...")
        
        # Get firewall logs
        try:
            response = requests.get(
                f"{self.api_url}/api/v1/network-security/firewall/logs",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Found {data['total']} firewall logs")
                for log in data['logs'][:3]:  # Show first 3 logs
                    print(f"   - {log['source_ip']} -> {log['dest_ip']} ({log['action']})")
                return True
            else:
                print(f"❌ Failed to get firewall logs: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error testing firewall logs: {e}")
            return False
    
    def test_firewall_stats(self):
        """Test firewall statistics"""
        print("\n🔍 Testing Firewall Statistics...")
        
        try:
            response = requests.get(
                f"{self.api_url}/api/v1/network-security/firewall/stats",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Firewall stats: {data['total_logs']} total logs")
                print(f"   - Allowed: {data['allowed_connections']}")
                print(f"   - Denied: {data['denied_connections']}")
                print(f"   - Dropped: {data['dropped_connections']}")
                return True
            else:
                print(f"❌ Failed to get firewall stats: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error testing firewall stats: {e}")
            return False
    
    def test_ids_alerts(self):
        """Test IDS alerts endpoints"""
        print("\n🔍 Testing IDS Alerts...")
        
        # Get IDS alerts
        try:
            response = requests.get(
                f"{self.api_url}/api/v1/network-security/ids/alerts",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Found {data['total']} IDS alerts")
                for alert in data['alerts'][:3]:  # Show first 3 alerts
                    print(f"   - {alert['severity']}: {alert['description'][:50]}...")
                return True
            else:
                print(f"❌ Failed to get IDS alerts: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error testing IDS alerts: {e}")
            return False
    
    def test_ids_stats(self):
        """Test IDS statistics"""
        print("\n🔍 Testing IDS Statistics...")
        
        try:
            response = requests.get(
                f"{self.api_url}/api/v1/network-security/ids/stats",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ IDS stats: {data['total_alerts']} total alerts")
                print(f"   - Critical: {data['critical_alerts']}")
                print(f"   - High: {data['high_alerts']}")
                print(f"   - Medium: {data['medium_alerts']}")
                print(f"   - Low: {data['low_alerts']}")
                return True
            else:
                print(f"❌ Failed to get IDS stats: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error testing IDS stats: {e}")
            return False
    
    def test_vpn_sessions(self):
        """Test VPN sessions endpoints"""
        print("\n🔍 Testing VPN Sessions...")
        
        # Get VPN sessions
        try:
            response = requests.get(
                f"{self.api_url}/api/v1/network-security/vpn/sessions",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Found {data['total']} VPN sessions")
                for session in data['sessions'][:3]:  # Show first 3 sessions
                    print(f"   - {session['username']} ({session['status']}) - {session['ip_address']}")
                return True
            else:
                print(f"❌ Failed to get VPN sessions: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error testing VPN sessions: {e}")
            return False
    
    def test_vpn_stats(self):
        """Test VPN statistics"""
        print("\n🔍 Testing VPN Statistics...")
        
        try:
            response = requests.get(
                f"{self.api_url}/api/v1/network-security/vpn/stats",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ VPN stats: {data['active_sessions']} active sessions")
                print(f"   - Total users: {data['total_users']}")
                print(f"   - Total traffic: {data['total_traffic']} bytes")
                return True
            else:
                print(f"❌ Failed to get VPN stats: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error testing VPN stats: {e}")
            return False
    
    def test_nac_logs(self):
        """Test NAC logs endpoints"""
        print("\n🔍 Testing NAC Logs...")
        
        # Get NAC logs
        try:
            response = requests.get(
                f"{self.api_url}/api/v1/network-security/nac/logs",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Found {data['total']} NAC logs")
                for log in data['logs'][:3]:  # Show first 3 logs
                    print(f"   - {log['device_name']} ({log['action']}) - {log['device_mac']}")
                return True
            else:
                print(f"❌ Failed to get NAC logs: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error testing NAC logs: {e}")
            return False
    
    def test_nac_stats(self):
        """Test NAC statistics"""
        print("\n🔍 Testing NAC Statistics...")
        
        try:
            response = requests.get(
                f"{self.api_url}/api/v1/network-security/nac/stats",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ NAC stats: {data['total_events']} total events")
                print(f"   - Allowed: {data['allowed_devices']}")
                print(f"   - Blocked: {data['blocked_devices']}")
                print(f"   - Quarantined: {data['quarantined_devices']}")
                return True
            else:
                print(f"❌ Failed to get NAC stats: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error testing NAC stats: {e}")
            return False
    
    def test_overview(self):
        """Test network security overview"""
        print("\n🔍 Testing Network Security Overview...")
        
        try:
            response = requests.get(
                f"{self.api_url}/api/v1/network-security/overview",
                headers=self.get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print("✅ Network Security Overview:")
                print(f"   - Devices: {data['total_devices']} total, {data['online_devices']} online")
                print(f"   - Firewall logs (24h): {data['firewall_logs_24h']}")
                print(f"   - IDS alerts (24h): {data['ids_alerts_24h']}")
                print(f"   - Active VPN sessions: {data['active_vpn_sessions']}")
                print(f"   - NAC events (24h): {data['nac_events_24h']}")
                print(f"   - Critical alerts: {data['critical_alerts']}")
                print(f"   - High alerts: {data['high_alerts']}")
                return True
            else:
                print(f"❌ Failed to get overview: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error testing overview: {e}")
            return False
    
    def run_all_tests(self):
        """Run all network security tests"""
        print("🚀 Starting Network Security Module Tests")
        print("=" * 60)
        
        # Login first
        if not self.login():
            print("❌ Cannot proceed without authentication")
            return False
        
        tests = [
            ("Network Devices", self.test_network_devices),
            ("Firewall Logs", self.test_firewall_logs),
            ("Firewall Stats", self.test_firewall_stats),
            ("IDS Alerts", self.test_ids_alerts),
            ("IDS Stats", self.test_ids_stats),
            ("VPN Sessions", self.test_vpn_sessions),
            ("VPN Stats", self.test_vpn_stats),
            ("NAC Logs", self.test_nac_logs),
            ("NAC Stats", self.test_nac_stats),
            ("Overview", self.test_overview)
        ]
        
        results = []
        for test_name, test_func in tests:
            try:
                result = test_func()
                results.append((test_name, result))
            except Exception as e:
                print(f"❌ {test_name} test failed with exception: {e}")
                results.append((test_name, False))
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 Network Security Module Test Summary")
        print("=" * 60)
        
        passed = 0
        total = len(results)
        
        for test_name, result in results:
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{status} {test_name}")
            if result:
                passed += 1
        
        print(f"\n🎯 Results: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
        
        if passed == total:
            print("🎉 All Network Security Module tests passed!")
            return True
        else:
            print("⚠️  Some tests failed. Check the logs above for details.")
            return False

def main():
    tester = NetworkSecurityTester()
    success = tester.run_all_tests()
    exit(0 if success else 1)

if __name__ == "__main__":
    main() 