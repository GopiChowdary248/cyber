#!/usr/bin/env python3
"""
RASP Demo Application
Demonstrates RASP protection in a vulnerable web application
"""

import asyncio
import aiohttp
import json
import time
import random
from datetime import datetime
from typing import Dict, Any

class RASPDemoAgent:
    """Simulated RASP agent for demo purposes"""
    
    def __init__(self, api_url: str = "http://localhost:8000"):
        self.api_url = api_url
        self.agent_id = None
        self.app_name = "Demo Vulnerable Web App"
        self.language = "python"
        self.version = "1.0.0"
        
    async def register_agent(self):
        """Register the agent with RASP backend"""
        agent_data = {
            "app_name": self.app_name,
            "language": self.language,
            "version": self.version,
            "config": {
                "monitoring_level": "high",
                "auto_block": True,
                "heartbeat_interval": 30
            }
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{self.api_url}/api/rasp/agents", json=agent_data) as response:
                if response.status == 200:
                    agent = await response.json()
                    self.agent_id = agent['agent_id']
                    print(f"✅ Agent registered with ID: {self.agent_id}")
                    return True
                else:
                    print(f"❌ Failed to register agent: {response.status}")
                    return False
    
    async def send_heartbeat(self):
        """Send heartbeat to RASP backend"""
        if not self.agent_id:
            return False
            
        heartbeat_data = {
            "status": "active",
            "telemetry": [
                {
                    "metric_name": "requests_per_minute",
                    "metric_value": random.randint(50, 200)
                },
                {
                    "metric_name": "memory_usage_mb",
                    "metric_value": random.randint(100, 500)
                }
            ]
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.api_url}/api/rasp/agents/{self.agent_id}/heartbeat",
                json=heartbeat_data
            ) as response:
                return response.status == 200
    
    async def report_attack(self, attack_data: Dict[str, Any]):
        """Report an attack to RASP backend"""
        if not self.agent_id:
            return False
            
        attack_data["agent_id"] = self.agent_id
        
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{self.api_url}/api/rasp/attacks", json=attack_data) as response:
                if response.status == 200:
                    attack = await response.json()
                    print(f"🚨 Attack reported with ID: {attack['attack_id']}")
                    return True
                else:
                    print(f"❌ Failed to report attack: {response.status}")
                    return False

class VulnerableWebApp:
    """Simulated vulnerable web application"""
    
    def __init__(self, rasp_agent: RASPDemoAgent):
        self.rasp_agent = rasp_agent
        self.users_db = [
            {"id": 1, "name": "Alice", "email": "alice@example.com"},
            {"id": 2, "name": "Bob", "email": "bob@example.com"},
            {"id": 3, "name": "Charlie", "email": "charlie@example.com"}
        ]
    
    async def vulnerable_sql_query(self, user_input: str):
        """Vulnerable SQL query - demonstrates SQL injection"""
        print(f"🔍 Processing SQL query with input: {user_input}")
        
        # Simulate vulnerable SQL query
        query = f"SELECT * FROM users WHERE name = '{user_input}'"
        print(f"📝 Generated SQL: {query}")
        
        # Check if this looks like an attack
        if any(pattern in user_input.lower() for pattern in ["'", "drop", "delete", "union", "select"]):
            print("🚨 RASP: Potential SQL injection detected!")
            
            # Report the attack
            attack_data = {
                "source_ip": "192.168.1.100",
                "url": "/api/users",
                "payload": user_input,
                "vuln_type": "SQLi",
                "severity": "critical",
                "stack_trace": "Traceback (most recent call last):\n  File \"app.py\", line 15, in <module>",
                "blocked": True,
                "context": {"user_id": 123, "session_id": "abc123"},
                "request_data": {"method": "GET", "headers": {"Content-Type": "application/json"}},
                "response_data": {"status_code": 500, "error": "Database error"}
            }
            
            await self.rasp_agent.report_attack(attack_data)
            return {"error": "Access denied - potential SQL injection detected"}
        
        # Simulate normal response
        return {"users": self.users_db}
    
    async def vulnerable_xss_endpoint(self, user_input: str):
        """Vulnerable XSS endpoint - demonstrates XSS attack"""
        print(f"🔍 Processing XSS endpoint with input: {user_input}")
        
        # Simulate vulnerable HTML rendering
        html_response = f"<div>User comment: {user_input}</div>"
        print(f"📝 Generated HTML: {html_response}")
        
        # Check if this looks like an XSS attack
        if any(pattern in user_input.lower() for pattern in ["<script", "javascript:", "onerror", "onload"]):
            print("🚨 RASP: Potential XSS attack detected!")
            
            # Report the attack
            attack_data = {
                "source_ip": "192.168.1.101",
                "url": "/api/comments",
                "payload": user_input,
                "vuln_type": "XSS",
                "severity": "high",
                "stack_trace": "Traceback (most recent call last):\n  File \"views.py\", line 25, in <module>",
                "blocked": True,
                "context": {"user_id": 456, "session_id": "def456"},
                "request_data": {"method": "POST", "headers": {"Content-Type": "application/json"}},
                "response_data": {"status_code": 400, "error": "Invalid input"}
            }
            
            await self.rasp_agent.report_attack(attack_data)
            return {"error": "Access denied - potential XSS attack detected"}
        
        # Simulate normal response
        return {"message": "Comment posted successfully", "html": html_response}
    
    async def vulnerable_command_execution(self, user_input: str):
        """Vulnerable command execution - demonstrates command injection"""
        print(f"🔍 Processing command execution with input: {user_input}")
        
        # Simulate vulnerable command execution
        command = f"ls {user_input}"
        print(f"📝 Generated command: {command}")
        
        # Check if this looks like a command injection attack
        if any(pattern in user_input for pattern in [";", "&&", "||", "|", "`", "$("]):
            print("🚨 RASP: Potential command injection detected!")
            
            # Report the attack
            attack_data = {
                "source_ip": "192.168.1.102",
                "url": "/api/system",
                "payload": user_input,
                "vuln_type": "Command Injection",
                "severity": "critical",
                "stack_trace": "Traceback (most recent call last):\n  File \"admin.py\", line 15, in <module>",
                "blocked": True,
                "context": {"user_id": 789, "session_id": "ghi789"},
                "request_data": {"method": "POST", "headers": {"Content-Type": "application/json"}},
                "response_data": {"status_code": 403, "error": "Command execution blocked"}
            }
            
            await self.rasp_agent.report_attack(attack_data)
            return {"error": "Access denied - potential command injection detected"}
        
        # Simulate normal response
        return {"files": ["file1.txt", "file2.txt", "file3.txt"]}

class RASPDemo:
    """Main RASP demo class"""
    
    def __init__(self):
        self.rasp_agent = RASPDemoAgent()
        self.web_app = VulnerableWebApp(self.rasp_agent)
        
    async def run_demo(self):
        """Run the complete RASP demo"""
        print("🚀 Starting RASP Demo Application")
        print("=" * 50)
        
        # Register agent
        print("\n📋 Step 1: Registering RASP Agent")
        if not await self.rasp_agent.register_agent():
            print("❌ Failed to register agent. Exiting.")
            return
        
        # Send initial heartbeat
        print("\n💓 Step 2: Sending Agent Heartbeat")
        await self.rasp_agent.send_heartbeat()
        
        # Demo scenarios
        print("\n🎭 Step 3: Running Attack Scenarios")
        
        # Scenario 1: Normal usage
        print("\n--- Scenario 1: Normal Usage ---")
        await self.web_app.vulnerable_sql_query("Alice")
        await self.web_app.vulnerable_xss_endpoint("Great product!")
        await self.web_app.vulnerable_command_execution("/home/user")
        
        # Scenario 2: SQL Injection attack
        print("\n--- Scenario 2: SQL Injection Attack ---")
        await self.web_app.vulnerable_sql_query("'; DROP TABLE users; --")
        
        # Scenario 3: XSS attack
        print("\n--- Scenario 3: XSS Attack ---")
        await self.web_app.vulnerable_xss_endpoint("<script>alert('XSS')</script>")
        
        # Scenario 4: Command Injection attack
        print("\n--- Scenario 4: Command Injection Attack ---")
        await self.web_app.vulnerable_command_execution("; rm -rf /")
        
        # Scenario 5: Another normal usage
        print("\n--- Scenario 5: Normal Usage (After Attacks) ---")
        await self.web_app.vulnerable_sql_query("Bob")
        await self.web_app.vulnerable_xss_endpoint("Nice website!")
        
        # Send final heartbeat
        print("\n💓 Step 4: Sending Final Heartbeat")
        await self.rasp_agent.send_heartbeat()
        
        print("\n✅ RASP Demo completed successfully!")
        print("Check the RASP dashboard at http://localhost:8000/docs to see the detected attacks.")

async def main():
    """Main demo function"""
    demo = RASPDemo()
    await demo.run_demo()

if __name__ == "__main__":
    asyncio.run(main()) 