#!/usr/bin/env python3
"""
SAST Integration Test Script
Tests the SAST API endpoints with database integration.
"""

import requests
import json
import time
from datetime import datetime

def test_sast_endpoints():
    """Test SAST API endpoints"""
    
    base_url = "http://localhost:8000"
    
    print("🔍 Testing SAST API Integration")
    print("=" * 50)
    
    # Test 1: SAST Overview
    print("\n1️⃣ Testing SAST Overview...")
    try:
        response = requests.get(f"{base_url}/api/v1/sast/overview", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ SAST Overview: {data.get('overview', {}).get('totalProjects', 0)} projects")
            print(f"   - Total scans: {data.get('overview', {}).get('totalScans', 0)}")
            print(f"   - Total vulnerabilities: {data.get('overview', {}).get('totalVulnerabilities', 0)}")
        else:
            print(f"❌ SAST Overview failed: {response.status_code}")
    except Exception as e:
        print(f"❌ SAST Overview error: {e}")
    
    # Test 2: SAST Projects
    print("\n2️⃣ Testing SAST Projects...")
    try:
        response = requests.get(f"{base_url}/api/v1/sast/projects", timeout=10)
        if response.status_code == 200:
            data = response.json()
            projects = data.get('projects', [])
            print(f"✅ SAST Projects: {len(projects)} projects found")
            for project in projects[:3]:  # Show first 3
                print(f"   - {project.get('name', 'Unknown')} ({project.get('language', 'Unknown')})")
        else:
            print(f"❌ SAST Projects failed: {response.status_code}")
    except Exception as e:
        print(f"❌ SAST Projects error: {e}")
    
    # Test 3: SAST Rules
    print("\n3️⃣ Testing SAST Rules...")
    try:
        response = requests.get(f"{base_url}/api/v1/sast/rules", timeout=10)
        if response.status_code == 200:
            data = response.json()
            rules = data.get('rules', [])
            print(f"✅ SAST Rules: {len(rules)} rules found")
            
            # Count by language
            languages = {}
            for rule in rules:
                lang = rule.get('language', 'unknown')
                languages[lang] = languages.get(lang, 0) + 1
            
            for lang, count in languages.items():
                print(f"   - {lang}: {count} rules")
        else:
            print(f"❌ SAST Rules failed: {response.status_code}")
    except Exception as e:
        print(f"❌ SAST Rules error: {e}")
    
    # Test 4: SAST Vulnerabilities
    print("\n4️⃣ Testing SAST Vulnerabilities...")
    try:
        response = requests.get(f"{base_url}/api/v1/sast/vulnerabilities", timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            print(f"✅ SAST Vulnerabilities: {len(vulnerabilities)} vulnerabilities found")
            
            # Count by severity
            severities = {}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'unknown')
                severities[severity] = severities.get(severity, 0) + 1
            
            for severity, count in severities.items():
                print(f"   - {severity}: {count} vulnerabilities")
        else:
            print(f"❌ SAST Vulnerabilities failed: {response.status_code}")
    except Exception as e:
        print(f"❌ SAST Vulnerabilities error: {e}")
    
    # Test 5: Create a new SAST project
    print("\n5️⃣ Testing SAST Project Creation...")
    try:
        new_project = {
            "name": "Test Project",
            "repository_url": "https://github.com/test/project",
            "language": "python",
            "description": "Test project for SAST integration"
        }
        
        response = requests.post(
            f"{base_url}/api/v1/sast/projects",
            json=new_project,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Project created: {data.get('name', 'Unknown')}")
            project_id = data.get('id')
            
            # Test 6: Create a scan for the new project
            if project_id:
                print("\n6️⃣ Testing SAST Scan Creation...")
                scan_data = {
                    "project_id": project_id,
                    "scan_type": "full",
                    "scan_config": {
                        "languages": ["python"],
                        "severity_threshold": "medium"
                    }
                }
                
                scan_response = requests.post(
                    f"{base_url}/api/v1/sast/scans",
                    json=scan_data,
                    timeout=10
                )
                
                if scan_response.status_code == 200:
                    scan_data = scan_response.json()
                    print(f"✅ Scan created: {scan_data.get('id', 'Unknown')}")
                    print(f"   - Status: {scan_data.get('status', 'Unknown')}")
                else:
                    print(f"❌ Scan creation failed: {scan_response.status_code}")
        else:
            print(f"❌ Project creation failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Project creation error: {e}")
    
    print("\n" + "=" * 50)
    print("🎉 SAST Integration Test Completed!")

def test_database_connection():
    """Test direct database connection"""
    print("\n🔍 Testing Database Connection...")
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
            
            # Test SAST tables
            tables = await conn.fetch("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name LIKE 'sast_%'
                ORDER BY table_name
            """)
            
            print(f"✅ Database connection successful!")
            print(f"   - SAST tables found: {[t['table_name'] for t in tables]}")
            
            # Test data
            projects_count = await conn.fetchval("SELECT COUNT(*) FROM sast_projects")
            rules_count = await conn.fetchval("SELECT COUNT(*) FROM sast_rules")
            
            print(f"   - Projects: {projects_count}")
            print(f"   - Rules: {rules_count}")
            
            await conn.close()
        
        asyncio.run(test_db())
        
    except Exception as e:
        print(f"❌ Database connection failed: {e}")

if __name__ == "__main__":
    print("🚀 SAST Integration Test")
    print("=" * 50)
    
    # Test database connection first
    test_database_connection()
    
    # Test API endpoints
    test_sast_endpoints() 