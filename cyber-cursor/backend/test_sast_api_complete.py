#!/usr/bin/env python3
"""
Complete SAST API Test Script
Tests authentication and SAST project creation
"""

import asyncio
import aiohttp
import json
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api/v1"

async def test_sast_api_complete():
    """Test complete SAST API flow"""
    
    print("🚀 Testing Complete SAST API Flow")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        # Step 1: Login to get authentication token
        print("\n1️⃣  Testing Authentication...")
        login_data = {
            "username": "admin@cybershield.com",
            "password": "password"
        }
        
        try:
            async with session.post(f"{API_BASE}/auth/login", json=login_data) as response:
                if response.status == 200:
                    auth_data = await response.json()
                    access_token = auth_data.get('access_token')
                    user_id = auth_data.get('user_id')
                    role = auth_data.get('role')
                    print(f"✅ Login successful!")
                    print(f"   User ID: {user_id}")
                    print(f"   Role: {role}")
                    print(f"   Token: {access_token[:20]}...")
                else:
                    print(f"❌ Login failed: {response.status}")
                    error_text = await response.text()
                    print(f"   Error: {error_text}")
                    return
        except Exception as e:
            print(f"❌ Login error: {e}")
            return
        
        # Set up headers for authenticated requests
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        # Step 2: Test SAST Dashboard (authenticated)
        print("\n2️⃣  Testing SAST Dashboard...")
        try:
            async with session.get(f"{API_BASE}/sast/dashboard", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Dashboard: {data.get('total_projects', 0)} projects found")
                    print(f"   Active scans: {data.get('active_scans', 0)}")
                    print(f"   Total issues: {data.get('total_issues', 0)}")
                else:
                    print(f"❌ Dashboard failed: {response.status}")
                    error_text = await response.text()
                    print(f"   Error: {error_text}")
        except Exception as e:
            print(f"❌ Dashboard error: {e}")
        
        # Step 3: Test SAST Overview
        print("\n3️⃣  Testing SAST Overview...")
        try:
            async with session.get(f"{API_BASE}/sast/overview", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Overview: {data.get('total_projects', 0)} projects, {data.get('total_issues', 0)} issues")
                    print(f"   Security rating: {data.get('overall_security_rating', 'Unknown')}")
                    print(f"   Reliability rating: {data.get('overall_reliability_rating', 'Unknown')}")
                else:
                    print(f"❌ Overview failed: {response.status}")
                    error_text = await response.text()
                    print(f"   Error: {error_text}")
        except Exception as e:
            print(f"❌ Overview error: {e}")
        
        # Step 4: Test SAST Projects List
        print("\n4️⃣  Testing SAST Projects List...")
        try:
            async with session.get(f"{API_BASE}/sast/projects", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    projects = data.get('projects', [])
                    print(f"✅ Projects: {len(projects)} projects found")
                    
                    if projects:
                        project_id = projects[0]['id']
                        print(f"   Using project ID: {project_id}")
                        
                        # Test 5: Get Project Details
                        print("\n5️⃣  Testing Project Details...")
                        async with session.get(f"{API_BASE}/sast/projects/{project_id}", headers=headers) as detail_response:
                            if detail_response.status == 200:
                                detail_data = await detail_response.json()
                                print(f"✅ Project Details: {detail_data.get('name', 'Unknown')}")
                                print(f"   Language: {detail_data.get('language', 'Unknown')}")
                                print(f"   Repository: {detail_data.get('repository_url', 'Unknown')}")
                            else:
                                print(f"❌ Project Details failed: {detail_response.status}")
                    else:
                        print("   No existing projects found")
                else:
                    print(f"❌ Projects failed: {response.status}")
                    error_text = await response.text()
                    print(f"   Error: {error_text}")
        except Exception as e:
            print(f"❌ Projects error: {e}")
        
        # Step 6: Test SAST Project Creation
        print("\n6️⃣  Testing SAST Project Creation...")
        project_data = {
            "name": f"Test Security Project {datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "key": f"test-sec-project-{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "language": "Python",
            "repository_url": "https://github.com/test/security-project",
            "branch": "main"
        }
        
        try:
            async with session.post(f"{API_BASE}/sast/projects", json=project_data, headers=headers) as response:
                if response.status == 201:
                    created_project = await response.json()
                    print(f"✅ Project created successfully!")
                    print(f"   Project ID: {created_project.get('id')}")
                    print(f"   Name: {created_project.get('name')}")
                    print(f"   Key: {created_project.get('key')}")
                    print(f"   Language: {created_project.get('language')}")
                    print(f"   Status: {created_project.get('status', 'Unknown')}")
                    
                    # Store the created project ID for further testing
                    new_project_id = created_project.get('id')
                    
                    # Step 7: Test Project Configuration
                    print("\n7️⃣  Testing Project Configuration...")
                    async with session.get(f"{API_BASE}/sast/projects/{new_project_id}/configuration", headers=headers) as config_response:
                        if config_response.status == 200:
                            config_data = await config_response.json()
                            print(f"✅ Configuration retrieved")
                            print(f"   Project ID: {config_data.get('project_id')}")
                        else:
                            print(f"❌ Configuration failed: {config_response.status}")
                    
                    # Step 8: Test Project Metrics
                    print("\n8️⃣  Testing Project Metrics...")
                    async with session.get(f"{API_BASE}/sast/projects/{new_project_id}/metrics", headers=headers) as metrics_response:
                        if metrics_response.status == 200:
                            metrics_data = await metrics_response.json()
                            print(f"✅ Metrics retrieved")
                            print(f"   Security Rating: {metrics_data.get('security_rating', 'Unknown')}")
                            print(f"   Reliability Rating: {metrics_data.get('reliability_rating', 'Unknown')}")
                        else:
                            print(f"❌ Metrics failed: {metrics_response.status}")
                    
                else:
                    print(f"❌ Project creation failed: {response.status}")
                    error_text = await response.text()
                    print(f"   Error: {error_text}")
        except Exception as e:
            print(f"❌ Project creation error: {e}")
        
        # Step 9: Test SAST Statistics
        print("\n9️⃣  Testing SAST Statistics...")
        try:
            async with session.get(f"{API_BASE}/sast/statistics", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Statistics: {data.get('total_projects', 0)} projects")
                    print(f"   Total issues: {data.get('total_issues', 0)}")
                    print(f"   Security hotspots: {data.get('total_hotspots', 0)}")
                    print(f"   Code coverage: {data.get('average_coverage', 0)}%")
                else:
                    print(f"❌ Statistics failed: {response.status}")
                    error_text = await response.text()
                    print(f"   Error: {error_text}")
        except Exception as e:
            print(f"❌ Statistics error: {e}")
        
        # Step 10: Test SAST Rules
        print("\n🔟 Testing SAST Rules...")
        try:
            async with session.get(f"{API_BASE}/sast/rules", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    rules = data.get('rules', [])
                    print(f"✅ Rules: {len(rules)} rules found")
                    if rules:
                        print(f"   Sample rule: {rules[0].get('name', 'Unknown')}")
                else:
                    print(f"❌ Rules failed: {response.status}")
                    error_text = await response.text()
                    print(f"   Error: {error_text}")
        except Exception as e:
            print(f"❌ Rules error: {e}")
        
        print("\n🎉 Complete SAST API Testing Complete!")
        print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test_sast_api_complete())
