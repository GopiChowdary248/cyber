#!/usr/bin/env python3
"""
Test SAST endpoints with real database integration
"""

import asyncio
import aiohttp
import json
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api/v1"

async def test_sast_endpoints():
    """Test all SAST endpoints"""
    
    # Test data
    test_project_data = {
        "name": "Test Security Project",
        "key": "test-sec-project",
        "language": "Python",
        "repository_url": "https://github.com/test/security-project",
        "branch": "main"
    }
    
    async with aiohttp.ClientSession() as session:
        print("🔍 Testing SAST Endpoints...")
        
        # Test 1: Get SAST Dashboard
        print("\n1. Testing SAST Dashboard...")
        try:
            async with session.get(f"{API_BASE}/sast/dashboard") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Dashboard: {data.get('total_projects', 0)} projects found")
                else:
                    print(f"❌ Dashboard failed: {response.status}")
        except Exception as e:
            print(f"❌ Dashboard error: {e}")
        
        # Test 2: Get SAST Overview
        print("\n2. Testing SAST Overview...")
        try:
            async with session.get(f"{API_BASE}/sast/overview") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Overview: {data.get('total_projects', 0)} projects, {data.get('total_issues', 0)} issues")
                else:
                    print(f"❌ Overview failed: {response.status}")
        except Exception as e:
            print(f"❌ Overview error: {e}")
        
        # Test 3: Get SAST Projects
        print("\n3. Testing SAST Projects...")
        try:
            async with session.get(f"{API_BASE}/sast/projects") as response:
                if response.status == 200:
                    data = await response.json()
                    projects = data.get('projects', [])
                    print(f"✅ Projects: {len(projects)} projects found")
                    
                    if projects:
                        project_id = projects[0]['id']
                        print(f"   Using project ID: {project_id}")
                        
                        # Test 4: Get Project Details
                        print("\n4. Testing Project Details...")
                        async with session.get(f"{API_BASE}/sast/projects/{project_id}") as detail_response:
                            if detail_response.status == 200:
                                detail_data = await detail_response.json()
                                print(f"✅ Project Details: {detail_data.get('name', 'Unknown')}")
                            else:
                                print(f"❌ Project Details failed: {detail_response.status}")
                        
                        # Test 5: Get Project Duplications
                        print("\n5. Testing Project Duplications...")
                        async with session.get(f"{API_BASE}/sast/projects/{project_id}/duplications") as dup_response:
                            if dup_response.status == 200:
                                dup_data = await dup_response.json()
                                print(f"✅ Duplications: {dup_data.get('duplicatedLines', 0)} duplicated lines")
                                print(f"   Files: {dup_data.get('duplicatedFiles', 0)}, Density: {dup_data.get('duplicationDensity', 0)}%")
                            else:
                                print(f"❌ Duplications failed: {dup_response.status}")
                        
                        # Test 6: Get Project Security Reports
                        print("\n6. Testing Project Security Reports...")
                        async with session.get(f"{API_BASE}/sast/projects/{project_id}/security-reports") as sec_response:
                            if sec_response.status == 200:
                                sec_data = await sec_response.json()
                                print(f"✅ Security Reports: Rating {sec_data.get('overallSecurityRating', 'Unknown')}")
                                print(f"   Score: {sec_data.get('securityScore', 0)}")
                            else:
                                print(f"❌ Security Reports failed: {sec_response.status}")
                        
                        # Test 7: Get Project Reliability
                        print("\n7. Testing Project Reliability...")
                        async with session.get(f"{API_BASE}/sast/projects/{project_id}/reliability") as rel_response:
                            if rel_response.status == 200:
                                rel_data = await rel_response.json()
                                print(f"✅ Reliability: Rating {rel_data.get('reliabilityRating', 'Unknown')}")
                                print(f"   Bugs: {rel_data.get('bugCount', 0)}")
                            else:
                                print(f"❌ Reliability failed: {rel_response.status}")
                        
                        # Test 8: Get Project Maintainability
                        print("\n8. Testing Project Maintainability...")
                        async with session.get(f"{API_BASE}/sast/projects/{project_id}/maintainability") as maint_response:
                            if maint_response.status == 200:
                                maint_data = await maint_response.json()
                                print(f"✅ Maintainability: Rating {maint_data.get('maintainabilityRating', 'Unknown')}")
                                print(f"   Code Smells: {maint_data.get('codeSmellCount', 0)}")
                            else:
                                print(f"❌ Maintainability failed: {maint_response.status}")
                        
                        # Test 9: Get Project Activity
                        print("\n9. Testing Project Activity...")
                        async with session.get(f"{API_BASE}/sast/projects/{project_id}/activity") as act_response:
                            if act_response.status == 200:
                                act_data = await act_response.json()
                                print(f"✅ Activity: {len(act_data.get('recentCommits', []))} recent commits")
                                print(f"   Contributors: {len(act_data.get('contributors', []))}")
                            else:
                                print(f"❌ Activity failed: {act_response.status}")
                        
                        # Test 10: Get Project Configuration
                        print("\n10. Testing Project Configuration...")
                        async with session.get(f"{API_BASE}/sast/projects/{project_id}/configuration") as config_response:
                            if config_response.status == 200:
                                config_data = await config_response.json()
                                print(f"✅ Configuration: Auto scan {config_data.get('autoScan', False)}")
                            else:
                                print(f"❌ Configuration failed: {config_response.status}")
                        
                        # Test 11: Get Project Metrics
                        print("\n11. Testing Project Metrics...")
                        async with session.get(f"{API_BASE}/sast/projects/{project_id}/metrics") as metrics_response:
                            if metrics_response.status == 200:
                                metrics_data = await metrics_response.json()
                                print(f"✅ Metrics: {metrics_data.get('linesOfCode', 0)} lines of code")
                                print(f"   Coverage: {metrics_data.get('coverage', 0)}%")
                            else:
                                print(f"❌ Metrics failed: {metrics_response.status}")
                        
                        # Test 12: Get Project Trends
                        print("\n12. Testing Project Trends...")
                        async with session.get(f"{API_BASE}/sast/projects/{project_id}/trends") as trends_response:
                            if trends_response.status == 200:
                                trends_data = await trends_response.json()
                                print(f"✅ Trends: {len(trends_data.get('trends', []))} data points")
                            else:
                                print(f"❌ Trends failed: {trends_response.status}")
                    else:
                        print("   No projects found to test individual endpoints")
                else:
                    print(f"❌ Projects failed: {response.status}")
        except Exception as e:
            print(f"❌ Projects error: {e}")
        
        # Test 13: Get Vulnerabilities
        print("\n13. Testing Vulnerabilities...")
        try:
            async with session.get(f"{API_BASE}/sast/vulnerabilities") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Vulnerabilities: {len(data.get('vulnerabilities', []))} found")
                else:
                    print(f"❌ Vulnerabilities failed: {response.status}")
        except Exception as e:
            print(f"❌ Vulnerabilities error: {e}")
        
        # Test 14: Get Security Hotspots
        print("\n14. Testing Security Hotspots...")
        try:
            async with session.get(f"{API_BASE}/sast/security-hotspots") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Security Hotspots: {len(data.get('hotspots', []))} found")
                else:
                    print(f"❌ Security Hotspots failed: {response.status}")
        except Exception as e:
            print(f"❌ Security Hotspots error: {e}")
        
        # Test 15: Get Quality Gates
        print("\n15. Testing Quality Gates...")
        try:
            async with session.get(f"{API_BASE}/sast/quality-gates") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Quality Gates: {len(data.get('quality_gates', []))} found")
                else:
                    print(f"❌ Quality Gates failed: {response.status}")
        except Exception as e:
            print(f"❌ Quality Gates error: {e}")
        
        # Test 16: Get Code Coverage
        print("\n16. Testing Code Coverage...")
        try:
            async with session.get(f"{API_BASE}/sast/code-coverage") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Code Coverage: {len(data.get('coverages', []))} files")
                else:
                    print(f"❌ Code Coverage failed: {response.status}")
        except Exception as e:
            print(f"❌ Code Coverage error: {e}")
        
        # Test 17: Get Duplications
        print("\n17. Testing Duplications...")
        try:
            async with session.get(f"{API_BASE}/sast/duplications") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Duplications: {len(data.get('duplications', []))} files")
                else:
                    print(f"❌ Duplications failed: {response.status}")
        except Exception as e:
            print(f"❌ Duplications error: {e}")
        
        # Test 18: Get Statistics
        print("\n18. Testing Statistics...")
        try:
            async with session.get(f"{API_BASE}/sast/statistics") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Statistics: {data.get('total_projects', 0)} projects")
                    print(f"   Issues: {data.get('total_issues', 0)}, Hotspots: {data.get('total_hotspots', 0)}")
                else:
                    print(f"❌ Statistics failed: {response.status}")
        except Exception as e:
            print(f"❌ Statistics error: {e}")
        
        # Test 19: Get Rules
        print("\n19. Testing Rules...")
        try:
            async with session.get(f"{API_BASE}/sast/rules") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Rules: {len(data.get('rules', []))} rules found")
                else:
                    print(f"❌ Rules failed: {response.status}")
        except Exception as e:
            print(f"❌ Rules error: {e}")
        
        # Test 20: Get Languages
        print("\n20. Testing Languages...")
        try:
            async with session.get(f"{API_BASE}/sast/languages") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"✅ Languages: {len(data.get('languages', []))} supported")
                else:
                    print(f"❌ Languages failed: {response.status}")
        except Exception as e:
            print(f"❌ Languages error: {e}")
        
        print("\n🎉 SAST Endpoint Testing Complete!")

if __name__ == "__main__":
    asyncio.run(test_sast_endpoints()) 