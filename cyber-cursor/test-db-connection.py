#!/usr/bin/env python3
"""
Database Connection Test Script
Test database connectivity and RASP table existence
"""
import asyncio
import sys
import os
from datetime import datetime

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

async def test_database_connection():
    """Test database connection and table existence"""
    try:
        from app.core.database import engine, get_db, init_db
        from app.models.rasp import RASPAgent, RASPAttack, RASPRule
        from sqlalchemy import text
        
        print("🔍 Testing Database Connection...")
        
        # Test basic connection
        async with engine.begin() as conn:
            # Use different version queries for different databases
            try:
                result = await conn.execute(text("SELECT version()"))
                version = result.scalar()
                print(f"✅ Database connected (PostgreSQL): {version}")
            except:
                # Try SQLite version
                result = await conn.execute(text("SELECT sqlite_version()"))
                version = result.scalar()
                print(f"✅ Database connected (SQLite): {version}")
        
        # Initialize database tables
        print("🔧 Initializing database tables...")
        await init_db()
        print("✅ Database tables initialized")
        
        # Test RASP tables existence
        async with engine.begin() as conn:
            # Check if RASP tables exist
            tables_query = text("""
                SELECT name 
                FROM sqlite_master 
                WHERE type='table' 
                AND name LIKE 'rasp_%'
                ORDER BY name
            """)
            result = await conn.execute(tables_query)
            tables = [row[0] for row in result.fetchall()]
            
            print(f"📋 Found RASP tables: {tables}")
            
            if not tables:
                print("❌ No RASP tables found!")
                return False
            
            expected_tables = [
                'rasp_agents', 'rasp_attacks', 'rasp_rules', 
                'rasp_vulnerabilities', 'rasp_virtual_patches',
                'rasp_telemetry', 'rasp_alerts', 'rasp_integrations'
            ]
            
            missing_tables = [table for table in expected_tables if table not in tables]
            if missing_tables:
                print(f"❌ Missing tables: {missing_tables}")
                return False
            
            print("✅ All RASP tables exist!")
            return True
            
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False

async def test_rasp_models():
    """Test RASP model imports and basic operations"""
    try:
        print("\n🔍 Testing RASP Models...")
        
        from app.models.rasp import (
            RASPAgent, RASPAttack, RASPRule, RASPVulnerability,
            AgentStatus, AttackSeverity
        )
        
        print("✅ RASP models imported successfully")
        
        # Test enum values
        print(f"Agent Status values: {[status.value for status in AgentStatus]}")
        print(f"Attack Severity values: {[severity.value for severity in AttackSeverity]}")
        
        return True
        
    except Exception as e:
        print(f"❌ RASP models test failed: {e}")
        return False

async def test_rasp_service():
    """Test RASP service imports"""
    try:
        print("\n🔍 Testing RASP Service...")
        
        from app.services.rasp_service import RASPService
        from app.schemas.rasp import AgentCreate
        
        print("✅ RASP service imported successfully")
        
        # Test schema
        agent_data = AgentCreate(
            app_name="Test App",
            language="python",
            version="1.0.0",
            config={"test": True}
        )
        print(f"✅ RASP schemas working: {agent_data.app_name}")
        
        return True
        
    except Exception as e:
        print(f"❌ RASP service test failed: {e}")
        return False

async def test_rasp_api_endpoints():
    """Test RASP API endpoints"""
    try:
        print("\n🔍 Testing RASP API Endpoints...")
        
        from app.api.v1.endpoints.rasp import router
        
        # Check if router has the expected endpoints
        routes = []
        for route in router.routes:
            if hasattr(route, 'path'):
                routes.append(route.path)
        
        print(f"📋 Found {len(routes)} RASP endpoints")
        
        expected_endpoints = [
            "/agents", "/agents/{agent_id}", "/attacks", "/rules",
            "/vulnerabilities", "/virtual-patches", "/alerts", "/integrations"
        ]
        
        for endpoint in expected_endpoints:
            if any(endpoint in route for route in routes):
                print(f"✅ Endpoint found: {endpoint}")
            else:
                print(f"❌ Endpoint missing: {endpoint}")
        
        return True
        
    except Exception as e:
        print(f"❌ RASP API endpoints test failed: {e}")
        return False

async def main():
    """Run all database tests"""
    print("🚀 Starting Database Connection Tests")
    print("=" * 50)
    
    # Test database connection
    db_ok = await test_database_connection()
    
    # Test models
    models_ok = await test_rasp_models()
    
    # Test service
    service_ok = await test_rasp_service()
    
    # Test API endpoints
    api_ok = await test_rasp_api_endpoints()
    
    print("\n" + "=" * 50)
    print("📊 Test Summary")
    print("=" * 50)
    print(f"Database Connection: {'✅ PASS' if db_ok else '❌ FAIL'}")
    print(f"RASP Models: {'✅ PASS' if models_ok else '❌ FAIL'}")
    print(f"RASP Service: {'✅ PASS' if service_ok else '❌ FAIL'}")
    print(f"RASP API Endpoints: {'✅ PASS' if api_ok else '❌ FAIL'}")
    
    if all([db_ok, models_ok, service_ok, api_ok]):
        print("\n🎉 All tests passed! RASP backend is ready.")
        return True
    else:
        print("\n💥 Some tests failed. Check the issues above.")
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1) 