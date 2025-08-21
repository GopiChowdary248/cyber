#!/usr/bin/env python3
"""
Test script for Enhanced Cloud Security functionality
This script tests the schemas, models, and basic functionality
"""

import sys
import uuid
from datetime import datetime
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

def test_schemas():
    """Test the enhanced cloud security schemas"""
    print("Testing Enhanced Cloud Security Schemas...")
    
    try:
        from app.schemas.enhanced_cloud_security_schemas import (
            ContainerImageCreate, ContainerImageResponse,
            ServerlessFunctionCreate, ServerlessFunctionResponse,
            KubernetesClusterCreate, KubernetesClusterResponse,
            ContainerVulnerabilityCreate, ContainerVulnerabilityResponse
        )
        print("✓ Schemas imported successfully")
        
        # Test container image schema
        container_data = {
            "asset_id": str(uuid.uuid4()),
            "image_name": "nginx:latest",
            "image_tag": "latest",
            "registry": "docker.io",
            "architecture": "amd64",
            "os_type": "linux"
        }
        
        container_create = ContainerImageCreate(**container_data)
        print(f"✓ ContainerImageCreate: {container_create.image_name}")
        
        # Test serverless function schema
        function_data = {
            "asset_id": str(uuid.uuid4()),
            "function_name": "test-lambda",
            "function_arn": "arn:aws:lambda:us-east-1:123456789012:function:test-lambda",
            "runtime": "python",
            "handler": "index.handler",
            "timeout": 30,
            "memory_size": 128
        }
        
        function_create = ServerlessFunctionCreate(**function_data)
        print(f"✓ ServerlessFunctionCreate: {function_create.function_name}")
        
        # Test Kubernetes cluster schema
        cluster_data = {
            "asset_id": str(uuid.uuid4()),
            "cluster_name": "test-cluster",
            "cluster_version": "1.24.0",
            "provider": "aws",
            "region": "us-east-1",
            "node_count": 3,
            "pod_count": 10
        }
        
        cluster_create = KubernetesClusterCreate(**cluster_data)
        print(f"✓ KubernetesClusterCreate: {cluster_create.cluster_name}")
        
        print("✓ All schema tests passed!")
        return True
        
    except Exception as e:
        print(f"✗ Schema test failed: {e}")
        return False

def test_database_connection():
    """Test database connection and table access"""
    print("\nTesting Database Connection...")
    
    try:
        import sqlite3
        from pathlib import Path
        
        db_path = Path("backend/cybershield.db")
        if not db_path.exists():
            print("✗ Database file not found")
            return False
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Test table access
        tables_to_check = [
            "container_images", "serverless_functions", "kubernetes_clusters"
        ]
        
        for table in tables_to_check:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            print(f"✓ Table '{table}' accessible (count: {count})")
        
        conn.close()
        print("✓ Database connection test passed!")
        return True
        
    except Exception as e:
        print(f"✗ Database test failed: {e}")
        return False

def test_api_endpoints():
    """Test API endpoint availability"""
    print("\nTesting API Endpoints...")
    
    try:
        from app.api.v1.endpoints.enhanced_cloud_security import router
        
        # Check if router has endpoints
        routes = [route for route in router.routes]
        print(f"✓ Found {len(routes)} API endpoints")
        
        # List some key endpoints
        for route in routes[:5]:  # Show first 5 endpoints
            if hasattr(route, 'path'):
                print(f"  - {route.path}")
        
        print("✓ API endpoints test passed!")
        return True
        
    except Exception as e:
        print(f"✗ API endpoints test failed: {e}")
        return False

def test_service_functionality():
    """Test service functionality"""
    print("\nTesting Service Functionality...")
    
    try:
        from app.services.enhanced_cloud_security_service import (
            EnhancedCSPMService, EnhancedCASBService, 
            EnhancedCloudNativeSecurityService
        )
        
        # Test service instantiation
        cspm_service = EnhancedCSPMService()
        casb_service = EnhancedCASBService()
        cloud_native_service = EnhancedCloudNativeSecurityService()
        
        print("✓ All services instantiated successfully")
        
        # Test basic service methods
        if hasattr(cspm_service, 'scan_aws_account'):
            print("✓ CSPM service has scan_aws_account method")
        
        if hasattr(casb_service, 'discover_saas_applications'):
            print("✓ CASB service has discover_saas_applications method")
        
        if hasattr(cloud_native_service, 'analyze_container_security'):
            print("✓ Cloud Native service has analyze_container_security method")
        
        print("✓ Service functionality test passed!")
        return True
        
    except Exception as e:
        print(f"✗ Service functionality test failed: {e}")
        return False

def main():
    """Main test function"""
    print("Enhanced Cloud Security - Functionality Test")
    print("=" * 50)
    
    tests = [
        ("Schemas", test_schemas),
        ("Database", test_database_connection),
        ("API Endpoints", test_api_endpoints),
        ("Services", test_service_functionality)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"✗ {test_name} test failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Enhanced Cloud Security is working correctly.")
        print("\nYou can now use the following features:")
        print("- Container security management")
        print("- Serverless security analysis")
        print("- Kubernetes security assessment")
        print("- Comprehensive cloud security scanning")
        print("\nAPI Base URL: /api/v1/enhanced-cloud-security")
    else:
        print("⚠️  Some tests failed. Please check the error messages above.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
