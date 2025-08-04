#!/usr/bin/env python3
"""
Test script to check DAST router import and mounting
"""

import sys
import os

# Add the backend directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

def test_dast_import():
    """Test if DAST router can be imported"""
    try:
        print("Testing DAST router import...")
        from app.api.v1.endpoints.dast import router as dast_router
        print(f"✅ DAST router imported successfully")
        print(f"Router type: {type(dast_router)}")
        print(f"Router routes: {len(dast_router.routes)}")
        
        # Print all routes
        for route in dast_router.routes:
            print(f"  - {route.path} -> {route.name}")
        
        return True
    except Exception as e:
        print(f"❌ Failed to import DAST router: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_dast_mounting():
    """Test if DAST router can be mounted in FastAPI"""
    try:
        print("\nTesting DAST router mounting...")
        from fastapi import FastAPI
        from app.api.v1.endpoints.dast import router as dast_router
        
        app = FastAPI()
        app.include_router(dast_router, prefix="/api/v1/dast", tags=["DAST"])
        
        print(f"✅ DAST router mounted successfully")
        print(f"App routes: {len(app.routes)}")
        
        # Print all app routes
        for route in app.routes:
            print(f"  - {route.path} -> {route.name}")
        
        return True
    except Exception as e:
        print(f"❌ Failed to mount DAST router: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("=== DAST Router Import Test ===")
    
    # Test import
    import_success = test_dast_import()
    
    # Test mounting
    mount_success = test_dast_mounting()
    
    if import_success and mount_success:
        print("\n✅ All tests passed!")
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1) 