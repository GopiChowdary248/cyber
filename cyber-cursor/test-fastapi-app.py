#!/usr/bin/env python3
"""
Test script to check FastAPI app structure
"""

import sys
import os

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

def test_fastapi_app():
    """Test the FastAPI app structure"""
    try:
        print("Testing FastAPI app import...")
        from main import app
        
        print("✅ FastAPI app imported successfully!")
        print(f"App: {app}")
        print(f"App routes: {len(app.routes)}")
        
        # Print all routes
        print("\n📋 All app routes:")
        for route in app.routes:
            if hasattr(route, 'path'):
                print(f"  - {route.path} [{', '.join(route.methods)}]")
            elif hasattr(route, 'routes'):
                print(f"  - Router with {len(route.routes)} routes")
                for sub_route in route.routes:
                    if hasattr(sub_route, 'path'):
                        print(f"    - {sub_route.path} [{', '.join(sub_route.methods)}]")
        
        # Check if auth router is included
        auth_routes = []
        for route in app.routes:
            if hasattr(route, 'routes'):
                for sub_route in route.routes:
                    if hasattr(sub_route, 'path') and '/login' in sub_route.path:
                        auth_routes.append(sub_route.path)
        
        if auth_routes:
            print(f"\n✅ Auth routes found: {auth_routes}")
        else:
            print("\n❌ No auth routes found!")
            
        return True
        
    except Exception as e:
        print(f"❌ FastAPI app import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_fastapi_app() 