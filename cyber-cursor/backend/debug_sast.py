#!/usr/bin/env python3
"""
Debug script to test SAST router import and mounting
"""

try:
    print("Testing SAST router import...")
    from app.api.v1.endpoints.sast import router
    print("✓ SAST router imported successfully")
    
    print(f"Router has {len(router.routes)} routes")
    
    print("Testing router mounting...")
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(router, prefix="/api/v1/sast", tags=["SAST"])
    print("✓ Router mounted successfully")
    
    print("Available routes:")
    for route in app.routes:
        if hasattr(route, 'path'):
            print(f"  {route.path}")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
