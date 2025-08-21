#!/usr/bin/env python3
"""
Minimal test server with SAST router
"""

import uvicorn
from fastapi import FastAPI
from app.api.v1.endpoints.sast import router as sast_router

app = FastAPI(title="SAST Test Server")

# Mount the SAST router
app.include_router(sast_router, prefix="/api/v1/sast", tags=["SAST"])

if __name__ == "__main__":
    print("Starting SAST test server...")
    print("Available routes:")
    for route in app.routes:
        if hasattr(route, 'path'):
            print(f"  {route.path}")
    
    uvicorn.run(app, host="127.0.0.1", port=8001)
