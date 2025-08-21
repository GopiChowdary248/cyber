#!/usr/bin/env python3
"""
Working SAST Server - Minimal FastAPI server with SAST endpoints
"""

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.api.v1.endpoints.sast import router as sast_router

# Security
security = HTTPBearer()

# Authentication dependency (simplified for testing)
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current authenticated user"""
    try:
        # For testing, accept any valid Bearer token
        if not credentials or not credentials.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"user_id": "authenticated_user", "token": credentials.credentials}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Create FastAPI app
app = FastAPI(
    title="Cyber Cursor SAST Server",
    description="SAST (Static Application Security Testing) Endpoints",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"]
)

# Mount the SAST router with authentication
app.include_router(
    sast_router, 
    prefix="/api/v1/sast", 
    tags=["SAST - Static Application Security Testing"],
    dependencies=[Depends(get_current_user)]
)

# Health check endpoint (no auth required)
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Cyber Cursor SAST Server",
        "version": "2.0.0",
        "endpoints": "/api/v1/sast"
    }

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Cyber Cursor SAST Server",
        "docs": "/docs",
        "health": "/health",
        "sast_endpoints": "/api/v1/sast"
    }

if __name__ == "__main__":
    print("Starting Cyber Cursor SAST Server...")
    print("Available routes:")
    for route in app.routes:
        if hasattr(route, 'path'):
            print(f"  {route.path}")
    
    print(f"\nServer starting on http://localhost:8000")
    print("API Documentation: http://localhost:8000/docs")
    print("SAST Endpoints: http://localhost:8000/api/v1/sast")
    
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
