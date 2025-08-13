#!/usr/bin/env python3
"""
CyberShield Backend Startup Script
Starts the FastAPI backend server with proper environment configuration
"""

import os
import sys
import uvicorn
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_dir))

# Load environment variables
env_file = backend_dir / "env.dev"
if env_file.exists():
    print(f"Loading environment from {env_file}")
    with open(env_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key] = value

# Set default environment variables if not set
os.environ.setdefault('ENVIRONMENT', 'development')
os.environ.setdefault('DEBUG', 'true')
os.environ.setdefault('DATABASE_URL', 'postgresql+asyncpg://cybershield_user:cybershield_password@localhost:5432/cybershield_dev')
os.environ.setdefault('REDIS_URL', 'redis://:redis_password@localhost:6379/0')
os.environ.setdefault('SECRET_KEY', 'dev-secret-key-change-in-production-32-chars-minimum')

print("Starting CyberShield Backend...")
print(f"Environment: {os.environ.get('ENVIRONMENT', 'development')}")
print(f"Debug: {os.environ.get('DEBUG', 'true')}")
print(f"Database: {os.environ.get('DATABASE_URL', 'Not set')}")

if __name__ == "__main__":
    try:
        uvicorn.run(
            "backend.main:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
    except Exception as e:
        print(f"Failed to start backend: {e}")
        sys.exit(1)
