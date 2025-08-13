#!/usr/bin/env python3
"""
CyberShield Simple Backend Startup Script
Starts the simplified FastAPI backend server without SQLAlchemy
"""

import os
import sys
import uvicorn
from pathlib import Path

# Load environment variables
env_file = Path(__file__).parent / "backend" / "env.dev"
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
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_USER', 'cybershield_user')
os.environ.setdefault('DB_PASSWORD', 'cybershield_password')
os.environ.setdefault('DB_NAME', 'cybershield')
os.environ.setdefault('REDIS_HOST', 'localhost')
os.environ.setdefault('REDIS_PORT', '6379')
os.environ.setdefault('REDIS_PASSWORD', 'redis_password')
os.environ.setdefault('SECRET_KEY', 'dev-secret-key-change-in-production-32-chars-minimum')

print("Starting CyberShield Simple Backend (No SQLAlchemy)...")
print(f"Environment: {os.environ.get('ENVIRONMENT', 'development')}")
print(f"Debug: {os.environ.get('DEBUG', 'true')}")
print(f"Database: {os.environ.get('DB_HOST', 'localhost')}:{os.environ.get('DB_PORT', '5432')}")
print(f"Redis: {os.environ.get('REDIS_HOST', 'localhost')}:{os.environ.get('REDIS_PORT', '6379')}")

if __name__ == "__main__":
    try:
        uvicorn.run(
            "backend.main_simple_no_sqlalchemy:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
    except Exception as e:
        print(f"Failed to start backend: {e}")
        sys.exit(1)
