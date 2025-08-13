#!/usr/bin/env python3
"""
Debug script to check configuration loading
"""

import sys
import os
from pathlib import Path

# Add the backend directory to the Python path
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

from app.core.config import settings

print("=== Configuration Debug ===")
print(f"Database URL: {settings.database.DATABASE_URL}")
print(f"Environment: {os.getenv('ENVIRONMENT', 'Not set')}")
print(f"Database URL from env: {os.getenv('DATABASE_URL', 'Not set')}")

# Check if there are any other config files
print("\n=== Checking for other config files ===")
config_files = list(Path(".").glob("*.env*"))
for config_file in config_files:
    print(f"Found config file: {config_file}")
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                content = f.read()
                if 'DATABASE_URL' in content:
                    print(f"  Contains DATABASE_URL: {config_file}")
        except Exception as e:
            print(f"  Error reading {config_file}: {e}")
