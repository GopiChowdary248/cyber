#!/usr/bin/env python3
"""
CyberShield Frontend Startup Script
Starts the React Native web development server
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def start_frontend():
    """Start the React Native web frontend"""
    frontend_dir = Path(__file__).parent / "frontend"
    
    if not frontend_dir.exists():
        print(f"Frontend directory not found: {frontend_dir}")
        return False
    
    print("Starting CyberShield Frontend...")
    print(f"Frontend directory: {frontend_dir}")
    
    # Change to frontend directory
    os.chdir(frontend_dir)
    
    # Check if node_modules exists
    if not (frontend_dir / "node_modules").exists():
        print("Installing dependencies...")
        try:
            subprocess.run(["npm", "install"], check=True, capture_output=True)
            print("Dependencies installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install dependencies: {e}")
            return False
    
    # Start the development server
    print("Starting development server...")
    try:
        subprocess.run(["npm", "start"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to start frontend: {e}")
        return False
    except KeyboardInterrupt:
        print("\nFrontend stopped by user")
        return True
    
    return True

if __name__ == "__main__":
    try:
        start_frontend()
    except Exception as e:
        print(f"Error starting frontend: {e}")
        sys.exit(1)
