#!/usr/bin/env python3
"""
CyberShield Complete Startup Script
Starts all services: PostgreSQL, Redis, Backend, and Frontend
"""

import os
import sys
import subprocess
import time
import signal
import threading
from pathlib import Path

class CyberShieldStarter:
    def __init__(self):
        self.processes = []
        self.running = True
        
    def start_containers(self):
        """Start PostgreSQL and Redis containers"""
        print("🚀 Starting CyberShield Infrastructure...")
        
        # Check if Docker is running
        try:
            subprocess.run(["docker", "version"], check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("❌ Docker is not running. Please start Docker Desktop first.")
            return False
        
        # Start containers
        try:
            print("📦 Starting PostgreSQL and Redis containers...")
            subprocess.run([
                "docker-compose", "-f", "docker-compose.dev.yml", "up", "-d"
            ], check=True)
            
            # Wait for containers to be healthy
            print("⏳ Waiting for containers to be ready...")
            time.sleep(10)
            
            # Check container status
            result = subprocess.run([
                "docker-compose", "-f", "docker-compose.dev.yml", "ps"
            ], capture_output=True, text=True)
            
            if "healthy" in result.stdout:
                print("✅ Containers are running and healthy")
                return True
            else:
                print("⚠️  Containers may not be fully ready yet")
                return True
                
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to start containers: {e}")
            return False
    
    def start_backend(self):
        """Start the Python backend"""
        print("🐍 Starting CyberShield Backend...")
        
        backend_dir = Path(__file__).parent / "backend"
        if not backend_dir.exists():
            print(f"❌ Backend directory not found: {backend_dir}")
            return False
        
        try:
            # Install Python dependencies if needed
            requirements_file = backend_dir / "requirements.txt"
            if requirements_file.exists():
                print("📦 Installing Python dependencies...")
                subprocess.run([
                    sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
                ], check=True, capture_output=True)
            
            # Start backend
            print("🚀 Starting FastAPI backend...")
            process = subprocess.Popen([
                sys.executable, "start-backend.py"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.processes.append(("Backend", process))
            print("✅ Backend started successfully")
            return True
            
        except Exception as e:
            print(f"❌ Failed to start backend: {e}")
            return False
    
    def start_frontend(self):
        """Start the React Native frontend"""
        print("⚛️  Starting CyberShield Frontend...")
        
        frontend_dir = Path(__file__).parent / "frontend"
        if not frontend_dir.exists():
            print(f"❌ Frontend directory not found: {frontend_dir}")
            return False
        
        try:
            # Install Node.js dependencies if needed
            node_modules = frontend_dir / "node_modules"
            if not node_modules.exists():
                print("📦 Installing Node.js dependencies...")
                subprocess.run(["npm", "install"], cwd=frontend_dir, check=True, capture_output=True)
            
            # Start frontend
            print("🚀 Starting React Native web development server...")
            process = subprocess.Popen([
                "npm", "start"
            ], cwd=frontend_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.processes.append(("Frontend", process))
            print("✅ Frontend started successfully")
            return True
            
        except Exception as e:
            print(f"❌ Failed to start frontend: {e}")
            return False
    
    def wait_for_services(self):
        """Wait for services to be ready"""
        print("⏳ Waiting for services to be ready...")
        
        # Wait for backend
        backend_ready = False
        for i in range(30):  # Wait up to 30 seconds
            try:
                import requests
                response = requests.get("http://localhost:8000/health", timeout=5)
                if response.status_code == 200:
                    backend_ready = True
                    print("✅ Backend is ready")
                    break
            except:
                pass
            time.sleep(1)
        
        if not backend_ready:
            print("⚠️  Backend may not be fully ready yet")
        
        # Wait for frontend
        frontend_ready = False
        for i in range(30):  # Wait up to 30 seconds
            try:
                import requests
                response = requests.get("http://localhost:3000", timeout=5)
                if response.status_code == 200:
                    frontend_ready = True
                    print("✅ Frontend is ready")
                    break
            except:
                pass
            time.sleep(1)
        
        if not frontend_ready:
            print("⚠️  Frontend may not be fully ready yet")
    
    def show_status(self):
        """Show service status and access information"""
        print("\n" + "="*60)
        print("🎯 CyberShield Services Status")
        print("="*60)
        
        # Check backend
        try:
            import requests
            response = requests.get("http://localhost:8000/health", timeout=5)
            if response.status_code == 200:
                print("✅ Backend: Running at http://localhost:8000")
                print("   📚 API Docs: http://localhost:8000/docs")
            else:
                print("⚠️  Backend: Responding but may have issues")
        except:
            print("❌ Backend: Not responding")
        
        # Check frontend
        try:
            import requests
            response = requests.get("http://localhost:3000", timeout=5)
            if response.status_code == 200:
                print("✅ Frontend: Running at http://localhost:3000")
            else:
                print("⚠️  Frontend: Responding but may have issues")
        except:
            print("❌ Frontend: Not responding")
        
        # Check database
        try:
            import psycopg2
            conn = psycopg2.connect(
                host="localhost",
                port=5432,
                database="cybershield_dev",
                user="cybershield_user",
                password="cybershield_password"
            )
            conn.close()
            print("✅ Database: PostgreSQL is accessible")
        except:
            print("❌ Database: PostgreSQL not accessible")
        
        # Check Redis
        try:
            import redis
            r = redis.Redis(host="localhost", port=6379, password="redis_password", db=0)
            r.ping()
            print("✅ Redis: Cache service is accessible")
        except:
            print("❌ Redis: Cache service not accessible")
        
        print("\n🔐 Demo Accounts:")
        print("   Admin: admin@cybershield.com / password")
        print("   Analyst: analyst@cybershield.com / password")
        print("   User: user@cybershield.com / password")
        
        print("\n📱 Access URLs:")
        print("   Frontend: http://localhost:3000")
        print("   Backend API: http://localhost:8000")
        print("   API Documentation: http://localhost:8000/docs")
        
        print("\n💡 Press Ctrl+C to stop all services")
        print("="*60)
    
    def cleanup(self):
        """Cleanup processes and containers"""
        print("\n🛑 Shutting down CyberShield...")
        
        # Stop processes
        for name, process in self.processes:
            print(f"🛑 Stopping {name}...")
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                process.kill()
        
        # Stop containers
        try:
            subprocess.run([
                "docker-compose", "-f", "docker-compose.dev.yml", "down"
            ], check=True, capture_output=True)
            print("✅ Containers stopped")
        except:
            print("⚠️  Failed to stop containers")
        
        print("👋 CyberShield stopped successfully")
    
    def run(self):
        """Main run method"""
        try:
            # Start infrastructure
            if not self.start_containers():
                return False
            
            # Start services
            if not self.start_backend():
                return False
            
            if not self.start_frontend():
                return False
            
            # Wait for services
            self.wait_for_services()
            
            # Show status
            self.show_status()
            
            # Keep running until interrupted
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n🛑 Received interrupt signal")
        finally:
            self.cleanup()
    
    def signal_handler(self, signum, frame):
        """Handle interrupt signals"""
        self.running = False

def main():
    starter = CyberShieldStarter()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, starter.signal_handler)
    signal.signal(signal.SIGTERM, starter.signal_handler)
    
    # Run the starter
    starter.run()

if __name__ == "__main__":
    main()
