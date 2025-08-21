# CyberShield Platform Startup Script
# This script starts both the backend and frontend services

Write-Host "🚀 Starting CyberShield Security Platform..." -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green

# Check if Python is installed
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Python not found. Please install Python 3.8+ and try again." -ForegroundColor Red
    exit 1
}

# Check if Node.js is installed
try {
    $nodeVersion = node --version 2>&1
    Write-Host "✅ Node.js found: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Node.js not found. Please install Node.js 16+ and try again." -ForegroundColor Red
    exit 1
}

# Check if PostgreSQL is running
try {
    $pgStatus = Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq "Running"}
    if ($pgStatus) {
        Write-Host "✅ PostgreSQL service is running" -ForegroundColor Green
    } else {
        Write-Host "⚠️  PostgreSQL service not running. Starting..." -ForegroundColor Yellow
        Start-Service -Name "postgresql*" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
    }
} catch {
    Write-Host "⚠️  Could not verify PostgreSQL status. Please ensure it's running." -ForegroundColor Yellow
}

# Function to start backend
function Start-Backend {
    Write-Host "`n🔧 Starting Backend Service..." -ForegroundColor Blue
    
    # Change to backend directory
    Set-Location "backend"
    
    # Check if virtual environment exists
    if (-not (Test-Path "venv")) {
        Write-Host "📦 Creating virtual environment..." -ForegroundColor Yellow
        python -m venv venv
    }
    
    # Activate virtual environment
    Write-Host "🔌 Activating virtual environment..." -ForegroundColor Yellow
    & "venv\Scripts\Activate.ps1"
    
    # Install/update dependencies
    Write-Host "📥 Installing/updating dependencies..." -ForegroundColor Yellow
    pip install -r requirements.txt
    
    # Start backend server
    Write-Host "🚀 Starting FastAPI backend server..." -ForegroundColor Green
    Start-Process -FilePath "python" -ArgumentList "main.py" -WindowStyle Minimized
    
    # Wait a moment for backend to start
    Start-Sleep -Seconds 3
    
    # Return to root directory
    Set-Location ".."
}

# Function to start frontend
function Start-Frontend {
    Write-Host "`n🎨 Starting Frontend Service..." -ForegroundColor Blue
    
    # Change to frontend directory
    Set-Location "frontend"
    
    # Install/update dependencies
    Write-Host "📥 Installing/updating dependencies..." -ForegroundColor Yellow
    npm install
    
    # Start frontend development server
    Write-Host "🚀 Starting React development server..." -ForegroundColor Green
    Start-Process -FilePath "npm" -ArgumentList "start" -WindowStyle Minimized
    
    # Return to root directory
    Set-Location ".."
}

# Function to check service health
function Test-ServiceHealth {
    Write-Host "`n🏥 Checking Service Health..." -ForegroundColor Blue
    
    # Test backend health
    try {
        $backendHealth = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get -TimeoutSec 10
        Write-Host "✅ Backend is healthy: $($backendHealth.status)" -ForegroundColor Green
    } catch {
        Write-Host "❌ Backend health check failed" -ForegroundColor Red
    }
    
    # Test frontend (give it more time to start)
    Start-Sleep -Seconds 5
    try {
        $frontendHealth = Invoke-WebRequest -Uri "http://localhost:3000" -Method Get -TimeoutSec 10
        Write-Host "✅ Frontend is accessible" -ForegroundColor Green
    } catch {
        Write-Host "❌ Frontend health check failed" -ForegroundColor Red
    }
}

# Function to open services in browser
function Open-ServicesInBrowser {
    Write-Host "`n🌐 Opening Services in Browser..." -ForegroundColor Blue
    
    # Open backend API docs
    Start-Sleep -Seconds 2
    Start-Process "http://localhost:8000/docs"
    Write-Host "📚 Backend API documentation opened" -ForegroundColor Green
    
    # Open frontend
    Start-Sleep -Seconds 3
    Start-Process "http://localhost:3000"
    Write-Host "🎨 Frontend application opened" -ForegroundColor Green
}

# Main execution
try {
    # Start backend
    Start-Backend
    
    # Start frontend
    Start-Frontend
    
    # Wait for services to start
    Write-Host "`n⏳ Waiting for services to start..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    
    # Check health
    Test-ServiceHealth
    
    # Open in browser
    Open-ServicesInBrowser
    
    Write-Host "`n🎉 CyberShield Platform started successfully!" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "Backend API: http://localhost:8000" -ForegroundColor Cyan
    Write-Host "Frontend App: http://localhost:3000" -ForegroundColor Cyan
    Write-Host "API Docs: http://localhost:8000/docs" -ForegroundColor Cyan
    Write-Host "`nPress Ctrl+C to stop all services" -ForegroundColor Yellow
    
    # Keep script running
    while ($true) {
        Start-Sleep -Seconds 10
    }
    
} catch {
    Write-Host "`n❌ Error starting CyberShield Platform: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Please check the logs and try again." -ForegroundColor Red
} finally {
    Write-Host "`n🛑 Stopping CyberShield Platform..." -ForegroundColor Yellow
    
    # Stop backend processes
    Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {$_.ProcessName -eq "python"} | Stop-Process -Force
    
    # Stop frontend processes
    Get-Process -Name "node" -ErrorAction SilentlyContinue | Stop-Process -Force
    
    Write-Host "✅ All services stopped" -ForegroundColor Green
}
