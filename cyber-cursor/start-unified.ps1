# CyberShield Unified Backend Startup Script
# This script starts the comprehensive backend with all functionalities

Write-Host "🛡️ CyberShield Unified Backend Startup" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Cyan

# Check if Docker is running
Write-Host "🐳 Checking Docker status..." -ForegroundColor Yellow
try {
    docker ps > $null 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Docker is running" -ForegroundColor Green
        
        # Start PostgreSQL and Redis containers
        Write-Host "📊 Starting PostgreSQL and Redis containers..." -ForegroundColor Yellow
        docker-compose up -d postgres redis
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Containers started successfully" -ForegroundColor Green
            Write-Host "⏳ Waiting for services to be ready..." -ForegroundColor Yellow
            Start-Sleep -Seconds 10
        } else {
            Write-Host "⚠️ Container startup failed, continuing with backend..." -ForegroundColor Yellow
        }
    } else {
        Write-Host "⚠️ Docker is not running, continuing without containers..." -ForegroundColor Yellow
    }
} catch {
    Write-Host "⚠️ Docker check failed, continuing without containers..." -ForegroundColor Yellow
}

# Check if Python dependencies are installed
Write-Host "🐍 Checking Python dependencies..." -ForegroundColor Yellow
if (-not (Test-Path "backend\venv")) {
    Write-Host "📦 Creating virtual environment..." -ForegroundColor Yellow
    cd backend
    python -m venv venv
    cd ..
}

# Activate virtual environment and install dependencies
Write-Host "📦 Installing/updating dependencies..." -ForegroundColor Yellow
cd backend
.\venv\Scripts\Activate.ps1

# Install core dependencies first
Write-Host "🔧 Installing core dependencies..." -ForegroundColor Yellow
pip install fastapi uvicorn sqlalchemy asyncpg psycopg2-binary redis python-jose[cryptography] passlib[bcrypt] python-multipart structlog pydantic-settings

# Try to install all dependencies
Write-Host "📚 Installing all dependencies..." -ForegroundColor Yellow
pip install -r requirements_unified.txt

cd ..

# Start the unified backend
Write-Host "🚀 Starting CyberShield Unified Backend..." -ForegroundColor Green
Write-Host "📚 This backend includes ALL functionalities:" -ForegroundColor Cyan
Write-Host "   • SAST (Static Application Security Testing)" -ForegroundColor White
Write-Host "   • DAST (Dynamic Application Security Testing)" -ForegroundColor White
Write-Host "   • RASP (Runtime Application Self-Protection)" -ForegroundColor White
Write-Host "   • Cloud Security" -ForegroundColor White
Write-Host "   • Network Security" -ForegroundColor White
Write-Host "   • Data Security" -ForegroundColor White
Write-Host "   • Threat Intelligence" -ForegroundColor White
Write-Host "   • IAM & Authentication" -ForegroundColor White
Write-Host "   • Compliance Management" -ForegroundColor White
Write-Host "   • Incident Response" -ForegroundColor White
Write-Host "   • AI/ML Security" -ForegroundColor White
Write-Host "   • DevSecOps & CI/CD" -ForegroundColor White
Write-Host "   • SIEM/SOAR" -ForegroundColor White
Write-Host "   • And much more..." -ForegroundColor White

Write-Host ""
Write-Host "🌐 Access URLs:" -ForegroundColor Green
Write-Host "   • API Documentation: http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host "   • ReDoc: http://localhost:8000/redoc" -ForegroundColor Cyan
Write-Host "   • Health Check: http://localhost:8000/health" -ForegroundColor Cyan
Write-Host "   • Root API: http://localhost:8000/" -ForegroundColor Cyan

Write-Host ""
Write-Host "🔄 Starting backend server..." -ForegroundColor Yellow

# Start the unified backend
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD\backend'; .\venv\Scripts\Activate.ps1; python main_unified.py"

Write-Host ""
Write-Host "✅ Backend startup initiated!" -ForegroundColor Green
Write-Host "📱 Frontend is already running at: http://localhost:3000" -ForegroundColor Cyan
Write-Host ""
Write-Host "🎯 You now have access to ALL cybersecurity functionalities!" -ForegroundColor Green
Write-Host ""
Write-Host "Press any key to exit this script..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Write-Host "✅ Startup script completed!" -ForegroundColor Green
