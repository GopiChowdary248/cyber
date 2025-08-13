# CyberShield Comprehensive Integration Startup Script
# Starts PostgreSQL and Redis containers, then runs backend and frontend locally

Write-Host "🚀 Starting CyberShield Comprehensive Integration..." -ForegroundColor Green

# Check if Docker is running
try {
    docker version | Out-Null
    Write-Host "✅ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not running. Please start Docker Desktop first." -ForegroundColor Red
    exit 1
}

# Start database containers only
Write-Host "📦 Starting PostgreSQL and Redis containers..." -ForegroundColor Yellow
docker-compose -f docker-compose.db-only.yml up -d

# Wait for containers to be ready
Write-Host "⏳ Waiting for containers to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

# Check container status
Write-Host "🔍 Checking container status..." -ForegroundColor Yellow
$postgresStatus = docker ps --filter "name=cybershield-postgres" --format "table {{.Status}}"
$redisStatus = docker ps --filter "name=cybershield-redis" --format "table {{.Status}}"

Write-Host "PostgreSQL Status:" -ForegroundColor Cyan
Write-Host $postgresStatus -ForegroundColor White

Write-Host "Redis Status:" -ForegroundColor Cyan
Write-Host $redisStatus -ForegroundColor White

# Check if containers are healthy
$postgresHealthy = docker ps --filter "name=cybershield-postgres" --filter "status=running" --format '{{.Names}}' | Out-String
$redisHealthy = docker ps --filter "name=cybershield-redis" --filter "status=running" --format '{{.Names}}' | Out-String

if ($postgresHealthy.Trim() -and $redisHealthy.Trim()) {
    Write-Host "✅ Database containers are running" -ForegroundColor Green
} else {
    Write-Host "❌ Database containers failed to start properly" -ForegroundColor Red
    exit 1
}

# Install Python dependencies for backend
Write-Host "🐍 Installing Python dependencies..." -ForegroundColor Yellow
cd backend
if (Test-Path "requirements_no_sqlalchemy.txt") {
    pip install -r requirements_no_sqlalchemy.txt
} else {
    pip install fastapi uvicorn asyncpg redis structlog python-jose[cryptography] passlib[bcrypt] python-multipart
}
cd ..

# Start backend in background
Write-Host "🚀 Starting CyberShield Backend (No SQLAlchemy)..." -ForegroundColor Yellow
Start-Process -FilePath "python" -ArgumentList "start-backend-no-sqlalchemy.py" -WindowStyle Minimized

# Wait for backend to start
Write-Host "⏳ Waiting for backend to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Check if backend is running
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Backend is running at http://localhost:8000" -ForegroundColor Green
    } else {
        Write-Host "⚠️ Backend is responding but may have issues" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Backend is not responding yet" -ForegroundColor Red
}

# Start frontend
Write-Host "⚛️ Starting CyberShield Frontend..." -ForegroundColor Yellow
cd frontend

# Check if node_modules exists
if (-not (Test-Path "node_modules")) {
    Write-Host "📦 Installing Node.js dependencies..." -ForegroundColor Yellow
    npm install
}

# Start frontend in background
Write-Host "🚀 Starting React development server..." -ForegroundColor Yellow
Start-Process -FilePath "npm" -ArgumentList "start" -WindowStyle Minimized

cd ..

# Wait for frontend to start
Write-Host "⏳ Waiting for frontend to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

# Check if frontend is running
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3000" -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Frontend is running at http://localhost:3000" -ForegroundColor Green
    } else {
        Write-Host "⚠️ Frontend is responding but may have issues" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Frontend is not responding yet" -ForegroundColor Red
}

# Show final status
Write-Host ""
Write-Host "🎯 CyberShield Integration Status" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

# Check backend
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Backend: Running at http://localhost:8000" -ForegroundColor Green
        Write-Host "   📚 API Docs: http://localhost:8000/docs" -ForegroundColor Cyan
    } else {
        Write-Host "⚠️ Backend: Responding but may have issues" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Backend: Not responding" -ForegroundColor Red
}

# Check frontend
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3000" -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Frontend: Running at http://localhost:3000" -ForegroundColor Green
    } else {
        Write-Host "⚠️ Frontend: Responding but may have issues" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Frontend: Not responding" -ForegroundColor Red
}

# Check database
try {
    $postgresRunning = docker ps --filter "name=cybershield-postgres" --filter "status=running" --format '{{.Names}}' | Out-String
    if ($postgresRunning.Trim()) {
        Write-Host "✅ Database: PostgreSQL is running in container" -ForegroundColor Green
    } else {
        Write-Host "❌ Database: PostgreSQL not running" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Database: Cannot check status" -ForegroundColor Red
}

# Check Redis
try {
    $redisRunning = docker ps --filter "name=cybershield-redis" --filter "status=running" --format '{{.Names}}' | Out-String
    if ($redisRunning.Trim()) {
        Write-Host "✅ Redis: Cache service is running in container" -ForegroundColor Green
    } else {
        Write-Host "❌ Redis: Cache service not running" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Redis: Cannot check status" -ForegroundColor Red
}

Write-Host ""
Write-Host "🔐 Demo Accounts:" -ForegroundColor Cyan
Write-Host "   Admin: admin@cybershield.com / password" -ForegroundColor White
Write-Host "   Analyst: analyst@cybershield.com / password" -ForegroundColor White
Write-Host "   User: user@cybershield.com / password" -ForegroundColor White

Write-Host ""
Write-Host "📱 Access URLs:" -ForegroundColor Cyan
Write-Host "   Frontend: http://localhost:3000" -ForegroundColor White
Write-Host "   Backend API: http://localhost:8000" -ForegroundColor White
Write-Host "   API Documentation: http://localhost:8000/docs" -ForegroundColor White
Write-Host "   Health Check: http://localhost:8000/health" -ForegroundColor White

Write-Host ""
Write-Host "💡 Services are running in background. Use Task Manager to stop them." -ForegroundColor Yellow
Write-Host "   To stop containers: docker-compose -f docker-compose.db-only.yml down" -ForegroundColor Yellow
Write-Host "=================================" -ForegroundColor Green
