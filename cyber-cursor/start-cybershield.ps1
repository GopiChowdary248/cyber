# CyberShield Startup Script for Windows
# This script starts all CyberShield services

Write-Host "🚀 Starting CyberShield..." -ForegroundColor Green

# Check if Docker is running
try {
    docker version | Out-Null
    Write-Host "✅ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not running. Please start Docker Desktop first." -ForegroundColor Red
    exit 1
}

# Start PostgreSQL and Redis containers
Write-Host "📦 Starting PostgreSQL and Redis containers..." -ForegroundColor Yellow
try {
    docker-compose -f docker-compose.dev.yml up -d
    Write-Host "✅ Containers started successfully" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to start containers" -ForegroundColor Red
    exit 1
}

# Wait for containers to be ready
Write-Host "⏳ Waiting for containers to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

# Check container status
$containerStatus = docker-compose -f docker-compose.dev.yml ps
Write-Host "📊 Container Status:" -ForegroundColor Cyan
Write-Host $containerStatus

# Start Backend (Python)
Write-Host "🐍 Starting Python Backend..." -ForegroundColor Yellow
Start-Process -FilePath "python" -ArgumentList "start-backend.py" -WindowStyle Minimized

# Wait for backend to start
Write-Host "⏳ Waiting for backend to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Start Frontend (React Native)
Write-Host "⚛️ Starting React Native Frontend..." -ForegroundColor Yellow
Start-Process -FilePath "cmd" -ArgumentList "/c", "cd frontend && npm start" -WindowStyle Minimized

# Wait for frontend to start
Write-Host "⏳ Waiting for frontend to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

# Show status
Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "🎯 CyberShield Services Status" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

# Check backend
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Backend: Running at http://localhost:8000" -ForegroundColor Green
        Write-Host "   📚 API Docs: http://localhost:8000/docs" -ForegroundColor Green
    }
} catch {
    Write-Host "❌ Backend: Not responding yet" -ForegroundColor Red
}

# Check frontend
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3000" -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Frontend: Running at http://localhost:3000" -ForegroundColor Green
    }
} catch {
    Write-Host "❌ Frontend: Not responding yet" -ForegroundColor Red
}

Write-Host ""
Write-Host "🔐 Demo Accounts:" -ForegroundColor Yellow
Write-Host "   Admin: admin@cybershield.com / password" -ForegroundColor White
Write-Host "   Analyst: analyst@cybershield.com / password" -ForegroundColor White
Write-Host "   User: user@cybershield.com / password" -ForegroundColor White

Write-Host ""
Write-Host "📱 Access URLs:" -ForegroundColor Yellow
Write-Host "   Frontend: http://localhost:3000" -ForegroundColor White
Write-Host "   Backend API: http://localhost:8000" -ForegroundColor White
Write-Host "   API Documentation: http://localhost:8000/docs" -ForegroundColor White

Write-Host ""
Write-Host "💡 Services are starting in background windows" -ForegroundColor Cyan
Write-Host "   Close those windows to stop the services" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

# Keep script running
Write-Host "Press any key to stop all services..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Stop services
Write-Host ""
Write-Host "🛑 Stopping services..." -ForegroundColor Red

# Stop containers
try {
    docker-compose -f docker-compose.dev.yml down
    Write-Host "✅ Containers stopped" -ForegroundColor Green
} catch {
    Write-Host "⚠️ Failed to stop containers" -ForegroundColor Yellow
}

Write-Host "👋 CyberShield stopped" -ForegroundColor Green
