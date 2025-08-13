# CyberShield Services Startup Script
Write-Host "🚀 Starting CyberShield Services..." -ForegroundColor Green

# Check if containers are running
Write-Host "📦 Checking containers..." -ForegroundColor Yellow
try {
    $containerStatus = docker-compose -f docker-compose.dev.yml ps
    Write-Host "✅ Containers are running" -ForegroundColor Green
} catch {
    Write-Host "❌ Starting containers..." -ForegroundColor Red
    docker-compose -f docker-compose.dev.yml up -d
    Start-Sleep -Seconds 10
}

# Start Backend
Write-Host "🐍 Starting Python Backend..." -ForegroundColor Yellow
Start-Process -FilePath "python" -ArgumentList "backend\main-simple.py" -WindowStyle Minimized
Start-Sleep -Seconds 10

# Start Frontend
Write-Host "⚛️ Starting React Frontend..." -ForegroundColor Yellow
Start-Process -FilePath "cmd" -ArgumentList "/c", "cd frontend", "npm start" -WindowStyle Minimized

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "🎯 Services Starting..." -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "Backend: http://localhost:8000" -ForegroundColor White
Write-Host "Frontend: http://localhost:3000" -ForegroundColor White
Write-Host "API Docs: http://localhost:8000/docs" -ForegroundColor White
Write-Host ""
Write-Host "Demo Accounts:" -ForegroundColor Yellow
Write-Host "  Admin: admin@cybershield.com / password" -ForegroundColor White
Write-Host "  Analyst: analyst@cybershield.com / password" -ForegroundColor White
Write-Host "  User: user@cybershield.com / password" -ForegroundColor White
Write-Host ""
Write-Host "⏳ Waiting for services to be ready..." -ForegroundColor Yellow
Write-Host "=" * 60 -ForegroundColor Cyan

# Wait and check services
Start-Sleep -Seconds 20

# Check backend
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Backend: Running at http://localhost:8000" -ForegroundColor Green
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
Write-Host "💡 Services are starting in background windows" -ForegroundColor Cyan
Write-Host "   Close those windows to stop the services" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
