# CyberShield Production Container Startup Script
# This script starts the production containers excluding the mobile module

Write-Host "🚀 Starting CyberShield Production Containers..." -ForegroundColor Green

# Stop any existing containers
Write-Host "🛑 Stopping existing containers..." -ForegroundColor Yellow
docker-compose -f docker-compose.production-no-mobile.yml down

# Remove any existing volumes (optional - uncomment if you want fresh data)
# Write-Host "🗑️ Removing existing volumes..." -ForegroundColor Yellow
# docker-compose -f docker-compose.production-no-mobile.yml down -v

# Build and start containers
Write-Host "🔨 Building and starting containers..." -ForegroundColor Yellow
docker-compose -f docker-compose.production-no-mobile.yml up --build -d

# Wait for containers to start
Write-Host "⏳ Waiting for containers to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

# Check container status
Write-Host "📊 Checking container status..." -ForegroundColor Yellow
docker-compose -f docker-compose.production-no-mobile.yml ps

# Check container logs for any errors
Write-Host "📋 Checking container logs..." -ForegroundColor Yellow
Write-Host "`n🔍 PostgreSQL Logs:" -ForegroundColor Cyan
docker-compose -f docker-compose.production-no-mobile.yml logs postgres

Write-Host "`n🔍 Redis Logs:" -ForegroundColor Cyan
docker-compose -f docker-compose.production-no-mobile.yml logs redis

Write-Host "`n🔍 Backend Logs:" -ForegroundColor Cyan
docker-compose -f docker-compose.production-no-mobile.yml logs backend

Write-Host "`n🔍 Frontend Logs:" -ForegroundColor Cyan
docker-compose -f docker-compose.production-no-mobile.yml logs frontend

Write-Host "`n🔍 Nginx Logs:" -ForegroundColor Cyan
docker-compose -f docker-compose.production-no-mobile.yml logs nginx

# Wait a bit more for services to be ready
Write-Host "⏳ Waiting for services to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

# Test backend health
Write-Host "🏥 Testing backend health..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 10
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Backend is healthy!" -ForegroundColor Green
    } else {
        Write-Host "❌ Backend health check failed with status: $($response.StatusCode)" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Backend health check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test frontend
Write-Host "🌐 Testing frontend..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3000" -TimeoutSec 10
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Frontend is accessible!" -ForegroundColor Green
    } else {
        Write-Host "❌ Frontend check failed with status: $($response.StatusCode)" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Frontend check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test nginx proxy
Write-Host "🌐 Testing nginx proxy..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost" -TimeoutSec 10
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Nginx proxy is working!" -ForegroundColor Green
    } else {
        Write-Host "❌ Nginx proxy check failed with status: $($response.StatusCode)" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Nginx proxy check failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n🎉 CyberShield Production Containers Started!" -ForegroundColor Green
Write-Host "`n📱 Access Points:" -ForegroundColor Cyan
Write-Host "   Frontend: http://localhost:3000" -ForegroundColor White
Write-Host "   Backend API: http://localhost:8000" -ForegroundColor White
Write-Host "   API Docs: http://localhost:8000/docs" -ForegroundColor White
Write-Host "   Nginx Proxy: http://localhost" -ForegroundColor White
Write-Host "   PostgreSQL: localhost:5432" -ForegroundColor White
Write-Host "   Redis: localhost:6379" -ForegroundColor White

Write-Host "`n🔧 Useful Commands:" -ForegroundColor Cyan
Write-Host "   View logs: docker-compose -f docker-compose.production-no-mobile.yml logs -f" -ForegroundColor White
Write-Host "   Stop containers: docker-compose -f docker-compose.production-no-mobile.yml down" -ForegroundColor White
Write-Host "   Restart containers: docker-compose -f docker-compose.production-no-mobile.yml restart" -ForegroundColor White

Write-Host "`n⚠️  If you encounter issues:" -ForegroundColor Yellow
Write-Host "   1. Check container logs above" -ForegroundColor White
Write-Host "   2. Ensure ports 80, 3000, 8000, 5432, 6379 are not in use" -ForegroundColor White
Write-Host "   3. Check Docker Desktop is running" -ForegroundColor White
Write-Host "   4. Restart containers if needed" -ForegroundColor White 