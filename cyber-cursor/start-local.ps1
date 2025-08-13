# CyberShield Local Development Startup Script
# This script starts PostgreSQL and Redis in Docker, then runs the backend and frontend locally

Write-Host "🚀 Starting CyberShield Local Development Environment..." -ForegroundColor Green

# Check if Docker is running
Write-Host "📋 Checking Docker status..." -ForegroundColor Yellow
try {
    docker info | Out-Null
    Write-Host "✅ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not running. Please start Docker Desktop first." -ForegroundColor Red
    exit 1
}

# Start database services
Write-Host "🗄️ Starting PostgreSQL and Redis..." -ForegroundColor Yellow
docker-compose -f docker-compose.db-only.yml up -d

# Wait for services to be healthy
Write-Host "⏳ Waiting for services to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Check if services are running
Write-Host "🔍 Checking service status..." -ForegroundColor Yellow
$postgresStatus = docker ps --filter "name=cybershield-postgres" --format "table {{.Status}}"
$redisStatus = docker ps --filter "name=cybershield-redis" --format "table {{.Status}}"

Write-Host "PostgreSQL: $postgresStatus" -ForegroundColor Cyan
Write-Host "Redis: $redisStatus" -ForegroundColor Cyan

# Start backend in a new PowerShell window
Write-Host "🐍 Starting Backend API..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD\backend'; Write-Host 'Starting CyberShield Backend...' -ForegroundColor Green; python main.py"

# Wait a moment for backend to start
Start-Sleep -Seconds 5

# Start frontend in a new PowerShell window
Write-Host "⚛️ Starting Frontend..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD\frontend'; Write-Host 'Starting CyberShield Frontend...' -ForegroundColor Green; npm start"

Write-Host "🎉 CyberShield is starting up!" -ForegroundColor Green
Write-Host "📱 Frontend will be available at: http://localhost:3000" -ForegroundColor Cyan
Write-Host "🔌 Backend API will be available at: http://localhost:8000" -ForegroundColor Cyan
Write-Host "🗄️ PostgreSQL is running on: localhost:5432" -ForegroundColor Cyan
Write-Host "🔴 Redis is running on: localhost:6379" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press any key to stop the database services..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Stop database services
Write-Host "🛑 Stopping database services..." -ForegroundColor Yellow
docker-compose -f docker-compose.db-only.yml down

Write-Host "✅ All services stopped. Goodbye!" -ForegroundColor Green
