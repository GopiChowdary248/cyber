# Production Startup Script for CyberShield Backend
# This script starts the backend in production mode with PostgreSQL

Write-Host "Starting CyberShield Backend in Production Mode..." -ForegroundColor Green

# Set production environment variables
$env:ENVIRONMENT = "production"
$env:DATABASE_URL = "postgresql+asyncpg://cybershield_user:cybershield_password@localhost:5432/cybershield"
$env:REDIS_URL = "redis://localhost:6379/0"
$env:SECRET_KEY = "your-super-secret-production-key-change-this-immediately"
$env:DEBUG = "false"
$env:LOG_LEVEL = "INFO"

# Navigate to backend directory
Set-Location backend

# Check if PostgreSQL is running
Write-Host "Checking PostgreSQL connection..." -ForegroundColor Yellow
try {
    $pgTest = Invoke-RestMethod -Uri "http://localhost:5432" -Method GET -TimeoutSec 5 -ErrorAction Stop
    Write-Host "PostgreSQL is accessible" -ForegroundColor Green
} catch {
    Write-Host "Warning: PostgreSQL connection test failed. Make sure PostgreSQL is running on localhost:5432" -ForegroundColor Yellow
}

# Start the backend in production mode
Write-Host "Starting FastAPI backend..." -ForegroundColor Green
python main.py 