# Production Container Startup Script for CyberShield
# This script starts all services in production mode using Docker Compose

Write-Host "Starting CyberShield in Production Mode with Containers..." -ForegroundColor Green

# Check if Docker is running
Write-Host "Checking Docker status..." -ForegroundColor Yellow
try {
    docker version | Out-Null
    Write-Host "Docker is running" -ForegroundColor Green
} catch {
    Write-Host "Error: Docker is not running. Please start Docker Desktop first." -ForegroundColor Red
    exit 1
}

# Check if Docker Compose is available
Write-Host "Checking Docker Compose..." -ForegroundColor Yellow
try {
    docker-compose --version | Out-Null
    Write-Host "Docker Compose is available" -ForegroundColor Green
} catch {
    Write-Host "Error: Docker Compose is not available. Please install Docker Compose." -ForegroundColor Red
    exit 1
}

# Create necessary directories
Write-Host "Creating necessary directories..." -ForegroundColor Yellow
$directories = @(
    "backend/logs",
    "backend/uploads",
    "nginx/ssl"
)

foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "Created directory: $dir" -ForegroundColor Green
    }
}

# Build and start containers
Write-Host "Building and starting containers..." -ForegroundColor Yellow
try {
    # Stop any existing containers
    docker-compose -f docker-compose.production.yml down
    
    # Build and start all services
    docker-compose -f docker-compose.production.yml up --build -d
    
    Write-Host "Containers started successfully!" -ForegroundColor Green
} catch {
    Write-Host "Error starting containers: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Wait for services to be ready
Write-Host "Waiting for services to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

# Check service status
Write-Host "Checking service status..." -ForegroundColor Yellow
try {
    $services = docker-compose -f docker-compose.production.yml ps
    Write-Host $services -ForegroundColor Cyan
} catch {
    Write-Host "Error checking service status" -ForegroundColor Red
}

# Display access information
Write-Host "`n=== CyberShield Production Access Information ===" -ForegroundColor Green
Write-Host "Backend API: http://localhost:8000" -ForegroundColor White
Write-Host "API Documentation: http://localhost:8000/docs" -ForegroundColor White
Write-Host "Frontend (Web): http://localhost:3000" -ForegroundColor White
Write-Host "Mobile App (Expo): http://localhost:19000" -ForegroundColor White
Write-Host "Nginx Proxy: http://localhost:80" -ForegroundColor White
Write-Host "PostgreSQL: localhost:5432" -ForegroundColor White
Write-Host "Redis: localhost:6379" -ForegroundColor White

Write-Host "`n=== Container Management ===" -ForegroundColor Green
Write-Host "View logs: docker-compose -f docker-compose.production.yml logs -f" -ForegroundColor White
Write-Host "Stop services: docker-compose -f docker-compose.production.yml down" -ForegroundColor White
Write-Host "Restart services: docker-compose -f docker-compose.production.yml restart" -ForegroundColor White

Write-Host "`n=== Mobile App Development ===" -ForegroundColor Green
Write-Host "Scan QR code at http://localhost:19000 with Expo Go app" -ForegroundColor White
Write-Host "Or access web version at http://localhost:19002" -ForegroundColor White

Write-Host "`nCyberShield is now running in production mode!" -ForegroundColor Green 