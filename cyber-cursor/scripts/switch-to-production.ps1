# CyberShield Switch to Production Script (PowerShell)
# This script safely switches from development mode to production mode

Write-Host "🔄 Switching CyberShield to Production Mode..." -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# Function to print colored output
function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Check current status
Write-Status "Checking current service status..."

try {
    $currentStatus = docker-compose ps --format json | ConvertFrom-Json
    if ($currentStatus.Count -gt 0) {
        Write-Status "Found $($currentStatus.Count) running services:"
        foreach ($service in $currentStatus) {
            Write-Host "  - $($service.Service): $($service.State)" -ForegroundColor Gray
        }
    } else {
        Write-Status "No services currently running"
    }
} catch {
    Write-Warning "Could not determine current service status"
}

# Stop current services
Write-Status "Stopping current development services..."
try {
    docker-compose down --remove-orphans
    Write-Success "Development services stopped"
} catch {
    Write-Warning "Error stopping development services or no services were running"
}

# Wait a moment for cleanup
Write-Status "Waiting for cleanup..."
Start-Sleep -Seconds 3

# Check if any containers are still running
$remainingContainers = docker ps -q --filter "name=cybershield-*"
if ($remainingContainers) {
    Write-Warning "Some containers are still running. Force stopping them..."
    docker stop $remainingContainers
    docker rm $remainingContainers
}

# Start production services
Write-Status "Starting production services..."
try {
    # Build production images
    Write-Status "Building production backend image..."
    docker-compose -f docker-compose.production-no-mobile.yml build backend
    
    Write-Status "Building production frontend image..."
    docker-compose -f docker-compose.production-no-mobile.yml build frontend
    
    # Start all production services
    Write-Status "Starting all production services..."
    docker-compose -f docker-compose.production-no-mobile.yml up -d
    
    Write-Success "Production services started successfully"
} catch {
    Write-Error "Failed to start production services"
    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Wait for services to be healthy
Write-Status "Waiting for services to be healthy..."
Write-Status "This may take a few minutes..."

# Wait for PostgreSQL
Write-Status "Waiting for PostgreSQL..."
$timeout = 60
while ($timeout -gt 0) {
    try {
        docker exec cybershield-postgres pg_isready -U cybershield_user -d cybershield | Out-Null
        Write-Success "PostgreSQL is healthy"
        break
    } catch {
        Start-Sleep -Seconds 2
        $timeout -= 2
    }
}

if ($timeout -le 0) {
    Write-Error "PostgreSQL failed to become healthy within 60 seconds"
    exit 1
}

# Wait for Redis
Write-Status "Waiting for Redis..."
$timeout = 30
while ($timeout -gt 0) {
    try {
        docker exec cybershield-redis redis-cli --raw incr ping | Out-Null
        Write-Success "Redis is healthy"
        break
    } catch {
        Start-Sleep -Seconds 2
        $timeout -= 2
    }
}

if ($timeout -le 0) {
    Write-Error "Redis failed to become healthy within 30 seconds"
    exit 1
}

# Wait for Backend
Write-Status "Waiting for Backend API..."
$timeout = 60
while ($timeout -gt 0) {
    try {
        Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing | Out-Null
        Write-Success "Backend API is healthy"
        break
    } catch {
        Start-Sleep -Seconds 2
        $timeout -= 2
    }
}

if ($timeout -le 0) {
    Write-Error "Backend API failed to become healthy within 60 seconds"
    exit 1
}

# Wait for Frontend
Write-Status "Waiting for Frontend..."
$timeout = 60
while ($timeout -gt 0) {
    try {
        Invoke-WebRequest -Uri "http://localhost:3000" -UseBasicParsing | Out-Null
        Write-Success "Frontend is healthy"
        break
    } catch {
        Start-Sleep -Seconds 2
        $timeout -= 2
    }
}

if ($timeout -le 0) {
    Write-Error "Frontend failed to become healthy within 60 seconds"
    exit 1
}

# Show final status
Write-Host ""
Write-Status "Production Service Status:"
Write-Host "===========================" -ForegroundColor Gray
docker-compose -f docker-compose.production-no-mobile.yml ps

Write-Host ""
Write-Status "Service URLs:"
Write-Host "=============" -ForegroundColor Gray
Write-Host "Main Application: http://localhost" -ForegroundColor White
Write-Host "Frontend Direct:  http://localhost:3000" -ForegroundColor White
Write-Host "Backend API:      http://localhost:8000" -ForegroundColor White
Write-Host "API Docs:         http://localhost:8000/docs" -ForegroundColor White

Write-Host ""
Write-Success "🎉 Successfully switched to production mode!"
Write-Host "Your application is now running in production mode without mobile components." -ForegroundColor Cyan

Write-Host ""
Write-Host "Useful Commands:" -ForegroundColor White
Write-Host "================" -ForegroundColor Gray
Write-Host "Check status:     .\scripts\check-production-status.ps1" -ForegroundColor Cyan
Write-Host "View logs:        docker-compose -f docker-compose.production-no-mobile.yml logs -f [service_name]" -ForegroundColor Cyan
Write-Host "Stop services:    .\scripts\stop-production.ps1" -ForegroundColor Cyan
Write-Host "Switch back:      docker-compose up -d" -ForegroundColor Cyan
