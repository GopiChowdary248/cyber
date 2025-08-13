# CyberShield Production Startup Script (PowerShell)
# This script starts the application in production mode without mobile components

param(
    [switch]$SkipBuild,
    [switch]$Verbose
)

# Set error action preference
$ErrorActionPreference = "Stop"

Write-Host "🚀 Starting CyberShield in Production Mode..." -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

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

# Check if Docker is running
function Test-Docker {
    Write-Status "Checking Docker status..."
    try {
        docker info | Out-Null
        Write-Success "Docker is running"
        return $true
    }
    catch {
        Write-Error "Docker is not running. Please start Docker and try again."
        return $false
    }
}

# Check if Docker Compose is available
function Test-DockerCompose {
    Write-Status "Checking Docker Compose..."
    try {
        docker-compose --version | Out-Null
        Write-Success "Docker Compose is available"
        return $true
    }
    catch {
        Write-Error "Docker Compose is not available. Please install Docker Compose and try again."
        return $false
    }
}

# Stop any existing containers
function Stop-ExistingContainers {
    Write-Status "Stopping any existing containers..."
    try {
        docker-compose -f docker-compose.production-no-mobile.yml down --remove-orphans
        Write-Success "Existing containers stopped"
    }
    catch {
        Write-Warning "No existing containers to stop or error occurred"
    }
}

# Build and start services
function Start-Services {
    Write-Status "Building and starting production services..."
    
    if (-not $SkipBuild) {
        # Build images
        Write-Status "Building backend image..."
        docker-compose -f docker-compose.production-no-mobile.yml build backend
        
        Write-Status "Building frontend image..."
        docker-compose -f docker-compose.production-no-mobile.yml build frontend
    }
    
    # Start all services
    Write-Status "Starting all services..."
    docker-compose -f docker-compose.production-no-mobile.yml up -d
    
    Write-Success "All services started successfully"
}

# Wait for services to be healthy
function Wait-ForHealth {
    Write-Status "Waiting for services to be healthy..."
    
    # Wait for PostgreSQL
    Write-Status "Waiting for PostgreSQL..."
    $timeout = 60
    while ($timeout -gt 0) {
        try {
            docker exec cybershield-postgres pg_isready -U cybershield_user -d cybershield | Out-Null
            Write-Success "PostgreSQL is healthy"
            break
        }
        catch {
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
        }
        catch {
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
        }
        catch {
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
        }
        catch {
            Start-Sleep -Seconds 2
            $timeout -= 2
        }
    }
    
    if ($timeout -le 0) {
        Write-Error "Frontend failed to become healthy within 60 seconds"
        exit 1
    }
}

# Show service status
function Show-Status {
    Write-Status "Service Status:"
    Write-Host "==================" -ForegroundColor Gray
    docker-compose -f docker-compose.production-no-mobile.yml ps
    
    Write-Host ""
    Write-Status "Service URLs:"
    Write-Host "================" -ForegroundColor Gray
    Write-Host "Frontend: http://localhost:3000" -ForegroundColor White
    Write-Host "Backend API: http://localhost:8000" -ForegroundColor White
    Write-Host "Nginx Proxy: http://localhost:80" -ForegroundColor White
    Write-Host "PostgreSQL: localhost:5432" -ForegroundColor White
    Write-Host "Redis: localhost:6379" -ForegroundColor White
    
    Write-Host ""
    Write-Status "Container Logs:"
    Write-Host "===================" -ForegroundColor Gray
    Write-Host "View logs with: docker-compose -f docker-compose.production-no-mobile.yml logs -f [service_name]" -ForegroundColor White
    Write-Host "Stop services with: docker-compose -f docker-compose.production-no-mobile.yml down" -ForegroundColor White
}

# Main execution
function Main {
    if (-not (Test-Docker)) { exit 1 }
    if (-not (Test-DockerCompose)) { exit 1 }
    
    Stop-ExistingContainers
    Start-Services
    Wait-ForHealth
    Show-Status
    
    Write-Host ""
    Write-Success "🎉 CyberShield is now running in production mode!"
    Write-Success "Access your application at: http://localhost"
}

# Run main function
Main
