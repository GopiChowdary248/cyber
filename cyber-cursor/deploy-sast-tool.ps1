#!/usr/bin/env pwsh
<#
.SYNOPSIS
    SAST Tool Deployment Script

.DESCRIPTION
    This script deploys the comprehensive SAST tool including:
    - Backend API with SAST scanning engine
    - Frontend React Native dashboard
    - PostgreSQL database
    - Redis cache
    - Monitoring stack (Prometheus, Grafana)
    - Logging stack (ELK)
    - DevSecOps integrations
#>

param(
    [string]$Environment = "development",
    [switch]$SkipTests,
    [switch]$SkipFrontend,
    [switch]$SkipMonitoring,
    [switch]$Force
)

# Configuration
$Config = @{
    Development = @{
        DockerComposeFile = "docker-compose.sast.yml"
        BackendPort = 8000
        FrontendPort = 3000
        DatabasePort = 5432
        RedisPort = 6379
        PrometheusPort = 9090
        GrafanaPort = 3001
        ElasticsearchPort = 9200
        KibanaPort = 5601
    }
    Production = @{
        DockerComposeFile = "docker-compose.sast.prod.yml"
        BackendPort = 8000
        FrontendPort = 3000
        DatabasePort = 5432
        RedisPort = 6379
        PrometheusPort = 9090
        GrafanaPort = 3001
        ElasticsearchPort = 9200
        KibanaPort = 5601
    }
}

$CurrentConfig = $Config[$Environment]

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
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

function Test-Prerequisites {
    Write-Info "Checking prerequisites..."
    
    # Check Docker
    try {
        $DockerVersion = docker --version
        Write-Success "Docker found: $DockerVersion"
    }
    catch {
        Write-Error "Docker not found. Please install Docker Desktop."
        exit 1
    }
    
    # Check Docker Compose
    try {
        $ComposeVersion = docker-compose --version
        Write-Success "Docker Compose found: $ComposeVersion"
    }
    catch {
        Write-Error "Docker Compose not found. Please install Docker Compose."
        exit 1
    }
    
    # Check if ports are available
    $Ports = @($CurrentConfig.BackendPort, $CurrentConfig.FrontendPort, $CurrentConfig.DatabasePort)
    foreach ($Port in $Ports) {
        try {
            $Connection = Test-NetConnection -ComputerName localhost -Port $Port -WarningAction SilentlyContinue
            if ($Connection.TcpTestSucceeded) {
                Write-Warning "Port $Port is already in use. Please stop the service using this port."
                if (-not $Force) {
                    exit 1
                }
            }
        }
        catch {
            Write-Success "Port $Port is available"
        }
    }
}

function Initialize-Environment {
    Write-Info "Initializing environment..."
    
    # Create necessary directories
    $Directories = @(
        "logs",
        "data/postgres",
        "data/redis",
        "data/elasticsearch",
        "uploads",
        "reports"
    )
    
    foreach ($Dir in $Directories) {
        if (-not (Test-Path $Dir)) {
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null
            Write-Success "Created directory: $Dir"
        }
    }
    
    # Create .env file if it doesn't exist
    if (-not (Test-Path ".env")) {
        Copy-Item "env.example" ".env" -Force
        Write-Success "Created .env file from template"
    }
}

function Build-Images {
    Write-Info "Building Docker images..."
    
    try {
        # Build backend image
        Write-Info "Building backend image..."
        docker build -t cybershield-sast-backend ./backend
        
        # Build frontend image
        if (-not $SkipFrontend) {
            Write-Info "Building frontend image..."
            docker build -t cybershield-sast-frontend ./frontend
        }
        
        Write-Success "All images built successfully"
    }
    catch {
        Write-Error "Failed to build images: $($_.Exception.Message)"
        exit 1
    }
}

function Start-Services {
    Write-Info "Starting SAST tool services..."
    
    try {
        # Start core services
        docker-compose -f $CurrentConfig.DockerComposeFile up -d postgres redis
        
        # Wait for database to be ready
        Write-Info "Waiting for database to be ready..."
        Start-Sleep -Seconds 10
        
        # Start backend
        docker-compose -f $CurrentConfig.DockerComposeFile up -d sast_backend
        
        # Wait for backend to be ready
        Write-Info "Waiting for backend to be ready..."
        Start-Sleep -Seconds 15
        
        # Start frontend
        if (-not $SkipFrontend) {
            docker-compose -f $CurrentConfig.DockerComposeFile up -d sast_frontend
        }
        
        # Start monitoring stack
        if (-not $SkipMonitoring) {
            Write-Info "Starting monitoring stack..."
            docker-compose -f $CurrentConfig.DockerComposeFile up -d prometheus grafana elasticsearch kibana
        }
        
        # Start SAST worker
        docker-compose -f $CurrentConfig.DockerComposeFile up -d sast_worker
        
        Write-Success "All services started successfully"
    }
    catch {
        Write-Error "Failed to start services: $($_.Exception.Message)"
        exit 1
    }
}

function Test-Services {
    if ($SkipTests) {
        Write-Warning "Skipping service tests"
        return
    }
    
    Write-Info "Testing services..."
    
    $Services = @(
        @{ Name = "Backend API"; Url = "http://localhost:$($CurrentConfig.BackendPort)/health" },
        @{ Name = "Frontend"; Url = "http://localhost:$($CurrentConfig.FrontendPort)"; Skip = $SkipFrontend },
        @{ Name = "Database"; Url = "http://localhost:$($CurrentConfig.DatabasePort)"; Skip = $false },
        @{ Name = "Prometheus"; Url = "http://localhost:$($CurrentConfig.PrometheusPort)"; Skip = $SkipMonitoring },
        @{ Name = "Grafana"; Url = "http://localhost:$($CurrentConfig.GrafanaPort)"; Skip = $SkipMonitoring }
    )
    
    foreach ($Service in $Services) {
        if ($Service.Skip) {
            Write-Warning "Skipping $($Service.Name) test"
            continue
        }
        
        try {
            $Response = Invoke-WebRequest -Uri $Service.Url -Method Get -TimeoutSec 10 -ErrorAction Stop
            if ($Response.StatusCode -eq 200) {
                Write-Success "$($Service.Name) is running"
            } else {
                Write-Warning "$($Service.Name) returned status: $($Response.StatusCode)"
            }
        }
        catch {
            Write-Error "$($Service.Name) is not accessible: $($_.Exception.Message)"
        }
    }
}

function Initialize-Database {
    Write-Info "Initializing database..."
    
    try {
        # Wait for database to be ready
        Start-Sleep -Seconds 5
        
        # Run database migrations
        docker-compose -f $CurrentConfig.DockerComposeFile exec sast_backend python -c "
from app.database import init_db
init_db()
print('Database initialized successfully')
"
        
        Write-Success "Database initialized successfully"
    }
    catch {
        Write-Error "Failed to initialize database: $($_.Exception.Message)"
    }
}

function Show-Status {
    Write-Info "SAST Tool Status:"
    Write-Host "=" * 50 -ForegroundColor Cyan
    
    # Show running containers
    Write-Info "Running containers:"
    docker-compose -f $CurrentConfig.DockerComposeFile ps
    
    Write-Host "`n" -ForegroundColor White
    Write-Info "Service URLs:"
    Write-Host "  Backend API: http://localhost:$($CurrentConfig.BackendPort)" -ForegroundColor Green
    if (-not $SkipFrontend) {
        Write-Host "  Frontend: http://localhost:$($CurrentConfig.FrontendPort)" -ForegroundColor Green
    }
    Write-Host "  Database: localhost:$($CurrentConfig.DatabasePort)" -ForegroundColor Green
    if (-not $SkipMonitoring) {
        Write-Host "  Prometheus: http://localhost:$($CurrentConfig.PrometheusPort)" -ForegroundColor Green
        Write-Host "  Grafana: http://localhost:$($CurrentConfig.GrafanaPort)" -ForegroundColor Green
        Write-Host "  Kibana: http://localhost:$($CurrentConfig.KibanaPort)" -ForegroundColor Green
    }
    
    Write-Host "`n" -ForegroundColor White
    Write-Info "Next steps:"
    Write-Host "  1. Access the frontend at http://localhost:$($CurrentConfig.FrontendPort)" -ForegroundColor Yellow
    Write-Host "  2. Run end-to-end tests: .\test-app\sast-end-to-end-test.ps1" -ForegroundColor Yellow
    Write-Host "  3. Check logs: docker-compose -f $($CurrentConfig.DockerComposeFile) logs" -ForegroundColor Yellow
}

function Stop-Services {
    Write-Info "Stopping SAST tool services..."
    
    try {
        docker-compose -f $CurrentConfig.DockerComposeFile down
        Write-Success "Services stopped successfully"
    }
    catch {
        Write-Error "Failed to stop services: $($_.Exception.Message)"
    }
}

function Cleanup-Environment {
    Write-Info "Cleaning up environment..."
    
    try {
        # Stop and remove containers
        docker-compose -f $CurrentConfig.DockerComposeFile down -v
        
        # Remove images
        docker rmi cybershield-sast-backend cybershield-sast-frontend -f
        
        # Remove data directories
        Remove-Item -Path "data" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "logs" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "uploads" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "reports" -Recurse -Force -ErrorAction SilentlyContinue
        
        Write-Success "Environment cleaned up successfully"
    }
    catch {
        Write-Error "Failed to cleanup environment: $($_.Exception.Message)"
    }
}

# Main execution
try {
    Write-Host "🚀 SAST Tool Deployment Script" -ForegroundColor Green
    Write-Host "Environment: $Environment" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    # Check prerequisites
    Test-Prerequisites
    
    # Initialize environment
    Initialize-Environment
    
    # Build images
    Build-Images
    
    # Start services
    Start-Services
    
    # Initialize database
    Initialize-Database
    
    # Test services
    Test-Services
    
    # Show status
    Show-Status
    
    Write-Success "SAST Tool deployment completed successfully!"
}
catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
    exit 1
} 