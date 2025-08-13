# CyberShield Production Status Check Script (PowerShell)
# This script checks the status of production services

Write-Host "📊 CyberShield Production Status Check" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

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

# Check if production services are running
Write-Status "Checking production service status..."

try {
    $status = docker-compose -f docker-compose.production-no-mobile.yml ps --format json | ConvertFrom-Json
    $runningServices = $status | Where-Object { $_.State -eq "running" }
    $totalServices = $status.Count
    
    Write-Host ""
    Write-Host "Service Status Summary:" -ForegroundColor White
    Write-Host "=======================" -ForegroundColor Gray
    
    foreach ($service in $status) {
        $serviceName = $service.Service
        $serviceState = $service.State
        $servicePort = $service.Ports
        
        switch ($serviceState) {
            "running" { 
                Write-Host "✅ $serviceName: $serviceState" -ForegroundColor Green
                if ($servicePort) { Write-Host "   Ports: $servicePort" -ForegroundColor Gray }
            }
            "exited" { Write-Host "❌ $serviceName: $serviceState" -ForegroundColor Red }
            "created" { Write-Host "⏳ $serviceName: $serviceState" -ForegroundColor Yellow }
            default { Write-Host "❓ $serviceName: $serviceState" -ForegroundColor Yellow }
        }
    }
    
    Write-Host ""
    Write-Host "Overall Status:" -ForegroundColor White
    Write-Host "===============" -ForegroundColor Gray
    
    if ($runningServices.Count -eq $totalServices) {
        Write-Success "All services are running! ($runningServices.Count/$totalServices)"
    } elseif ($runningServices.Count -gt 0) {
        Write-Warning "Some services are running ($runningServices.Count/$totalServices)"
    } else {
        Write-Error "No services are running (0/$totalServices)"
    }
    
} catch {
    Write-Error "Failed to get service status. Services may not be running."
    Write-Host "To start services, run: .\scripts\start-production.ps1" -ForegroundColor Cyan
    exit 1
}

# Check service health if running
if ($runningServices.Count -gt 0) {
    Write-Host ""
    Write-Status "Checking service health..."
    
    # Check backend health
    try {
        $backendHealth = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 5
        if ($backendHealth.StatusCode -eq 200) {
            Write-Success "Backend API is healthy"
        } else {
            Write-Warning "Backend API returned status: $($backendHealth.StatusCode)"
        }
    } catch {
        Write-Warning "Backend API health check failed"
    }
    
    # Check frontend health
    try {
        $frontendHealth = Invoke-WebRequest -Uri "http://localhost:3000" -UseBasicParsing -TimeoutSec 5
        if ($frontendHealth.StatusCode -eq 200) {
            Write-Success "Frontend is healthy"
        } else {
            Write-Warning "Frontend returned status: $($frontendHealth.StatusCode)"
        }
    } catch {
        Write-Warning "Frontend health check failed"
    }
    
    # Check nginx proxy
    try {
        $nginxHealth = Invoke-WebRequest -Uri "http://localhost" -UseBasicParsing -TimeoutSec 5
        if ($nginxHealth.StatusCode -eq 200) {
            Write-Success "Nginx proxy is healthy"
        } else {
            Write-Warning "Nginx proxy returned status: $($nginxHealth.StatusCode)"
        }
    } catch {
        Write-Warning "Nginx proxy health check failed"
    }
}

# Show resource usage
Write-Host ""
Write-Status "Container Resource Usage:"
Write-Host "==========================" -ForegroundColor Gray

try {
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"
} catch {
    Write-Warning "Could not retrieve resource usage information"
}

# Show service URLs
Write-Host ""
Write-Status "Service URLs:"
Write-Host "=============" -ForegroundColor Gray
Write-Host "Main Application: http://localhost" -ForegroundColor White
Write-Host "Frontend Direct:  http://localhost:3000" -ForegroundColor White
Write-Host "Backend API:      http://localhost:8000" -ForegroundColor White
Write-Host "API Docs:         http://localhost:8000/docs" -ForegroundColor White

Write-Host ""
Write-Host "Useful Commands:" -ForegroundColor White
Write-Host "================" -ForegroundColor Gray
Write-Host "View logs:        docker-compose -f docker-compose.production-no-mobile.yml logs -f [service_name]" -ForegroundColor Cyan
Write-Host "Stop services:    .\scripts\stop-production.ps1" -ForegroundColor Cyan
Write-Host "Restart services: docker-compose -f docker-compose.production-no-mobile.yml restart [service_name]" -ForegroundColor Cyan
