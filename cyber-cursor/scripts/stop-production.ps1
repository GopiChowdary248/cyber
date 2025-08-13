# CyberShield Production Stop Script (PowerShell)
# This script stops the production services

Write-Host "🛑 Stopping CyberShield Production Services..." -ForegroundColor Red
Write-Host "=============================================" -ForegroundColor Red

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

# Stop all production services
Write-Status "Stopping all production services..."
try {
    docker-compose -f docker-compose.production-no-mobile.yml down --remove-orphans
    Write-Success "All production services stopped successfully"
}
catch {
    Write-Warning "Error stopping services or no services were running"
}

# Remove any dangling containers
Write-Status "Cleaning up any remaining containers..."
try {
    docker container prune -f
    Write-Success "Container cleanup completed"
}
catch {
    Write-Warning "Error during container cleanup"
}

# Show final status
Write-Status "Current Docker containers:"
docker ps -a

Write-Host ""
Write-Success "🎉 Production services have been stopped!"
Write-Host "To start them again, run: .\scripts\start-production.ps1" -ForegroundColor Cyan
