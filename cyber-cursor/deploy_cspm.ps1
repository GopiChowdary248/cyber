# Simple CSPM Deployment Script
Write-Host "Starting CSPM deployment..." -ForegroundColor Green

# Check if Docker is running
try {
    docker info | Out-Null
    Write-Host "Docker is running" -ForegroundColor Green
}
catch {
    Write-Host "Docker is not running. Please start Docker Desktop first." -ForegroundColor Red
    exit 1
}

# Create .env file if it doesn't exist
if (-not (Test-Path ".env.cspm")) {
    Write-Host "Creating .env.cspm file..." -ForegroundColor Yellow
    $envContent = @"
POSTGRES_PASSWORD=cybershield123
POSTGRES_DB=cybershield_cspm
REDIS_PASSWORD=redis123
SECRET_KEY=secret123
ENVIRONMENT=development
"@
    $envContent | Out-File -FilePath ".env.cspm" -Encoding UTF8
    Write-Host ".env.cspm created" -ForegroundColor Green
}

# Create directories
Write-Host "Creating directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Path "logs" -Force | Out-Null
New-Item -ItemType Directory -Path "policies" -Force | Out-Null
New-Item -ItemType Directory -Path "monitoring" -Force | Out-Null

# Start services
Write-Host "Starting services with Docker Compose..." -ForegroundColor Yellow
docker-compose -f docker-compose.cspm.yml up -d

Write-Host "CSPM deployment started!" -ForegroundColor Green
Write-Host "Check services with: docker-compose -f docker-compose.cspm.yml ps" -ForegroundColor Cyan
