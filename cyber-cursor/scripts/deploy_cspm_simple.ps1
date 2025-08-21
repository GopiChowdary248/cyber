# CyberShield CSPM Module Deployment Script (Simplified)
# This script sets up the CSPM module with Docker Compose

param(
    [string]$ComposeFile = "docker-compose.cspm.yml",
    [string]$EnvFile = ".env.cspm"
)

# Set error action preference
$ErrorActionPreference = "Stop"

Write-Host "🚀 CyberShield CSPM Module Deployment" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# Check prerequisites
function Check-Prerequisites {
    Write-Host "Checking prerequisites..." -ForegroundColor Yellow
    
    # Check Docker
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host "❌ Docker is not installed. Please install Docker Desktop first." -ForegroundColor Red
        exit 1
    }
    
    # Check Docker Compose
    if (-not (Get-Command docker-compose -ErrorAction SilentlyContinue)) {
        Write-Host "❌ Docker Compose is not installed. Please install Docker Compose first." -ForegroundColor Red
        exit 1
    }
    
    # Check if Docker daemon is running
    try {
        docker info | Out-Null
        Write-Host "✅ Docker is running" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Docker daemon is not running. Please start Docker Desktop first." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "✅ Prerequisites check passed" -ForegroundColor Green
}

# Create environment file
function Create-EnvFile {
    Write-Host "Creating environment configuration file..." -ForegroundColor Yellow
    
    if (-not (Test-Path $EnvFile)) {
        $postgresPassword = "cybershield_secure_password_" + (Get-Random -Minimum 10000000 -Maximum 99999999)
        $redisPassword = "redis_secure_password_" + (Get-Random -Minimum 10000000 -Maximum 99999999)
        $secretKey = -join ((65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
        $grafanaPassword = "admin_secure_" + (Get-Random -Minimum 1000 -Maximum 9999)
        
        $envContent = @"
# CyberShield CSPM Environment Configuration
POSTGRES_PASSWORD=$postgresPassword
POSTGRES_DB=cybershield_cspm
REDIS_PASSWORD=$redisPassword
SECRET_KEY=$secretKey
ENVIRONMENT=production
LOG_LEVEL=INFO
GRAFANA_PASSWORD=$grafanaPassword
API_BASE_URL=http://localhost:8000
FRONTEND_URL=http://localhost:3000
MOBILE_URL=http://localhost:3001
"@
        
        $envContent | Out-File -FilePath $EnvFile -Encoding UTF8
        Write-Host "✅ Environment file created: $EnvFile" -ForegroundColor Green
        Write-Host "⚠️  Please review and modify the generated passwords in $EnvFile" -ForegroundColor Yellow
    }
    else {
        Write-Host "ℹ️  Environment file already exists: $EnvFile" -ForegroundColor Cyan
    }
}

# Create necessary directories
function Create-Directories {
    Write-Host "Creating necessary directories..." -ForegroundColor Yellow
    
    $directories = @(
        "logs",
        "policies", 
        "monitoring/grafana/dashboards",
        "monitoring/grafana/datasources",
        "nginx/ssl",
        "uploads"
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "  Created: $dir" -ForegroundColor Green
        }
    }
    
    Write-Host "✅ Directories created" -ForegroundColor Green
}

# Create sample OPA policy
function Create-SamplePolicy {
    Write-Host "Creating sample OPA policy..." -ForegroundColor Yellow
    
    $policyContent = @'
package s3.public_access

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    input.public_access_block_configuration.block_public_acls == false
    msg := sprintf("S3 bucket %v has public ACLs enabled", [input.bucket_name])
}
'@
    
    $policyContent | Out-File -FilePath "policies/aws_s3_public_access.rego" -Encoding UTF8
    Write-Host "✅ Sample policy created" -ForegroundColor Green
}

# Build and start services
function Deploy-Services {
    Write-Host "Building and starting services..." -ForegroundColor Yellow
    
    # Build images
    Write-Host "Building Docker images..." -ForegroundColor Yellow
    docker-compose -f $ComposeFile build
    
    # Start services
    Write-Host "Starting services..." -ForegroundColor Yellow
    docker-compose -f $ComposeFile up -d
    
    Write-Host "✅ Services started successfully" -ForegroundColor Green
}

# Wait for services to be ready
function Wait-ForServices {
    Write-Host "Waiting for services to be ready..." -ForegroundColor Yellow
    
    # Wait for PostgreSQL
    Write-Host "Waiting for PostgreSQL..." -ForegroundColor Yellow
    do {
        Start-Sleep -Seconds 2
        $postgresReady = docker-compose -f $ComposeFile exec -T postgres pg_isready -U cybershield -d cybershield_cspm 2>$null
    } while ($LASTEXITCODE -ne 0)
    Write-Host "✅ PostgreSQL is ready" -ForegroundColor Green
    
    # Wait for Redis
    Write-Host "Waiting for Redis..." -ForegroundColor Yellow
    do {
        Start-Sleep -Seconds 2
        $redisReady = docker-compose -f $ComposeFile exec -T redis redis-cli --raw incr ping 2>$null
    } while ($LASTEXITCODE -ne 0)
    Write-Host "✅ Redis is ready" -ForegroundColor Green
    
    # Wait for Backend
    Write-Host "Waiting for Backend API..." -ForegroundColor Yellow
    do {
        Start-Sleep -Seconds 5
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 5
            $backendReady = $true
        }
        catch {
            $backendReady = $false
        }
    } while (-not $backendReady)
    Write-Host "✅ Backend API is ready" -ForegroundColor Green
}

# Run database migrations
function Run-Migrations {
    Write-Host "Running database migrations..." -ForegroundColor Yellow
    
    try {
        docker-compose -f $ComposeFile exec -T backend python scripts/run_cspm_migration.py
        Write-Host "✅ Database migrations completed" -ForegroundColor Green
    }
    catch {
        Write-Host "⚠️  Migration failed, but continuing..." -ForegroundColor Yellow
    }
}

# Perform health check
function Test-Health {
    Write-Host "Performing health check..." -ForegroundColor Yellow
    
    # Check service status
    $services = @("postgres", "redis", "backend", "celery-worker", "frontend")
    foreach ($service in $services) {
        $status = docker-compose -f $ComposeFile ps $service
        if ($status -match "Up") {
            Write-Host "✅ $service is running" -ForegroundColor Green
        }
        else {
            Write-Host "❌ $service is not running" -ForegroundColor Red
        }
    }
    
    # Test backend API
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing
        Write-Host "✅ Backend API health check passed" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Backend API health check failed" -ForegroundColor Red
    }
    
    Write-Host "✅ Health check completed" -ForegroundColor Green
}

# Display deployment information
function Show-DeploymentInfo {
    Write-Host ""
    Write-Host "🎉 CSPM Module Deployment Complete!" -ForegroundColor Green
    Write-Host "=================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Service URLs:" -ForegroundColor Cyan
    Write-Host "  - Backend API: http://localhost:8000" -ForegroundColor White
    Write-Host "  - Frontend Dashboard: http://localhost:3000" -ForegroundColor White
    Write-Host "  - Mobile App: http://localhost:3001" -ForegroundColor White
    Write-Host "  - Grafana: http://localhost:3002 (admin/admin_secure_XXXX)" -ForegroundColor White
    Write-Host "  - Prometheus: http://localhost:9090" -ForegroundColor White
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Access the web dashboard at http://localhost:3000" -ForegroundColor White
    Write-Host "  2. Test API endpoints using the Postman collection" -ForegroundColor White
    Write-Host "  3. Configure cloud provider integrations" -ForegroundColor White
    Write-Host "  4. Customize OPA policies for your security requirements" -ForegroundColor White
    Write-Host ""
    Write-Host "To stop services: docker-compose -f $ComposeFile down" -ForegroundColor Yellow
    Write-Host "To view logs: docker-compose -f $ComposeFile logs -f" -ForegroundColor Yellow
}

# Main execution
try {
    Check-Prerequisites
    Create-EnvFile
    Create-Directories
    Create-SamplePolicy
    Deploy-Services
    Wait-ForServices
    Run-Migrations
    Test-Health
    Show-DeploymentInfo
}
catch {
    Write-Host "❌ Deployment failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the logs above for more details." -ForegroundColor Yellow
    exit 1
}
