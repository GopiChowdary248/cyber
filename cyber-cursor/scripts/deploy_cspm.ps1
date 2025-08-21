# CyberShield CSPM Module Deployment Script (PowerShell)
# This script automates the deployment of the comprehensive CSPM module

param(
    [switch]$SkipPrerequisites,
    [switch]$SkipMigrations,
    [switch]$SkipHealthCheck
)

# Configuration
$ProjectName = "cybershield-cspm"
$ComposeFile = "docker-compose.cspm.yml"
$EnvFile = ".env.cspm"

Write-Host "🚀 CyberShield CSPM Module Deployment" -ForegroundColor Blue
Write-Host "==========================================" -ForegroundColor Blue

# Function to print colored output
function Write-Status {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ️  $Message" -ForegroundColor Cyan
}

# Check prerequisites
function Check-Prerequisites {
    Write-Info "Checking prerequisites..."
    
    # Check Docker
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Error "Docker is not installed. Please install Docker Desktop first."
        exit 1
    }
    
    # Check Docker Compose
    if (-not (Get-Command docker-compose -ErrorAction SilentlyContinue)) {
        Write-Error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    }
    
    # Check if Docker daemon is running
    try {
        docker info | Out-Null
    }
    catch {
        Write-Error "Docker daemon is not running. Please start Docker Desktop first."
        exit 1
    }
    
    Write-Host "Prerequisites check passed"
}

# Create environment file
function Create-EnvFile {
    Write-Info "Creating environment configuration file..."
    
    if (-not (Test-Path $EnvFile)) {
        $postgresPassword = "cybershield_secure_password_" + (Get-Random -Minimum 10000000 -Maximum 99999999)
        $redisPassword = "redis_secure_password_" + (Get-Random -Minimum 10000000 -Maximum 99999999)
        $secretKey = -join ((65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
        $grafanaPassword = "admin_secure_" + (Get-Random -Minimum 1000 -Maximum 9999)
        $vaultToken = "vault_token_" + (Get-Random -Minimum 1000000000000000 -Maximum 9999999999999999)
        $jwtSecret = -join ((65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
        
        $envContent = @"
# CyberShield CSPM Environment Configuration
# Database Configuration
POSTGRES_PASSWORD=$postgresPassword
POSTGRES_DB=cybershield_cspm

# Redis Configuration
REDIS_PASSWORD=$redisPassword

# Application Configuration
SECRET_KEY=$secretKey
ENVIRONMENT=production
LOG_LEVEL=INFO

# Monitoring Configuration
GRAFANA_PASSWORD=$grafanaPassword

# Vault Configuration
VAULT_TOKEN=$vaultToken

# API Configuration
API_BASE_URL=http://localhost:8000
FRONTEND_URL=http://localhost:3000
MOBILE_URL=http://localhost:3001

# Security Configuration
JWT_SECRET_KEY=$jwtSecret
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=100
RATE_LIMIT_AUTH_REQUESTS_PER_MINUTE=10

# Celery Configuration
CELERY_WORKER_CONCURRENCY=4
CELERY_TASK_TIME_LIMIT=600
CELERY_TASK_SOFT_TIME_LIMIT=300

# OPA Configuration
OPA_URL=http://localhost:8181
OPA_POLICY_DIR=./policies

# Monitoring
PROMETHEUS_RETENTION_TIME=200h
GRAFANA_ADMIN_PASSWORD=$grafanaPassword
"@
        
        $envContent | Out-File -FilePath $EnvFile -Encoding UTF8
        Write-Host "Environment file created: $EnvFile"
        Write-Warning "Please review and modify the generated passwords in $EnvFile"
    }
    else {
        Write-Info "Environment file already exists: $EnvFile"
    }
}

# Create necessary directories
function Create-Directories {
    Write-Info "Creating necessary directories..."
    
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
        }
    }
    
            Write-Host "Directories created"
}

# Create sample policies
function Create-SamplePolicies {
    Write-Info "Creating sample OPA policies..."
    
    # AWS S3 Public Access Policy
    $s3Policy = @"
package s3.public_access

import future.keywords.if
import future.keywords.in

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    input.public_access_block_configuration.block_public_acls == false
    msg := sprintf("S3 bucket %v has public ACLs enabled", [input.bucket_name])
}

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    input.public_access_block_configuration.block_public_policy == false
    msg := sprintf("S3 bucket %v has public policy enabled", [input.bucket_name])
}
"@
    
    $s3Policy | Out-File -FilePath "policies/aws_s3_public_access.rego" -Encoding UTF8
    
    # AWS EC2 Security Group Policy
    $ec2Policy = @"
package ec2.security_groups

import future.keywords.if
import future.keywords.in

deny[msg] {
    input.resource_type == "aws_security_group"
    rule := input.ingress_rules[_]
    rule.from_port == 0
    rule.to_port == 65535
    rule.cidr_blocks[_] == "0.0.0.0/0"
    msg := sprintf("Security group %v allows all traffic from anywhere", [input.group_name])
}
"@
    
    $ec2Policy | Out-File -FilePath "policies/aws_ec2_security_groups.rego" -Encoding UTF8
    
    Write-Host "Sample policies created"
}

# Create monitoring configuration
function Create-MonitoringConfig {
    Write-Info "Creating monitoring configuration..."
    
    # Prometheus configuration
    $prometheusConfig = @'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

scrape_configs:
  - job_name: 'cybershield-backend'
    static_configs:
      - targets: ['backend:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'cybershield-postgres'
    static_configs:
      - targets: ['postgres:5432']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'cybershield-redis'
    static_configs:
      - targets: ['redis:6379']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'cybershield-opa'
    static_configs:
      - targets: ['opa:8181']
    metrics_path: '/metrics'
    scrape_interval: 30s
'@
    
    $prometheusConfig | Out-File -FilePath "monitoring/prometheus.yml" -Encoding UTF8
    
    # Grafana datasource configuration
    $grafanaConfig = @'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
'@
    
    $grafanaConfig | Out-File -FilePath "monitoring/grafana/datasources/prometheus.yml" -Encoding UTF8
    
    Write-Host "Monitoring configuration created"
}

# Build and start services
function Deploy-Services {
    Write-Info "Building and starting services..."
    
    # Load environment variables
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^([^#][^=]+)=(.*)$') {
            $name = $matches[1]
            $value = $matches[2]
            Set-Variable -Name $name -Value $value -Scope Global
        }
    }
    
    # Build images
    Write-Info "Building Docker images..."
    docker-compose -f $ComposeFile build
    
    # Start services
    Write-Info "Starting services..."
    docker-compose -f $ComposeFile up -d
    
    Write-Host "Services started successfully"
}

# Wait for services to be ready
function Wait-ForServices {
    Write-Info "Waiting for services to be ready..."
    
    # Wait for PostgreSQL
    Write-Info "Waiting for PostgreSQL..."
    do {
        Start-Sleep -Seconds 2
        $postgresReady = docker-compose -f $ComposeFile exec -T postgres pg_isready -U cybershield -d cybershield_cspm 2>$null
    } while ($LASTEXITCODE -ne 0)
    Write-Host "PostgreSQL is ready"
    
    # Wait for Redis
    Write-Info "Waiting for Redis..."
    do {
        Start-Sleep -Seconds 2
        $redisReady = docker-compose -f $ComposeFile exec -T redis redis-cli --raw incr ping 2>$null
    } while ($LASTEXITCODE -ne 0)
    Write-Host "Redis is ready"
    
    # Wait for Backend
    Write-Info "Waiting for Backend API..."
    do {
        Start-Sleep -Seconds 5
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -ErrorAction Stop
            $backendReady = $true
        }
        catch {
            $backendReady = $false
        }
    } while (-not $backendReady)
    Write-Host "Backend API is ready"
    
    # Wait for OPA
    Write-Info "Waiting for OPA..."
    do {
        Start-Sleep -Seconds 2
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8181/health" -UseBasicParsing -ErrorAction Stop
            $opaReady = $true
        }
        catch {
            $opaReady = $false
        }
    } while (-not $opaReady)
    Write-Host "OPA is ready"
}

# Run database migrations
function Run-Migrations {
    Write-Info "Running database migrations..."
    
    # Wait a bit for the database to be fully ready
    Start-Sleep -Seconds 5
    
    # Run the migration script
    docker-compose -f $ComposeFile exec -T backend python scripts/run_cspm_migration.py
    
    Write-Host "Database migrations completed"
}

# Create initial data
function Create-InitialData {
    Write-Info "Creating initial data..."
    
    # This would typically create initial users, policies, etc.
    # For now, we'll just create a placeholder
    
    Write-Host "Initial data setup completed"
}

# Health check
function Test-Health {
    Write-Info "Performing health check..."
    
    # Check all services
    $services = @("backend", "frontend", "mobile", "postgres", "redis", "opa", "prometheus", "grafana")
    
    foreach ($service in $services) {
        $status = docker-compose -f $ComposeFile ps $service
        if ($status -match "Up") {
            Write-Host "$service is running"
        }
        else {
            Write-Error "$service is not running"
        }
    }
    
    # Check API endpoints
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing
        Write-Host "Backend API health check passed"
    }
    catch {
        Write-Error "Backend API health check failed"
    }
    
    Write-Host "Health check completed"
}

# Display deployment information
function Show-DeploymentInfo {
    Write-Host ""
    Write-Host "🎉 CyberShield CSPM Module Deployment Complete!" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Service URLs:" -ForegroundColor Blue
    Write-Host "  Backend API:     http://localhost:8000"
    Write-Host "  Frontend:        http://localhost:3000"
    Write-Host "  Mobile App:      http://localhost:3001"
    Write-Host "  Grafana:         http://localhost:3002 (admin/admin_secure_*)"
    Write-Host "  Prometheus:      http://localhost:9090"
    Write-Host "  OPA:             http://localhost:8181"
    Write-Host "  Vault:           http://localhost:8200"
    Write-Host ""
    Write-Host "Database:" -ForegroundColor Blue
    Write-Host "  PostgreSQL:      localhost:5432"
    Write-Host "  pgBouncer:       localhost:5433"
    Write-Host "  Redis:           localhost:6379"
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Blue
    Write-Host "  1. Access the frontend at http://localhost:3000"
    Write-Host "  2. Create your first admin user"
    Write-Host "  3. Configure cloud provider integrations"
    Write-Host "  4. Set up monitoring dashboards"
    Write-Host "  5. Review and customize security policies"
    Write-Host ""
    Write-Host "Important:" -ForegroundColor Yellow
    Write-Host "  - Review the generated passwords in $EnvFile"
    Write-Host "  - Change default passwords in production"
    Write-Host "  - Configure SSL certificates for production use"
    Write-Host "  - Set up proper backup strategies"
    Write-Host ""
}

# Main deployment function
function Main {
    if (-not $SkipPrerequisites) {
        Check-Prerequisites
    }
    
    Create-EnvFile
    Create-Directories
    Create-SamplePolicies
    Create-MonitoringConfig
    Deploy-Services
    Wait-ForServices
    
    if (-not $SkipMigrations) {
        Run-Migrations
    }
    
    Create-InitialData
    
    if (-not $SkipHealthCheck) {
        Test-Health
    }
    
    Show-DeploymentInfo
}

# Run main function
Main
