#!/usr/bin/env pwsh
<#
.SYNOPSIS
    RASP Backend Deployment Script
.DESCRIPTION
    Comprehensive deployment script for the RASP (Runtime Application Self-Protection) backend.
    Handles database initialization, environment setup, and service deployment.
.PARAMETER Environment
    Deployment environment (development, staging, production)
.PARAMETER DatabaseHost
    PostgreSQL database host
.PARAMETER DatabasePort
    PostgreSQL database port
.PARAMETER DatabaseName
    PostgreSQL database name
.PARAMETER DatabaseUser
    PostgreSQL database user
.PARAMETER DatabasePassword
    PostgreSQL database password
.PARAMETER RedisHost
    Redis host for caching and message queues
.PARAMETER RedisPort
    Redis port
.PARAMETER RedisPassword
    Redis password
.PARAMETER ApiPort
    API server port
.PARAMETER UseDocker
    Use Docker for deployment
.PARAMETER SkipTests
    Skip running test suite
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("development", "staging", "production")]
    [string]$Environment = "development",
    
    [Parameter(Mandatory=$false)]
    [string]$DatabaseHost = "localhost",
    
    [Parameter(Mandatory=$false)]
    [int]$DatabasePort = 5432,
    
    [Parameter(Mandatory=$false)]
    [string]$DatabaseName = "cybershield",
    
    [Parameter(Mandatory=$false)]
    [string]$DatabaseUser = "cybershield_user",
    
    [Parameter(Mandatory=$false)]
    [string]$DatabasePassword = "cybershield_password",
    
    [Parameter(Mandatory=$false)]
    [string]$RedisHost = "localhost",
    
    [Parameter(Mandatory=$false)]
    [int]$RedisPort = 6379,
    
    [Parameter(Mandatory=$false)]
    [string]$RedisPassword = "redis_password",
    
    [Parameter(Mandatory=$false)]
    [int]$ApiPort = 8000,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseDocker,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipTests
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Colors for output
$Red = "Red"
$Green = "Green"
$Yellow = "Yellow"
$Blue = "Blue"
$Cyan = "Cyan"

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Step {
    param([string]$Step)
    Write-ColorOutput "`n🔧 $Step" $Cyan
}

function Write-Success {
    param([string]$Message)
    Write-ColorOutput "✅ $Message" $Green
}

function Write-Warning {
    param([string]$Message)
    Write-ColorOutput "⚠️  $Message" $Yellow
}

function Write-Error {
    param([string]$Message)
    Write-ColorOutput "❌ $Message" $Red
}

function Test-Command {
    param([string]$Command)
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Test-Port {
    param(
        [string]$Host,
        [int]$Port
    )
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.ConnectAsync($Host, $Port).Wait(5000) | Out-Null
        $tcp.Close()
        return $true
    }
    catch {
        return $false
    }
}

function Test-DatabaseConnection {
    param(
        [string]$Host,
        [int]$Port,
        [string]$Database,
        [string]$User,
        [string]$Password
    )
    try {
        $connectionString = "Server=$Host;Port=$Port;Database=$Database;User Id=$User;Password=$Password;"
        $connection = New-Object System.Data.Odbc.OdbcConnection($connectionString)
        $connection.Open()
        $connection.Close()
        return $true
    }
    catch {
        return $false
    }
}

function Initialize-Environment {
    Write-Step "Initializing deployment environment"
    
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    
    if (-not $isAdmin) {
        Write-Warning "Not running as administrator. Some operations may require elevated privileges."
    }
    
    # Set environment variables
    $env:ENVIRONMENT = $Environment
    $env:DATABASE_HOST = $DatabaseHost
    $env:DATABASE_PORT = $DatabasePort
    $env:DATABASE_NAME = $DatabaseName
    $env:DATABASE_USER = $DatabaseUser
    $env:DATABASE_PASSWORD = $DatabasePassword
    $env:REDIS_HOST = $RedisHost
    $env:REDIS_PORT = $RedisPort
    $env:REDIS_PASSWORD = $RedisPassword
    $env:API_PORT = $ApiPort
    
    Write-Success "Environment variables set"
}

function Install-Dependencies {
    Write-Step "Installing system dependencies"
    
    # Check Python
    if (-not (Test-Command "python")) {
        Write-Error "Python is not installed. Please install Python 3.8+ first."
        exit 1
    }
    
    $pythonVersion = python --version
    Write-Success "Python version: $pythonVersion"
    
    # Check pip
    if (-not (Test-Command "pip")) {
        Write-Error "pip is not installed. Please install pip first."
        exit 1
    }
    
    # Check PostgreSQL client
    if (-not (Test-Command "psql")) {
        Write-Warning "PostgreSQL client (psql) not found. Database operations may fail."
    }
    
    # Check Redis client
    if (-not (Test-Command "redis-cli")) {
        Write-Warning "Redis client (redis-cli) not found. Redis operations may fail."
    }
    
    Write-Success "System dependencies checked"
}

function Install-PythonDependencies {
    Write-Step "Installing Python dependencies"
    
    try {
        # Navigate to backend directory
        Push-Location "backend"
        
        # Upgrade pip
        python -m pip install --upgrade pip
        
        # Install requirements
        if (Test-Path "requirements.txt") {
            pip install -r requirements.txt
            Write-Success "Python dependencies installed from requirements.txt"
        } else {
            Write-Warning "requirements.txt not found, installing minimal dependencies"
            pip install fastapi uvicorn sqlalchemy asyncpg redis pydantic pydantic-settings structlog
        }
        
        # Install additional RASP dependencies
        pip install aiohttp asyncio-mqtt prometheus-client psutil
        Write-Success "RASP-specific dependencies installed"
        
        Pop-Location
    }
    catch {
        Pop-Location
        Write-Error "Failed to install Python dependencies: $($_.Exception.Message)"
        exit 1
    }
}

function Initialize-Database {
    Write-Step "Initializing database"
    
    try {
        # Test database connection
        if (Test-DatabaseConnection -Host $DatabaseHost -Port $DatabasePort -Database $DatabaseName -User $DatabaseUser -Password $DatabasePassword) {
            Write-Success "Database connection successful"
        } else {
            Write-Error "Cannot connect to database. Please check your database configuration."
            exit 1
        }
        
        # Run database initialization script
        if (Test-Path "scripts/init-rasp-db.sql") {
            Write-Step "Running RASP database initialization script"
            
            $env:PGPASSWORD = $DatabasePassword
            $initScript = Get-Content "scripts/init-rasp-db.sql" -Raw
            
            # Execute SQL script
            $initScript | psql -h $DatabaseHost -p $DatabasePort -U $DatabaseUser -d $DatabaseName
            
            if ($LASTEXITCODE -eq 0) {
                Write-Success "RASP database schema initialized successfully"
            } else {
                Write-Error "Failed to initialize RASP database schema"
                exit 1
            }
        } else {
            Write-Warning "RASP database initialization script not found"
        }
        
        # Initialize database tables using Python
        Write-Step "Creating database tables"
        python -c "
import asyncio
import sys
import os
sys.path.append('backend')
from app.core.database import init_db
from app.models.rasp import Base
from app.core.config import settings

async def init():
    try:
        await init_db()
        print('Database tables created successfully')
    except Exception as e:
        print(f'Error creating tables: {e}')
        sys.exit(1)

asyncio.run(init())
"
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Database tables created successfully"
        } else {
            Write-Error "Failed to create database tables"
            exit 1
        }
    }
    catch {
        Write-Error "Database initialization failed: $($_.Exception.Message)"
        exit 1
    }
}

function Test-Services {
    Write-Step "Testing service connectivity"
    
    # Test database
    if (Test-Port -Host $DatabaseHost -Port $DatabasePort) {
        Write-Success "Database is accessible"
    } else {
        Write-Error "Database is not accessible"
        exit 1
    }
    
    # Test Redis
    if (Test-Port -Host $RedisHost -Port $RedisPort) {
        Write-Success "Redis is accessible"
    } else {
        Write-Warning "Redis is not accessible. Some features may not work properly."
    }
    
    Write-Success "Service connectivity tests completed"
}

function Run-TestSuite {
    if ($SkipTests) {
        Write-Warning "Skipping test suite as requested"
        return
    }
    
    Write-Step "Running RASP test suite"
    
    try {
        # Run the RASP test script
        python test-rasp.py
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "RASP test suite passed"
        } else {
            Write-Error "RASP test suite failed"
            exit 1
        }
    }
    catch {
        Write-Error "Test suite execution failed: $($_.Exception.Message)"
        exit 1
    }
}

function Start-Backend {
    Write-Step "Starting RASP backend"
    
    try {
        # Navigate to backend directory
        Push-Location "backend"
        
        # Start the FastAPI application
        Write-ColorOutput "Starting RASP backend on port $ApiPort..." $Blue
        
        if ($UseDocker) {
            # Use Docker deployment
            if (Test-Command "docker") {
                Write-Step "Deploying with Docker"
                
                # Build Docker image
                docker build -t cybershield-rasp .
                
                # Run Docker container
                docker run -d `
                    --name cybershield-rasp `
                    -p $ApiPort`:8000 `
                    -e ENVIRONMENT=$Environment `
                    -e DATABASE_HOST=$DatabaseHost `
                    -e DATABASE_PORT=$DatabasePort `
                    -e DATABASE_NAME=$DatabaseName `
                    -e DATABASE_USER=$DatabaseUser `
                    -e DATABASE_PASSWORD=$DatabasePassword `
                    -e REDIS_HOST=$RedisHost `
                    -e REDIS_PORT=$RedisPort `
                    -e REDIS_PASSWORD=$RedisPassword `
                    cybershield-rasp
                
                Write-Success "RASP backend deployed with Docker"
            } else {
                Write-Error "Docker is not installed. Please install Docker or use native deployment."
                exit 1
            }
        } else {
            # Native deployment
            Write-Step "Starting native RASP backend"
            
            # Start the application in background
            Start-Process -FilePath "python" -ArgumentList "main.py" -WorkingDirectory (Get-Location) -WindowStyle Hidden
            
            # Wait for service to start
            Start-Sleep -Seconds 5
            
            # Test if service is running
            try {
                $response = Invoke-RestMethod -Uri "http://localhost:$ApiPort/health" -Method Get -TimeoutSec 10
                if ($response.status -eq "healthy") {
                    Write-Success "RASP backend started successfully"
                } else {
                    Write-Error "RASP backend health check failed"
                    exit 1
                }
            }
            catch {
                Write-Error "RASP backend is not responding: $($_.Exception.Message)"
                exit 1
            }
        }
        
        Pop-Location
    }
    catch {
        Pop-Location
        Write-Error "Failed to start RASP backend: $($_.Exception.Message)"
        exit 1
    }
}

function Show-DeploymentInfo {
    Write-Step "Deployment Information"
    
    Write-ColorOutput "`n🎯 RASP Backend Deployment Summary:" $Cyan
    Write-ColorOutput "Environment: $Environment" $Blue
    Write-ColorOutput "API URL: http://localhost:$ApiPort" $Blue
    Write-ColorOutput "API Documentation: http://localhost:$ApiPort/docs" $Blue
    Write-ColorOutput "Database: $DatabaseHost`:$DatabasePort/$DatabaseName" $Blue
    Write-ColorOutput "Redis: $RedisHost`:$RedisPort" $Blue
    
    Write-ColorOutput "`n📋 Key RASP Endpoints:" $Cyan
    Write-ColorOutput "GET  /api/rasp/agents - List RASP agents" $Blue
    Write-ColorOutput "POST /api/rasp/agents - Create new agent" $Blue
    Write-ColorOutput "GET  /api/rasp/attacks - List detected attacks" $Blue
    Write-ColorOutput "GET  /api/rasp/rules - List detection rules" $Blue
    Write-ColorOutput "GET  /api/rasp/dashboard/overview - Dashboard overview" $Blue
    Write-ColorOutput "POST /api/rasp/webhook - Webhook for integrations" $Blue
    
    Write-ColorOutput "`n🔧 Next Steps:" $Cyan
    Write-ColorOutput "1. Configure RASP agents for your applications" $Blue
    Write-ColorOutput "2. Set up detection rules based on your security requirements" $Blue
    Write-ColorOutput "3. Integrate with SIEM/SOAR systems" $Blue
    Write-ColorOutput "4. Monitor and tune based on real-world usage" $Blue
    
    Write-ColorOutput "`n📚 Documentation:" $Cyan
    Write-ColorOutput "RASP README: RASP_README.md" $Blue
    Write-ColorOutput "Implementation Document: RASP_IMPLEMENTATION_DOCUMENT.md" $Blue
    Write-ColorOutput "Test Script: test-rasp.py" $Blue
}

# Main deployment process
try {
    Write-ColorOutput "🚀 RASP Backend Deployment Script" $Cyan
    Write-ColorOutput "Environment: $Environment" $Blue
    Write-ColorOutput "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" $Blue
    
    Initialize-Environment
    Install-Dependencies
    Install-PythonDependencies
    Initialize-Database
    Test-Services
    Run-TestSuite
    Start-Backend
    Show-DeploymentInfo
    
    Write-ColorOutput "`n🎉 RASP Backend deployment completed successfully!" $Green
}
catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
    exit 1
} 