#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Comprehensive RASP Production Deployment Script
.DESCRIPTION
    This script deploys the RASP (Runtime Application Self-Protection) system
    with database initialization, agent configuration, detection rules, and SIEM integration.
.PARAMETER Environment
    Target environment (dev, staging, production)
.PARAMETER DatabaseHost
    PostgreSQL database host
.PARAMETER DatabaseName
    Database name for RASP
.PARAMETER DatabaseUser
    Database username
.PARAMETER DatabasePassword
    Database password
.PARAMETER APIPort
    API server port (default: 8000)
.PARAMETER RedisHost
    Redis host for caching (default: localhost)
.PARAMETER RedisPort
    Redis port (default: 6379)
#>

param(
    [string]$Environment = "production",
    [string]$DatabaseHost = "localhost",
    [string]$DatabaseName = "cybershield_rasp",
    [string]$DatabaseUser = "postgres",
    [string]$DatabasePassword = "",
    [int]$APIPort = 8000,
    [string]$RedisHost = "localhost",
    [int]$RedisPort = 6379
)

# Color output functions
function Write-Success { param($Message) Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Info { param($Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Warning { param($Message) Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Error { param($Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

# Test connection function
function Test-Connection {
    param($Host, $Port, $Service)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.ConnectAsync($Host, $Port).Wait(5000) | Out-Null
        if ($tcp.Connected) {
            $tcp.Close()
            Write-Success "$Service connection successful"
            return $true
        }
    }
    catch {
        Write-Warning "$Service connection failed: $($_.Exception.Message)"
        return $false
    }
}

# Database initialization function
function Initialize-Database {
    Write-Info "Initializing RASP database..."
    
    # Check if psql is available
    try {
        $psqlVersion = psql --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "PostgreSQL client found"
        } else {
            Write-Warning "PostgreSQL client not found. Please install PostgreSQL or ensure psql is in PATH"
            return $false
        }
    }
    catch {
        Write-Warning "PostgreSQL client not found. Please install PostgreSQL or ensure psql is in PATH"
        return $false
    }
    
    # Set PGPASSWORD environment variable
    $env:PGPASSWORD = $DatabasePassword
    
    # Create database if it doesn't exist
    Write-Info "Creating database '$DatabaseName' if it doesn't exist..."
    $createDbCmd = "psql -h $DatabaseHost -U $DatabaseUser -d postgres -c `"CREATE DATABASE $DatabaseName;`" 2>$null"
    Invoke-Expression $createDbCmd
    
    # Run RASP database schema
    Write-Info "Running RASP database schema..."
    $schemaCmd = "psql -h $DatabaseHost -U $DatabaseUser -d $DatabaseName -f scripts/init-rasp-db.sql"
    Invoke-Expression $schemaCmd
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Database initialization completed successfully"
        return $true
    } else {
        Write-Error "Database initialization failed"
        return $false
    }
}

# Setup detection rules function
function Setup-DetectionRules {
    Write-Info "Setting up RASP detection rules..."
    
    $rules = @(
        @{
            vuln_type = "SQLi"
            language = "python"
            pattern = ".*SELECT.*FROM.*\\+.*"
            severity = "critical"
            auto_block = $true
            description = "SQL injection detection for Python applications"
        },
        @{
            vuln_type = "SQLi"
            language = "java"
            pattern = ".*Statement.*executeQuery.*\\+.*"
            severity = "critical"
            auto_block = $true
            description = "SQL injection detection for Java applications"
        },
        @{
            vuln_type = "XSS"
            language = "python"
            pattern = ".*<script.*>.*"
            severity = "high"
            auto_block = $true
            description = "Cross-site scripting detection"
        },
        @{
            vuln_type = "Command Injection"
            language = "python"
            pattern = ".*os\\.system.*\\+.*"
            severity = "critical"
            auto_block = $true
            description = "Command injection detection for Python"
        },
        @{
            vuln_type = "Path Traversal"
            language = "python"
            pattern = ".*\\.\\./.*"
            severity = "high"
            auto_block = $true
            description = "Path traversal detection"
        },
        @{
            vuln_type = "Deserialization"
            language = "python"
            pattern = ".*pickle\\.loads.*"
            severity = "high"
            auto_block = $false
            description = "Unsafe deserialization detection"
        }
    )
    
    foreach ($rule in $rules) {
        $ruleJson = $rule | ConvertTo-Json -Compress
        $response = Invoke-RestMethod -Uri "http://localhost:$APIPort/api/rasp/rules" -Method POST -Body $ruleJson -ContentType "application/json" -ErrorAction SilentlyContinue
        if ($response) {
            Write-Success "Created rule: $($rule.vuln_type) for $($rule.language)"
        } else {
            Write-Warning "Failed to create rule: $($rule.vuln_type) for $($rule.language)"
        }
    }
}

# Setup SIEM integration function
function Setup-SIEMIntegration {
    Write-Info "Setting up SIEM integrations..."
    
    $integrations = @(
        @{
            integration_type = "siem"
            name = "Splunk Integration"
            config = @{
                endpoint = "https://splunk.example.com:8088/services/collector"
                token = "your_splunk_token"
                index = "security"
                sourcetype = "rasp_events"
            }
        },
        @{
            integration_type = "soar"
            name = "Cortex XSOAR Integration"
            config = @{
                endpoint = "https://xsoar.example.com/api/v1"
                api_key = "your_xsoar_api_key"
                incident_type = "RASP Alert"
            }
        }
    )
    
    foreach ($integration in $integrations) {
        $integrationJson = $integration | ConvertTo-Json -Depth 3 -Compress
        $response = Invoke-RestMethod -Uri "http://localhost:$APIPort/api/rasp/integrations" -Method POST -Body $integrationJson -ContentType "application/json" -ErrorAction SilentlyContinue
        if ($response) {
            Write-Success "Created integration: $($integration.name)"
        } else {
            Write-Warning "Failed to create integration: $($integration.name)"
        }
    }
}

# Create agent configuration templates
function Create-AgentConfigs {
    Write-Info "Creating agent configuration templates..."
    
    $configDir = "agent-configs"
    if (!(Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir | Out-Null
    }
    
    # Python agent config
    $pythonConfig = @{
        agent_type = "python"
        app_name = "your-python-app"
        language = "python"
        version = "1.0.0"
        config = @{
            monitoring_level = "high"
            auto_block = $true
            log_level = "INFO"
            api_endpoint = "http://localhost:$APIPort/api/rasp"
            heartbeat_interval = 30
            hooks = @(
                "sqlalchemy.engine.Engine.execute",
                "os.system",
                "subprocess.run",
                "eval",
                "exec"
            )
        }
    }
    $pythonConfig | ConvertTo-Json -Depth 3 | Out-File "$configDir/python-agent-config.json" -Encoding UTF8
    
    # Java agent config
    $javaConfig = @{
        agent_type = "java"
        app_name = "your-java-app"
        language = "java"
        version = "1.0.0"
        config = @{
            monitoring_level = "high"
            auto_block = $true
            log_level = "INFO"
            api_endpoint = "http://localhost:$APIPort/api/rasp"
            heartbeat_interval = 30
            hooks = @(
                "java.sql.Statement.executeQuery",
                "java.sql.Statement.executeUpdate",
                "java.lang.Runtime.exec",
                "java.io.FileInputStream.<init>"
            )
        }
    }
    $javaConfig | ConvertTo-Json -Depth 3 | Out-File "$configDir/java-agent-config.json" -Encoding UTF8
    
    # Node.js agent config
    $nodeConfig = @{
        agent_type = "nodejs"
        app_name = "your-nodejs-app"
        language = "nodejs"
        version = "1.0.0"
        config = @{
            monitoring_level = "high"
            auto_block = $true
            log_level = "info"
            api_endpoint = "http://localhost:$APIPort/api/rasp"
            heartbeat_interval = 30
            hooks = @(
                "child_process.exec",
                "child_process.spawn",
                "fs.readFile",
                "eval"
            )
        }
    }
    $nodeConfig | ConvertTo-Json -Depth 3 | Out-File "$configDir/nodejs-agent-config.json" -Encoding UTF8
    
    Write-Success "Agent configuration templates created in $configDir/"
}

# Test RASP functionality
function Test-RASPSystem {
    Write-Info "Testing RASP system functionality..."
    
    # Test API connectivity
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:$APIPort/api/rasp/agents" -Method GET
        Write-Success "RASP API is accessible"
    }
    catch {
        Write-Error "RASP API is not accessible: $($_.Exception.Message)"
        return $false
    }
    
    # Test dashboard
    try {
        $dashboard = Invoke-RestMethod -Uri "http://localhost:$APIPort/api/rasp/dashboard/overview" -Method GET
        Write-Success "Dashboard is accessible"
    }
    catch {
        Write-Warning "Dashboard test failed: $($_.Exception.Message)"
    }
    
    return $true
}

# Main deployment function
function Start-RASPDeployment {
    Write-Host "Starting RASP Production Deployment" -ForegroundColor Magenta
    Write-Host "=====================================" -ForegroundColor Magenta
    
    # Test connections
    Write-Info "Testing service connections..."
    Test-Connection -Host $DatabaseHost -Port 5432 -Service "PostgreSQL"
    Test-Connection -Host $RedisHost -Port $RedisPort -Service "Redis"
    Test-Connection -Host "localhost" -Port $APIPort -Service "RASP API"
    
    # Initialize database
    if (Initialize-Database) {
        Write-Success "Database initialization completed"
    } else {
        Write-Error "Database initialization failed. Please check your PostgreSQL setup."
        return
    }
    
    # Setup detection rules
    Setup-DetectionRules
    
    # Setup SIEM integrations
    Setup-SIEMIntegration
    
    # Create agent configurations
    Create-AgentConfigs
    
    # Test system
    if (Test-RASPSystem) {
        Write-Success "RASP system deployment completed successfully!"
    } else {
        Write-Error "RASP system deployment failed!"
        return
    }
    
    # Display next steps
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "1. Configure your applications with the agent configs in agent-configs/"
    Write-Host "2. Update SIEM integration endpoints with your actual URLs"
    Write-Host "3. Deploy RASP agents to your target applications"
    Write-Host "4. Monitor the dashboard at http://localhost:$APIPort/docs"
    Write-Host "5. Review and tune detection rules based on your environment"
    Write-Host ""
    Write-Host "Documentation:" -ForegroundColor Yellow
    Write-Host "- RASP_AGENT_SETUP.md - Agent configuration guide"
    Write-Host "- RASP_DEPLOYMENT_SUMMARY.md - Deployment checklist"
    Write-Host "- RASP_README.md - User guide"
}

# Run deployment
Start-RASPDeployment 