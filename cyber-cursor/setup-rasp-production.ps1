#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Simplified RASP Production Setup Script
.DESCRIPTION
    This script sets up RASP detection rules, SIEM integrations, and agent configurations.
#>

param(
    [string]$Environment = "production",
    [int]$APIPort = 8000
)

# Color output functions
function Write-Success { param($Message) Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Info { param($Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Warning { param($Message) Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Error { param($Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

# Test API connectivity
function Test-APIConnectivity {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:$APIPort/api/rasp/agents" -Method GET -ErrorAction Stop
        Write-Success "RASP API is accessible"
        return $true
    }
    catch {
        Write-Error "RASP API is not accessible: $($_.Exception.Message)"
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
    
    $successCount = 0
    foreach ($rule in $rules) {
        try {
            $ruleJson = $rule | ConvertTo-Json -Compress
            $response = Invoke-RestMethod -Uri "http://localhost:$APIPort/api/rasp/rules" -Method POST -Body $ruleJson -ContentType "application/json" -ErrorAction Stop
            Write-Success "Created rule: $($rule.vuln_type) for $($rule.language)"
            $successCount++
        }
        catch {
            Write-Warning "Failed to create rule: $($rule.vuln_type) for $($rule.language) - $($_.Exception.Message)"
        }
    }
    
    Write-Info "Created $successCount out of $($rules.Count) detection rules"
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
    
    $successCount = 0
    foreach ($integration in $integrations) {
        try {
            $integrationJson = $integration | ConvertTo-Json -Depth 3 -Compress
            $response = Invoke-RestMethod -Uri "http://localhost:$APIPort/api/rasp/integrations" -Method POST -Body $integrationJson -ContentType "application/json" -ErrorAction Stop
            Write-Success "Created integration: $($integration.name)"
            $successCount++
        }
        catch {
            Write-Warning "Failed to create integration: $($integration.name) - $($_.Exception.Message)"
        }
    }
    
    Write-Info "Created $successCount out of $($integrations.Count) SIEM integrations"
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
    
    # Test dashboard
    try {
        $dashboard = Invoke-RestMethod -Uri "http://localhost:$APIPort/api/rasp/dashboard/overview" -Method GET -ErrorAction Stop
        Write-Success "Dashboard is accessible"
        Write-Info "Dashboard stats: $($dashboard | ConvertTo-Json -Compress)"
    }
    catch {
        Write-Warning "Dashboard test failed: $($_.Exception.Message)"
    }
    
    return $true
}

# Main setup function
function Start-RASPSetup {
    Write-Host "Starting RASP Production Setup" -ForegroundColor Magenta
    Write-Host "==============================" -ForegroundColor Magenta
    
    # Test API connectivity
    if (!(Test-APIConnectivity)) {
        Write-Error "Cannot proceed without API connectivity"
        return
    }
    
    # Setup detection rules
    Setup-DetectionRules
    
    # Setup SIEM integrations
    Setup-SIEMIntegration
    
    # Create agent configurations
    Create-AgentConfigs
    
    # Test system
    Test-RASPSystem
    
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
    Write-Host "- RASP_AGENT_DEPLOYMENT_GUIDE.md - Agent deployment guide"
    Write-Host "- RASP_DEPLOYMENT_SUMMARY.md - Deployment checklist"
    Write-Host "- RASP_README.md - User guide"
    
    Write-Success "RASP production setup completed!"
}

# Run setup
Start-RASPSetup 