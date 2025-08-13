# CyberShield Endpoint Integration Tester (PowerShell)
# Tests the integration between frontend services and backend endpoints

param(
    [string]$BaseUrl = "http://localhost:8000",
    [string]$ApiVersion = "v1"
)

# Configuration
$Headers = @{
    "Content-Type" = "application/json"
    "Accept" = "application/json"
}

# Test endpoints to verify
$Endpoints = @{
    "auth" = @{
        "login" = "/api/$ApiVersion/auth/login"
        "register" = "/api/$ApiVersion/auth/register"
        "refresh" = "/api/$ApiVersion/auth/refresh"
        "logout" = "/api/$ApiVersion/auth/logout"
    }
    "sast" = @{
        "projects" = "/api/$ApiVersion/sast/projects"
        "scans" = "/api/$ApiVersion/sast/scans"
        "vulnerabilities" = "/api/$ApiVersion/sast/vulnerabilities"
        "metrics" = "/api/$ApiVersion/sast/metrics"
    }
    "dast" = @{
        "projects" = "/api/$ApiVersion/dast/projects"
        "scans" = "/api/$ApiVersion/dast/scans"
        "reports" = "/api/$ApiVersion/dast/reports"
    }
    "rasp" = @{
        "status" = "/api/$ApiVersion/rasp/status"
        "alerts" = "/api/$ApiVersion/rasp/alerts"
        "config" = "/api/$ApiVersion/rasp/config"
    }
    "cloud_security" = @{
        "status" = "/api/$ApiVersion/cloud-security/status"
        "providers" = "/api/$ApiVersion/cloud-security/providers"
        "compliance" = "/api/$ApiVersion/cloud-security/compliance"
    }
    "endpoint_security" = @{
        "status" = "/api/$ApiVersion/endpoint-antivirus-edr/status"
        "threats" = "/api/$ApiVersion/endpoint-antivirus-edr/threats"
        "quarantine" = "/api/$ApiVersion/endpoint-antivirus-edr/quarantine"
    }
    "device_control" = @{
        "devices" = "/api/$ApiVersion/device-control/devices"
        "policies" = "/api/$ApiVersion/device-control/policies"
        "logs" = "/api/$ApiVersion/device-control/logs"
    }
    "network_security" = @{
        "status" = "/api/$ApiVersion/network-security/status"
        "threats" = "/api/$ApiVersion/network-security/threats"
        "traffic" = "/api/$ApiVersion/network-security/traffic"
    }
    "iam" = @{
        "users" = "/api/$ApiVersion/iam/users"
        "roles" = "/api/$ApiVersion/iam/roles"
        "permissions" = "/api/$ApiVersion/iam/permissions"
    }
    "data_protection" = @{
        "status" = "/api/$ApiVersion/data-protection/status"
        "policies" = "/api/$ApiVersion/data-protection/policies"
        "compliance" = "/api/$ApiVersion/data-protection/compliance"
    }
    "threat_intelligence" = @{
        "indicators" = "/api/$ApiVersion/threat-intelligence/indicators"
        "threats" = "/api/$ApiVersion/threat-intelligence/threats"
        "feeds" = "/api/$ApiVersion/threat-intelligence/feeds"
    }
}

# Global variables
$Results = @{}
$AuthToken = $null
$TestStartTime = Get-Date

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Color = switch ($Level) {
        "SUCCESS" { "Green" }
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "INFO" { "White" }
        default { "White" }
    }
    
    Write-Host "[$Timestamp] [$Level] $Message" -ForegroundColor $Color
}

function Test-HealthCheck {
    try {
        $Response = Invoke-RestMethod -Uri "$BaseUrl/health" -Method Get -TimeoutSec 10 -ErrorAction Stop
        Write-Log "✅ Health check passed" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "❌ Health check failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-AuthEndpoints {
    Write-Log "Testing authentication endpoints..." "INFO"
    $AuthResults = @{}
    
    # Test registration
    try {
        $RegisterData = @{
            email = "test@example.com"
            password = "testpassword123"
            full_name = "Test User"
        } | ConvertTo-Json
        
        $Response = Invoke-RestMethod -Uri "$BaseUrl$($Endpoints.auth.register)" -Method Post -Body $RegisterData -Headers $Headers -TimeoutSec 10 -ErrorAction Stop
        
        if ($Response) {
            $AuthResults.register = "PASS"
            Write-Log "✅ Registration endpoint working" "SUCCESS"
        }
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 409) {
            $AuthResults.register = "PASS"
            Write-Log "✅ Registration endpoint working (user already exists)" "SUCCESS"
        }
        else {
            $AuthResults.register = "FAIL: $($_.Exception.Response.StatusCode)"
            Write-Log "❌ Registration failed: $($_.Exception.Response.StatusCode)" "ERROR"
        }
    }
    
    # Test login
    try {
        $LoginData = @{
            email = "test@example.com"
            password = "testpassword123"
        } | ConvertTo-Json
        
        $Response = Invoke-RestMethod -Uri "$BaseUrl$($Endpoints.auth.login)" -Method Post -Body $LoginData -Headers $Headers -TimeoutSec 10 -ErrorAction Stop
        
        if ($Response.access_token) {
            $AuthResults.login = "PASS"
            $script:AuthToken = $Response.access_token
            $Headers.Authorization = "Bearer $AuthToken"
            Write-Log "✅ Login endpoint working" "SUCCESS"
            Write-Log "✅ Authentication token obtained" "SUCCESS"
        }
        else {
            $AuthResults.login = "FAIL: No token received"
            Write-Log "❌ Login failed: No token received" "ERROR"
        }
    }
    catch {
        $AuthResults.login = "FAIL: $($_.Exception.Message)"
        Write-Log "❌ Login error: $($_.Exception.Message)" "ERROR"
    }
    
    return $AuthResults
}

function Test-ModuleEndpoints {
    param(
        [string]$ModuleName,
        [hashtable]$ModuleEndpoints
    )
    
    Write-Log "Testing $ModuleName endpoints..." "INFO"
    $ModuleResults = @{}
    
    foreach ($EndpointName in $ModuleEndpoints.Keys) {
        $EndpointPath = $ModuleEndpoints[$EndpointName]
        
        try {
            $Response = Invoke-RestMethod -Uri "$BaseUrl$EndpointPath" -Method Get -Headers $Headers -TimeoutSec 10 -ErrorAction Stop
            
            $ModuleResults[$EndpointName] = "PASS"
            Write-Log "✅ $ModuleName.$EndpointName`: PASS" "SUCCESS"
        }
        catch {
            if ($_.Exception.Response.StatusCode -eq 401) {
                $ModuleResults[$EndpointName] = "AUTH_REQUIRED"
                Write-Log "⚠️ $ModuleName.$EndpointName`: Authentication required" "WARNING"
            }
            elseif ($_.Exception.Response.StatusCode -eq 404) {
                $ModuleResults[$EndpointName] = "NOT_FOUND"
                Write-Log "⚠️ $ModuleName.$EndpointName`: Endpoint not found" "WARNING"
            }
            else {
                $ModuleResults[$EndpointName] = "FAIL: $($_.Exception.Response.StatusCode)"
                Write-Log "❌ $ModuleName.$EndpointName`: $($_.Exception.Response.StatusCode)" "ERROR"
            }
        }
    }
    
    return $ModuleResults
}

function Run-AllTests {
    Write-Log "🚀 Starting Endpoint Integration Tests" "INFO"
    Write-Log "Base URL: $BaseUrl" "INFO"
    Write-Log "Test started at: $TestStartTime" "INFO"
    
    # Test health check first
    if (-not (Test-HealthCheck)) {
        Write-Log "❌ Health check failed. Stopping tests." "ERROR"
        return @{ status = "FAILED"; reason = "Health check failed" }
    }
    
    # Test authentication
    $AuthResults = Test-AuthEndpoints
    $Results.auth = $AuthResults
    
    # Test all module endpoints
    foreach ($ModuleName in $Endpoints.Keys) {
        if ($ModuleName -ne "auth") {
            $ModuleResults = Test-ModuleEndpoints -ModuleName $ModuleName -ModuleEndpoints $Endpoints[$ModuleName]
            $Results[$ModuleName] = $ModuleResults
        }
    }
    
    return $Results
}

function Generate-Report {
    $TestEndTime = Get-Date
    $TestDuration = $TestEndTime - $TestStartTime
    
    $Report = @()
    $Report += "=" * 80
    $Report += "ENDPOINT INTEGRATION TEST REPORT"
    $Report += "=" * 80
    $Report += "Test Start Time: $TestStartTime"
    $Report += "Test End Time: $TestEndTime"
    $Report += "Test Duration: $TestDuration"
    $Report += ""
    
    # Summary statistics
    $TotalEndpoints = 0
    $PassedEndpoints = 0
    $FailedEndpoints = 0
    $AuthRequiredEndpoints = 0
    $NotFoundEndpoints = 0
    $ErrorEndpoints = 0
    
    foreach ($ModuleName in $Results.Keys) {
        if ($ModuleName -eq "auth") {
            continue
        }
        
        $Report += "📋 $($ModuleName.ToUpper()) MODULE"
        $Report += "-" * 40
        
        foreach ($EndpointName in $Results[$ModuleName].Keys) {
            $Result = $Results[$ModuleName][$EndpointName]
            $TotalEndpoints++
            
            switch -Wildcard ($Result) {
                "PASS" {
                    $PassedEndpoints++
                    $Report += "✅ $EndpointName`: PASS"
                }
                "AUTH_REQUIRED" {
                    $AuthRequiredEndpoints++
                    $Report += "⚠️ $EndpointName`: Authentication Required"
                }
                "NOT_FOUND" {
                    $NotFoundEndpoints++
                    $Report += "⚠️ $EndpointName`: Not Found"
                }
                "FAIL*" {
                    $FailedEndpoints++
                    $Report += "❌ $EndpointName`: $Result"
                }
                default {
                    $ErrorEndpoints++
                    $Report += "❌ $EndpointName`: $Result"
                }
            }
        }
        
        $Report += ""
    }
    
    # Overall summary
    $Report += "=" * 80
    $Report += "OVERALL SUMMARY"
    $Report += "=" * 80
    $Report += "Total Endpoints Tested: $TotalEndpoints"
    $Report += "✅ Passed: $PassedEndpoints"
    $Report += "⚠️ Auth Required: $AuthRequiredEndpoints"
    $Report += "⚠️ Not Found: $NotFoundEndpoints"
    $Report += "❌ Failed: $FailedEndpoints"
    $Report += "❌ Errors: $ErrorEndpoints"
    
    # Calculate success rate
    if ($TotalEndpoints -gt 0) {
        $SuccessRate = ($PassedEndpoints / $TotalEndpoints) * 100
        $Report += "Success Rate: $([math]::Round($SuccessRate, 1))%"
        
        $OverallStatus = if ($SuccessRate -ge 90) { "🟢 EXCELLENT" }
                        elseif ($SuccessRate -ge 80) { "🟡 GOOD" }
                        elseif ($SuccessRate -ge 70) { "🟠 FAIR" }
                        else { "🔴 POOR" }
        
        $Report += "Overall Status: $OverallStatus"
    }
    
    $Report += ""
    $Report += "=" * 80
    
    return $Report -join "`n"
}

function Save-Results {
    param([string]$Filename = $null)
    
    if (-not $Filename) {
        $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $Filename = "endpoint_integration_results_$Timestamp.json"
    }
    
    try {
        $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $Filename -Encoding UTF8
        Write-Log "Results saved to: $Filename" "INFO"
    }
    catch {
        Write-Log "Error saving results: $($_.Exception.Message)" "ERROR"
    }
}

# Main execution
Write-Host "🔍 CyberShield Endpoint Integration Tester" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Cyan

# Check if backend is accessible
try {
    $Response = Invoke-RestMethod -Uri "$BaseUrl/health" -Method Get -TimeoutSec 5 -ErrorAction Stop
    if ($Response) {
        Write-Log "✅ Backend is accessible" "SUCCESS"
    }
}
catch {
    Write-Host "❌ Cannot connect to backend server" -ForegroundColor Red
    Write-Host "Please ensure the backend server is running on $BaseUrl" -ForegroundColor Yellow
    exit 1
}

# Run tests
$Results = Run-AllTests

# Generate and display report
$Report = Generate-Report
Write-Host "`n$Report" -ForegroundColor White

# Save results
Save-Results

# Exit with appropriate code
if ($Results.status -eq "FAILED") {
    exit 1
}
else {
    # Check if we have any successful endpoints
    $TotalPassed = 0
    foreach ($ModuleName in $Results.Keys) {
        if ($ModuleName -ne "auth" -and $Results[$ModuleName] -is [hashtable]) {
            foreach ($Result in $Results[$ModuleName].Values) {
                if ($Result -eq "PASS") {
                    $TotalPassed++
                }
            }
        }
    }
    
    if ($TotalPassed -gt 0) {
        Write-Host "`n✅ Integration test completed with $TotalPassed successful endpoints" -ForegroundColor Green
        exit 0
    }
    else {
        Write-Host "`n❌ No endpoints passed the integration test" -ForegroundColor Red
        exit 1
    }
}
