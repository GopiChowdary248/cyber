#!/usr/bin/env pwsh
<#
.SYNOPSIS
    SAST Tool End-to-End Test Script (PowerShell Version)

.DESCRIPTION
    This script performs comprehensive testing of the SAST tool implementation:
    1. Database connectivity and model creation
    2. SAST scanner functionality
    3. AI recommendation engine
    4. API endpoints
    5. DevSecOps integration
    6. Frontend integration
#>

# Test configuration
$BaseUrl = "http://localhost:8000"
$ApiBase = "$BaseUrl/api/v1"
$FrontendUrl = "http://localhost:3000"

# Global variables
$TestResults = @()
$AuthToken = $null

function Write-TestLog {
    param(
        [string]$TestName,
        [string]$Status,
        [string]$Details = ""
    )
    
    $Result = @{
        Test = $TestName
        Status = $Status
        Details = $Details
        Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    }
    
    $script:TestResults += $Result
    
    $StatusColor = switch ($Status.ToUpper()) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "ERROR" { "Red" }
        "SKIP" { "Yellow" }
        default { "White" }
    }
    
    Write-Host "[$($Status.ToUpper())] $TestName`: $Details" -ForegroundColor $StatusColor
}

function Test-HealthCheck {
    try {
        $Response = Invoke-RestMethod -Uri "$BaseUrl/health" -Method Get -ErrorAction Stop
        
        if ($Response.status) {
            Write-TestLog -TestName "Health Check" -Status "PASS" -Details "Status: $($Response.status)"
            return $true
        } else {
            Write-TestLog -TestName "Health Check" -Status "FAIL" -Details "Invalid response"
            return $false
        }
    }
    catch {
        Write-TestLog -TestName "Health Check" -Status "ERROR" -Details $_.Exception.Message
        return $false
    }
}

function Test-Authentication {
    try {
        $AuthData = @{
            username = "admin"
            password = "admin123"
        }
        
        $Response = Invoke-RestMethod -Uri "$ApiBase/auth/login" -Method Post -Body $AuthData -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        
        if ($Response.access_token) {
            $script:AuthToken = $Response.access_token
            Write-TestLog -TestName "Authentication" -Status "PASS" -Details "Successfully authenticated"
            return $true
        } else {
            Write-TestLog -TestName "Authentication" -Status "FAIL" -Details "No access token received"
            return $false
        }
    }
    catch {
        Write-TestLog -TestName "Authentication" -Status "ERROR" -Details $_.Exception.Message
        return $false
    }
}

function Test-SastApiEndpoints {
    $Endpoints = @(
        @{ Method = "GET"; Path = "/sast/scans"; Description = "Get SAST Scans" },
        @{ Method = "GET"; Path = "/sast/summary"; Description = "Get SAST Summary" },
        @{ Method = "POST"; Path = "/sast/scan"; Description = "Trigger SAST Scan" }
    )
    
    foreach ($Endpoint in $Endpoints) {
        try {
            $Headers = @{}
            if ($script:AuthToken) {
                $Headers.Authorization = "Bearer $script:AuthToken"
            }
            
            if ($Endpoint.Method -eq "GET") {
                $Response = Invoke-RestMethod -Uri "$ApiBase$($Endpoint.Path)" -Method Get -Headers $Headers -ErrorAction Stop
            } else {
                $Response = Invoke-RestMethod -Uri "$ApiBase$($Endpoint.Path)" -Method Post -Headers $Headers -ErrorAction Stop
            }
            
            Write-TestLog -TestName "SAST API - $($Endpoint.Description)" -Status "PASS" -Details "Endpoint accessible"
        }
        catch {
            Write-TestLog -TestName "SAST API - $($Endpoint.Description)" -Status "ERROR" -Details $_.Exception.Message
        }
    }
}

function Test-SastScanTrigger {
    try {
        $ScanData = @{
            project_path = "/tmp/test-project"
            scan_type = "full"
            languages = @("python", "javascript")
        } | ConvertTo-Json
        
        $Headers = @{
            Authorization = "Bearer $script:AuthToken"
            "Content-Type" = "application/json"
        }
        
        $Response = Invoke-RestMethod -Uri "$ApiBase/sast/scan" -Method Post -Body $ScanData -Headers $Headers -ErrorAction Stop
        
        if ($Response.scan_id) {
            Write-TestLog -TestName "SAST Scan Trigger" -Status "PASS" -Details "Scan ID: $($Response.scan_id)"
            
            # Wait and check scan status
            Start-Sleep -Seconds 2
            
            try {
                $StatusResponse = Invoke-RestMethod -Uri "$ApiBase/sast/scans/$($Response.scan_id)" -Method Get -Headers $Headers -ErrorAction Stop
                Write-TestLog -TestName "SAST Scan Status" -Status "PASS" -Details "Status: $($StatusResponse.status)"
            }
            catch {
                Write-TestLog -TestName "SAST Scan Status" -Status "FAIL" -Details $_.Exception.Message
            }
            
            return $Response.scan_id
        } else {
            Write-TestLog -TestName "SAST Scan Trigger" -Status "FAIL" -Details "No scan ID received"
            return $null
        }
    }
    catch {
        Write-TestLog -TestName "SAST Scan Trigger" -Status "ERROR" -Details $_.Exception.Message
        return $null
    }
}

function Test-SastVulnerabilities {
    try {
        $Headers = @{
            Authorization = "Bearer $script:AuthToken"
        }
        
        $Response = Invoke-RestMethod -Uri "$ApiBase/sast/scans" -Method Get -Headers $Headers -ErrorAction Stop
        
        if ($Response -and $Response.Count -gt 0) {
            $ScanId = $Response[0].id
            
            try {
                $VulnResponse = Invoke-RestMethod -Uri "$ApiBase/sast/scans/$ScanId/vulnerabilities" -Method Get -Headers $Headers -ErrorAction Stop
                Write-TestLog -TestName "SAST Vulnerabilities" -Status "PASS" -Details "Found $($VulnResponse.Count) vulnerabilities"
            }
            catch {
                Write-TestLog -TestName "SAST Vulnerabilities" -Status "FAIL" -Details $_.Exception.Message
            }
        } else {
            Write-TestLog -TestName "SAST Vulnerabilities" -Status "SKIP" -Details "No scans available"
        }
    }
    catch {
        Write-TestLog -TestName "SAST Vulnerabilities" -Status "ERROR" -Details $_.Exception.Message
    }
}

function Test-AiRecommendations {
    try {
        $Headers = @{
            Authorization = "Bearer $script:AuthToken"
        }
        
        $Response = Invoke-RestMethod -Uri "$ApiBase/sast/vulnerabilities/1/recommendations" -Method Get -Headers $Headers -ErrorAction Stop
        
        if ($Response) {
            Write-TestLog -TestName "AI Recommendations" -Status "PASS" -Details "Generated $($Response.Count) recommendations"
        } else {
            Write-TestLog -TestName "AI Recommendations" -Status "FAIL" -Details "No recommendations received"
        }
    }
    catch {
        Write-TestLog -TestName "AI Recommendations" -Status "ERROR" -Details $_.Exception.Message
    }
}

function Test-DevSecOpsIntegration {
    try {
        $WebhookData = @{
            event = "push"
            repository = "test-repo"
            branch = "main"
            commit = "abc123"
        } | ConvertTo-Json
        
        $Headers = @{
            Authorization = "Bearer $script:AuthToken"
            "Content-Type" = "application/json"
        }
        
        $Response = Invoke-RestMethod -Uri "$ApiBase/sast/webhook/github" -Method Post -Body $WebhookData -Headers $Headers -ErrorAction Stop
        
        Write-TestLog -TestName "DevSecOps Webhook" -Status "PASS" -Details "Webhook processed successfully"
    }
    catch {
        Write-TestLog -TestName "DevSecOps Webhook" -Status "ERROR" -Details $_.Exception.Message
    }
}

function Test-FrontendIntegration {
    try {
        $Response = Invoke-WebRequest -Uri $FrontendUrl -Method Get -ErrorAction Stop
        
        if ($Response.StatusCode -eq 200) {
            Write-TestLog -TestName "Frontend Accessibility" -Status "PASS" -Details "Frontend is accessible"
            
            try {
                $SastResponse = Invoke-WebRequest -Uri "$FrontendUrl/sast" -Method Get -ErrorAction Stop
                if ($SastResponse.StatusCode -eq 200) {
                    Write-TestLog -TestName "SAST Dashboard" -Status "PASS" -Details "SAST dashboard is accessible"
                } else {
                    Write-TestLog -TestName "SAST Dashboard" -Status "FAIL" -Details "Status: $($SastResponse.StatusCode)"
                }
            }
            catch {
                Write-TestLog -TestName "SAST Dashboard" -Status "FAIL" -Details $_.Exception.Message
            }
        } else {
            Write-TestLog -TestName "Frontend Accessibility" -Status "FAIL" -Details "Status: $($Response.StatusCode)"
        }
    }
    catch {
        Write-TestLog -TestName "Frontend Integration" -Status "ERROR" -Details $_.Exception.Message
    }
}

function Test-DatabaseIntegration {
    try {
        $Headers = @{
            Authorization = "Bearer $script:AuthToken"
        }
        
        $Response = Invoke-RestMethod -Uri "$ApiBase/sast/scans" -Method Get -Headers $Headers -ErrorAction Stop
        
        if ($Response) {
            Write-TestLog -TestName "Database Integration" -Status "PASS" -Details "Retrieved $($Response.Count) scans from database"
        } else {
            Write-TestLog -TestName "Database Integration" -Status "FAIL" -Details "No scans retrieved"
        }
    }
    catch {
        Write-TestLog -TestName "Database Integration" -Status "ERROR" -Details $_.Exception.Message
    }
}

function Generate-TestReport {
    $Passed = ($script:TestResults | Where-Object { $_.Status -eq "PASS" }).Count
    $Failed = ($script:TestResults | Where-Object { $_.Status -eq "FAIL" }).Count
    $Errors = ($script:TestResults | Where-Object { $_.Status -eq "ERROR" }).Count
    $Skipped = ($script:TestResults | Where-Object { $_.Status -eq "SKIP" }).Count
    $Total = $script:TestResults.Count
    
    $Report = @{
        TestSuite = "SAST Tool End-to-End Test (PowerShell)"
        Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
        Summary = @{
            TotalTests = $Total
            Passed = $Passed
            Failed = $Failed
            Errors = $Errors
            Skipped = $Skipped
        }
        Results = $script:TestResults
    }
    
    # Save report to file
    $ReportFile = "sast-e2e-test-report.json"
    $Report | ConvertTo-Json -Depth 10 | Out-File -FilePath $ReportFile -Encoding UTF8
    
    Write-Host "`n📊 Test Report Summary:" -ForegroundColor Cyan
    Write-Host "   Total Tests: $Total" -ForegroundColor White
    Write-Host "   Passed: $Passed" -ForegroundColor Green
    Write-Host "   Failed: $Failed" -ForegroundColor Red
    Write-Host "   Errors: $Errors" -ForegroundColor Red
    Write-Host "   Skipped: $Skipped" -ForegroundColor Yellow
    Write-Host "`n📄 Detailed report saved to: $ReportFile" -ForegroundColor Cyan
    
    return $Report
}

function Start-SastEndToEndTests {
    Write-Host "🚀 Starting SAST Tool End-to-End Tests (PowerShell)..." -ForegroundColor Green
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    # Run tests in sequence
    $Tests = @(
        @{ Name = "Health Check"; Function = ${function:Test-HealthCheck} },
        @{ Name = "Authentication"; Function = ${function:Test-Authentication} },
        @{ Name = "SAST API Endpoints"; Function = ${function:Test-SastApiEndpoints} },
        @{ Name = "SAST Scan Trigger"; Function = ${function:Test-SastScanTrigger} },
        @{ Name = "SAST Vulnerabilities"; Function = ${function:Test-SastVulnerabilities} },
        @{ Name = "AI Recommendations"; Function = ${function:Test-AiRecommendations} },
        @{ Name = "DevSecOps Integration"; Function = ${function:Test-DevSecOpsIntegration} },
        @{ Name = "Frontend Integration"; Function = ${function:Test-FrontendIntegration} },
        @{ Name = "Database Integration"; Function = ${function:Test-DatabaseIntegration} }
    )
    
    foreach ($Test in $Tests) {
        Write-Host "`n🔍 Running: $($Test.Name)" -ForegroundColor Yellow
        Write-Host "-" * 40 -ForegroundColor Gray
        & $Test.Function
    }
    
    # Generate report
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    $Report = Generate-TestReport
    
    # Final status
    if ($Report.Summary.Failed -eq 0 -and $Report.Summary.Errors -eq 0) {
        Write-Host "✅ All tests completed successfully!" -ForegroundColor Green
        return $true
    } else {
        Write-Host "❌ Some tests failed. Check the report for details." -ForegroundColor Red
        return $false
    }
}

# Main execution
try {
    $Success = Start-SastEndToEndTests
    exit $(if ($Success) { 0 } else { 1 })
}
catch {
    Write-Host "❌ Test execution failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} 