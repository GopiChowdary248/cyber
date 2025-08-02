# Comprehensive Security Test Runner for PowerShell
# Tests all Application Security features: SAST, DAST, and RASP

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# Configuration
$CyberShieldAPI = "http://localhost:8000"
$VulnerableApp = "http://localhost:5000"
$AuthToken = "mock_admin_token_123"
$Headers = @{
    "Authorization" = "Bearer $AuthToken"
    "Content-Type" = "application/json"
}

# Test results storage
$TestResults = @{
    "sast" = @()
    "dast" = @()
    "rasp" = @()
    "frontend" = @()
    "summary" = @{}
}

function Write-TestLog {
    param(
        [string]$TestType,
        [string]$TestName,
        [string]$Status,
        [string]$Details = ""
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    $result = @{
        "test_name" = $TestName
        "status" = $Status
        "timestamp" = $timestamp
        "details" = $Details
    }
    
    $TestResults[$TestType] += $result
    
    $statusColor = switch ($Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "ERROR" { "Yellow" }
        "WARN" { "Yellow" }
        default { "White" }
    }
    
    Write-Host "[$Status]" -ForegroundColor $statusColor -NoNewline
    Write-Host " $TestType.ToUpper() - $TestName`: $Details"
}

function Test-SASTFunctionality {
    Write-Host "`n🔍 Testing SAST Functionality..." -ForegroundColor Cyan
    Write-Host "=" * 50
    
    # Test 1: Trigger SAST scan
    try {
        $response = Invoke-RestMethod -Uri "$CyberShieldAPI/api/v1/security/sast/scan" -Method POST -Headers $Headers
        Write-TestLog "sast" "SAST Scan Trigger" "PASS" "Scan triggered successfully"
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-TestLog "sast" "SAST Scan Trigger" "FAIL" "Status: $statusCode"
    }
    
    # Test 2: Get SAST results
    try {
        $response = Invoke-RestMethod -Uri "$CyberShieldAPI/api/v1/security/sast/results" -Method GET -Headers $Headers
        $vulnerabilityCount = $response.Count
        Write-TestLog "sast" "SAST Results Retrieval" "PASS" "Found $vulnerabilityCount vulnerabilities"
        
        # Analyze vulnerability types
        $severityCounts = @{
            "critical" = 0
            "high" = 0
            "medium" = 0
            "low" = 0
        }
        
        foreach ($vuln in $response) {
            $severity = $vuln.severity.ToLower()
            if ($severityCounts.ContainsKey($severity)) {
                $severityCounts[$severity]++
            }
        }
        
        $details = "Critical: $($severityCounts['critical']), High: $($severityCounts['high']), Medium: $($severityCounts['medium']), Low: $($severityCounts['low'])"
        Write-TestLog "sast" "SAST Vulnerability Analysis" "PASS" $details
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-TestLog "sast" "SAST Results Retrieval" "FAIL" "Status: $statusCode"
    }
    
    # Test 3: Validate SAST vulnerability details
    try {
        $response = Invoke-RestMethod -Uri "$CyberShieldAPI/api/v1/security/sast/results" -Method GET -Headers $Headers
        if ($response.Count -gt 0) {
            $vuln = $response[0]
            $requiredFields = @("file_name", "severity", "description", "recommendation")
            $missingFields = @()
            
            foreach ($field in $requiredFields) {
                if (-not $vuln.PSObject.Properties.Name.Contains($field)) {
                    $missingFields += $field
                }
            }
            
            if ($missingFields.Count -eq 0) {
                Write-TestLog "sast" "SAST Vulnerability Details" "PASS" "All required fields present"
            }
            else {
                Write-TestLog "sast" "SAST Vulnerability Details" "FAIL" "Missing fields: $($missingFields -join ', ')"
            }
        }
        else {
            Write-TestLog "sast" "SAST Vulnerability Details" "WARN" "No vulnerabilities found"
        }
    }
    catch {
        Write-TestLog "sast" "SAST Vulnerability Details" "ERROR" $_.Exception.Message
    }
}

function Test-DASTFunctionality {
    Write-Host "`n🔍 Testing DAST Functionality..." -ForegroundColor Cyan
    Write-Host "=" * 50
    
    # Test 1: Trigger DAST scan
    try {
        $response = Invoke-RestMethod -Uri "$CyberShieldAPI/api/v1/security/dast/scan" -Method POST -Headers $Headers
        Write-TestLog "dast" "DAST Scan Trigger" "PASS" "Scan triggered successfully"
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-TestLog "dast" "DAST Scan Trigger" "FAIL" "Status: $statusCode"
    }
    
    # Test 2: Get DAST results
    try {
        $response = Invoke-RestMethod -Uri "$CyberShieldAPI/api/v1/security/dast/results" -Method GET -Headers $Headers
        $vulnerabilityCount = $response.Count
        Write-TestLog "dast" "DAST Results Retrieval" "PASS" "Found $vulnerabilityCount vulnerabilities"
        
        # Analyze vulnerability types
        $vulnTypes = @{}
        foreach ($vuln in $response) {
            $vulnType = $vuln.vulnerability_type
            if ($vulnTypes.ContainsKey($vulnType)) {
                $vulnTypes[$vulnType]++
            }
            else {
                $vulnTypes[$vulnType] = 1
            }
        }
        
        $typesList = $vulnTypes.Keys -join ", "
        Write-TestLog "dast" "DAST Vulnerability Types" "PASS" "Types found: $typesList"
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-TestLog "dast" "DAST Results Retrieval" "FAIL" "Status: $statusCode"
    }
    
    # Test 3: Validate DAST vulnerability details
    try {
        $response = Invoke-RestMethod -Uri "$CyberShieldAPI/api/v1/security/dast/results" -Method GET -Headers $Headers
        if ($response.Count -gt 0) {
            $vuln = $response[0]
            $requiredFields = @("url", "severity", "vulnerability_type", "recommendation", "cwe_id")
            $missingFields = @()
            
            foreach ($field in $requiredFields) {
                if (-not $vuln.PSObject.Properties.Name.Contains($field)) {
                    $missingFields += $field
                }
            }
            
            if ($missingFields.Count -eq 0) {
                Write-TestLog "dast" "DAST Vulnerability Details" "PASS" "All required fields present"
            }
            else {
                Write-TestLog "dast" "DAST Vulnerability Details" "FAIL" "Missing fields: $($missingFields -join ', ')"
            }
        }
        else {
            Write-TestLog "dast" "DAST Vulnerability Details" "WARN" "No vulnerabilities found"
        }
    }
    catch {
        Write-TestLog "dast" "DAST Vulnerability Details" "ERROR" $_.Exception.Message
    }
}

function Test-RASPFunctionality {
    Write-Host "`n🔍 Testing RASP Functionality..." -ForegroundColor Cyan
    Write-Host "=" * 50
    
    # Test 1: Get RASP logs
    try {
        $response = Invoke-RestMethod -Uri "$CyberShieldAPI/api/v1/security/rasp/logs" -Method GET -Headers $Headers
        $incidentCount = $response.Count
        Write-TestLog "rasp" "RASP Logs Retrieval" "PASS" "Found $incidentCount incidents"
        
        # Analyze incident types
        $incidentTypes = @{}
        $blockedCount = 0
        foreach ($log in $response) {
            $incidentType = $log.incident_type
            if ($incidentTypes.ContainsKey($incidentType)) {
                $incidentTypes[$incidentType]++
            }
            else {
                $incidentTypes[$incidentType] = 1
            }
            
            if ($log.blocked) {
                $blockedCount++
            }
        }
        
        $typesList = $incidentTypes.Keys -join ", "
        Write-TestLog "rasp" "RASP Incident Analysis" "PASS" "Types: $typesList, Blocked: $blockedCount"
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-TestLog "rasp" "RASP Logs Retrieval" "FAIL" "Status: $statusCode"
    }
    
    # Test 2: Get RASP status
    try {
        $response = Invoke-RestMethod -Uri "$CyberShieldAPI/api/v1/security/rasp/status" -Method GET -Headers $Headers
        if ($response.protection_enabled) {
            Write-TestLog "rasp" "RASP Protection Status" "PASS" "Protection is active"
        }
        else {
            Write-TestLog "rasp" "RASP Protection Status" "WARN" "Protection is not active"
        }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-TestLog "rasp" "RASP Protection Status" "FAIL" "Status: $statusCode"
    }
    
    # Test 3: Validate RASP log details
    try {
        $response = Invoke-RestMethod -Uri "$CyberShieldAPI/api/v1/security/rasp/logs" -Method GET -Headers $Headers
        if ($response.Count -gt 0) {
            $log = $response[0]
            $requiredFields = @("incident_type", "status", "description", "blocked", "timestamp")
            $missingFields = @()
            
            foreach ($field in $requiredFields) {
                if (-not $log.PSObject.Properties.Name.Contains($field)) {
                    $missingFields += $field
                }
            }
            
            if ($missingFields.Count -eq 0) {
                Write-TestLog "rasp" "RASP Log Details" "PASS" "All required fields present"
            }
            else {
                Write-TestLog "rasp" "RASP Log Details" "FAIL" "Missing fields: $($missingFields -join ', ')"
            }
        }
        else {
            Write-TestLog "rasp" "RASP Log Details" "WARN" "No incidents found"
        }
    }
    catch {
        Write-TestLog "rasp" "RASP Log Details" "ERROR" $_.Exception.Message
    }
}

function Test-SecuritySummary {
    Write-Host "`n🔍 Testing Security Summary..." -ForegroundColor Cyan
    Write-Host "=" * 50
    
    try {
        $response = Invoke-RestMethod -Uri "$CyberShieldAPI/api/v1/security/summary" -Method GET -Headers $Headers
        Write-TestLog "summary" "Security Summary Retrieval" "PASS" "Summary retrieved successfully"
        
        # Validate summary structure
        $requiredFields = @(
            "sast_critical", "sast_high", "sast_medium", "sast_low",
            "dast_critical", "dast_high", "dast_medium", "dast_low",
            "rasp_blocked", "rasp_incidents"
        )
        $missingFields = @()
        
        foreach ($field in $requiredFields) {
            if (-not $response.PSObject.Properties.Name.Contains($field)) {
                $missingFields += $field
            }
        }
        
        if ($missingFields.Count -eq 0) {
            Write-TestLog "summary" "Security Summary Structure" "PASS" "All required fields present"
            
            # Calculate totals
            $totalSast = $response.sast_critical + $response.sast_high + $response.sast_medium + $response.sast_low
            $totalDast = $response.dast_critical + $response.dast_high + $response.dast_medium + $response.dast_low
            
            $details = "SAST: $totalSast, DAST: $totalDast, RASP: $($response.rasp_incidents)"
            Write-TestLog "summary" "Security Summary Totals" "PASS" $details
        }
        else {
            Write-TestLog "summary" "Security Summary Structure" "FAIL" "Missing fields: $($missingFields -join ', ')"
        }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-TestLog "summary" "Security Summary Retrieval" "FAIL" "Status: $statusCode"
    }
}

function Test-FrontendIntegration {
    Write-Host "`n🔍 Testing Frontend Integration..." -ForegroundColor Cyan
    Write-Host "=" * 50
    
    # Test Application Security page accessibility
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:3000/application-security" -Method GET
        Write-TestLog "frontend" "Application Security Page" "PASS" "Page accessible"
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-TestLog "frontend" "Application Security Page" "FAIL" "Status: $statusCode"
    }
    
    # Test main application accessibility
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:3000" -Method GET
        Write-TestLog "frontend" "Main Application" "PASS" "Application accessible"
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-TestLog "frontend" "Main Application" "FAIL" "Status: $statusCode"
    }
}

function Generate-TestReport {
    Write-Host "`n📊 Generating Test Report..." -ForegroundColor Cyan
    Write-Host "=" * 50
    
    # Calculate test statistics
    $totalTests = 0
    $passedTests = 0
    $failedTests = 0
    $errorTests = 0
    
    foreach ($testType in @("sast", "dast", "rasp", "frontend")) {
        foreach ($test in $TestResults[$testType]) {
            $totalTests++
            switch ($test.status) {
                "PASS" { $passedTests++ }
                "FAIL" { $failedTests++ }
                "ERROR" { $errorTests++ }
            }
        }
    }
    
    $successRate = if ($totalTests -gt 0) { ($passedTests / $totalTests) * 100 } else { 0 }
    
    # Generate summary
    $TestResults["summary"] = @{
        "total_tests" = $totalTests
        "passed_tests" = $passedTests
        "failed_tests" = $failedTests
        "error_tests" = $errorTests
        "success_rate" = $successRate
        "timestamp" = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    }
    
    # Print summary
    Write-Host "📈 Test Summary:" -ForegroundColor Green
    Write-Host "   Total Tests: $totalTests"
    Write-Host "   Passed: $passedTests" -ForegroundColor Green
    Write-Host "   Failed: $failedTests" -ForegroundColor Red
    Write-Host "   Errors: $errorTests" -ForegroundColor Yellow
    Write-Host "   Success Rate: $([math]::Round($successRate, 1))%" -ForegroundColor Green
    
    # Save report to file
    $reportFile = "security_test_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $TestResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportFile -Encoding UTF8
    
    Write-Host "📄 Test report saved to: $reportFile" -ForegroundColor Cyan
    
    return $TestResults
}

# Main execution
Write-Host "🚀 Starting Comprehensive Security Testing..." -ForegroundColor Green
Write-Host "=" * 60

Test-SASTFunctionality
Test-DASTFunctionality
Test-RASPFunctionality
Test-SecuritySummary
Test-FrontendIntegration

Write-Host "`n" + ("=" * 60)
Write-Host "✅ All tests completed!" -ForegroundColor Green

$results = Generate-TestReport 