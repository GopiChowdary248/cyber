# SAST Tool End-to-End Test Script (PowerShell)
# Tests all SAST tool functionality including scanning, AI recommendations, and API endpoints

param(
    [string]$SastUrl = "http://localhost:8000"
)

# Configure logging
$LogFile = "sast_tool_test.log"
$TestResults = @()

function Write-TestLog {
    param(
        [string]$TestName,
        [string]$Status,
        [string]$Details = ""
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $result = @{
        Test = $TestName
        Status = $Status
        Details = $Details
        Timestamp = $timestamp
    }
    
    $TestResults += $result
    
    $statusIcon = if ($Status -eq "PASSED") { "✅" } else { "❌" }
    Write-Host "$statusIcon $TestName`: $Status"
    if ($Details) {
        Write-Host "   Details: $Details"
    }
    
    # Log to file
    $logMessage = "[$timestamp] $TestName`: $Status - $Details"
    Add-Content -Path $LogFile -Value $logMessage
}

function Test-HealthCheck {
    try {
        $response = Invoke-RestMethod -Uri "$SastUrl/health" -Method Get -TimeoutSec 10
        Write-TestLog -TestName "Health Check" -Status "PASSED" -Details "Service: $($response.service)"
        return $true
    }
    catch {
        Write-TestLog -TestName "Health Check" -Status "FAILED" -Details $_.Exception.Message
        return $false
    }
}

function Test-ApiDocumentation {
    try {
        $response = Invoke-WebRequest -Uri "$SastUrl/docs" -Method Get -TimeoutSec 10
        if ($response.StatusCode -eq 200) {
            Write-TestLog -TestName "API Documentation" -Status "PASSED" -Details "Swagger UI accessible"
            return $true
        }
        else {
            Write-TestLog -TestName "API Documentation" -Status "FAILED" -Details "Status: $($response.StatusCode)"
            return $false
        }
    }
    catch {
        Write-TestLog -TestName "API Documentation" -Status "FAILED" -Details $_.Exception.Message
        return $false
    }
}

function Test-SastScanTrigger {
    try {
        $scanData = @{
            project_path = "/app/test-project"
            scan_type = "full"
            languages = @("python", "javascript")
            tools = @("bandit", "pylint", "eslint")
        } | ConvertTo-Json
        
        $headers = @{
            "Content-Type" = "application/json"
        }
        
        $response = Invoke-RestMethod -Uri "$SastUrl/api/v1/sast/scan" -Method Post -Body $scanData -Headers $headers -TimeoutSec 30
        
        if ($response.scan_id) {
            Write-TestLog -TestName "SAST Scan Trigger" -Status "PASSED" -Details "Scan ID: $($response.scan_id)"
            return $response.scan_id
        }
        else {
            Write-TestLog -TestName "SAST Scan Trigger" -Status "FAILED" -Details "No scan ID returned"
            return $null
        }
    }
    catch {
        Write-TestLog -TestName "SAST Scan Trigger" -Status "FAILED" -Details $_.Exception.Message
        return $null
    }
}

function Test-SastScanStatus {
    param([string]$ScanId)
    
    try {
        $response = Invoke-RestMethod -Uri "$SastUrl/api/v1/sast/scans/$ScanId" -Method Get -TimeoutSec 10
        
        if ($response.status) {
            Write-TestLog -TestName "SAST Scan Status" -Status "PASSED" -Details "Status: $($response.status)"
            return $response.status
        }
        else {
            Write-TestLog -TestName "SAST Scan Status" -Status "FAILED" -Details "No status returned"
            return $null
        }
    }
    catch {
        Write-TestLog -TestName "SAST Scan Status" -Status "FAILED" -Details $_.Exception.Message
        return $null
    }
}

function Test-SastResultsRetrieval {
    param([string]$ScanId)
    
    try {
        $response = Invoke-RestMethod -Uri "$SastUrl/api/v1/sast/scans/$ScanId/vulnerabilities" -Method Get -TimeoutSec 10
        
        if ($response.vulnerabilities) {
            $vulnCount = $response.vulnerabilities.Count
            Write-TestLog -TestName "SAST Results Retrieval" -Status "PASSED" -Details "Found $vulnCount vulnerabilities"
            return $response.vulnerabilities
        }
        else {
            Write-TestLog -TestName "SAST Results Retrieval" -Status "PASSED" -Details "No vulnerabilities found"
            return @()
        }
    }
    catch {
        Write-TestLog -TestName "SAST Results Retrieval" -Status "FAILED" -Details $_.Exception.Message
        return @()
    }
}

function Test-AiRecommendations {
    param([string]$VulnerabilityId)
    
    try {
        $response = Invoke-RestMethod -Uri "$SastUrl/api/v1/sast/vulnerabilities/$VulnerabilityId/recommendations" -Method Get -TimeoutSec 10
        
        if ($response.recommendations) {
            $recCount = $response.recommendations.Count
            Write-TestLog -TestName "AI Recommendations" -Status "PASSED" -Details "Generated $recCount recommendations"
            return $response.recommendations
        }
        else {
            Write-TestLog -TestName "AI Recommendations" -Status "PASSED" -Details "No recommendations generated"
            return @()
        }
    }
    catch {
        Write-TestLog -TestName "AI Recommendations" -Status "FAILED" -Details $_.Exception.Message
        return @()
    }
}

function Test-SastSummary {
    try {
        $response = Invoke-RestMethod -Uri "$SastUrl/api/v1/sast/summary" -Method Get -TimeoutSec 10
        
        Write-TestLog -TestName "SAST Summary" -Status "PASSED" -Details "Summary retrieved successfully"
        return $response
    }
    catch {
        Write-TestLog -TestName "SAST Summary" -Status "FAILED" -Details $_.Exception.Message
        return $null
    }
}

function Test-FileUploadScan {
    try {
        # Create a test file with vulnerabilities
        $testFileContent = @"
import os
import subprocess

# SQL Injection vulnerability
def vulnerable_query(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query

# Command injection vulnerability
def vulnerable_command(command):
    os.system(command)

# Hardcoded credentials
password = "admin123"
api_key = "sk-1234567890abcdef"

# XSS vulnerability
def vulnerable_xss(user_input):
    return f"<div>{user_input}</div>"
"@
        
        # Create test file
        $testFilePath = "test_vulnerable_code.py"
        $testFileContent | Out-File -FilePath $testFilePath -Encoding UTF8
        
        # Upload and scan
        $form = @{
            file = Get-Item -Path $testFilePath
            scan_type = "full"
            languages = "python"
            tools = "bandit,pylint"
        }
        
        $response = Invoke-RestMethod -Uri "$SastUrl/api/v1/sast/scan/upload" -Method Post -Form $form -TimeoutSec 60
        
        # Clean up test file
        Remove-Item -Path $testFilePath -Force
        
        if ($response.scan_id) {
            Write-TestLog -TestName "File Upload Scan" -Status "PASSED" -Details "Scan ID: $($response.scan_id)"
            return $response.scan_id
        }
        else {
            Write-TestLog -TestName "File Upload Scan" -Status "FAILED" -Details "No scan ID returned"
            return $null
        }
    }
    catch {
        Write-TestLog -TestName "File Upload Scan" -Status "FAILED" -Details $_.Exception.Message
        return $null
    }
}

function Test-ReportGeneration {
    param([string]$ScanId)
    
    try {
        $response = Invoke-RestMethod -Uri "$SastUrl/api/v1/sast/reports/$ScanId" -Method Get -TimeoutSec 30
        
        Write-TestLog -TestName "Report Generation" -Status "PASSED" -Details "Report generated successfully"
        return $response
    }
    catch {
        Write-TestLog -TestName "Report Generation" -Status "FAILED" -Details $_.Exception.Message
        return $null
    }
}

function Test-VulnerabilityStatusUpdate {
    param([string]$VulnerabilityId)
    
    try {
        $updateData = @{
            status = "false_positive"
            comment = "Test status update"
        } | ConvertTo-Json
        
        $headers = @{
            "Content-Type" = "application/json"
        }
        
        $response = Invoke-RestMethod -Uri "$SastUrl/api/v1/sast/vulnerabilities/$VulnerabilityId/status" -Method Post -Body $updateData -Headers $headers -TimeoutSec 10
        
        Write-TestLog -TestName "Vulnerability Status Update" -Status "PASSED" -Details "Status updated successfully"
        return $true
    }
    catch {
        Write-TestLog -TestName "Vulnerability Status Update" -Status "FAILED" -Details $_.Exception.Message
        return $false
    }
}

function Test-ScanListing {
    try {
        $response = Invoke-RestMethod -Uri "$SastUrl/api/v1/sast/scans" -Method Get -TimeoutSec 10
        
        if ($response.scans) {
            $scanCount = $response.scans.Count
            Write-TestLog -TestName "Scan Listing" -Status "PASSED" -Details "Found $scanCount scans"
            return $response.scans
        }
        else {
            Write-TestLog -TestName "Scan Listing" -Status "PASSED" -Details "No scans found"
            return @()
        }
    }
    catch {
        Write-TestLog -TestName "Scan Listing" -Status "FAILED" -Details $_.Exception.Message
        return @()
    }
}

function Start-ComprehensiveTest {
    Write-Host "🚀 Starting Comprehensive SAST Tool Test" -ForegroundColor Green
    
    # Basic connectivity tests
    if (-not (Test-HealthCheck)) {
        Write-Host "❌ Health check failed. SAST tool may not be running." -ForegroundColor Red
        return $false
    }
    
    if (-not (Test-ApiDocumentation)) {
        Write-Host "⚠️ API documentation not accessible" -ForegroundColor Yellow
    }
    
    # Test scan triggering
    $scanId = Test-SastScanTrigger
    if ($scanId) {
        # Wait for scan to complete
        Write-Host "⏳ Waiting for scan to complete..." -ForegroundColor Yellow
        Start-Sleep -Seconds 10
        
        # Test scan status
        $status = Test-SastScanStatus -ScanId $scanId
        
        # Test results retrieval
        $vulnerabilities = Test-SastResultsRetrieval -ScanId $scanId
        
        # Test AI recommendations if vulnerabilities found
        if ($vulnerabilities -and $vulnerabilities.Count -gt 0) {
            $firstVuln = $vulnerabilities[0]
            $vulnId = $firstVuln.id
            if ($vulnId) {
                Test-AiRecommendations -VulnerabilityId $vulnId
                Test-VulnerabilityStatusUpdate -VulnerabilityId $vulnId
            }
        }
    }
    
    # Test file upload scan
    $uploadScanId = Test-FileUploadScan
    if ($uploadScanId) {
        Start-Sleep -Seconds 10
        Test-ReportGeneration -ScanId $uploadScanId
    }
    
    # Test summary and listing
    Test-SastSummary
    Test-ScanListing
    
    # Generate test report
    Generate-TestReport
    
    Write-Host "🎉 Comprehensive SAST Tool Test Completed!" -ForegroundColor Green
    return $true
}

function Generate-TestReport {
    $passedTests = ($TestResults | Where-Object { $_.Status -eq "PASSED" }).Count
    $totalTests = $TestResults.Count
    $failedTests = $totalTests - $passedTests
    
    $report = @{
        test_summary = @{
            total_tests = $totalTests
            passed = $passedTests
            failed = $failedTests
            timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        test_results = $TestResults
        recommendations = Generate-Recommendations
    }
    
    # Save report
    $reportFile = "sast_tool_test_report.json"
    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportFile -Encoding UTF8
    
    Write-Host "📊 Test report saved to: $reportFile" -ForegroundColor Cyan
    
    # Print summary
    Write-Host "📈 Test Results: $passedTests/$totalTests tests passed" -ForegroundColor Cyan
}

function Generate-Recommendations {
    $recommendations = @()
    
    $failedTests = $TestResults | Where-Object { $_.Status -eq "FAILED" }
    
    if ($failedTests) {
        $recommendations += "Review failed tests and fix underlying issues"
    }
    
    $healthCheckPassed = $TestResults | Where-Object { $_.Test -eq "Health Check" -and $_.Status -eq "PASSED" }
    if (-not $healthCheckPassed) {
        $recommendations += "Ensure SAST tool is running and accessible"
    }
    
    $apiDocPassed = $TestResults | Where-Object { $_.Test -eq "API Documentation" -and $_.Status -eq "PASSED" }
    if (-not $apiDocPassed) {
        $recommendations += "Check API documentation endpoint configuration"
    }
    
    return $recommendations
}

# Main execution
Write-Host "🔧 Testing SAST Tool at: $SastUrl" -ForegroundColor Green

# Clear log file
if (Test-Path $LogFile) {
    Remove-Item $LogFile -Force
}

$success = Start-ComprehensiveTest

if ($success) {
    Write-Host "✅ All SAST tool tests completed successfully!" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "❌ Some SAST tool tests failed!" -ForegroundColor Red
    exit 1
} 