# Comprehensive End-to-End Test Runner for CyberShield Platform
# PowerShell script for Windows systems

param(
    [switch]$StartApplication,
    [switch]$SkipInfrastructure,
    [switch]$Verbose
)

# Set error action preference
$ErrorActionPreference = "Continue"

# Colors for output
$Colors = @{
    Success = "Green"
    Error = "Red"
    Warning = "Yellow"
    Info = "Cyan"
    Header = "Magenta"
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Colors[$Color]
}

function Test-ApplicationRunning {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:3000" -TimeoutSec 5 -UseBasicParsing
        return $response.StatusCode -eq 200
    }
    catch {
        return $false
    }
}

function Start-CyberShieldApplication {
    Write-ColorOutput "🚀 Starting CyberShield Application..." "Header"
    
    # Check if Docker is running
    try {
        docker version | Out-Null
        Write-ColorOutput "✅ Docker is running" "Success"
    }
    catch {
        Write-ColorOutput "❌ Docker is not running. Please start Docker Desktop first." "Error"
        exit 1
    }
    
    # Start the application
    Write-ColorOutput "📦 Starting containers with docker-compose..." "Info"
    docker-compose up -d
    
    if ($LASTEXITCODE -eq 0) {
        Write-ColorOutput "✅ Containers started successfully" "Success"
    }
    else {
        Write-ColorOutput "❌ Failed to start containers" "Error"
        exit 1
    }
    
    # Wait for services to be ready
    Write-ColorOutput "⏳ Waiting for services to be ready..." "Info"
    $maxAttempts = 30
    $attempt = 0
    
    while ($attempt -lt $maxAttempts) {
        if (Test-ApplicationRunning) {
            Write-ColorOutput "✅ Application is ready!" "Success"
            break
        }
        
        $attempt++
        Write-ColorOutput "⏳ Attempt $attempt/$maxAttempts - Waiting for application to be ready..." "Warning"
        Start-Sleep -Seconds 10
    }
    
    if ($attempt -eq $maxAttempts) {
        Write-ColorOutput "❌ Application failed to start within expected time" "Error"
        Write-ColorOutput "📋 Checking container status..." "Info"
        docker-compose ps
        exit 1
    }
}

function Install-PythonDependencies {
    Write-ColorOutput "🐍 Installing Python dependencies..." "Info"
    
    $requirements = @(
        "requests",
        "docker",
        "psutil"
    )
    
    foreach ($package in $requirements) {
        try {
            pip install $package --quiet
            Write-ColorOutput "✅ Installed $package" "Success"
        }
        catch {
            Write-ColorOutput "⚠️ Failed to install $package (may already be installed)" "Warning"
        }
    }
}

function Run-ComprehensiveTest {
    Write-ColorOutput "🧪 Running Comprehensive End-to-End Test Suite..." "Header"
    
    # Check if Python is available
    try {
        python --version | Out-Null
        Write-ColorOutput "✅ Python is available" "Success"
    }
    catch {
        Write-ColorOutput "❌ Python is not available. Please install Python 3.7+ first." "Error"
        exit 1
    }
    
    # Install dependencies
    Install-PythonDependencies
    
    # Run the comprehensive test
    $testScript = Join-Path $PSScriptRoot "comprehensive-e2e-test.py"
    
    if (Test-Path $testScript) {
        Write-ColorOutput "🚀 Executing comprehensive test suite..." "Info"
        python $testScript
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "✅ All tests passed! Application is ready for production." "Success"
        }
        else {
            Write-ColorOutput "❌ Some tests failed. Please review the test report." "Error"
        }
    }
    else {
        Write-ColorOutput "❌ Test script not found: $testScript" "Error"
        exit 1
    }
}

function Show-ApplicationStatus {
    Write-ColorOutput "📊 Application Status Check..." "Header"
    
    # Check container status
    Write-ColorOutput "🐳 Container Status:" "Info"
    docker-compose ps
    
    # Check service health
    $services = @(
        @{Name="Frontend"; URL="http://localhost:3000"},
        @{Name="Backend API"; URL="http://localhost:8000"},
        @{Name="API Docs"; URL="http://localhost:8000/docs"},
        @{Name="Database"; URL="http://localhost:5432"}
    )
    
    Write-ColorOutput "🔍 Service Health Check:" "Info"
    foreach ($service in $services) {
        try {
            $response = Invoke-WebRequest -Uri $service.URL -TimeoutSec 5 -UseBasicParsing
            Write-ColorOutput "✅ $($service.Name): $($response.StatusCode)" "Success"
        }
        catch {
            Write-ColorOutput "❌ $($service.Name): Not accessible" "Error"
        }
    }
}

function Show-TestResults {
    Write-ColorOutput "📋 Recent Test Results:" "Header"
    
    $testReports = Get-ChildItem -Path $PSScriptRoot -Filter "comprehensive_e2e_test_report_*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 3
    
    if ($testReports) {
        foreach ($report in $testReports) {
            try {
                $content = Get-Content $report.FullName | ConvertFrom-Json
                $summary = $content.test_summary
                
                Write-ColorOutput "📄 $($report.Name):" "Info"
                Write-ColorOutput "   Date: $($summary.test_date)" "Info"
                Write-ColorOutput "   Total Tests: $($summary.total_tests)" "Info"
                Write-ColorOutput "   Passed: $($summary.passed_tests) ✅" "Success"
                Write-ColorOutput "   Failed: $($summary.failed_tests) ❌" "Error"
                Write-ColorOutput "   Success Rate: $([math]::Round($summary.success_rate, 1))%" "Info"
                Write-ColorOutput "   Status: $($summary.overall_status)" "Info"
                Write-ColorOutput ""
            }
            catch {
                Write-ColorOutput "⚠️ Could not parse report: $($report.Name)" "Warning"
            }
        }
    }
    else {
        Write-ColorOutput "ℹ️ No test reports found" "Info"
    }
}

function Show-Help {
    Write-ColorOutput "🛡️ CyberShield Comprehensive End-to-End Test Suite" "Header"
    Write-ColorOutput "=" * 60 "Info"
    Write-ColorOutput ""
    Write-ColorOutput "Usage:" "Info"
    Write-ColorOutput "  .\run-comprehensive-e2e-test.ps1 [Options]" "Info"
    Write-ColorOutput ""
    Write-ColorOutput "Options:" "Info"
    Write-ColorOutput "  -StartApplication    Start the application before running tests" "Info"
    Write-ColorOutput "  -SkipInfrastructure  Skip infrastructure checks" "Info"
    Write-ColorOutput "  -Verbose            Show detailed output" "Info"
    Write-ColorOutput "  -Help               Show this help message" "Info"
    Write-ColorOutput ""
    Write-ColorOutput "Examples:" "Info"
    Write-ColorOutput "  .\run-comprehensive-e2e-test.ps1" "Info"
    Write-ColorOutput "  .\run-comprehensive-e2e-test.ps1 -StartApplication" "Info"
    Write-ColorOutput "  .\run-comprehensive-e2e-test.ps1 -Verbose" "Info"
    Write-ColorOutput ""
    Write-ColorOutput "Prerequisites:" "Info"
    Write-ColorOutput "  - Docker Desktop running" "Info"
    Write-ColorOutput "  - Python 3.7+ installed" "Info"
    Write-ColorOutput "  - PowerShell 5.0+" "Info"
    Write-ColorOutput ""
}

# Main execution
Write-ColorOutput "🛡️ CyberShield Comprehensive End-to-End Test Suite" "Header"
Write-ColorOutput "=" * 60 "Info"
Write-ColorOutput "Started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "Info"
Write-ColorOutput ""

# Parse parameters
if ($args -contains "-Help" -or $args -contains "-h") {
    Show-Help
    exit 0
}

# Check if application is running
$appRunning = Test-ApplicationRunning

if (-not $appRunning) {
    if ($StartApplication) {
        Start-CyberShieldApplication
    }
    else {
        Write-ColorOutput "❌ Application is not running" "Error"
        Write-ColorOutput "💡 Use -StartApplication to start the application automatically" "Info"
        Write-ColorOutput "💡 Or run 'docker-compose up -d' manually" "Info"
        exit 1
    }
}
else {
    Write-ColorOutput "✅ Application is already running" "Success"
}

# Show application status if verbose
if ($Verbose) {
    Show-ApplicationStatus
    Write-ColorOutput ""
}

# Run comprehensive test
Run-ComprehensiveTest

# Show test results
Write-ColorOutput ""
Show-TestResults

Write-ColorOutput ""
Write-ColorOutput "🎉 Test execution completed!" "Success"
Write-ColorOutput "📄 Check the generated test reports for detailed results" "Info" 