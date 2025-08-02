# Simple End-to-End Test Runner for CyberShield Application

param(
    [switch]$StartApp,
    [switch]$Verbose
)

Write-Host "🔧 End-to-End Test Runner for CyberShield" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Python not found. Please install Python 3.7+ and try again." -ForegroundColor Red
    exit 1
}

# Check if Docker is available
try {
    $dockerVersion = docker --version 2>&1
    Write-Host "✅ Docker found: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker not found. Please install Docker and try again." -ForegroundColor Red
    exit 1
}

# Start application if requested
if ($StartApp) {
    Write-Host "🚀 Starting CyberShield application..." -ForegroundColor Yellow
    docker-compose up -d
    Write-Host "⏳ Waiting for application to start..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
}

# Check Python dependencies
Write-Host "📦 Checking Python dependencies..." -ForegroundColor Yellow
try {
    python -c "import requests; print('OK')" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "📥 Installing requests module..." -ForegroundColor Yellow
        pip install requests
    } else {
        Write-Host "✅ Python dependencies are available" -ForegroundColor Green
    }
} catch {
    Write-Host "❌ Failed to check Python dependencies" -ForegroundColor Red
    exit 1
}

# Run the E2E test
Write-Host "🧪 Running End-to-End Tests..." -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan

if ($Verbose) {
    python fixed-e2e-test.py
} else {
    python fixed-e2e-test.py
}

$exitCode = $LASTEXITCODE

if ($exitCode -eq 0) {
    Write-Host "🎉 All tests passed!" -ForegroundColor Green
} else {
    Write-Host "❌ Some tests failed. Check the output above for details." -ForegroundColor Red
}

# Show results if available
if (Test-Path "fixed-e2e-test-results.json") {
    Write-Host "📄 Test results saved to: fixed-e2e-test-results.json" -ForegroundColor Cyan
}

exit $exitCode 