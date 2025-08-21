# Dashboard API Diagnostic Script
# This script will check which API endpoints the dashboard is trying to call

Write-Host "🔍 Dashboard API Diagnostic" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan

# Check if backend is running
Write-Host "🔍 Checking backend status..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get -TimeoutSec 5
    Write-Host "✅ Backend is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Backend is not running. Please start the backend first!" -ForegroundColor Red
    Write-Host "💡 Run: cd backend && python main.py" -ForegroundColor Yellow
    exit 1
}

# Test dashboard API endpoints
Write-Host ""
Write-Host "🔍 Testing Dashboard API Endpoints..." -ForegroundColor Yellow
Write-Host "=====================================" -ForegroundColor Yellow

# Test incidents endpoint
Write-Host "📊 Testing incidents endpoint..." -ForegroundColor White
try {
    $response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/incident-management/incidents?page=1&size=5" -Method Get -TimeoutSec 5
    Write-Host "✅ Incidents endpoint working" -ForegroundColor Green
} catch {
    Write-Host "❌ Incidents endpoint failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test system status endpoint
Write-Host "🖥️ Testing system status endpoint..." -ForegroundColor White
try {
    $response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/admin/status" -Method Get -TimeoutSec 5
    Write-Host "✅ System status endpoint working" -ForegroundColor Green
} catch {
    Write-Host "❌ System status endpoint failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test admin overview endpoint
Write-Host "⚙️ Testing admin overview endpoint..." -ForegroundColor White
try {
    $response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/admin/dashboard" -Method Get -TimeoutSec 5
    Write-Host "✅ Admin overview endpoint working" -ForegroundColor Green
} catch {
    Write-Host "❌ Admin overview endpoint failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test users management endpoint
Write-Host "👥 Testing users management endpoint..." -ForegroundColor White
try {
    $response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/user-management/profiles?page=1&size=5" -Method Get -TimeoutSec 5
    Write-Host "✅ Users management endpoint working" -ForegroundColor Green
} catch {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/admin/users?page=1&size=5" -Method Get -TimeoutSec 5
        Write-Host "✅ Users management endpoint working (admin path)" -ForegroundColor Green
    } catch {
        Write-Host "❌ Users management endpoint failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "🎯 Summary:" -ForegroundColor Cyan
Write-Host "If any endpoints are failing, the dashboard will show 'Failed to load dashboard data'" -ForegroundColor White
Write-Host "Check the browser console for specific error messages" -ForegroundColor Yellow
Write-Host "Run the test scripts to verify all endpoints are working" -ForegroundColor Yellow
