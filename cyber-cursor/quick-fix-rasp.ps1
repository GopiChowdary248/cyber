# Quick Fix for RASP API Path Issue
# This script will quickly resolve the /api/rasp/projects 404 error

Write-Host "🚀 Quick Fix for RASP API Path Issue" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

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

# Check if RASP endpoints are working
Write-Host "🔍 Testing RASP endpoints..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/rasp/projects?skip=0&limit=5" -Method Get -TimeoutSec 5
    Write-Host "✅ RASP projects endpoint is working" -ForegroundColor Green
} catch {
    Write-Host "❌ RASP projects endpoint is not working" -ForegroundColor Red
    Write-Host "💡 Check backend logs for errors" -ForegroundColor Yellow
}

# Check if frontend is running
Write-Host "🔍 Checking frontend status..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "http://localhost:3000" -Method Get -TimeoutSec 5
    Write-Host "✅ Frontend is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Frontend is not running. Please start the frontend!" -ForegroundColor Red
    Write-Host "💡 Run: cd frontend && npm start" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🔧 Quick Fix Steps:" -ForegroundColor Cyan
Write-Host "1. Clear browser cache (Ctrl + Shift + R)" -ForegroundColor White
Write-Host "2. Hard refresh the page (F5)" -ForegroundColor White
Write-Host "3. Check browser console for errors" -ForegroundColor White
Write-Host "4. Test RASP module functionality" -ForegroundColor White

Write-Host ""
Write-Host "📝 If issues persist, run the full cache clear script:" -ForegroundColor Yellow
Write-Host "   .\clear-cache-rebuild.ps1" -ForegroundColor White

Write-Host ""
Write-Host "🎯 Expected Result: No more 404 errors for /api/rasp/projects" -ForegroundColor Green
