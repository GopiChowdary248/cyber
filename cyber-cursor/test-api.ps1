# CyberShield API Testing Script
# This script helps you test various API endpoints and create test data

Write-Host "🧪 CyberShield API Testing Script" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Green

# Test basic endpoints
Write-Host "`n📋 Testing Basic Endpoints..." -ForegroundColor Yellow

try {
    # Test root endpoint
    Write-Host "Testing root endpoint..." -ForegroundColor Cyan
    $response = Invoke-WebRequest -Uri "http://localhost:8000/" -UseBasicParsing
    Write-Host "✅ Root endpoint: $($response.StatusCode)" -ForegroundColor Green
    Write-Host "Response: $($response.Content)" -ForegroundColor Gray
    
    # Test health endpoint
    Write-Host "`nTesting health endpoint..." -ForegroundColor Cyan
    $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing
    Write-Host "✅ Health endpoint: $($response.StatusCode)" -ForegroundColor Green
    Write-Host "Response: $($response.Content)" -ForegroundColor Gray
    
    # Test API health endpoint
    Write-Host "`nTesting API health endpoint..." -ForegroundColor Cyan
    $response = Invoke-WebRequest -Uri "http://localhost:8000/api/v1/health" -UseBasicParsing
    Write-Host "✅ API Health endpoint: $($response.StatusCode)" -ForegroundColor Green
    Write-Host "Response: $($response.Content)" -ForegroundColor Gray
    
} catch {
    Write-Host "❌ Error testing endpoints: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n🌐 Available URLs:" -ForegroundColor Green
Write-Host "Frontend: http://localhost:3000" -ForegroundColor Cyan
Write-Host "Backend API: http://localhost:8000" -ForegroundColor Cyan
Write-Host "API Documentation: http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host "Health Check: http://localhost:8000/health" -ForegroundColor Cyan

Write-Host "`n🔧 Next Steps:" -ForegroundColor Green
Write-Host "1. Open http://localhost:3000 to explore the frontend" -ForegroundColor White
Write-Host "2. Open http://localhost:8000/docs to test API endpoints" -ForegroundColor White
Write-Host "3. Edit files in backend/ and frontend/ folders" -ForegroundColor White
Write-Host "4. Watch for auto-reload changes" -ForegroundColor White

Write-Host "`n✅ API testing complete!" -ForegroundColor Green
