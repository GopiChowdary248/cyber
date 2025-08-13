# Start Frontend with HTTPS (Simple Method)
Write-Host "Starting CyberShield Frontend with HTTPS..." -ForegroundColor Green
Write-Host ""
Write-Host "Frontend will be available at: https://localhost:3000" -ForegroundColor Cyan
Write-Host "Backend API URL: https://localhost:8000" -ForegroundColor Cyan
Write-Host ""
Write-Host "Note: This uses React's built-in HTTPS with self-signed certificates" -ForegroundColor Yellow
Write-Host "You may need to accept security warnings in your browser" -ForegroundColor Yellow
Write-Host ""

# Set environment variables
$env:HTTPS = "true"
$env:REACT_APP_API_URL = "https://localhost:8000"
$env:PORT = "3000"

Write-Host "Environment variables set:" -ForegroundColor Green
Write-Host "HTTPS: $env:HTTPS" -ForegroundColor Cyan
Write-Host "REACT_APP_API_URL: $env:REACT_APP_API_URL" -ForegroundColor Cyan
Write-Host "PORT: $env:PORT" -ForegroundColor Cyan
Write-Host ""

# Start the application
Write-Host "Starting npm start..." -ForegroundColor Green
npm start
