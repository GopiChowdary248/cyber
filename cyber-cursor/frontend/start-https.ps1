# Start CyberShield Frontend with HTTPS
Write-Host "Starting CyberShield Frontend with HTTPS..." -ForegroundColor Green
Write-Host ""
Write-Host "Make sure you have generated SSL certificates first using generate-ssl-certs.ps1" -ForegroundColor Yellow
Write-Host ""
Write-Host "Frontend will be available at: https://localhost:3000" -ForegroundColor Cyan
Write-Host "Backend API URL: https://localhost:8000" -ForegroundColor Cyan
Write-Host ""

# Set environment variables
$env:HTTPS = "true"
$env:SSL_CRT_FILE = "./ssl/cert.pem"
$env:SSL_KEY_FILE = "./ssl/key.pem"
$env:REACT_APP_API_URL = "https://localhost:8000"
$env:PORT = "3000"

Write-Host "Environment variables set:" -ForegroundColor Green
Write-Host "HTTPS: $env:HTTPS" -ForegroundColor Cyan
Write-Host "SSL_CRT_FILE: $env:SSL_CRT_FILE" -ForegroundColor Cyan
Write-Host "SSL_KEY_FILE: $env:SSL_KEY_FILE" -ForegroundColor Cyan
Write-Host "REACT_APP_API_URL: $env:REACT_APP_API_URL" -ForegroundColor Cyan
Write-Host "PORT: $env:PORT" -ForegroundColor Cyan
Write-Host ""

# Start the application
Write-Host "Starting npm start..." -ForegroundColor Green
npm start
