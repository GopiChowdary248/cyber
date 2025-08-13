# Setup HTTPS Frontend and Backend Communication
# This script configures the CyberShield application to use HTTPS

Write-Host "Setting up HTTPS for CyberShield Frontend and Backend Communication" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host ""

# Check if OpenSSL is available
Write-Host "Checking OpenSSL availability..." -ForegroundColor Yellow
try {
    $opensslVersion = openssl version 2>$null
    if ($opensslVersion) {
        Write-Host "OpenSSL found: $opensslVersion" -ForegroundColor Green
    } else {
        Write-Host "OpenSSL not found. Please install OpenSSL first." -ForegroundColor Red
        Write-Host "You can download it from: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Yellow
        exit 1
    }
} catch {
    Write-Host "OpenSSL not found. Please install OpenSSL first." -ForegroundColor Red
    Write-Host "You can download it from: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Yellow
    exit 1
}

# Generate SSL certificates
Write-Host ""
Write-Host "Generating SSL certificates..." -ForegroundColor Yellow
if (!(Test-Path "frontend/ssl")) {
    New-Item -ItemType Directory -Path "frontend/ssl" -Force
    Write-Host "Created frontend/ssl directory" -ForegroundColor Cyan
}

# Generate private key
Write-Host "Generating private key..." -ForegroundColor Yellow
openssl genrsa -out frontend/ssl/key.pem 2048

# Generate certificate signing request
Write-Host "Generating certificate signing request..." -ForegroundColor Yellow
openssl req -new -key frontend/ssl/key.pem -out frontend/ssl/cert.csr -subj "/C=US/ST=State/L=City/O=CyberShield/CN=localhost"

# Generate self-signed certificate
Write-Host "Generating self-signed certificate..." -ForegroundColor Yellow
openssl x509 -req -in frontend/ssl/cert.csr -signkey frontend/ssl/key.pem -out frontend/ssl/cert.pem -days 365

# Clean up CSR file
Remove-Item frontend/ssl/cert.csr -Force

Write-Host "SSL certificates generated successfully!" -ForegroundColor Green

# Update environment files
Write-Host ""
Write-Host "Updating environment configuration..." -ForegroundColor Yellow

# Create .env.local for frontend
$frontendEnvContent = @"
# Frontend Environment Variables
REACT_APP_API_URL=https://localhost:8000
REACT_APP_ENVIRONMENT=development
REACT_APP_VERSION=2.0.0
REACT_APP_APP_NAME=CyberShield
HTTPS=true
SSL_CRT_FILE=./ssl/cert.pem
SSL_KEY_FILE=./ssl/key.pem
PORT=3000
"@

Set-Content -Path "frontend/.env.local" -Value $frontendEnvContent
Write-Host "Created frontend/.env.local" -ForegroundColor Cyan

# Update root env.local
$rootEnvContent = Get-Content "env.local" -Raw
$rootEnvContent = $rootEnvContent -replace "REACT_APP_API_URL=http://localhost:8000", "REACT_APP_API_URL=https://localhost:8000"
$rootEnvContent = $rootEnvContent -replace "ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001", "ALLOWED_ORIGINS=http://localhost:3000,https://localhost:3000,http://localhost:3001"
Set-Content -Path "env.local" -Value $rootEnvContent
Write-Host "Updated env.local" -ForegroundColor Cyan

# Update root env.production
$prodEnvContent = Get-Content "env.production" -Raw
$prodEnvContent = $prodEnvContent -replace "REACT_APP_API_URL=http://localhost:8000/api/v1", "REACT_APP_API_URL=https://localhost:8000/api/v1"
$prodEnvContent = $prodEnvContent -replace "ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001,http://frontend:80,http://localhost", "ALLOWED_ORIGINS=http://localhost:3000,https://localhost:3000,http://localhost:3001,https://localhost:3001,http://frontend:80,https://frontend:443,http://localhost"
Set-Content -Path "env.production" -Value $prodEnvContent
Write-Host "Updated env.production" -ForegroundColor Cyan

# Check if PostgreSQL is running
Write-Host ""
Write-Host "Checking PostgreSQL status..." -ForegroundColor Yellow
try {
    $pgStatus = Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue
    if ($pgStatus) {
        foreach ($service in $pgStatus) {
            Write-Host "PostgreSQL service '$($service.Name)': $($service.Status)" -ForegroundColor Cyan
        }
    } else {
        Write-Host "PostgreSQL service not found. Please ensure PostgreSQL is installed and running." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Could not check PostgreSQL service status." -ForegroundColor Yellow
}

# Check if backend is accessible
Write-Host ""
Write-Host "Testing backend connectivity..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 5 -ErrorAction Stop
    if ($response.StatusCode -eq 200) {
        Write-Host "Backend is accessible at http://localhost:8000" -ForegroundColor Green
    }
} catch {
    Write-Host "Backend is not accessible at http://localhost:8000" -ForegroundColor Red
    Write-Host "Please start the backend first using: python backend/main.py" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Setup completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Start the backend: python backend/main.py" -ForegroundColor White
Write-Host "2. Start the frontend with HTTPS: cd frontend && .\start-https.ps1" -ForegroundColor White
Write-Host "3. Access the frontend at: https://localhost:3000" -ForegroundColor White
Write-Host "4. Backend API will be at: https://localhost:8000" -ForegroundColor White
Write-Host ""
Write-Host "Note: You may need to accept the self-signed certificate in your browser" -ForegroundColor Yellow
Write-Host "The certificate is valid for 365 days" -ForegroundColor Yellow
