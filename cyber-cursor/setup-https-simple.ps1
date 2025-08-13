# Simple HTTPS Setup for CyberShield Frontend
# This script configures the application without requiring OpenSSL

Write-Host "Setting up HTTPS for CyberShield Frontend (Simple Method)" -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green
Write-Host ""

# Create frontend environment file
Write-Host "Creating frontend environment configuration..." -ForegroundColor Yellow

$frontendEnvContent = @"
# Frontend Environment Variables
REACT_APP_API_URL=https://localhost:8000
REACT_APP_ENVIRONMENT=development
REACT_APP_VERSION=2.0.0
REACT_APP_APP_NAME=CyberShield
HTTPS=true
PORT=3000
"@

# Try to create .env.local, if blocked create a different file
try {
    Set-Content -Path "frontend/.env.local" -Value $frontendEnvContent
    Write-Host "Created frontend/.env.local" -ForegroundColor Green
} catch {
    try {
        Set-Content -Path "frontend/env.https" -Value $frontendEnvContent
        Write-Host "Created frontend/env.https (use this instead of .env.local)" -ForegroundColor Yellow
    } catch {
        Write-Host "Could not create environment file. Please create manually:" -ForegroundColor Red
        Write-Host "File: frontend/.env.local" -ForegroundColor Cyan
        Write-Host "Content:" -ForegroundColor Cyan
        Write-Host $frontendEnvContent -ForegroundColor White
    }
}

# Update package.json scripts
Write-Host ""
Write-Host "Updating package.json scripts..." -ForegroundColor Yellow

try {
    $packageJson = Get-Content "frontend/package.json" -Raw
    $packageJson = $packageJson -replace '"start": "HTTPS=true SSL_CRT_FILE=./ssl/cert.pem SSL_KEY_FILE=./ssl/key.pem react-scripts start"', '"start": "HTTPS=true react-scripts start"'
    Set-Content -Path "frontend/package.json" -Value $packageJson
    Write-Host "Updated package.json start script" -ForegroundColor Green
} catch {
    Write-Host "Could not update package.json. Please update manually:" -ForegroundColor Red
    Write-Host 'Change "start" script to: "HTTPS=true react-scripts start"' -ForegroundColor Yellow
}

# Create startup scripts
Write-Host ""
Write-Host "Creating startup scripts..." -ForegroundColor Yellow

# PowerShell startup script
$psStartupContent = @"
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
`$env:HTTPS = "true"
`$env:REACT_APP_API_URL = "https://localhost:8000"
`$env:PORT = "3000"

Write-Host "Environment variables set:" -ForegroundColor Green
Write-Host "HTTPS: `$env:HTTPS" -ForegroundColor Cyan
Write-Host "REACT_APP_API_URL: `$env:REACT_APP_API_URL" -ForegroundColor Cyan
Write-Host "PORT: `$env:PORT" -ForegroundColor Cyan
Write-Host ""

# Start the application
Write-Host "Starting npm start..." -ForegroundColor Green
npm start
"@

Set-Content -Path "frontend/start-https-simple.ps1" -Value $psStartupContent
Write-Host "Created frontend/start-https-simple.ps1" -ForegroundColor Green

# Batch startup script
$batchStartupContent = @"
@echo off
echo Starting CyberShield Frontend with HTTPS (Simple Method)...
echo.
echo Frontend will be available at: https://localhost:3000
echo Backend API URL: https://localhost:8000
echo.
echo Note: This uses React's built-in HTTPS with self-signed certificates
echo You may need to accept security warnings in your browser
echo.
pause

set HTTPS=true
set REACT_APP_API_URL=https://localhost:8000
set PORT=3000

echo Environment variables set:
echo HTTPS: %HTTPS%
echo REACT_APP_API_URL: %REACT_APP_API_URL%
echo PORT: %PORT%
echo.

echo Starting npm start...
npm start
"@

Set-Content -Path "frontend/start-https-simple.bat" -Value $batchStartupContent
Write-Host "Created frontend/start-https-simple.bat" -ForegroundColor Green

# Update root environment files
Write-Host ""
Write-Host "Updating root environment files..." -ForegroundColor Yellow

try {
    # Update env.local
    $rootEnvContent = Get-Content "env.local" -Raw
    $rootEnvContent = $rootEnvContent -replace "REACT_APP_API_URL=http://localhost:8000", "REACT_APP_API_URL=https://localhost:8000"
    $rootEnvContent = $rootEnvContent -replace "ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001", "ALLOWED_ORIGINS=http://localhost:3000,https://localhost:3000,http://localhost:3001"
    Set-Content -Path "env.local" -Value $rootEnvContent
    Write-Host "Updated env.local" -ForegroundColor Green
} catch {
    Write-Host "Could not update env.local" -ForegroundColor Red
}

try {
    # Update env.production
    $prodEnvContent = Get-Content "env.production" -Raw
    $prodEnvContent = $prodEnvContent -replace "REACT_APP_API_URL=http://localhost:8000/api/v1", "REACT_APP_API_URL=https://localhost:8000/api/v1"
    $prodEnvContent = $prodEnvContent -replace "ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001,http://frontend:80,http://localhost", "ALLOWED_ORIGINS=http://localhost:3000,https://localhost:3000,http://localhost:3001,https://localhost:3001,http://frontend:80,https://frontend:443,http://localhost"
    Set-Content -Path "env.production" -Value $prodEnvContent
    Write-Host "Updated env.production" -ForegroundColor Green
} catch {
    Write-Host "Could not update env.production" -ForegroundColor Red
}

# Check services
Write-Host ""
Write-Host "Checking service status..." -ForegroundColor Yellow

# Check PostgreSQL
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
Write-Host "2. Start the frontend with HTTPS: cd frontend && .\start-https-simple.ps1" -ForegroundColor White
Write-Host "3. Access the frontend at: https://localhost:3000" -ForegroundColor White
Write-Host "4. Backend API will be at: https://localhost:8000" -ForegroundColor White
Write-Host ""
Write-Host "Note: This method uses React's built-in HTTPS with self-signed certificates" -ForegroundColor Yellow
Write-Host "You may need to accept security warnings in your browser" -ForegroundColor Yellow
Write-Host ""
Write-Host "Alternative: If you want proper SSL certificates, install OpenSSL and run:" -ForegroundColor Cyan
Write-Host "  .\setup-https-frontend.ps1" -ForegroundColor White
