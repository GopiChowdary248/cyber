@echo off
REM CyberShield Production Startup Script (Batch)
REM This script starts the application in production mode without mobile components

echo 🚀 Starting CyberShield in Production Mode...
echo ==============================================

REM Check if Docker is running
echo [INFO] Checking Docker status...
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not running. Please start Docker and try again.
    pause
    exit /b 1
)
echo [SUCCESS] Docker is running

REM Check if Docker Compose is available
echo [INFO] Checking Docker Compose...
docker-compose --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker Compose is not available. Please install Docker Compose and try again.
    pause
    exit /b 1
)
echo [SUCCESS] Docker Compose is available

REM Stop any existing containers
echo [INFO] Stopping any existing containers...
docker-compose -f docker-compose.production-no-mobile.yml down --remove-orphans
if %errorlevel% neq 0 (
    echo [WARNING] No existing containers to stop or error occurred
)

REM Build and start services
echo [INFO] Building and starting production services...

echo [INFO] Building backend image...
docker-compose -f docker-compose.production-no-mobile.yml build backend
if %errorlevel% neq 0 (
    echo [ERROR] Failed to build backend image
    pause
    exit /b 1
)

echo [INFO] Building frontend image...
docker-compose -f docker-compose.production-no-mobile.yml build frontend
if %errorlevel% neq 0 (
    echo [ERROR] Failed to build frontend image
    pause
    exit /b 1
)

echo [INFO] Starting all services...
docker-compose -f docker-compose.production-no-mobile.yml up -d
if %errorlevel% neq 0 (
    echo [ERROR] Failed to start services
    pause
    exit /b 1
)

echo [SUCCESS] All services started successfully

REM Wait for services to be ready
echo [INFO] Waiting for services to be ready...
echo [INFO] This may take a few minutes...

REM Wait for backend
echo [INFO] Waiting for Backend API...
:wait_backend
timeout /t 5 /nobreak >nul
curl -f http://localhost:8000/health >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Backend not ready yet, waiting...
    goto wait_backend
)
echo [SUCCESS] Backend API is ready

REM Wait for frontend
echo [INFO] Waiting for Frontend...
:wait_frontend
timeout /t 5 /nobreak >nul
curl -f http://localhost:3000 >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Frontend not ready yet, waiting...
    goto wait_frontend
)
echo [SUCCESS] Frontend is ready

REM Show service status
echo.
echo [INFO] Service Status:
echo ==================
docker-compose -f docker-compose.production-no-mobile.yml ps

echo.
echo [INFO] Service URLs:
echo ================
echo Frontend: http://localhost:3000
echo Backend API: http://localhost:8000
echo Nginx Proxy: http://localhost:80
echo PostgreSQL: localhost:5432
echo Redis: localhost:6379

echo.
echo [INFO] Container Logs:
echo ===================
echo View logs with: docker-compose -f docker-compose.production-no-mobile.yml logs -f [service_name]
echo Stop services with: docker-compose -f docker-compose.production-no-mobile.yml down

echo.
echo [SUCCESS] 🎉 CyberShield is now running in production mode!
echo [SUCCESS] Access your application at: http://localhost

pause
