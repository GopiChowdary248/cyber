@echo off
setlocal enabledelayedexpansion

REM CyberShield Containerized Application Startup Script for Windows
REM This script helps you start the full-stack application with Docker Compose

set "SCRIPT_NAME=%~n0"
set "COMMAND=%1"

if "%COMMAND%"=="" set "COMMAND=start"

echo [INFO] CyberShield Containerized Application Startup Script
echo.

REM Function to check if Docker is running
call :check_docker
if errorlevel 1 (
    echo [ERROR] Docker is not running. Please start Docker Desktop and try again.
    exit /b 1
)

REM Function to check if Docker Compose is available
call :check_docker_compose
if errorlevel 1 (
    echo [ERROR] Docker Compose is not available. Please install Docker Compose and try again.
    exit /b 1
)

REM Function to check if .env file exists
call :check_env_file

REM Function to check available ports
call :check_ports

REM Main command logic
if "%COMMAND%"=="start" (
    echo [INFO] Starting CyberShield application in development mode...
    call :start_services
    call :wait_for_services
    call :show_status
    call :show_logs
) else if "%COMMAND%"=="start-production" (
    echo [INFO] Starting CyberShield application in production mode...
    call :start_services production
    call :wait_for_services
    call :show_status production
    call :show_logs
) else if "%COMMAND%"=="stop" (
    call :stop_services
) else if "%COMMAND%"=="restart" (
    call :restart_services
) else if "%COMMAND%"=="status" (
    call :show_status
) else if "%COMMAND%"=="logs" (
    call :show_logs
) else if "%COMMAND%"=="cleanup" (
    call :cleanup
) else if "%COMMAND%"=="help" (
    call :show_help
) else (
    echo [ERROR] Unknown command: %COMMAND%
    echo.
    call :show_help
    exit /b 1
)

exit /b 0

:check_docker
echo [INFO] Checking if Docker is running...
docker info >nul 2>&1
if errorlevel 1 (
    exit /b 1
) else (
    echo [SUCCESS] Docker is running
    exit /b 0
)

:check_docker_compose
echo [INFO] Checking if Docker Compose is available...
docker-compose --version >nul 2>&1
if errorlevel 1 (
    exit /b 1
) else (
    echo [SUCCESS] Docker Compose is available
    exit /b 0
)

:check_env_file
if not exist ".env" (
    echo [WARNING] .env file not found. Creating from template...
    if exist "env.example" (
        copy env.example .env >nul
        echo [SUCCESS] Created .env file from template
        echo [WARNING] Please review and update the .env file with your configuration
    ) else (
        echo [ERROR] env.example file not found. Please create a .env file manually.
        exit /b 1
    )
) else (
    echo [SUCCESS] .env file found
)
exit /b 0

:check_ports
echo [INFO] Checking available ports...
REM Note: Windows port checking is more complex, so we'll skip it for now
echo [INFO] Port availability check skipped on Windows
exit /b 0

:start_services
if "%1"=="production" (
    echo [INFO] Starting services in production mode...
    docker-compose --profile production up --build -d
) else (
    echo [INFO] Starting services in development mode...
    docker-compose up --build -d
)
if errorlevel 1 (
    echo [ERROR] Failed to start services
    exit /b 1
) else (
    echo [SUCCESS] Services started successfully
)
exit /b 0

:wait_for_services
echo [INFO] Waiting for services to be ready...
echo [INFO] Waiting for PostgreSQL...
timeout /t 10 /nobreak >nul
echo [INFO] Waiting for backend API...
timeout /t 10 /nobreak >nul
echo [SUCCESS] Services should be ready
exit /b 0

:show_status
echo [INFO] Service Status:
docker-compose ps
echo.
echo [INFO] Application URLs:
echo   Frontend: http://localhost:3000
echo   Backend API: http://localhost:8000
echo   API Documentation: http://localhost:8000/docs
echo   Health Check: http://localhost:8000/health
if "%1"=="production" (
    echo   Nginx ^(HTTP^): http://localhost:80
    echo   Nginx ^(HTTPS^): https://localhost:443
)
exit /b 0

:show_logs
echo [INFO] Recent logs ^(last 20 lines^):
docker-compose logs --tail=20
exit /b 0

:stop_services
echo [INFO] Stopping services...
docker-compose down
echo [SUCCESS] Services stopped
exit /b 0

:restart_services
echo [INFO] Restarting services...
docker-compose restart
echo [SUCCESS] Services restarted
exit /b 0

:cleanup
echo [INFO] Cleaning up containers and volumes...
docker-compose down --volumes --remove-orphans
echo [SUCCESS] Cleanup completed
exit /b 0

:show_help
echo CyberShield Containerized Application Startup Script
echo.
echo Usage: %SCRIPT_NAME% [COMMAND]
echo.
echo Commands:
echo   start              Start services in development mode
echo   start-production   Start services in production mode ^(with Nginx, Celery^)
echo   stop               Stop all services
echo   restart            Restart all services
echo   status             Show service status and URLs
echo   logs               Show recent logs
echo   cleanup            Stop and remove all containers and volumes
echo   help               Show this help message
echo.
echo Examples:
echo   %SCRIPT_NAME% start           # Start in development mode
echo   %SCRIPT_NAME% start-production # Start in production mode
echo   %SCRIPT_NAME% status          # Check service status
exit /b 0 