# PostgreSQL Setup Script for CyberShield on Windows
# This script helps set up PostgreSQL for local development

Write-Host "Setting up PostgreSQL for CyberShield..." -ForegroundColor Green

# Check if Docker is running
try {
    docker version | Out-Null
    Write-Host "✓ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "✗ Docker is not running. Please start Docker Desktop first." -ForegroundColor Red
    exit 1
}

# Check if PostgreSQL container exists
$postgresContainer = docker ps -a --filter "name=cybershield-postgres" --format "{{.Names}}"
if ($postgresContainer) {
    Write-Host "✓ PostgreSQL container already exists" -ForegroundColor Green
} else {
    Write-Host "Creating PostgreSQL container..." -ForegroundColor Yellow
    
    # Create and start PostgreSQL container
    docker run -d `
        --name cybershield-postgres `
        --network cybershield-network `
        -e POSTGRES_DB=cybershield `
        -e POSTGRES_USER=cybershield_user `
        -e POSTGRES_PASSWORD=cybershield_password `
        -e POSTGRES_INITDB_ARGS="--encoding=UTF-8 --lc-collate=C --lc-ctype=C" `
        -p 5432:5432 `
        -v postgres_data:/var/lib/postgresql/data `
        postgres:15-alpine
    
    Write-Host "✓ PostgreSQL container created" -ForegroundColor Green
}

# Start PostgreSQL container if not running
$postgresRunning = docker ps --filter "name=cybershield-postgres" --format "{{.Names}}"
if (-not $postgresRunning) {
    Write-Host "Starting PostgreSQL container..." -ForegroundColor Yellow
    docker start cybershield-postgres
    Write-Host "✓ PostgreSQL container started" -ForegroundColor Green
}

# Wait for PostgreSQL to be ready
Write-Host "Waiting for PostgreSQL to be ready..." -ForegroundColor Yellow
$maxAttempts = 30
$attempt = 0
do {
    $attempt++
    try {
        $result = docker exec cybershield-postgres pg_isready -U cybershield_user -d cybershield
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ PostgreSQL is ready" -ForegroundColor Green
            break
        }
    } catch {
        # Ignore errors during startup
    }
    
    if ($attempt -lt $maxAttempts) {
        Write-Host "Attempt $attempt/$maxAttempts - Waiting for PostgreSQL..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
    }
} while ($attempt -lt $maxAttempts)

if ($attempt -ge $maxAttempts) {
    Write-Host "✗ PostgreSQL failed to start within expected time" -ForegroundColor Red
    exit 1
}

# Initialize database schema
Write-Host "Initializing database schema..." -ForegroundColor Yellow
Get-Content scripts/init-postgresql.sql | docker exec -i cybershield-postgres psql -U cybershield_user -d cybershield

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Database schema initialized" -ForegroundColor Green
} else {
    Write-Host "✗ Failed to initialize database schema" -ForegroundColor Red
}

# Test connection
Write-Host "Testing database connection..." -ForegroundColor Yellow
$testResult = docker exec cybershield-postgres psql -U cybershield_user -d cybershield -c "SELECT version();"
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Database connection successful" -ForegroundColor Green
    Write-Host "PostgreSQL version: $testResult" -ForegroundColor Cyan
} else {
    Write-Host "✗ Database connection failed" -ForegroundColor Red
}

Write-Host "`nPostgreSQL setup complete!" -ForegroundColor Green
Write-Host "Connection details:" -ForegroundColor Cyan
Write-Host "  Host: localhost" -ForegroundColor White
Write-Host "  Port: 5432" -ForegroundColor White
Write-Host "  Database: cybershield" -ForegroundColor White
Write-Host "  Username: cybershield_user" -ForegroundColor White
Write-Host "  Password: cybershield_password" -ForegroundColor White
Write-Host "`nYou can now start your CyberShield backend application." -ForegroundColor Green
