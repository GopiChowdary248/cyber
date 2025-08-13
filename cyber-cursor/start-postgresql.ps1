# Quick Start PostgreSQL for CyberShield
# This script quickly sets up and starts PostgreSQL

Write-Host "🚀 Quick Start PostgreSQL for CyberShield" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Cyan

# Check if Docker is running
try {
    docker version | Out-Null
    Write-Host "✅ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not running. Please start Docker Desktop first." -ForegroundColor Red
    exit 1
}

# Create network if it doesn't exist
$networkExists = docker network ls --filter "name=cybershield-network" --format "{{.Name}}"
if (-not $networkExists) {
    Write-Host "🌐 Creating Docker network..." -ForegroundColor Yellow
    docker network create cybershield-network
    Write-Host "✅ Network created" -ForegroundColor Green
}

# Check if PostgreSQL container exists
$containerExists = docker ps -a --filter "name=cybershield-postgres" --format "{{.Names}}"
if (-not $containerExists) {
    Write-Host "🐘 Creating PostgreSQL container..." -ForegroundColor Yellow
    
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
    
    Write-Host "✅ PostgreSQL container created" -ForegroundColor Green
} else {
    Write-Host "✅ PostgreSQL container already exists" -ForegroundColor Green
}

# Start PostgreSQL if not running
$containerRunning = docker ps --filter "name=cybershield-postgres" --format "{{.Names}}"
if (-not $containerRunning) {
    Write-Host "▶️  Starting PostgreSQL..." -ForegroundColor Yellow
    docker start cybershield-postgres
    Write-Host "✅ PostgreSQL started" -ForegroundColor Green
} else {
    Write-Host "✅ PostgreSQL is already running" -ForegroundColor Green
}

# Wait for PostgreSQL to be ready
Write-Host "⏳ Waiting for PostgreSQL to be ready..." -ForegroundColor Yellow
$maxAttempts = 15
$attempt = 0

do {
    $attempt++
    try {
        $result = docker exec cybershield-postgres pg_isready -U cybershield_user -d cybershield 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ PostgreSQL is ready!" -ForegroundColor Green
            break
        }
    } catch {
        # Ignore errors during startup
    }
    
    if ($attempt -lt $maxAttempts) {
        Write-Host "   Attempt $attempt/$maxAttempts..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
    }
} while ($attempt -lt $maxAttempts)

if ($attempt -ge $maxAttempts) {
    Write-Host "❌ PostgreSQL failed to start within expected time" -ForegroundColor Red
    Write-Host "💡 Check container logs: docker logs cybershield-postgres" -ForegroundColor Yellow
    exit 1
}

# Test connection
Write-Host "🧪 Testing database connection..." -ForegroundColor Yellow
$testResult = docker exec cybershield-postgres psql -U cybershield_user -d cybershield -c "SELECT 'Connection successful' as status;" 2>$null

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Database connection successful!" -ForegroundColor Green
} else {
    Write-Host "❌ Database connection failed" -ForegroundColor Red
    Write-Host "💡 Check container logs: docker logs cybershield-postgres" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n🎉 PostgreSQL is ready for CyberShield!" -ForegroundColor Green
Write-Host "`n📋 Connection Details:" -ForegroundColor Cyan
Write-Host "   Host: localhost" -ForegroundColor White
Write-Host "   Port: 5432" -ForegroundColor White
Write-Host "   Database: cybershield" -ForegroundColor White
Write-Host "   Username: cybershield_user" -ForegroundColor White
Write-Host "   Password: cybershield_password" -ForegroundColor White

Write-Host "`n🔗 Test the connection:" -ForegroundColor Cyan
Write-Host "   python scripts/test-postgresql.py" -ForegroundColor White

Write-Host "`n🚀 Start your CyberShield backend:" -ForegroundColor Cyan
Write-Host "   cd backend" -ForegroundColor White
Write-Host "   python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000" -ForegroundColor White

Write-Host "`n📚 For more details, see: POSTGRESQL_SETUP_GUIDE.md" -ForegroundColor Cyan
