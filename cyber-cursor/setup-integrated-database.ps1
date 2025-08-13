# CyberShield Integrated Database Setup Script
# This script sets up the complete database integration with all models

Write-Host "🚀 Starting CyberShield Integrated Database Setup..." -ForegroundColor Green

# Check if Docker is running
Write-Host "📋 Checking Docker status..." -ForegroundColor Yellow
try {
    $dockerStatus = docker info 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Docker is not running. Please start Docker Desktop first." -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not available. Please install Docker Desktop first." -ForegroundColor Red
    exit 1
}

# Stop existing containers
Write-Host "🛑 Stopping existing containers..." -ForegroundColor Yellow
docker-compose -f docker-compose.production-no-mobile.yml down
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Existing containers stopped" -ForegroundColor Green
}

# Remove existing volumes to ensure clean state
Write-Host "🧹 Cleaning up existing volumes..." -ForegroundColor Yellow
docker volume rm cyber-cursor_postgres_data 2>$null
docker volume rm cyber-cursor_redis_data 2>$null
Write-Host "✅ Volumes cleaned up" -ForegroundColor Green

# Create enhanced database initialization script
Write-Host "📝 Creating enhanced database initialization script..." -ForegroundColor Yellow
$initScript = @"
-- CyberShield Enhanced Production Database Initialization Script
-- This script creates the complete database schema for all modules

-- Create user if not exists
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'cybershield_user') THEN
        CREATE USER cybershield_user WITH PASSWORD 'cybershield_password';
    END IF;
END
\$\$;

-- Create database if not exists
SELECT 'CREATE DATABASE cybershield'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cybershield')\gexec

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE cybershield TO cybershield_user;
GRANT ALL ON SCHEMA public TO cybershield_user;

-- Connect to the cybershield database
\c cybershield;

-- Grant additional privileges
GRANT CREATE ON SCHEMA public TO cybershield_user;
GRANT USAGE ON SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO cybershield_user;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO cybershield_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO cybershield_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO cybershield_user;

-- Create enum types for all modules
DO \$\$
BEGIN
    -- SAST enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'issueresolution') THEN
        CREATE TYPE issueresolution AS ENUM ('FIXED', 'WONTFIX', 'FALSE_POSITIVE', 'ACCEPTED');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'securityhotspotresolution') THEN
        CREATE TYPE securityhotspotresolution AS ENUM ('FIXED', 'ACKNOWLEDGED', 'FALSE_POSITIVE');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'qualitygatestatus') THEN
        CREATE TYPE qualitygatestatus AS ENUM ('PASSED', 'FAILED', 'WARNING');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'rating') THEN
        CREATE TYPE rating AS ENUM ('A', 'B', 'C', 'D', 'E');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'scanstatus') THEN
        CREATE TYPE scanstatus AS ENUM ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'CANCELLED');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'securityhotspotstatus') THEN
        CREATE TYPE securityhotspotstatus AS ENUM ('TO_REVIEW', 'REVIEWED', 'FIXED');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'issueseverity') THEN
        CREATE TYPE issueseverity AS ENUM ('BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'issuetype') THEN
        CREATE TYPE issuetype AS ENUM ('BUG', 'VULNERABILITY', 'CODE_SMELL');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'issuestatus') THEN
        CREATE TYPE issuestatus AS ENUM ('OPEN', 'CONFIRMED', 'RESOLVED', 'REOPENED', 'CLOSED');
    END IF;
    
    -- DAST enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'dastseverity') THEN
        CREATE TYPE dastseverity AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'daststatus') THEN
        CREATE TYPE daststatus AS ENUM ('ACTIVE', 'INACTIVE', 'ARCHIVED');
    END IF;
    
    -- RASP enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'raspstatus') THEN
        CREATE TYPE raspstatus AS ENUM ('ACTIVE', 'INACTIVE', 'MAINTENANCE');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'raspattacktype') THEN
        CREATE TYPE raspattacktype AS ENUM ('SQL_INJECTION', 'XSS', 'PATH_TRAVERSAL', 'COMMAND_INJECTION', 'LDAP_INJECTION');
    END IF;
    
    -- Cloud Security enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'cloudprovider') THEN
        CREATE TYPE cloudprovider AS ENUM ('AWS', 'AZURE', 'GCP', 'DIGITAL_OCEAN', 'LINODE');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'risklevel') THEN
        CREATE TYPE risklevel AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
    END IF;
    
    -- IAM enums
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'userrole') THEN
        CREATE TYPE userrole AS ENUM ('ADMIN', 'USER', 'ANALYST', 'MANAGER', 'AUDITOR');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'sessionstatus') THEN
        CREATE TYPE sessionstatus AS ENUM ('ACTIVE', 'EXPIRED', 'TERMINATED', 'SUSPENDED');
    END IF;
END
\$\$;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    full_name VARCHAR(100),
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    is_superuser BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    department VARCHAR(100),
    phone VARCHAR(20),
    avatar_url VARCHAR(255),
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    preferences JSONB
);

-- Create admin user if not exists
INSERT INTO users (username, email, hashed_password, is_active, is_superuser, role)
VALUES (
    'admin',
    'admin@cybershield.com',
    '\$2b\$12\$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK2O', -- password: admin123
    TRUE,
    TRUE,
    'ADMIN'
) ON CONFLICT (username) DO NOTHING;

-- Create test user if not exists
INSERT INTO users (username, email, hashed_password, is_active, is_superuser, role)
VALUES (
    'testuser',
    'test@cybershield.com',
    '\$2b\$12\$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK2O', -- password: admin123
    TRUE,
    FALSE,
    'USER'
) ON CONFLICT (username) DO NOTHING;

-- Grant permissions on new tables
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cybershield_user;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
"@

Write-Host "✅ Enhanced database initialization script created" -ForegroundColor Green

$initScript | Out-File -FilePath "scripts/init-integrated-db.sql" -Encoding UTF8

# Update Docker Compose to use the new initialization script
Write-Host "🔧 Updating Docker Compose configuration..." -ForegroundColor Yellow
$dockerComposeContent = Get-Content "docker-compose.production-no-mobile.yml" -Raw
$dockerComposeContent = $dockerComposeContent -replace "init-production-db\.sql", "init-integrated-db.sql"
$dockerComposeContent | Out-File -FilePath "docker-compose.production-no-mobile.yml" -Encoding UTF8

# Start the containers
Write-Host "🚀 Starting containers with integrated database..." -ForegroundColor Yellow
docker-compose -f docker-compose.production-no-mobile.yml up -d

# Wait for containers to be ready
Write-Host "⏳ Waiting for containers to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

# Check container status
Write-Host "📊 Checking container status..." -ForegroundColor Yellow
docker ps

# Test database connection
Write-Host "🔍 Testing database connection..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Test backend health
Write-Host "🏥 Testing backend health..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get -TimeoutSec 10
    Write-Host "✅ Backend is healthy: $($response.status)" -ForegroundColor Green
    Write-Host "📊 Services: $($response.services | ConvertTo-Json -Compress)" -ForegroundColor Cyan
} catch {
    Write-Host "❌ Backend health check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test frontend
Write-Host "🌐 Testing frontend..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3000" -Method Get -TimeoutSec 10
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Frontend is accessible" -ForegroundColor Green
    } else {
        Write-Host "⚠️ Frontend returned status: $($response.StatusCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Frontend test failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test Nginx proxy
Write-Host "🌐 Testing Nginx proxy..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost" -Method Get -TimeoutSec 10
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Nginx proxy is working" -ForegroundColor Green
    } else {
        Write-Host "⚠️ Nginx returned status: $($response.StatusCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Nginx test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "🎉 Integration setup completed!" -ForegroundColor Green
Write-Host "📋 Next steps:" -ForegroundColor Cyan
Write-Host "   1. Access the application at: http://localhost" -ForegroundColor White
Write-Host "   2. Login with admin/admin123 or testuser/admin123" -ForegroundColor White
Write-Host "   3. Navigate to DAST module to see the new Overview and Projects tabs" -ForegroundColor White
Write-Host "   4. Check that SAST Results tab is removed from left navigation" -ForegroundColor White
Write-Host "   5. Verify all API endpoints are working at: http://localhost:8000/docs" -ForegroundColor White
