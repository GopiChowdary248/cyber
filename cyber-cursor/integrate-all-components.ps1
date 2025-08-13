# CyberShield Complete Integration Script
# This script integrates all UI, API changes, and PostgreSQL in the application

Write-Host "🚀 Starting CyberShield Complete Integration..." -ForegroundColor Green
Write-Host "This will integrate all UI, API changes, and PostgreSQL components" -ForegroundColor Cyan

# Function to check if Docker is running
function Test-DockerRunning {
    try {
        docker version | Out-Null
        Write-Host "✅ Docker is running" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "❌ Docker is not running. Please start Docker Desktop first." -ForegroundColor Red
        return $false
    }
}

# Function to create environment file
function Create-EnvironmentFile {
    Write-Host "Creating environment configuration..." -ForegroundColor Yellow
    
    $envContent = @"
# CyberShield Production Environment Configuration
APP_NAME=CyberShield
VERSION=2.0.0
DEBUG=false
LOG_LEVEL=INFO

# Security
SECRET_KEY=cybershield-super-secret-production-key-2024-change-immediately
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database Configuration
DATABASE_URL=postgresql+asyncpg://cybershield_user:cybershield_password@postgres:5432/cybershield

# Redis Configuration
REDIS_URL=redis://:redis_password@redis:6379/0

# CORS Settings
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001,http://frontend:80,http://localhost
ALLOWED_HOSTS=localhost,127.0.0.1,backend,frontend,postgres,redis

# Frontend Environment Variables
REACT_APP_API_URL=http://localhost:8000/api/v1
REACT_APP_ENVIRONMENT=production
REACT_APP_VERSION=2.0.0

# AI/ML Services (Optional)
OPENAI_API_KEY=your-openai-api-key
OPENAI_MODEL=gpt-4

# File Upload
UPLOAD_DIR=uploads
MAX_FILE_SIZE=10485760
"@

    $envContent | Out-File -FilePath ".env" -Encoding UTF8
    Write-Host "✅ Environment file created" -ForegroundColor Green
}

# Function to setup PostgreSQL database
function Setup-PostgreSQL {
    Write-Host "Setting up PostgreSQL database..." -ForegroundColor Yellow
    
    try {
        # Create database initialization script
        $initScript = @"
-- CyberShield Database Initialization Script
CREATE DATABASE cybershield;
\c cybershield;

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    is_superuser BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create security_events table
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    source_ip INET,
    user_id UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(100),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Insert default admin user (password: admin123)
INSERT INTO users (username, email, hashed_password, full_name, is_superuser) 
VALUES ('admin', 'admin@cybershield.com', '\$2b\$12\$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.sm6.', 'System Administrator', true)
ON CONFLICT (username) DO NOTHING;

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE cybershield TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cybershield_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cybershield_user;
"@

        $initScript | Out-File -FilePath "scripts/init-db.sql" -Encoding UTF8
        Write-Host "✅ Database initialization script created" -ForegroundColor Green
        
    } catch {
        Write-Host "❌ Failed to create database script: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
    
    return $true
}

# Function to build and start containers
function Start-Containers {
    Write-Host "Building and starting containers..." -ForegroundColor Yellow
    
    try {
        # Stop any existing containers
        Write-Host "Stopping existing containers..." -ForegroundColor Cyan
        docker-compose -f docker-compose.production.yml down
        
        # Build and start containers
        Write-Host "Building containers..." -ForegroundColor Cyan
        docker-compose -f docker-compose.production.yml build --no-cache
        
        Write-Host "Starting containers..." -ForegroundColor Cyan
        docker-compose -f docker-compose.production.yml up -d
        
        # Wait for services to be ready
        Write-Host "Waiting for services to be ready..." -ForegroundColor Cyan
        Start-Sleep -Seconds 30
        
        Write-Host "✅ Containers started successfully" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Host "❌ Failed to start containers: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to verify integration
function Verify-Integration {
    Write-Host "Verifying integration..." -ForegroundColor Yellow
    
    $success = $true
    
    # Test database connection
    try {
        Write-Host "Testing database connection..." -ForegroundColor Cyan
        $response = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get -TimeoutSec 15
        if ($response.services.database -eq "connected") {
            Write-Host "✅ Database: Connected" -ForegroundColor Green
        } else {
            Write-Host "❌ Database: Not connected" -ForegroundColor Red
            $success = $false
        }
    } catch {
        Write-Host "❌ Database test failed: $($_.Exception.Message)" -ForegroundColor Red
        $success = $false
    }
    
    # Test backend API
    try {
        Write-Host "Testing backend API..." -ForegroundColor Cyan
        $response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/health" -Method Get -TimeoutSec 10
        Write-Host "✅ Backend API: Working" -ForegroundColor Green
    } catch {
        Write-Host "❌ Backend API test failed: $($_.Exception.Message)" -ForegroundColor Red
        $success = $false
    }
    
    # Test frontend
    try {
        Write-Host "Testing frontend..." -ForegroundColor Cyan
        $response = Invoke-WebRequest -Uri "http://localhost:3000" -Method Get -TimeoutSec 10
        if ($response.StatusCode -eq 200) {
            Write-Host "✅ Frontend: Working" -ForegroundColor Green
        } else {
            Write-Host "❌ Frontend: Status $($response.StatusCode)" -ForegroundColor Red
            $success = $false
        }
    } catch {
        Write-Host "❌ Frontend test failed: $($_.Exception.Message)" -ForegroundColor Red
        $success = $false
    }
    
    return $success
}

# Function to create admin user
function Create-AdminUser {
    Write-Host "Creating admin user..." -ForegroundColor Yellow
    
    try {
        $adminData = @{
            username = "admin"
            email = "admin@cybershield.com"
            password = "admin123"
            full_name = "System Administrator"
            is_superuser = $true
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/users/create" -Method Post -Body $adminData -ContentType "application/json" -TimeoutSec 15
        Write-Host "✅ Admin user created successfully" -ForegroundColor Green
        
    } catch {
        Write-Host "⚠️ Admin user creation failed (may already exist): $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Main integration process
function Start-Integration {
    Write-Host "Starting CyberShield integration process..." -ForegroundColor Green
    
    # Check prerequisites
    if (-not (Test-DockerRunning)) {
        Write-Host "Please start Docker Desktop and run this script again." -ForegroundColor Red
        return
    }
    
    # Create environment file
    Create-EnvironmentFile
    
    # Setup PostgreSQL
    if (-not (Setup-PostgreSQL)) {
        Write-Host "PostgreSQL setup failed. Stopping integration." -ForegroundColor Red
        return
    }
    
    # Start containers
    if (-not (Start-Containers)) {
        Write-Host "Container startup failed. Stopping integration." -ForegroundColor Red
        return
    }
    
    # Wait for services to be fully ready
    Write-Host "Waiting for services to be fully ready..." -ForegroundColor Cyan
    Start-Sleep -Seconds 60
    
    # Verify integration
    if (Verify-Integration) {
        Write-Host "🎉 Integration successful! Creating admin user..." -ForegroundColor Green
        Create-AdminUser
        
        Write-Host "`n🚀 CyberShield is now fully integrated and running!" -ForegroundColor Green
        Write-Host "`n📱 Access your application:" -ForegroundColor Cyan
        Write-Host "   Frontend: http://localhost:3000" -ForegroundColor White
        Write-Host "   Backend API: http://localhost:8000" -ForegroundColor White
        Write-Host "   API Documentation: http://localhost:8000/docs" -ForegroundColor White
        Write-Host "   Database: localhost:5432" -ForegroundColor White
        Write-Host "`n🔑 Default admin credentials:" -ForegroundColor Cyan
        Write-Host "   Username: admin" -ForegroundColor White
        Write-Host "   Password: admin123" -ForegroundColor White
        Write-Host "`n⚠️  IMPORTANT: Change default passwords in production!" -ForegroundColor Yellow
        
    } else {
        Write-Host "❌ Integration verification failed. Please check the logs." -ForegroundColor Red
        Write-Host "You can check container logs with: docker-compose -f docker-compose.production.yml logs" -ForegroundColor Yellow
    }
}

# Run the integration
Start-Integration
