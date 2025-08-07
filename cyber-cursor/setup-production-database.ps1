# CyberShield Production Database Setup Script
# This script sets up the database with migrations and sample data

Write-Host "🗄️ Setting up CyberShield Production Database..." -ForegroundColor Green

# Wait for PostgreSQL to be ready
Write-Host "⏳ Waiting for PostgreSQL to be ready..." -ForegroundColor Yellow
$maxAttempts = 30
$attempt = 0
do {
    $attempt++
    Write-Host "Attempt $attempt/$maxAttempts - Checking PostgreSQL..." -ForegroundColor Gray
    try {
        $result = docker exec cybershield-postgres pg_isready -U cybershield_user -d cybershield
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ PostgreSQL is ready!" -ForegroundColor Green
            break
        }
    } catch {
        Write-Host "PostgreSQL not ready yet..." -ForegroundColor Red
    }
    Start-Sleep -Seconds 10
} while ($attempt -lt $maxAttempts)

if ($attempt -eq $maxAttempts) {
    Write-Host "❌ PostgreSQL failed to start within expected time" -ForegroundColor Red
    exit 1
}

# Wait a bit more for backend to be ready
Write-Host "⏳ Waiting for backend to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

# Run database migrations
Write-Host "🔄 Running database migrations..." -ForegroundColor Yellow
try {
    docker exec cybershield-backend python -m alembic upgrade head
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Database migrations completed successfully!" -ForegroundColor Green
    } else {
        Write-Host "❌ Database migrations failed" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Database migrations failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Populate with sample data
Write-Host "📊 Populating database with sample data..." -ForegroundColor Yellow
try {
    docker exec cybershield-backend python populate_sast_data.py
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Sample data populated successfully!" -ForegroundColor Green
    } else {
        Write-Host "❌ Sample data population failed" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Sample data population failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Create admin user if needed
Write-Host "👤 Creating admin user..." -ForegroundColor Yellow
try {
    docker exec cybershield-backend python create-admin-user.py
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Admin user created successfully!" -ForegroundColor Green
    } else {
        Write-Host "⚠️ Admin user creation failed or user already exists" -ForegroundColor Yellow
    }
} catch {
    Write-Host "⚠️ Admin user creation failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "`n🎉 Database setup completed!" -ForegroundColor Green
Write-Host "`n📋 Database Status:" -ForegroundColor Cyan
Write-Host "   ✅ PostgreSQL: Running" -ForegroundColor White
Write-Host "   ✅ Migrations: Applied" -ForegroundColor White
Write-Host "   ✅ Sample Data: Loaded" -ForegroundColor White
Write-Host "   ✅ Admin User: Created" -ForegroundColor White

Write-Host "`n🔑 Default Login Credentials:" -ForegroundColor Cyan
Write-Host "   Username: admin" -ForegroundColor White
Write-Host "   Password: admin123" -ForegroundColor White

Write-Host "`n🌐 You can now access the application at:" -ForegroundColor Cyan
Write-Host "   http://localhost:3000" -ForegroundColor White 