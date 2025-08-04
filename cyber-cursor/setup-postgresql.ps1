# PostgreSQL Setup Script for CyberShield
# This script sets up PostgreSQL database and user for the application

Write-Host "Setting up PostgreSQL for CyberShield..." -ForegroundColor Green

# PostgreSQL connection details
$PG_HOST = "localhost"
$PG_PORT = "5432"
$PG_DB = "cybershield"
$PG_USER = "cybershield_user"
$PG_PASSWORD = "cybershield_password"

Write-Host "Creating database and user..." -ForegroundColor Yellow

# Create database and user using psql
$createDB = @"
-- Create user if not exists
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$PG_USER') THEN
        CREATE USER $PG_USER WITH PASSWORD '$PG_PASSWORD';
    END IF;
END
\$\$;

-- Create database if not exists
SELECT 'CREATE DATABASE $PG_DB'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$PG_DB')\gexec

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE $PG_DB TO $PG_USER;
GRANT ALL ON SCHEMA public TO $PG_USER;
"@

# Save the SQL script
$createDB | Out-File -FilePath "setup_db.sql" -Encoding UTF8

Write-Host "Database setup script created. Please run the following command:" -ForegroundColor Cyan
Write-Host "psql -U postgres -f setup_db.sql" -ForegroundColor White

Write-Host "`nOr manually execute these commands in psql:" -ForegroundColor Yellow
Write-Host "1. CREATE USER $PG_USER WITH PASSWORD '$PG_PASSWORD';" -ForegroundColor White
Write-Host "2. CREATE DATABASE $PG_DB;" -ForegroundColor White
Write-Host "3. GRANT ALL PRIVILEGES ON DATABASE $PG_DB TO $PG_USER;" -ForegroundColor White
Write-Host "4. GRANT ALL ON SCHEMA public TO $PG_USER;" -ForegroundColor White

Write-Host "`nAfter setting up PostgreSQL, run: .\start-production.ps1" -ForegroundColor Green 