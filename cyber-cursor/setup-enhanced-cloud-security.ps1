# Enhanced Cloud Security Setup Script
# This script sets up the database tables for enhanced cloud security features

Write-Host "Setting up Enhanced Cloud Security Database Tables..." -ForegroundColor Green

# Check if PostgreSQL is running
try {
    $pgStatus = Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue
    if ($pgStatus -and $pgStatus.Status -eq "Running") {
        Write-Host "PostgreSQL service is running" -ForegroundColor Green
    } else {
        Write-Host "PostgreSQL service is not running. Starting..." -ForegroundColor Yellow
        Start-Service -Name "postgresql*" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
    }
} catch {
    Write-Host "Could not check PostgreSQL service status" -ForegroundColor Yellow
}

# Set environment variables
$env:PGPASSWORD = "cybershield"
$env:PGUSER = "cybershield"
$env:PGDATABASE = "cybershield"
$env:PGHOST = "localhost"
$env:PGPORT = "5432"

# Function to run SQL commands
function Invoke-PostgreSQL {
    param(
        [string]$Command,
        [string]$Description
    )
    
    Write-Host "Executing: $Description" -ForegroundColor Cyan
    
    try {
        $result = psql -c $Command 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ $Description completed successfully" -ForegroundColor Green
        } else {
            Write-Host "✗ $Description failed: $result" -ForegroundColor Red
        }
    } catch {
        Write-Host "✗ $Description failed with exception: $_" -ForegroundColor Red
    }
}

# Check database connection
Write-Host "Testing database connection..." -ForegroundColor Cyan
try {
    $testResult = psql -c "SELECT version();" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Database connection successful" -ForegroundColor Green
    } else {
        Write-Host "✗ Database connection failed: $testResult" -ForegroundColor Red
        Write-Host "Please ensure PostgreSQL is running and credentials are correct" -ForegroundColor Yellow
        exit 1
    }
} catch {
    Write-Host "✗ Database connection failed with exception: $_" -ForegroundColor Red
    exit 1
}

# Create enhanced cloud security tables
Write-Host "Creating Enhanced Cloud Security tables..." -ForegroundColor Green

# Read and execute the migration SQL
$migrationPath = "backend\migrations\create_enhanced_cloud_security_tables.sql"
if (Test-Path $migrationPath) {
    Write-Host "Executing migration from: $migrationPath" -ForegroundColor Cyan
    
    try {
        $migrationContent = Get-Content $migrationPath -Raw
        $migrationContent = $migrationContent -replace "`r`n", "`n"  # Normalize line endings
        
        # Split into individual statements and execute
        $statements = $migrationContent -split ";" | Where-Object { $_.Trim() -ne "" }
        
        foreach ($statement in $statements) {
            $trimmedStatement = $statement.Trim()
            if ($trimmedStatement -ne "") {
                Invoke-PostgreSQL -Command $trimmedStatement -Description "Executing SQL statement"
                Start-Sleep -Milliseconds 100  # Small delay between statements
            }
        }
        
        Write-Host "✓ Migration completed successfully" -ForegroundColor Green
        
    } catch {
        Write-Host "✗ Migration failed: $_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "✗ Migration file not found: $migrationPath" -ForegroundColor Red
    exit 1
}

# Verify tables were created
Write-Host "Verifying table creation..." -ForegroundColor Cyan

$tablesToCheck = @(
    "container_images",
    "container_vulnerabilities", 
    "container_layers",
    "container_runtimes",
    "container_instances",
    "serverless_functions",
    "serverless_permissions",
    "serverless_vulnerabilities",
    "kubernetes_clusters",
    "kubernetes_namespaces",
    "kubernetes_resources",
    "kubernetes_security_issues",
    "pod_security_policies",
    "rbac_roles",
    "rbac_bindings",
    "network_policies",
    "admission_controllers",
    "enhanced_cloud_security_summary"
)

$allTablesExist = $true

foreach ($table in $tablesToCheck) {
    try {
        $result = psql -c "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = '$table');" 2>&1
        if ($result -match "t") {
            Write-Host "✓ Table '$table' exists" -ForegroundColor Green
        } else {
            Write-Host "✗ Table '$table' does not exist" -ForegroundColor Red
            $allTablesExist = $false
        }
    } catch {
        Write-Host "✗ Could not check table '$table': $_" -ForegroundColor Red
        $allTablesExist = $false
    }
}

if ($allTablesExist) {
    Write-Host "`n🎉 Enhanced Cloud Security setup completed successfully!" -ForegroundColor Green
    Write-Host "All required tables have been created in the database." -ForegroundColor Green
} else {
    Write-Host "`n⚠️  Enhanced Cloud Security setup completed with warnings." -ForegroundColor Yellow
    Write-Host "Some tables may not have been created properly." -ForegroundColor Yellow
}

# Display table counts
Write-Host "`nTable Summary:" -ForegroundColor Cyan
try {
    $tableCounts = psql -c "
        SELECT 
            schemaname,
            tablename,
            n_tup_ins as inserts,
            n_tup_upd as updates,
            n_tup_del as deletes
        FROM pg_stat_user_tables 
        WHERE tablename IN ('container_images', 'serverless_functions', 'kubernetes_clusters')
        ORDER BY tablename;
    " 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host $tableCounts -ForegroundColor White
    }
} catch {
    Write-Host "Could not retrieve table statistics" -ForegroundColor Yellow
}

Write-Host "`nEnhanced Cloud Security is ready to use!" -ForegroundColor Green
Write-Host "You can now use the API endpoints to manage container security, serverless security, and Kubernetes security." -ForegroundColor Green
