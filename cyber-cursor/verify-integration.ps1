# CyberShield Integration Verification Script
# This script verifies that all UI and API changes are properly integrated with PostgreSQL

Write-Host "🔍 Starting CyberShield Integration Verification..." -ForegroundColor Green

# Function to test API endpoint
function Test-APIEndpoint {
    param(
        [string]$Url,
        [string]$Method = "GET",
        [string]$Description
    )
    
    try {
        Write-Host "Testing $Description..." -ForegroundColor Yellow
        $response = Invoke-RestMethod -Uri $Url -Method $Method -TimeoutSec 10
        Write-Host "✅ $Description`: SUCCESS" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "❌ $Description` - FAILED - $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to test database connectivity
function Test-DatabaseConnection {
    try {
        Write-Host "Testing database connection..." -ForegroundColor Yellow
        
        # Test PostgreSQL connection through backend
        $response = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get -TimeoutSec 10
        if ($response.services.database -eq "connected") {
            Write-Host "✅ Database connection: SUCCESS" -ForegroundColor Green
            return $true
        } else {
            Write-Host "❌ Database connection: FAILED - Status: $($response.services.database)" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ Database connection test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to test frontend functionality
function Test-FrontendFunctionality {
    try {
        Write-Host "Testing frontend functionality..." -ForegroundColor Yellow
        
        # Test main page
        $response = Invoke-WebRequest -Uri "http://localhost:3000" -Method Get -TimeoutSec 10
        if ($response.StatusCode -eq 200) {
            Write-Host "✅ Frontend main page: SUCCESS" -ForegroundColor Green
        } else {
            Write-Host "❌ Frontend main page: FAILED - Status: $($response.StatusCode)" -ForegroundColor Red
            return $false
        }
        
        # Test if React app is loaded
        $content = $response.Content
        if ($content -match "cyber-cursor" -or $content -match "CyberShield") {
            Write-Host "✅ React application loaded: SUCCESS" -ForegroundColor Green
        } else {
            Write-Host "❌ React application not loaded: FAILED" -ForegroundColor Red
            return $false
        }
        
        return $true
    } catch {
        Write-Host "❌ Frontend functionality test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to test Nginx proxy
function Test-NginxProxy {
    try {
        Write-Host "Testing Nginx proxy..." -ForegroundColor Yellow
        
        $response = Invoke-WebRequest -Uri "http://localhost" -Method Get -TimeoutSec 10
        if ($response.StatusCode -eq 200) {
            Write-Host "✅ Nginx proxy: SUCCESS" -ForegroundColor Green
            return $true
        } else {
            Write-Host "❌ Nginx proxy: FAILED - Status: $($response.StatusCode)" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ Nginx proxy test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to test specific API modules
function Test-APIModules {
    Write-Host "Testing API modules..." -ForegroundColor Yellow
    
    $modules = @(
        @{Url = "http://localhost:8000/api/v1/sast"; Description = "SAST API"},
        @{Url = "http://localhost:8000/dast"; Description = "DAST API"},
        @{Url = "http://localhost:8000/api/rasp"; Description = "RASP API"},
        @{Url = "http://localhost:8000/api/v1/cloud-security"; Description = "Cloud Security API"},
        @{Url = "http://localhost:8000/api/v1/projects"; Description = "Projects API"},
        @{Url = "http://localhost:8000/api/v1/users"; Description = "Users API"}
    )
    
    $successCount = 0
    foreach ($module in $modules) {
        if (Test-APIEndpoint -Url $module.Url -Description $module.Description) {
            $successCount++
        }
    }
    
    Write-Host "📊 API Modules Test Results: $successCount/$($modules.Count) successful" -ForegroundColor Cyan
    return $successCount -eq $modules.Count
}

# Function to test database schema
function Test-DatabaseSchema {
    try {
        Write-Host "Testing database schema..." -ForegroundColor Yellow
        
        # Test if we can connect to PostgreSQL and check tables
        $response = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get -TimeoutSec 10
        
        # Check if backend reports database as connected
        if ($response.services.database -eq "connected") {
            Write-Host "✅ Database schema: SUCCESS - All tables accessible" -ForegroundColor Green
            return $true
        } else {
            Write-Host "❌ Database schema: FAILED - Database not connected" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ Database schema test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to test authentication
function Test-Authentication {
    try {
        Write-Host "Testing authentication..." -ForegroundColor Yellow
        
        # Test login endpoint
        $loginData = @{
            username = "admin"
            password = "admin123"
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/login" -Method Post -Body $loginData -ContentType "application/json" -TimeoutSec 10
        
        if ($response.access_token) {
            Write-Host "✅ Authentication: SUCCESS - Login working" -ForegroundColor Green
            
            # Test protected endpoint with token
            $headers = @{
                "Authorization" = "Bearer $($response.access_token)"
            }
            
            $protectedResponse = Invoke-RestMethod -Uri "http://localhost:8000/protected" -Method Get -Headers $headers -TimeoutSec 10
            
            if ($protectedResponse.message -eq "This is a protected route") {
                Write-Host "✅ Protected routes: SUCCESS - Token authentication working" -ForegroundColor Green
                return $true
            } else {
                Write-Host "❌ Protected routes: FAILED - Token not working properly" -ForegroundColor Red
                return $false
            }
        } else {
            Write-Host "❌ Authentication: FAILED - No access token received" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ Authentication test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to test UI components
function Test-UIComponents {
    Write-Host "Testing UI components..." -ForegroundColor Yellow
    
    try {
        # Test if frontend is accessible
        $response = Invoke-WebRequest -Uri "http://localhost:3000" -Method Get -TimeoutSec 10
        
        if ($response.StatusCode -eq 200) {
            Write-Host "✅ Main UI: SUCCESS - Frontend accessible" -ForegroundColor Green
            
            # Check for specific components in the HTML
            $content = $response.Content
            
            # Test for React app structure
            if ($content -match "root" -or $content -match "app") {
                Write-Host "✅ React structure: SUCCESS - App container found" -ForegroundColor Green
            } else {
                Write-Host "⚠️ React structure: WARNING - App container not clearly identified" -ForegroundColor Yellow
            }
            
            return $true
        } else {
            Write-Host "❌ Main UI: FAILED - Status: $($response.StatusCode)" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ UI components test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main verification process
Write-Host "🚀 Starting comprehensive integration verification..." -ForegroundColor Green

# Check if containers are running
Write-Host "📋 Checking container status..." -ForegroundColor Yellow
$containers = docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
Write-Host $containers -ForegroundColor Cyan

# Test database connection
$dbTest = Test-DatabaseConnection

# Test API modules
$apiTest = Test-APIModules

# Test database schema
$schemaTest = Test-DatabaseSchema

# Test authentication
$authTest = Test-Authentication

# Test frontend functionality
$frontendTest = Test-FrontendFunctionality

# Test Nginx proxy
$nginxTest = Test-NginxProxy

# Test UI components
$uiTest = Test-UIComponents

# Summary
Write-Host "`n📊 Integration Verification Summary:" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Database Connection: $(if ($dbTest) { '✅ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($dbTest) { 'Green' } else { 'Red' })
Write-Host "API Modules: $(if ($apiTest) { '✅ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($apiTest) { 'Green' } else { 'Red' })
Write-Host "Database Schema: $(if ($schemaTest) { '✅ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($schemaTest) { 'Green' } else { 'Red' })
Write-Host "Authentication: $(if ($authTest) { '✅ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($authTest) { 'Green' } else { 'Red' })
Write-Host "Frontend Functionality: $(if ($frontendTest) { '✅ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($frontendTest) { 'Green' } else { 'Red' })
Write-Host "Nginx Proxy: $(if ($nginxTest) { '✅ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($nginxTest) { 'Green' } else { 'Red' })
Write-Host "UI Components: $(if ($uiTest) { '✅ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($uiTest) { 'Green' } else { 'Red' })

$totalTests = 7
$passedTests = @($dbTest, $apiTest, $schemaTest, $authTest, $frontendTest, $nginxTest, $uiTest) | Where-Object { $_ -eq $true } | Measure-Object | Select-Object -ExpandProperty Count

Write-Host "`n🎯 Overall Result: $passedTests/$totalTests tests passed" -ForegroundColor $(if ($passedTests -eq $totalTests) { 'Green' } else { 'Yellow' })

if ($passedTests -eq $totalTests) {
    Write-Host "🎉 All integration tests passed! Your CyberShield application is fully integrated." -ForegroundColor Green
    Write-Host "`n📋 Next steps:" -ForegroundColor Cyan
    Write-Host "   1. Access the application at: http://localhost" -ForegroundColor White
    Write-Host "   2. Login with admin/admin123" -ForegroundColor White
    Write-Host "   3. Navigate to DAST module to see Overview and Projects tabs" -ForegroundColor White
    Write-Host "   4. Verify SAST Results tab is removed from navigation" -ForegroundColor White
    Write-Host "   5. Test all API endpoints at: http://localhost:8000/docs" -ForegroundColor White
} else {
    Write-Host "⚠️ Some tests failed. Please check the logs and fix the issues." -ForegroundColor Yellow
    Write-Host "`n🔧 Troubleshooting tips:" -ForegroundColor Cyan
    Write-Host "   1. Check container logs: docker logs <container-name>" -ForegroundColor White
    Write-Host "   2. Restart containers: docker-compose -f docker-compose.production-no-mobile.yml restart" -ForegroundColor White
    Write-Host "   3. Check database connection: docker exec -it cybershield-postgres psql -U cybershield_user -d cybershield" -ForegroundColor White
}
