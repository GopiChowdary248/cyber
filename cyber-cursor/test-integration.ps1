# CyberShield Integration Test Script
# This script tests if all components are properly integrated

Write-Host "🧪 Testing CyberShield Integration..." -ForegroundColor Green

# Function to test service health
function Test-ServiceHealth {
    param(
        [string]$ServiceName,
        [string]$Url,
        [string]$ExpectedStatus = "200"
    )
    
    try {
        Write-Host "Testing $ServiceName..." -ForegroundColor Yellow
        $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 10
        if ($response.StatusCode -eq $ExpectedStatus) {
            Write-Host "✅ $ServiceName`: HEALTHY" -ForegroundColor Green
            return $true
        } else {
            Write-Host "❌ $ServiceName`: Status $($response.StatusCode)" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ $ServiceName`: FAILED - $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to test database connectivity
function Test-DatabaseConnectivity {
    try {
        Write-Host "Testing database connectivity..." -ForegroundColor Yellow
        
        # Test through backend health endpoint
        $response = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get -TimeoutSec 15
        if ($response.services.database -eq "connected") {
            Write-Host "✅ Database: CONNECTED" -ForegroundColor Green
            return $true
        } else {
            Write-Host "❌ Database: NOT CONNECTED - Status: $($response.services.database)" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ Database test failed: $($_.Exception.Message)" -ForegroundColor Red
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
        
        $response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/login" -Method Post -Body $loginData -ContentType "application/json" -TimeoutSec 15
        
        if ($response.access_token) {
            Write-Host "✅ Authentication: WORKING" -ForegroundColor Green
            return $true
        } else {
            Write-Host "❌ Authentication: FAILED - No token received" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ Authentication test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to test API endpoints
function Test-APIEndpoints {
    Write-Host "Testing API endpoints..." -ForegroundColor Yellow
    
    $endpoints = @(
        @{Url = "http://localhost:8000/api/v1/sast"; Description = "SAST API"},
        @{Url = "http://localhost:8000/api/v1/dast"; Description = "DAST API"},
        @{Url = "http://localhost:8000/api/v1/rasp"; Description = "RASP API"},
        @{Url = "http://localhost:8000/api/v1/cloud"; Description = "Cloud Security API"},
        @{Url = "http://localhost:8000/api/v1/threats"; Description = "Threat Intelligence API"},
        @{Url = "http://localhost:8000/api/v1/incidents"; Description = "Incidents API"}
    )
    
    $successCount = 0
    foreach ($endpoint in $endpoints) {
        try {
            $response = Invoke-WebRequest -Uri $endpoint.Url -Method Get -TimeoutSec 10
            if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 401) {
                Write-Host "✅ $($endpoint.Description): RESPONDING" -ForegroundColor Green
                $successCount++
            } else {
                Write-Host "❌ $($endpoint.Description): Status $($response.StatusCode)" -ForegroundColor Red
            }
        } catch {
            Write-Host "❌ $($endpoint.Description): FAILED - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    return $successCount -eq $endpoints.Count
}

# Function to test frontend functionality
function Test-FrontendFunctionality {
    try {
        Write-Host "Testing frontend functionality..." -ForegroundColor Yellow
        
        # Test main page
        $response = Invoke-WebRequest -Uri "http://localhost:3000" -Method Get -TimeoutSec 10
        if ($response.StatusCode -eq 200) {
            Write-Host "✅ Frontend main page: LOADING" -ForegroundColor Green
        } else {
            Write-Host "❌ Frontend main page: Status $($response.StatusCode)" -ForegroundColor Red
            return $false
        }
        
        # Test if React app is loaded
        $content = $response.Content
        if ($content -match "cyber-cursor" -or $content -match "CyberShield" -or $content -match "React") {
            Write-Host "✅ React application: LOADED" -ForegroundColor Green
        } else {
            Write-Host "❌ React application: NOT LOADED" -ForegroundColor Red
            return $false
        }
        
        return $true
    } catch {
        Write-Host "❌ Frontend functionality test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to test container status
function Test-ContainerStatus {
    try {
        Write-Host "Testing container status..." -ForegroundColor Yellow
        
        $containers = @("cybershield-postgres", "cybershield-redis", "cybershield-backend", "cybershield-frontend")
        $healthyCount = 0
        
        foreach ($container in $containers) {
            try {
                $status = docker inspect --format='{{.State.Status}}' $container 2>$null
                if ($status -eq "running") {
                    Write-Host "✅ $container`: RUNNING" -ForegroundColor Green
                    $healthyCount++
                } else {
                    Write-Host "❌ $container`: $status" -ForegroundColor Red
                }
            } catch {
                Write-Host "❌ $container`: NOT FOUND" -ForegroundColor Red
            }
        }
        
        return $healthyCount -eq $containers.Count
    } catch {
        Write-Host "❌ Container status test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main test execution
function Start-IntegrationTest {
    Write-Host "Starting CyberShield integration test..." -ForegroundColor Green
    Write-Host "This will test all components to ensure proper integration" -ForegroundColor Cyan
    
    $testResults = @{}
    
    # Test container status
    $testResults.Containers = Test-ContainerStatus
    
    # Test service health
    $testResults.BackendHealth = Test-ServiceHealth "Backend API" "http://localhost:8000/health"
    $testResults.FrontendHealth = Test-ServiceHealth "Frontend" "http://localhost:3000"
    
    # Test database connectivity
    $testResults.Database = Test-DatabaseConnectivity
    
    # Test authentication
    $testResults.Authentication = Test-Authentication
    
    # Test API endpoints
    $testResults.APIEndpoints = Test-APIEndpoints
    
    # Test frontend functionality
    $testResults.FrontendFunctionality = Test-FrontendFunctionality
    
    # Display results summary
    Write-Host "`n📊 Integration Test Results:" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    
    foreach ($test in $testResults.GetEnumerator()) {
        $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
        Write-Host "$($test.Key): $status" -ForegroundColor $(if ($test.Value) { "Green" } else { "Red" })
    }
    
    $passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count
    $totalTests = $testResults.Count
    $successRate = [math]::Round(($passedTests / $totalTests) * 100, 1)
    
    Write-Host "`n📈 Overall Success Rate: $successRate% ($passedTests/$totalTests tests passed)" -ForegroundColor $(if ($successRate -ge 80) { "Green" } else { "Yellow" })
    
    if ($successRate -ge 80) {
        Write-Host "`n🎉 Integration test PASSED! Your CyberShield application is properly integrated." -ForegroundColor Green
        Write-Host "`n📱 Access your application:" -ForegroundColor Cyan
        Write-Host "   Frontend: http://localhost:3000" -ForegroundColor White
        Write-Host "   Backend API: http://localhost:8000" -ForegroundColor White
        Write-Host "   API Documentation: http://localhost:8000/docs" -ForegroundColor White
        Write-Host "   Database: localhost:5432" -ForegroundColor White
    } else {
        Write-Host "`n⚠️  Integration test FAILED. Some components are not working properly." -ForegroundColor Red
        Write-Host "Please check the logs and fix the issues before proceeding." -ForegroundColor Yellow
        Write-Host "You can check container logs with: docker-compose -f docker-compose.production.yml logs" -ForegroundColor Cyan
    }
}

# Run the integration test
Start-IntegrationTest
