# Manual Login/Logout Test Script
Write-Host "🔐 Testing Login/Logout Functionality Manually" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green

# Test 1: Health Check
Write-Host "`n1. Testing Backend Health..." -ForegroundColor Yellow
try {
    $healthResponse = Invoke-WebRequest -Uri "http://localhost:8000/health" -Method GET
    if ($healthResponse.StatusCode -eq 200) {
        $healthData = $healthResponse.Content | ConvertFrom-Json
        Write-Host "✅ Backend is healthy" -ForegroundColor Green
        Write-Host "   Status: $($healthData.status)" -ForegroundColor Cyan
        Write-Host "   Version: $($healthData.version)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "❌ Backend health check failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 2: Login
Write-Host "`n2. Testing Login..." -ForegroundColor Yellow
try {
    $loginData = @{
        username = "admin@cybershield.com"
        password = "password"
    }
    
    $loginResponse = Invoke-WebRequest -Uri "http://localhost:8000/api/v1/auth/login" -Method POST -Body $loginData -ContentType "application/x-www-form-urlencoded"
    
    if ($loginResponse.StatusCode -eq 200) {
        $loginData = $loginResponse.Content | ConvertFrom-Json
        Write-Host "✅ Login successful!" -ForegroundColor Green
        Write-Host "   User: $($loginData.email)" -ForegroundColor Cyan
        Write-Host "   Role: $($loginData.role)" -ForegroundColor Cyan
        Write-Host "   Token: $($loginData.access_token.Substring(0,20))..." -ForegroundColor Cyan
        
        $token = $loginData.access_token
    } else {
        Write-Host "❌ Login failed with status: $($loginResponse.StatusCode)" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ Login failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 3: Get User Profile
Write-Host "`n3. Testing User Profile Access..." -ForegroundColor Yellow
try {
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type" = "application/json"
    }
    
    $profileResponse = Invoke-WebRequest -Uri "http://localhost:8000/api/v1/auth/me" -Method GET -Headers $headers
    
    if ($profileResponse.StatusCode -eq 200) {
        $profileData = $profileResponse.Content | ConvertFrom-Json
        Write-Host "✅ Profile access successful!" -ForegroundColor Green
        Write-Host "   Email: $($profileData.email)" -ForegroundColor Cyan
        Write-Host "   Username: $($profileData.username)" -ForegroundColor Cyan
        Write-Host "   Role: $($profileData.role)" -ForegroundColor Cyan
    } else {
        Write-Host "❌ Profile access failed with status: $($profileResponse.StatusCode)" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Profile access failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: Token Refresh
Write-Host "`n4. Testing Token Refresh..." -ForegroundColor Yellow
try {
    $refreshResponse = Invoke-WebRequest -Uri "http://localhost:8000/api/v1/auth/refresh" -Method POST -Headers $headers
    
    if ($refreshResponse.StatusCode -eq 200) {
        $refreshData = $refreshResponse.Content | ConvertFrom-Json
        Write-Host "✅ Token refresh successful!" -ForegroundColor Green
        Write-Host "   New token: $($refreshData.access_token.Substring(0,20))..." -ForegroundColor Cyan
        
        # Update token for logout test
        $token = $refreshData.access_token
        $headers["Authorization"] = "Bearer $token"
    } else {
        Write-Host "❌ Token refresh failed with status: $($refreshResponse.StatusCode)" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Token refresh failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: Logout
Write-Host "`n5. Testing Logout..." -ForegroundColor Yellow
try {
    $logoutResponse = Invoke-WebRequest -Uri "http://localhost:8000/api/v1/auth/logout" -Method POST -Headers $headers
    
    if ($logoutResponse.StatusCode -eq 200) {
        $logoutData = $logoutResponse.Content | ConvertFrom-Json
        Write-Host "✅ Logout successful!" -ForegroundColor Green
        Write-Host "   Message: $($logoutData.message)" -ForegroundColor Cyan
        Write-Host "   Logout time: $($logoutData.logout_time)" -ForegroundColor Cyan
    } else {
        Write-Host "❌ Logout failed with status: $($logoutResponse.StatusCode)" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Logout failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 6: Verify Logout (Token should be invalid)
Write-Host "`n6. Verifying Logout (Token Invalidation)..." -ForegroundColor Yellow
try {
    $verifyResponse = Invoke-WebRequest -Uri "http://localhost:8000/api/v1/auth/me" -Method GET -Headers $headers
    
    if ($verifyResponse.StatusCode -eq 401) {
        Write-Host "✅ Logout verified - token is properly invalidated" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Token still valid after logout (Status: $($verifyResponse.StatusCode))" -ForegroundColor Yellow
    }
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "✅ Logout verified - token is properly invalidated" -ForegroundColor Green
    } else {
        Write-Host "❌ Logout verification failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Test 7: Test Invalid Login
Write-Host "`n7. Testing Invalid Login..." -ForegroundColor Yellow
try {
    $invalidLoginData = @{
        username = "invalid@example.com"
        password = "wrongpassword"
    }
    
    $invalidResponse = Invoke-WebRequest -Uri "http://localhost:8000/api/v1/auth/login" -Method POST -Body $invalidLoginData -ContentType "application/x-www-form-urlencoded"
    
    if ($invalidResponse.StatusCode -eq 401) {
        Write-Host "✅ Invalid login correctly rejected" -ForegroundColor Green
    } else {
        Write-Host "❌ Invalid login not properly rejected (Status: $($invalidResponse.StatusCode))" -ForegroundColor Red
    }
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "✅ Invalid login correctly rejected" -ForegroundColor Green
    } else {
        Write-Host "❌ Invalid login test failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n🎉 Manual Login/Logout Testing Complete!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green 