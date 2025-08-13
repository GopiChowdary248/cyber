# CyberShield Application Startup Script
# This script starts both the frontend and backend servers

Write-Host "🚀 Starting CyberShield Application..." -ForegroundColor Green

# Start Frontend (React) in a new PowerShell window
Write-Host "⚛️ Starting Frontend (React)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD\frontend'; Write-Host 'Starting Frontend...' -ForegroundColor Green; npm start"

# Wait a moment for frontend to start
Start-Sleep -Seconds 5

# Start Backend (Python) in a new PowerShell window
Write-Host "🐍 Starting Backend (Python)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD\backend'; Write-Host 'Starting Backend...' -ForegroundColor Green; python main-simple.py"

Write-Host "✅ Both servers are starting up!" -ForegroundColor Green
Write-Host "📱 Frontend will be available at: http://localhost:3000" -ForegroundColor Cyan
Write-Host "🔌 Backend API will be available at: http://localhost:8000" -ForegroundColor Cyan
Write-Host ""
Write-Host "🌐 You can now access the login page at: http://localhost:3000/login" -ForegroundColor Green
Write-Host ""
Write-Host "Press any key to exit this script..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Write-Host "✅ Startup script completed!" -ForegroundColor Green
