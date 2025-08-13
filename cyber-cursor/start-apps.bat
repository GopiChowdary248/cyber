@echo off
echo 🚀 Starting CyberShield Application...
echo.

echo ⚛️ Starting Frontend (React)...
start "Frontend Server" cmd /k "cd /d %~dp0frontend && npm start"

echo ⏳ Waiting for frontend to start...
timeout /t 5 /nobreak >nul

echo 🐍 Starting Backend (Python)...
start "Backend Server" cmd /k "cd /d %~dp0backend && python main-simple.py"

echo.
echo ✅ Both servers are starting up!
echo 📱 Frontend will be available at: http://localhost:3000
echo 🔌 Backend API will be available at: http://localhost:8000
echo.
echo 🌐 You can now access the login page at: http://localhost:3000/login
echo.
pause
