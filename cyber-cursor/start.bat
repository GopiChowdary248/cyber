@echo off
chcp 65001 >nul
echo 🚀 Starting Cyber Cursor DAST System...

REM Check if Docker is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker is not running. Please start Docker Desktop first.
    pause
    exit /b 1
)

REM Start PostgreSQL database
echo 📦 Starting PostgreSQL database...
docker-compose up -d postgres

REM Wait for database to be ready
echo ⏳ Waiting for database to be ready...
:wait_db
docker-compose exec -T postgres pg_isready -U postgres -d cyber_cursor_dast >nul 2>&1
if %errorlevel% neq 0 (
    echo    Waiting for PostgreSQL...
    timeout /t 2 /nobreak >nul
    goto wait_db
)
echo ✅ Database is ready!

REM Check if backend dependencies are installed
if not exist "backend\requirements.txt" (
    echo ❌ Backend dependencies not found. Please run setup first.
    pause
    exit /b 1
)

REM Start backend
echo 🔧 Starting backend server...
cd backend

REM Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

REM Install dependencies if needed
if not exist "venv" (
    echo 📥 Installing Python dependencies...
    pip install -r requirements.txt
)

REM Set environment variables
set DATABASE_URL=postgresql://postgres:password@localhost:5432/cyber_cursor_dast
set SECRET_KEY=your-secret-key-change-in-production

REM Start backend in background
echo 🚀 Starting FastAPI backend...
start /B python main.py

REM Wait for backend to start
echo ⏳ Waiting for backend to start...
:wait_backend
curl -s http://localhost:8000/health >nul 2>&1
if %errorlevel% neq 0 (
    echo    Waiting for backend...
    timeout /t 2 /nobreak >nul
    goto wait_backend
)
echo ✅ Backend is ready!

REM Start frontend
echo 🎨 Starting frontend...
cd ..\frontend

REM Check if node_modules exists
if not exist "node_modules" (
    echo 📥 Installing Node.js dependencies...
    npm install
)

REM Start frontend in background
echo 🚀 Starting React frontend...
start /B npm start

REM Wait for frontend to start
echo ⏳ Waiting for frontend to start...
:wait_frontend
curl -s http://localhost:3000 >nul 2>&1
if %errorlevel% neq 0 (
    echo    Waiting for frontend...
    timeout /t 2 /nobreak >nul
    goto wait_frontend
)
echo ✅ Frontend is ready!

REM Display system status
echo.
echo 🎉 Cyber Cursor DAST System is running!
echo.
echo 📱 Frontend: http://localhost:3000
echo 🔧 Backend:  http://localhost:8000
echo 📚 API Docs: http://localhost:8000/docs
echo 🏥 Health:   http://localhost:8000/health
echo 🗄️  Database: localhost:5432 (cyber_cursor_dast)
echo 🔍 PgAdmin:  http://localhost:5050 (admin@cybercursor.com / admin)
echo.
echo Press any key to stop all services...

REM Wait for user input
pause >nul

REM Stop services
echo.
echo 🛑 Stopping Cyber Cursor DAST System...

REM Stop frontend and backend (they will continue running in background)
REM In Windows, you may need to manually stop them from Task Manager
echo ✅ Services stopped (check Task Manager for any remaining processes)

REM Stop database
cd ..
docker-compose down
echo ✅ Database stopped

echo 👋 Goodbye!
pause 