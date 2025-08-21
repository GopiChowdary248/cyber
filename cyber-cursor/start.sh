#!/bin/bash

# Cyber Cursor DAST Startup Script
echo "🚀 Starting Cyber Cursor DAST System..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop first."
    exit 1
fi

# Start PostgreSQL database
echo "📦 Starting PostgreSQL database..."
docker-compose up -d postgres

# Wait for database to be ready
echo "⏳ Waiting for database to be ready..."
until docker-compose exec -T postgres pg_isready -U postgres -d cyber_cursor_dast > /dev/null 2>&1; do
    echo "   Waiting for PostgreSQL..."
    sleep 2
done
echo "✅ Database is ready!"

# Check if backend dependencies are installed
if [ ! -d "backend/venv" ] && [ ! -f "backend/requirements.txt" ]; then
    echo "❌ Backend dependencies not found. Please run setup first."
    exit 1
fi

# Start backend
echo "🔧 Starting backend server..."
cd backend

# Check if virtual environment exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Install dependencies if needed
if [ ! -d "venv" ]; then
    echo "📥 Installing Python dependencies..."
    pip install -r requirements.txt
fi

# Set environment variables
export DATABASE_URL="postgresql://postgres:password@localhost:5432/cyber_cursor_dast"
export SECRET_KEY="your-secret-key-change-in-production"

# Start backend in background
echo "🚀 Starting FastAPI backend..."
python main.py &
BACKEND_PID=$!

# Wait for backend to start
echo "⏳ Waiting for backend to start..."
until curl -s http://localhost:8000/health > /dev/null 2>&1; do
    echo "   Waiting for backend..."
    sleep 2
done
echo "✅ Backend is ready!"

# Start frontend
echo "🎨 Starting frontend..."
cd ../frontend

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "📥 Installing Node.js dependencies..."
    npm install
fi

# Start frontend in background
echo "🚀 Starting React frontend..."
npm start &
FRONTEND_PID=$!

# Wait for frontend to start
echo "⏳ Waiting for frontend to start..."
until curl -s http://localhost:3000 > /dev/null 2>&1; do
    echo "   Waiting for frontend..."
    sleep 2
done
echo "✅ Frontend is ready!"

# Display system status
echo ""
echo "🎉 Cyber Cursor DAST System is running!"
echo ""
echo "📱 Frontend: http://localhost:3000"
echo "🔧 Backend:  http://localhost:8000"
echo "📚 API Docs: http://localhost:8000/docs"
echo "🏥 Health:   http://localhost:8000/health"
echo "🗄️  Database: localhost:5432 (cyber_cursor_dast)"
echo "🔍 PgAdmin:  http://localhost:5050 (admin@cybercursor.com / admin)"
echo ""
echo "Press Ctrl+C to stop all services..."

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Stopping Cyber Cursor DAST System..."
    
    # Stop frontend
    if [ ! -z "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null
        echo "✅ Frontend stopped"
    fi
    
    # Stop backend
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null
        echo "✅ Backend stopped"
    fi
    
    # Stop database
    cd ..
    docker-compose down
    echo "✅ Database stopped"
    
    echo "👋 Goodbye!"
    exit 0
}

# Set trap for cleanup
trap cleanup SIGINT SIGTERM

# Keep script running
wait 