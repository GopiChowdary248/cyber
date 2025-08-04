# Quick Start Guide - CyberShield Production Setup

## Immediate Steps to Get Started

### 1. Install PostgreSQL

**Option A: Download from Official Website**
1. Go to https://www.postgresql.org/download/windows/
2. Download PostgreSQL 15 or later
3. Run the installer
4. Set password for 'postgres' user
5. Keep default port (5432)

**Option B: Using Chocolatey (if installed)**
```powershell
choco install postgresql15
```

### 2. Start PostgreSQL Service
```powershell
# Start PostgreSQL service
Start-Service postgresql-x64-15

# Verify it's running
Get-Service postgresql-x64-15
```

### 3. Create Database and User
```powershell
# Connect to PostgreSQL
psql -U postgres

# In the PostgreSQL prompt, run:
CREATE USER cybershield_user WITH PASSWORD 'cybershield_password';
CREATE DATABASE cybershield;
GRANT ALL PRIVILEGES ON DATABASE cybershield TO cybershield_user;
GRANT ALL ON SCHEMA public TO cybershield_user;
\q
```

### 4. Install Python Dependencies
```powershell
cd backend
pip install fastapi uvicorn sqlalchemy asyncpg psycopg2-binary redis python-jose PyJWT passlib python-multipart structlog
```

### 5. Start Backend in Production Mode
```powershell
# Set production environment variables
$env:ENVIRONMENT="production"
$env:DATABASE_URL="postgresql+asyncpg://cybershield_user:cybershield_password@localhost:5432/cybershield"
$env:DEBUG="false"
$env:SECRET_KEY="your-super-secret-production-key-change-this-immediately"

# Start the backend
python main.py
```

### 6. Test the Application
```powershell
# Test health endpoint
Invoke-RestMethod -Uri "http://localhost:8000/health" -Method GET

# Test login endpoint
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/login" -Method POST -ContentType "application/json" -Body '{"username": "admin", "password": "admin123"}'
```

## React Native Frontend Setup

### 1. Install Node.js and React Native
```powershell
# Install Node.js (if not already installed)
# Download from https://nodejs.org/

# Install React Native CLI
npm install -g @react-native-community/cli

# Install Expo CLI (alternative)
npm install -g @expo/cli
```

### 2. Create React Native Project
```powershell
# Create new project
npx react-native init CyberShieldMobile --template react-native-template-typescript

# Or use Expo
npx create-expo-app CyberShieldMobile --template blank-typescript
```

### 3. Install Dependencies
```powershell
cd CyberShieldMobile
npm install @react-navigation/native @react-navigation/stack
npm install axios react-native-vector-icons
npm install @react-native-async-storage/async-storage
npm install react-native-elements
```

### 4. Configure API Connection
Update the API base URL in your React Native app to point to your backend:
```typescript
const API_BASE_URL = 'http://localhost:8000/api/v1';
```

## Troubleshooting

### PostgreSQL Connection Issues
1. Ensure PostgreSQL service is running
2. Check if port 5432 is not blocked by firewall
3. Verify database and user exist
4. Test connection: `psql -U cybershield_user -d cybershield -h localhost`

### Backend Startup Issues
1. Check if all dependencies are installed
2. Verify environment variables are set correctly
3. Check logs for specific error messages
4. Ensure PostgreSQL is accessible

### React Native Issues
1. Ensure Node.js is installed and in PATH
2. Check if React Native CLI is installed globally
3. Verify Android/iOS development environment is set up
4. Check network connectivity to backend

## Next Steps

1. **Set up proper security**: Change default passwords and secret keys
2. **Configure production environment**: Set up proper domain names and SSL
3. **Set up monitoring**: Implement logging and monitoring solutions
4. **Create backups**: Set up automated database backups
5. **Deploy to production**: Set up proper deployment pipeline

## Architecture Summary

- **Backend**: Python FastAPI with PostgreSQL
- **Frontend**: React Native mobile app
- **Database**: PostgreSQL with connection pooling
- **Authentication**: JWT tokens with refresh mechanism
- **Security**: CORS, rate limiting, input validation
- **Documentation**: Automatic API documentation with Swagger 