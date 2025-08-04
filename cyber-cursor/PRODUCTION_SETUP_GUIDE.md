# CyberShield Production Setup Guide

## Overview
This guide will help you set up the CyberShield application in production mode using PostgreSQL as the database and React Native for the frontend.

## Prerequisites

### 1. PostgreSQL Installation
- Install PostgreSQL 15 or later
- Ensure PostgreSQL service is running
- Default port: 5432

### 2. Python Dependencies
```bash
pip install fastapi uvicorn sqlalchemy asyncpg psycopg2-binary redis python-jose PyJWT passlib python-multipart structlog
```

### 3. Node.js and React Native
- Install Node.js 18 or later
- Install React Native CLI
- Install Expo CLI (for React Native development)

## Database Setup

### 1. Create PostgreSQL Database and User
```sql
-- Connect to PostgreSQL as superuser
psql -U postgres

-- Create user
CREATE USER cybershield_user WITH PASSWORD 'cybershield_password';

-- Create database
CREATE DATABASE cybershield;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE cybershield TO cybershield_user;
GRANT ALL ON SCHEMA public TO cybershield_user;
```

### 2. Initialize Database Schema
The application will automatically create all necessary tables on first startup.

## Backend Configuration

### 1. Environment Variables
Set the following environment variables for production:

```bash
# Production Environment
ENVIRONMENT=production

# Database Configuration
DATABASE_URL=postgresql+asyncpg://cybershield_user:cybershield_password@localhost:5432/cybershield
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=30

# Security
SECRET_KEY=your-super-secret-production-key-change-this-immediately
DEBUG=false
LOG_LEVEL=INFO

# Redis (optional)
REDIS_URL=redis://localhost:6379/0
```

### 2. Start Backend in Production Mode
```bash
# Navigate to backend directory
cd backend

# Set environment variables
$env:ENVIRONMENT="production"
$env:DATABASE_URL="postgresql+asyncpg://cybershield_user:cybershield_password@localhost:5432/cybershield"
$env:DEBUG="false"

# Start the application
python main.py
```

## Frontend Setup (React Native)

### 1. Create React Native Project
```bash
# Create new React Native project
npx react-native init CyberShieldMobile --template react-native-template-typescript

# Or use Expo
npx create-expo-app CyberShieldMobile --template blank-typescript
```

### 2. Install Dependencies
```bash
cd CyberShieldMobile
npm install @react-navigation/native @react-navigation/stack
npm install axios react-native-vector-icons
npm install @react-native-async-storage/async-storage
npm install react-native-elements
```

### 3. Configure API Client
Create `src/services/api.ts`:
```typescript
import axios from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';

const API_BASE_URL = 'http://localhost:8000/api/v1';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
});

// Request interceptor for authentication
api.interceptors.request.use(
  async (config) => {
    const token = await AsyncStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      // Handle token refresh or logout
      await AsyncStorage.removeItem('access_token');
    }
    return Promise.reject(error);
  }
);

export default api;
```

### 4. Create Authentication Service
Create `src/services/auth.ts`:
```typescript
import api from './api';
import AsyncStorage from '@react-native-async-storage/async-storage';

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  user_id: number;
  email: string;
  role: string;
}

export const authService = {
  async login(credentials: LoginCredentials): Promise<AuthResponse> {
    const response = await api.post('/auth/login', credentials);
    const data = response.data;
    
    await AsyncStorage.setItem('access_token', data.access_token);
    await AsyncStorage.setItem('refresh_token', data.refresh_token);
    
    return data;
  },

  async logout(): Promise<void> {
    await AsyncStorage.removeItem('access_token');
    await AsyncStorage.removeItem('refresh_token');
  },

  async getCurrentUser(): Promise<any> {
    const response = await api.get('/auth/me');
    return response.data;
  }
};
```

## Application Architecture

### Backend (Python/FastAPI)
- **Framework**: FastAPI with async/await support
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Authentication**: JWT tokens with refresh mechanism
- **API Documentation**: Automatic OpenAPI/Swagger docs
- **Security**: CORS, rate limiting, input validation

### Frontend (React Native)
- **Framework**: React Native with TypeScript
- **Navigation**: React Navigation
- **State Management**: React Context API or Redux
- **UI Components**: React Native Elements
- **HTTP Client**: Axios with interceptors

### Database (PostgreSQL)
- **Primary Database**: PostgreSQL for all persistent data
- **Connection Pooling**: SQLAlchemy async connection pool
- **Migrations**: Automatic schema creation
- **Backup**: Regular automated backups

## Security Features

### Backend Security
- JWT-based authentication
- Password hashing with bcrypt
- Rate limiting
- Input validation and sanitization
- CORS configuration
- Security headers

### Frontend Security
- Secure token storage
- API request/response validation
- Error handling
- Session management

## Deployment

### Backend Deployment
1. Set up PostgreSQL server
2. Configure environment variables
3. Install Python dependencies
4. Run database migrations
5. Start FastAPI server with uvicorn

### Frontend Deployment
1. Build React Native app
2. Deploy to app stores (iOS/Android)
3. Configure API endpoints for production

## Monitoring and Logging

### Backend Monitoring
- Structured logging with structlog
- Health check endpoints
- Performance monitoring
- Error tracking

### Frontend Monitoring
- Crash reporting
- Performance monitoring
- User analytics

## Testing

### Backend Testing
- Unit tests with pytest
- Integration tests
- API endpoint testing
- Database testing

### Frontend Testing
- Component testing with Jest
- E2E testing with Detox
- API integration testing

## Maintenance

### Database Maintenance
- Regular backups
- Performance optimization
- Index management
- Data cleanup

### Application Maintenance
- Security updates
- Dependency updates
- Performance monitoring
- User feedback collection 