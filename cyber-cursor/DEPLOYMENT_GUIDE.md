# 🚀 Application Deployment Guide

## Overview
This guide provides step-by-step instructions for deploying the cleaned and enhanced CyberShield application with all duplicate code removed and enhanced DAST/SAST features retained.

## 🎯 Pre-Deployment Checklist

### ✅ Cleanup Verification
- [x] All duplicate files removed
- [x] Enhanced features retained
- [x] Navigation properly configured
- [x] API endpoints cleaned up
- [x] Database models updated

### 🔧 System Requirements
- Docker and Docker Compose
- PostgreSQL 15+ (or use containerized version)
- Redis 7+ (or use containerized version)
- Node.js 18+ (for local development)
- Python 3.9+ (for local development)

## 🐳 Containerized Deployment

### 1. Start the Application
```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

### 2. Verify Services
```bash
# Check backend health
curl http://localhost:8000/health

# Check database connection
curl http://localhost:8000/health/database

# Check frontend
curl http://localhost:3000
```

### 3. Access Points
- **Frontend Application**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Database**: localhost:5432 (cybershield/cybershield_user)
- **Redis**: localhost:6379

## 🔧 Local Development Setup

### 1. Backend Setup
```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL="postgresql+asyncpg://cybershield_user:cybershield_password@localhost:5432/cybershield"
export REDIS_URL="redis://:redis_password@localhost:6379/0"
export SECRET_KEY="your-super-secret-key-change-in-production"

# Run database migrations
alembic upgrade head

# Start backend server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 2. Frontend Setup
```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm start
```

### 3. Mobile App Setup
```bash
cd mobile

# Install dependencies
npm install

# Start Expo development server
npx expo start
```

## 🗄️ Database Setup

### 1. PostgreSQL Configuration
```sql
-- Create database (if not using Docker)
CREATE DATABASE cybershield;
CREATE USER cybershield_user WITH PASSWORD 'cybershield_password';
GRANT ALL PRIVILEGES ON DATABASE cybershield TO cybershield_user;
```

### 2. Run Migrations
```bash
cd backend
alembic upgrade head
```

### 3. Initialize Data
```bash
# Create admin user
python scripts/create-admin-user.py

# Create test data (optional)
python scripts/create-test-data.py
```

## 🔐 Security Configuration

### 1. Environment Variables
```bash
# Required environment variables
SECRET_KEY=your-super-secret-key-change-in-production
DATABASE_URL=postgresql+asyncpg://user:password@host:port/database
REDIS_URL=redis://:password@host:port/database
ALLOWED_ORIGINS=["http://localhost:3000","http://localhost:3001"]
ALLOWED_HOSTS=["localhost","127.0.0.1"]
```

### 2. SSL/TLS Configuration (Production)
```bash
# Generate SSL certificates
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Update nginx configuration
# See nginx/nginx.conf for SSL configuration
```

## 📊 Monitoring and Health Checks

### 1. Health Endpoints
```bash
# Overall health
curl http://localhost:8000/health

# Database health
curl http://localhost:8000/health/database

# Redis health
curl http://localhost:8000/health/redis
```

### 2. Log Monitoring
```bash
# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f postgres
```

### 3. Performance Monitoring
```bash
# Check resource usage
docker stats

# Monitor database performance
docker exec -it cybershield-postgres psql -U cybershield_user -d cybershield -c "SELECT * FROM pg_stat_activity;"
```

## 🧪 Testing

### 1. Run Verification Tests
```bash
# Run cleanup verification
python test_cleanup_verification.py

# Run enhanced DAST tests
python test_enhanced_dast.py

# Run comprehensive tests
python test-backend-comprehensive.py
```

### 2. API Testing
```bash
# Test DAST endpoints
curl -X GET http://localhost:8000/dast/scans
curl -X GET http://localhost:8000/dast/vulnerabilities

# Test SAST endpoints
curl -X GET http://localhost:8000/sast/projects
curl -X GET http://localhost:8000/sast/scans

# Test authentication
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

## 🔄 Backup and Recovery

### 1. Database Backup
```bash
# Create backup
docker exec cybershield-postgres pg_dump -U cybershield_user cybershield > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore backup
docker exec -i cybershield-postgres psql -U cybershield_user cybershield < backup_file.sql
```

### 2. Application Backup
```bash
# Backup application data
tar -czf app_backup_$(date +%Y%m%d_%H%M%S).tar.gz \
  --exclude=node_modules \
  --exclude=__pycache__ \
  --exclude=.git \
  .
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Database Connection Issues
```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# Check database logs
docker-compose logs postgres

# Restart database
docker-compose restart postgres
```

#### 2. Backend Startup Issues
```bash
# Check backend logs
docker-compose logs backend

# Check environment variables
docker-compose exec backend env | grep -E "(DATABASE|REDIS|SECRET)"

# Restart backend
docker-compose restart backend
```

#### 3. Frontend Issues
```bash
# Check frontend logs
docker-compose logs frontend

# Rebuild frontend
docker-compose build frontend
docker-compose up -d frontend
```

#### 4. Port Conflicts
```bash
# Check port usage
netstat -tulpn | grep -E "(3000|8000|5432|6379)"

# Change ports in docker-compose.yml if needed
```

## 📈 Performance Optimization

### 1. Database Optimization
```sql
-- Create indexes for better performance
CREATE INDEX idx_dast_scans_created_at ON dast_scans(created_at);
CREATE INDEX idx_sast_projects_name ON sast_projects(name);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
```

### 2. Redis Optimization
```bash
# Configure Redis for better performance
# See redis.conf for optimization settings
```

### 3. Application Optimization
```bash
# Enable gzip compression
# Configure nginx for static file serving
# Use CDN for static assets in production
```

## 🔄 Updates and Maintenance

### 1. Application Updates
```bash
# Pull latest changes
git pull origin main

# Rebuild containers
docker-compose build

# Restart services
docker-compose up -d
```

### 2. Database Migrations
```bash
# Run new migrations
docker-compose exec backend alembic upgrade head

# Rollback if needed
docker-compose exec backend alembic downgrade -1
```

### 3. Security Updates
```bash
# Update base images
docker-compose pull

# Rebuild with security patches
docker-compose build --no-cache
```

## 🎯 Production Deployment

### 1. Production Environment Variables
```bash
# Create production .env file
SECRET_KEY=your-production-secret-key
DATABASE_URL=postgresql+asyncpg://prod_user:prod_password@prod_host:5432/prod_db
REDIS_URL=redis://:prod_redis_password@prod_redis_host:6379/0
DEBUG=false
ALLOWED_ORIGINS=["https://yourdomain.com"]
ALLOWED_HOSTS=["yourdomain.com"]
```

### 2. Production Docker Compose
```bash
# Use production profile
docker-compose --profile production up -d
```

### 3. SSL/TLS Setup
```bash
# Configure SSL certificates
# Update nginx configuration
# Enable HTTPS redirects
```

## 📞 Support

### Logs and Debugging
- Application logs: `docker-compose logs -f`
- Database logs: `docker-compose logs postgres`
- Nginx logs: `docker-compose logs nginx`

### Health Monitoring
- Health endpoint: `curl http://localhost:8000/health`
- Database status: `curl http://localhost:8000/health/database`
- API documentation: http://localhost:8000/docs

### Contact
For issues and support, check the application logs and health endpoints first. The application includes comprehensive error handling and logging for troubleshooting.

## 🎉 Deployment Complete

Once all steps are completed, your enhanced CyberShield application will be running with:

- ✅ Clean codebase with no duplicates
- ✅ Enhanced DAST and SAST features
- ✅ Seamless frontend-backend-database communication
- ✅ Containerized deployment
- ✅ Comprehensive monitoring and health checks
- ✅ Security features enabled
- ✅ Performance optimizations in place

The application is now ready for production use with enhanced security testing capabilities! 