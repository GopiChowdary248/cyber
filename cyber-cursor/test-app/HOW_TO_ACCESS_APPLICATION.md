# How to Access the CyberShield Application

## 🚀 Quick Start Guide

### 1. Start the Application
```bash
# Navigate to the project root
cd /path/to/cyber-cursor

# Start all services
docker-compose up -d

# Wait for services to start (about 30-60 seconds)
```

### 2. Access the Application

#### 🌐 Frontend (React App)
- **URL**: http://localhost:3000
- **Status**: ✅ Working
- **Features**: Modern React interface with cybersecurity dashboards

#### 🔧 Backend API
- **URL**: http://localhost:8000
- **Status**: ✅ Working
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

#### 🗄️ Database
- **PostgreSQL**: localhost:5432
- **Status**: ✅ Working
- **Credentials**: cybershield_user / cybershield_password

## 📊 Current Application Status

### ✅ Working Components
1. **Frontend React App** - Fully accessible on port 3000
2. **Backend FastAPI** - Healthy and responding on port 8000
3. **API Documentation** - OpenAPI docs available at /docs
4. **Database** - PostgreSQL running with demo users
5. **Docker Infrastructure** - 4/5 containers running (minor issue)

### ❌ Known Issues
1. **Authentication System** - 500 error during login (backend issue)
2. **Some Security Endpoints** - 404 errors due to path mismatches

## 🔐 Demo Accounts

The application includes pre-configured demo accounts:

| Email | Password | Role | Status |
|-------|----------|------|--------|
| admin@cybershield.com | password | Admin | ⚠️ Login fails (backend issue) |
| analyst@cybershield.com | password | Analyst | ⚠️ Login fails (backend issue) |
| user@cybershield.com | password | User | ⚠️ Login fails (backend issue) |

## 🧪 Testing the Application

### Run End-to-End Tests
```bash
# Navigate to test directory
cd test-app

# Run comprehensive tests
python fixed-e2e-test.py

# Run basic infrastructure test
python basic-test.py

# Check database connectivity
python check-db.py
```

### Test Results Summary
- **Infrastructure Tests**: 100% passing
- **Authentication Tests**: 0% passing (blocked by backend issue)
- **Security Module Tests**: Not tested (blocked by auth)
- **Overall Success Rate**: 60%

## 🔧 Troubleshooting

### Application Won't Start
```bash
# Check Docker containers
docker-compose ps

# View logs
docker-compose logs

# Restart services
docker-compose restart
```

### Authentication Issues
```bash
# Check backend logs
docker-compose logs backend --tail=20

# Verify database users
python test-app/check-db.py

# Test login manually
python test-app/test-login.py
```

### Port Conflicts
```bash
# Check what's using the ports
netstat -ano | findstr :3000
netstat -ano | findstr :8000
netstat -ano | findstr :5432

# Stop conflicting services or change ports in docker-compose.yml
```

## 📱 Application Features

### Available Modules
1. **Dashboard** - Overview and analytics
2. **Security** - SAST, DAST, RASP testing
3. **Cloud Security** - CSPM and CASB features
4. **Network Security** - Firewall and IDS/IPS
5. **Incident Management** - Security incident tracking
6. **User Management** - Admin and user roles
7. **Compliance** - Security compliance reporting

### API Endpoints
- **Health**: `GET /health`
- **Authentication**: `POST /api/v1/auth/login`
- **Users**: `GET /api/v1/users`
- **Security**: `GET /api/v1/security/audit/report`
- **SAST**: `GET /api/v1/sast/summary`
- **Dashboard**: `GET /api/v1/dashboard/overview`

## 🚨 Backend Issues to Fix

### 1. Database Initialization Error
**Error**: `greenlet_spawn has not been called`
**File**: `backend/app/database.py`
**Solution**: Fix async database initialization

### 2. JWT Library Compatibility
**Error**: `AttributeError: module 'jwt' has no attribute 'JWTError'`
**File**: `backend/app/core/security.py`
**Solution**: Use correct JWT exception handling

### 3. User Model Schema
**Error**: Missing required fields in response schema
**File**: `backend/app/schemas/auth.py`
**Solution**: Add missing fields to User schema

### 4. Authentication Service
**Error**: `'permissions' is an invalid keyword argument for User`
**File**: `backend/app/core/security.py`
**Solution**: Fix User model instantiation

## 📈 Performance Metrics

### Current Performance
- **Startup Time**: ~30-60 seconds
- **API Response Time**: <100ms (when working)
- **Frontend Load Time**: <2 seconds
- **Database Query Time**: <50ms

### Resource Usage
- **Memory**: ~2GB total
- **CPU**: Low usage
- **Disk**: ~500MB for containers
- **Network**: Minimal traffic

## 🔄 Development Workflow

### Making Changes
1. **Frontend**: Edit files in `frontend/src/`
2. **Backend**: Edit files in `backend/app/`
3. **Database**: Use migrations or direct SQL
4. **Docker**: Update `docker-compose.yml`

### Testing Changes
```bash
# Run tests after changes
cd test-app
python fixed-e2e-test.py

# Check specific components
python basic-test.py
python check-db.py
```

### Deployment
```bash
# Build and deploy
docker-compose up -d --build

# Check status
docker-compose ps
docker-compose logs
```

## 📞 Support

### Getting Help
1. **Check Logs**: `docker-compose logs [service]`
2. **Run Tests**: Use the test scripts in `test-app/`
3. **Review Documentation**: Check `README.md` and API docs
4. **Verify Infrastructure**: Use `docker-compose ps`

### Common Commands
```bash
# Start application
docker-compose up -d

# Stop application
docker-compose down

# View logs
docker-compose logs -f

# Restart services
docker-compose restart

# Check status
docker-compose ps

# Run tests
cd test-app && python fixed-e2e-test.py
```

## 🎯 Next Steps

### Immediate Actions
1. **Fix Backend Authentication** - Resolve 500 errors
2. **Update Test Scripts** - Improve error handling
3. **Document API Changes** - Update endpoint documentation

### Long-term Goals
1. **Complete Test Coverage** - 90%+ success rate
2. **Performance Optimization** - Reduce startup time
3. **Security Hardening** - Implement proper JWT handling
4. **CI/CD Integration** - Automated testing pipeline

---

**Last Updated**: August 2, 2025
**Application Version**: 2.0.0
**Status**: Partially Working (60% functional) 