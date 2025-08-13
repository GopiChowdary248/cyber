# CyberShield Complete Integration Guide

## Overview
This guide provides step-by-step instructions to integrate all UI, API changes, and PostgreSQL in your CyberShield cybersecurity application.

## 🎯 What This Integration Accomplishes

### 1. **Database Integration**
- ✅ PostgreSQL database setup with comprehensive schema
- ✅ All security modules (SAST, DAST, RASP, Cloud Security) integrated
- ✅ User management, authentication, and authorization
- ✅ Audit logging and security event tracking
- ✅ Compliance and policy management

### 2. **API Integration**
- ✅ FastAPI backend with all security endpoints
- ✅ Authentication and JWT token management
- ✅ Rate limiting and security middleware
- ✅ CORS configuration for frontend integration
- ✅ Comprehensive error handling and logging

### 3. **UI Integration**
- ✅ React frontend with all security dashboards
- ✅ Responsive design for all screen sizes
- ✅ Real-time data updates from backend APIs
- ✅ Secure authentication flow
- ✅ Role-based access control

### 4. **Container Integration**
- ✅ Docker containers for all services
- ✅ PostgreSQL and Redis services
- ✅ Production-ready configuration
- ✅ Health checks and monitoring
- ✅ Automated startup and shutdown

## 🚀 Quick Start Integration

### Prerequisites
- Docker Desktop installed and running
- PowerShell (Windows) or Bash (Linux/Mac)
- At least 4GB RAM available
- Ports 3000, 8000, 5432, 6379 available

### Step 1: Run the Integration Script
```powershell
# Windows PowerShell
.\integrate-all-components.ps1

# Linux/Mac Bash
chmod +x integrate-all-components.ps1
./integrate-all-components.ps1
```

### Step 2: Wait for Integration
The script will automatically:
1. Create environment configuration
2. Setup PostgreSQL database schema
3. Build and start Docker containers
4. Verify all services are running
5. Create default admin user

### Step 3: Access Your Application
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Database**: localhost:5432

## 🔧 Manual Integration Steps

If you prefer to integrate manually or need to troubleshoot:

### 1. Environment Configuration
```bash
# Copy the production environment file
cp env.production .env

# Edit .env with your specific values
# Update API keys, database passwords, etc.
```

### 2. Database Setup
```bash
# Start PostgreSQL container
docker-compose -f docker-compose.production.yml up -d postgres

# Wait for PostgreSQL to be ready
docker-compose -f docker-compose.production.yml logs postgres

# Initialize database schema
docker exec -i cybershield-postgres psql -U cybershield_user -d cybershield < scripts/init-db.sql
```

### 3. Backend Setup
```bash
# Start backend container
docker-compose -f docker-compose.production.yml up -d backend

# Check backend logs
docker-compose -f docker-compose.production.yml logs backend

# Test backend health
curl http://localhost:8000/health
```

### 4. Frontend Setup
```bash
# Start frontend container
docker-compose -f docker-compose.production.yml up -d frontend

# Check frontend logs
docker-compose -f docker-compose.production.yml logs frontend

# Test frontend
curl http://localhost:3000
```

### 5. Redis Setup
```bash
# Start Redis container
docker-compose -f docker-compose.production.yml up -d redis

# Test Redis connection
docker exec -it cybershield-redis redis-cli -a redis_password ping
```

## 📊 Database Schema Overview

### Core Tables
- **users**: User accounts and authentication
- **roles**: Role definitions and permissions
- **user_roles**: User-role assignments
- **security_events**: Security event tracking
- **audit_logs**: Comprehensive audit trail

### Security Module Tables
- **SAST**: `sast_projects`, `sast_scans`, `sast_issues`
- **DAST**: `dast_projects`, `dast_scans`, `dast_vulnerabilities`
- **RASP**: `rasp_agents`, `rasp_events`
- **Cloud Security**: `cloud_accounts`, `cloud_security_findings`
- **Threat Intelligence**: `threat_indicators`
- **Incidents**: `incidents`
- **Compliance**: `compliance_frameworks`, `compliance_controls`

## 🔐 Authentication & Authorization

### Default Admin User
- **Username**: admin
- **Password**: admin123
- **Role**: System Administrator

### User Roles
1. **Admin**: Full system access
2. **Security Analyst**: Security operations and analysis
3. **Developer**: Limited access for development
4. **Viewer**: Read-only access

### Security Features
- JWT token authentication
- Role-based access control
- Multi-factor authentication support
- Session management
- Password policy enforcement

## 🌐 API Endpoints

### Authentication
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/auth/refresh` - Refresh token
- `POST /api/v1/auth/mfa/setup` - Setup 2FA

### User Management
- `GET /api/v1/users/me` - Get current user
- `PUT /api/v1/users/me` - Update current user
- `GET /api/v1/users` - List users (admin only)
- `POST /api/v1/users` - Create user (admin only)

### Security Modules
- **SAST**: `/api/v1/sast/*`
- **DAST**: `/api/v1/dast/*`
- **RASP**: `/api/v1/rasp/*`
- **Cloud Security**: `/api/v1/cloud/*`
- **Threat Intelligence**: `/api/v1/threats/*`
- **Incidents**: `/api/v1/incidents/*`

## 🎨 Frontend Components

### Main Dashboards
- **Main Dashboard**: Overview of all security metrics
- **SAST Dashboard**: Static analysis results and issues
- **DAST Dashboard**: Dynamic testing results and vulnerabilities
- **RASP Dashboard**: Runtime protection events and alerts
- **Cloud Security Dashboard**: Cloud security findings and compliance
- **Threat Intelligence Dashboard**: Threat indicators and analysis

### Authentication Components
- **Login Form**: Secure authentication
- **MFA Setup**: Two-factor authentication configuration
- **User Profile**: User account management
- **Role Management**: User role assignments

### Security Module Components
- **Project Management**: Create and manage security projects
- **Scan Configuration**: Configure security scans
- **Results Display**: View and analyze security findings
- **Issue Tracking**: Track and manage security issues
- **Reporting**: Generate security reports

## 🔍 Monitoring & Health Checks

### Health Check Endpoints
- `GET /health` - Overall system health
- `GET /api/v1/health` - API health status
- `GET /api/v1/health/detailed` - Detailed health information

### Health Check Components
- Database connectivity
- Redis connectivity
- External service availability
- Container status
- Resource usage

### Logging
- Structured logging with structlog
- Security event logging
- Audit trail logging
- Error logging and monitoring

## 🚨 Troubleshooting

### Common Issues

#### 1. Database Connection Failed
```bash
# Check PostgreSQL container status
docker-compose -f docker-compose.production.yml ps postgres

# Check PostgreSQL logs
docker-compose -f docker-compose.production.yml logs postgres

# Test database connection
docker exec -it cybershield-postgres psql -U cybershield_user -d cybershield -c "SELECT 1;"
```

#### 2. Backend API Not Responding
```bash
# Check backend container status
docker-compose -f docker-compose.production.yml ps backend

# Check backend logs
docker-compose -f docker-compose.production.yml logs backend

# Test backend health
curl -v http://localhost:8000/health
```

#### 3. Frontend Not Loading
```bash
# Check frontend container status
docker-compose -f docker-compose.production.yml ps frontend

# Check frontend logs
docker-compose -f docker-compose.production.yml logs frontend

# Test frontend
curl -v http://localhost:3000
```

#### 4. Port Conflicts
```bash
# Check what's using the ports
netstat -an | findstr :3000
netstat -an | findstr :8000
netstat -an | findstr :5432

# Stop conflicting services or change ports in docker-compose.yml
```

### Reset and Restart
```bash
# Stop all containers
docker-compose -f docker-compose.production.yml down

# Remove volumes (WARNING: This will delete all data)
docker-compose -f docker-compose.production.yml down -v

# Rebuild and restart
docker-compose -f docker-compose.production.yml up -d --build
```

## 📈 Performance Optimization

### Database Optimization
- Connection pooling configured
- Indexes on frequently queried columns
- Query optimization with proper joins
- Regular database maintenance

### API Optimization
- Response caching with Redis
- Rate limiting to prevent abuse
- Pagination for large datasets
- Async processing for long operations

### Frontend Optimization
- Lazy loading of components
- Efficient state management
- Optimized bundle size
- Responsive design for all devices

## 🔒 Security Considerations

### Production Security
- Change all default passwords
- Use strong secret keys
- Enable SSL/TLS encryption
- Configure firewall rules
- Regular security updates

### Access Control
- Role-based permissions
- IP whitelisting (optional)
- Session timeout configuration
- Audit logging enabled

### Data Protection
- Encrypted data transmission
- Secure file uploads
- Data backup and recovery
- Compliance with security standards

## 📚 Additional Resources

### Documentation
- [API Documentation](http://localhost:8000/docs) - Interactive API docs
- [ReDoc Documentation](http://localhost:8000/redoc) - Alternative API docs
- [Backend Code](backend/) - Backend source code
- [Frontend Code](frontend/) - Frontend source code

### Configuration Files
- `docker-compose.production.yml` - Production container configuration
- `env.production` - Production environment variables
- `scripts/init-db.sql` - Database initialization script
- `integrate-all-components.ps1` - Automated integration script

### Testing
- `test-*.py` files - Various test scripts
- `verify-integration.ps1` - Integration verification script
- Health check endpoints for monitoring

## 🎉 Success Indicators

Your integration is successful when:

✅ **Database**: PostgreSQL running and accessible on port 5432
✅ **Backend**: FastAPI responding on port 8000 with health checks passing
✅ **Frontend**: React app loading on port 3000
✅ **Redis**: Cache service running on port 6379
✅ **Authentication**: Can login with admin/admin123
✅ **API Endpoints**: All security module endpoints responding
✅ **Health Checks**: All services reporting healthy status

## 🆘 Getting Help

If you encounter issues:

1. **Check the logs**: Use `docker-compose logs` to see detailed error messages
2. **Verify prerequisites**: Ensure Docker is running and ports are available
3. **Review configuration**: Check environment variables and database settings
4. **Test components**: Use the health check endpoints to isolate issues
5. **Reset and retry**: Use the reset commands to start fresh

---

**🎯 Your CyberShield application is now fully integrated with all UI, API, and PostgreSQL components!**

The platform provides a comprehensive cybersecurity solution with:
- Static and dynamic application security testing
- Runtime application self-protection
- Cloud security monitoring
- Threat intelligence and incident management
- Compliance and policy management
- User authentication and role-based access control
