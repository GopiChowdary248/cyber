# CyberShield Production Deployment Guide

This guide explains how to deploy and run the CyberShield application in production mode using Docker containers, excluding the mobile application components.

## 🚀 Quick Start

### Prerequisites

- Docker Desktop installed and running
- Docker Compose available
- At least 4GB of available RAM
- At least 10GB of available disk space

### One-Command Deployment

**Windows (PowerShell):**
```powershell
.\scripts\start-production.ps1
```

**Linux/macOS:**
```bash
chmod +x scripts/start-production.sh
./scripts/start-production.sh
```

## 📋 What Gets Deployed

The production deployment includes the following services:

- **Frontend**: React web application (port 3000)
- **Backend**: FastAPI REST API (port 8000)
- **Database**: PostgreSQL 15 (port 5432)
- **Cache**: Redis 7 (port 6379)
- **Reverse Proxy**: Nginx (port 80)

**Note**: Mobile application components are explicitly excluded from this deployment.

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Nginx (80)    │───▶│  Frontend (3000)│    │ Backend (8000)  │
│  Reverse Proxy  │    │   React App     │    │  FastAPI API    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │ PostgreSQL (5432)│    │   Redis (6379)  │
                       │    Database     │    │     Cache       │
                       └─────────────────┘    └─────────────────┘
```

## 🔧 Manual Deployment Steps

If you prefer to deploy manually or need to customize the deployment:

### 1. Stop Existing Containers
```bash
docker-compose -f docker-compose.production-no-mobile.yml down --remove-orphans
```

### 2. Build Images
```bash
# Build backend
docker-compose -f docker-compose.production-no-mobile.yml build backend

# Build frontend
docker-compose -f docker-compose.production-no-mobile.yml build frontend
```

### 3. Start Services
```bash
docker-compose -f docker-compose.production-no-mobile.yml up -d
```

### 4. Monitor Health
```bash
# Check service status
docker-compose -f docker-compose.production-no-mobile.yml ps

# View logs
docker-compose -f docker-compose.production-no-mobile.yml logs -f [service_name]
```

## 🌐 Access Points

Once deployed, you can access the application at:

- **Main Application**: http://localhost
- **Frontend Direct**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 📊 Monitoring and Management

### Service Health Checks
All services include health checks that automatically restart unhealthy containers:

- **PostgreSQL**: Database connectivity check
- **Redis**: Cache service availability
- **Backend**: API health endpoint
- **Frontend**: Web application availability

### Logs
View logs for specific services:
```bash
# Backend logs
docker-compose -f docker-compose.production-no-mobile.yml logs -f backend

# Frontend logs
docker-compose -f docker-compose.production-no-mobile.yml logs -f frontend

# Database logs
docker-compose -f docker-compose.production-no-mobile.yml logs -f postgres
```

### Container Management
```bash
# Stop all services
docker-compose -f docker-compose.production-no-mobile.yml down

# Restart specific service
docker-compose -f docker-compose.production-no-mobile.yml restart [service_name]

# View resource usage
docker stats
```

## ⚙️ Configuration

### Environment Variables

The production configuration uses the following key environment variables:

**Backend:**
- `ENVIRONMENT=production`
- `DEBUG=false`
- `LOG_LEVEL=INFO`
- `SECRET_KEY=your-super-secret-production-key-change-this-immediately`

**Frontend:**
- `REACT_APP_API_URL=http://localhost:8000`
- `REACT_APP_ENVIRONMENT=production`

### Database Configuration
- **Database**: `cybershield`
- **User**: `cybershield_user`
- **Password**: `cybershield_password`

**⚠️ Security Note**: Change default passwords in production!

### Redis Configuration
- **Password**: `redis_password`
- **Port**: 6379

## 🔒 Security Features

### Production Hardening
- Non-root user execution in containers
- Health checks with automatic restart
- Rate limiting via Nginx (10 requests/second)
- Security headers (XSS protection, frame options, etc.)
- Gzip compression for performance

### Network Isolation
- All services run on isolated `cybershield-network`
- Internal communication between containers
- External access only through Nginx proxy

## 📈 Performance Optimization

### Backend
- 4 Uvicorn workers for concurrent requests
- Async database connections
- Redis caching layer
- Gzip compression

### Frontend
- Production build with minification
- Static file serving via Nginx
- Browser caching headers

### Database
- Connection pooling
- Optimized PostgreSQL configuration
- Regular health checks

## 🚨 Troubleshooting

### Common Issues

**1. Port Already in Use**
```bash
# Check what's using the port
netstat -ano | findstr :80
netstat -ano | findstr :3000
netstat -ano | findstr :8000

# Stop conflicting services or change ports in docker-compose file
```

**2. Database Connection Issues**
```bash
# Check PostgreSQL container
docker exec cybershield-postgres pg_isready -U cybershield_user -d cybershield

# View database logs
docker-compose -f docker-compose.production-no-mobile.yml logs postgres
```

**3. Frontend Not Loading**
```bash
# Check frontend container
docker exec cybershield-frontend curl -f http://localhost:3000

# View frontend logs
docker-compose -f docker-compose.production-no-mobile.yml logs frontend
```

**4. Memory Issues**
```bash
# Check container resource usage
docker stats

# Increase Docker memory limit in Docker Desktop settings
```

### Debug Mode
For debugging, you can run with verbose logging:
```bash
# PowerShell
.\scripts\start-production.ps1 -Verbose

# Bash
./scripts/start-production.sh
```

## 🔄 Updates and Maintenance

### Updating the Application
```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker-compose -f docker-compose.production-no-mobile.yml down
docker-compose -f docker-compose.production-no-mobile.yml build --no-cache
docker-compose -f docker-compose.production-no-mobile.yml up -d
```

### Database Backups
```bash
# Create backup
docker exec cybershield-postgres pg_dump -U cybershield_user cybershield > backup.sql

# Restore backup
docker exec -i cybershield-postgres psql -U cybershield_user -d cybershield < backup.sql
```

### Log Rotation
Logs are stored in Docker volumes and can be managed with:
```bash
# View log sizes
docker system df

# Clean up old logs
docker system prune -f
```

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Reference](https://docs.docker.com/compose/)
- [FastAPI Production Deployment](https://fastapi.tiangolo.com/deployment/)
- [React Production Build](https://create-react-app.dev/docs/production-build/)

## 🆘 Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review container logs for error messages
3. Verify Docker and Docker Compose versions
4. Ensure sufficient system resources
5. Check firewall and antivirus settings

---

**Happy Deploying! 🚀**

For additional assistance, refer to the main project documentation or create an issue in the project repository.
