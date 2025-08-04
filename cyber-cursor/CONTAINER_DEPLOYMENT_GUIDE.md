# CyberShield Container Deployment Guide

## Overview
This guide provides step-by-step instructions for deploying the CyberShield application using Docker containers in production mode.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Nginx         │    │   Frontend      │    │   Backend       │
│   (Port 80/443) │◄──►│   (Port 3000)   │◄──►│   (Port 8000)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                                                       ▼
                                              ┌─────────────────┐
                                              │   PostgreSQL    │
                                              │   (Port 5432)   │
                                              └─────────────────┘
                                                       │
                                                       ▼
                                              ┌─────────────────┐
                                              │   Redis         │
                                              │   (Port 6379)   │
                                              └─────────────────┘
```

## Prerequisites

### 1. Docker Installation
- Install Docker Desktop for Windows/Mac
- Install Docker Engine for Linux
- Ensure Docker Compose is available

### 2. System Requirements
- **CPU**: Minimum 2 cores, Recommended 4+ cores
- **RAM**: Minimum 4GB, Recommended 8GB+
- **Storage**: Minimum 20GB free space
- **Network**: Stable internet connection for initial setup

## Quick Start

### 1. Clone and Setup
```bash
# Clone the repository
git clone <repository-url>
cd cyber-cursor

# Make scripts executable (Linux/Mac)
chmod +x start-production-containers.ps1
```

### 2. Start Production Stack
```powershell
# Windows PowerShell
.\start-production-containers.ps1

# Linux/Mac
docker-compose -f docker-compose.production.yml up --build -d
```

### 3. Access the Application
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

## Detailed Deployment Steps

### 1. Environment Configuration

#### Backend Environment Variables
```bash
# Production Environment
ENVIRONMENT=production
DATABASE_URL=postgresql+asyncpg://cybershield_user:cybershield_password@postgres:5432/cybershield
REDIS_URL=redis://:redis_password@redis:6379/0
SECRET_KEY=your-super-secret-production-key-change-this-immediately
DEBUG=false
LOG_LEVEL=INFO
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=30
```

#### Frontend Environment Variables
```bash
REACT_APP_API_URL=http://localhost:8000/api/v1
REACT_APP_ENVIRONMENT=production
```

### 2. Database Setup

The PostgreSQL database will be automatically initialized with:
- Database: `cybershield`
- User: `cybershield_user`
- Password: `cybershield_password`

### 3. Service Configuration

#### PostgreSQL Service
- **Image**: postgres:15-alpine
- **Port**: 5432
- **Volume**: postgres_data
- **Health Check**: pg_isready

#### Redis Service
- **Image**: redis:7-alpine
- **Port**: 6379
- **Password**: redis_password
- **Volume**: redis_data

#### Backend Service
- **Image**: Custom Python 3.11
- **Port**: 8000
- **Workers**: 4
- **Health Check**: HTTP /health endpoint

#### Frontend Service
- **Image**: Nginx serving React build
- **Port**: 3000
- **Proxy**: API requests to backend

#### Nginx Service
- **Image**: nginx:alpine
- **Ports**: 80, 443
- **SSL**: Configured for HTTPS

### 4. Security Configuration

#### Network Security
- All services run in isolated `cybershield_network`
- External access only through Nginx proxy
- Internal communication via service names

#### Data Security
- PostgreSQL data persisted in Docker volumes
- Redis data persisted in Docker volumes
- Upload files stored in mounted volumes

#### Application Security
- JWT authentication with secure tokens
- Password hashing with bcrypt
- CORS configuration for frontend
- Rate limiting on API endpoints

## Monitoring and Logging

### 1. Service Monitoring
```bash
# Check service status
docker-compose -f docker-compose.production.yml ps

# View service logs
docker-compose -f docker-compose.production.yml logs -f

# View specific service logs
docker-compose -f docker-compose.production.yml logs -f backend
```

### 2. Health Checks
- **Backend**: http://localhost:8000/health
- **Frontend**: http://localhost:3000/health
- **PostgreSQL**: Automatic health checks
- **Redis**: Automatic health checks

### 3. Performance Monitoring
- Backend logs in `/app/logs`
- Nginx access logs
- Database connection pooling
- Redis caching statistics

## Scaling and Optimization

### 1. Horizontal Scaling
```bash
# Scale backend workers
docker-compose -f docker-compose.production.yml up --scale backend=3 -d

# Scale with load balancer
docker-compose -f docker-compose.production.yml up --scale backend=5 -d
```

### 2. Resource Optimization
- **Database**: Connection pooling (20 connections)
- **Redis**: Connection pooling (20 connections)
- **Backend**: 4 worker processes
- **Frontend**: Static file serving with caching

### 3. Caching Strategy
- **Static Assets**: 1 year cache
- **API Responses**: Redis caching
- **Database**: Query optimization
- **Frontend**: Service worker caching

## Backup and Recovery

### 1. Database Backup
```bash
# Create backup
docker exec cybershield_postgres pg_dump -U cybershield_user cybershield > backup.sql

# Restore backup
docker exec -i cybershield_postgres psql -U cybershield_user cybershield < backup.sql
```

### 2. Volume Backup
```bash
# Backup volumes
docker run --rm -v cybershield_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_backup.tar.gz -C /data .

# Restore volumes
docker run --rm -v cybershield_postgres_data:/data -v $(pwd):/backup alpine tar xzf /backup/postgres_backup.tar.gz -C /data
```

## Troubleshooting

### 1. Common Issues

#### Service Won't Start
```bash
# Check Docker logs
docker-compose -f docker-compose.production.yml logs

# Check service health
docker-compose -f docker-compose.production.yml ps
```

#### Database Connection Issues
```bash
# Test database connection
docker exec cybershield_postgres psql -U cybershield_user -d cybershield -c "SELECT 1;"

# Check database logs
docker logs cybershield_postgres
```

#### Frontend Not Loading
```bash
# Check frontend logs
docker logs cybershield_frontend

# Test API connectivity
curl http://localhost:8000/health
```

### 2. Performance Issues
```bash
# Check resource usage
docker stats

# Monitor database performance
docker exec cybershield_postgres psql -U cybershield_user -d cybershield -c "SELECT * FROM pg_stat_activity;"
```

## Production Considerations

### 1. SSL/TLS Configuration
- Configure SSL certificates in nginx/ssl/
- Update nginx configuration for HTTPS
- Redirect HTTP to HTTPS

### 2. Domain Configuration
- Update ALLOWED_HOSTS in backend config
- Configure CORS origins for your domain
- Update frontend API URL

### 3. Monitoring Setup
- Set up external monitoring (Prometheus/Grafana)
- Configure alerting for service failures
- Set up log aggregation

### 4. Security Hardening
- Change default passwords
- Use strong secret keys
- Enable firewall rules
- Regular security updates

## Maintenance

### 1. Regular Updates
```bash
# Update images
docker-compose -f docker-compose.production.yml pull

# Rebuild and restart
docker-compose -f docker-compose.production.yml up --build -d
```

### 2. Log Rotation
- Configure log rotation for application logs
- Monitor disk usage
- Clean up old logs

### 3. Database Maintenance
- Regular database backups
- Monitor database size
- Optimize queries and indexes

## Support and Documentation

### 1. API Documentation
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- OpenAPI specification available

### 2. Application Features
- **Authentication**: JWT-based login/logout
- **User Management**: CRUD operations
- **Security Modules**: RASP, DAST, SAST, IAM
- **Cloud Security**: AWS, Azure, GCP integration
- **Device Control**: Endpoint management
- **Threat Intelligence**: Real-time threat feeds

### 3. Mobile Application
- React Native mobile app
- Cross-platform (iOS/Android)
- Offline capability
- Push notifications
- Biometric authentication

## Conclusion

This containerized deployment provides a scalable, secure, and maintainable solution for the CyberShield cybersecurity platform. The architecture ensures clear separation of concerns, high availability, and easy scaling for production environments. 