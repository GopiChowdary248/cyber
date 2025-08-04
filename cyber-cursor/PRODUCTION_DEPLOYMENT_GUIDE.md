# CyberShield Production Deployment Guide

## Overview
This guide provides step-by-step instructions for deploying the CyberShield application in production using Docker containers with PostgreSQL database and React Native frontend.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Nginx Proxy   │    │   PostgreSQL    │    │     Redis       │
│   (Port 80/443) │    │   (Port 5432)   │    │   (Port 6379)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React Frontend│    │  FastAPI Backend│    │   Container     │
│   (Port 3000)   │    │   (Port 8000)   │    │   Network       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Prerequisites

### 1. System Requirements
- **OS**: Windows 10/11, macOS, or Linux
- **Docker**: Docker Desktop 4.0+ or Docker Engine 20.10+
- **Docker Compose**: Version 2.0+
- **RAM**: Minimum 8GB (16GB recommended)
- **Storage**: At least 10GB free space
- **CPU**: 4 cores minimum

### 2. Install Docker
```bash
# Windows/macOS: Download Docker Desktop from https://www.docker.com/products/docker-desktop
# Linux: Follow instructions at https://docs.docker.com/engine/install/
```

### 3. Verify Installation
```bash
docker --version
docker-compose --version
```

## Quick Start

### 1. Clone and Navigate
```bash
git clone <repository-url>
cd cyber-cursor
```

### 2. Start Production Stack
```bash
# Windows PowerShell
.\start-production-containers.ps1

# Linux/macOS
./start-production-containers.sh
```

### 3. Access Application
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost/health

## Manual Deployment

### 1. Create Required Directories
```bash
mkdir -p uploads logs nginx/ssl
```

### 2. Build and Start Containers
```bash
# Stop any existing containers
docker-compose -f docker-compose.production.yml down

# Build and start
docker-compose -f docker-compose.production.yml up --build -d

# Check status
docker-compose -f docker-compose.production.yml ps
```

### 3. Monitor Logs
```bash
# All services
docker-compose -f docker-compose.production.yml logs -f

# Specific service
docker-compose -f docker-compose.production.yml logs -f backend
docker-compose -f docker-compose.production.yml logs -f frontend
docker-compose -f docker-compose.production.yml logs -f postgres
```

## Configuration

### Environment Variables

#### Backend (.env.production)
```bash
ENVIRONMENT=production
DATABASE_URL=postgresql+asyncpg://cybershield_user:cybershield_password@postgres:5432/cybershield
REDIS_URL=redis://:redis_password@redis:6379/0
SECRET_KEY=your-super-secret-production-key-change-this-immediately
DEBUG=false
LOG_LEVEL=INFO
ALLOWED_ORIGINS=["http://localhost:3000","http://frontend:3000"]
ALLOWED_HOSTS=["localhost","127.0.0.1","frontend","backend"]
```

#### Frontend (.env.production)
```bash
REACT_APP_API_URL=http://localhost:8000/api/v1
REACT_APP_ENVIRONMENT=production
NODE_ENV=production
```

### Database Configuration

#### PostgreSQL Settings
- **Database**: cybershield
- **User**: cybershield_user
- **Password**: cybershield_password
- **Port**: 5432
- **Host**: postgres (container name)

#### Redis Settings
- **Host**: redis (container name)
- **Port**: 6379
- **Password**: redis_password
- **Database**: 0

## Security Configuration

### 1. Change Default Passwords
```bash
# Update in docker-compose.production.yml
POSTGRES_PASSWORD: your-secure-postgres-password
REDIS_PASSWORD: your-secure-redis-password
SECRET_KEY: your-super-secret-production-key-change-this-immediately
```

### 2. SSL/TLS Configuration
```bash
# Generate SSL certificates
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/nginx.key \
  -out nginx/ssl/nginx.crt

# Update nginx configuration for HTTPS
```

### 3. Firewall Configuration
```bash
# Allow only necessary ports
ufw allow 80/tcp   # HTTP
ufw allow 443/tcp  # HTTPS
ufw allow 22/tcp   # SSH (if needed)
```

## Monitoring and Logging

### 1. Health Checks
```bash
# Backend health
curl http://localhost:8000/health

# Frontend health
curl http://localhost:3000

# Database health
docker exec cybershield_postgres pg_isready -U cybershield_user
```

### 2. Log Management
```bash
# View application logs
docker-compose -f docker-compose.production.yml logs -f

# Export logs
docker-compose -f docker-compose.production.yml logs > logs/app.log

# Log rotation (configure in nginx.conf)
```

### 3. Performance Monitoring
```bash
# Container resource usage
docker stats

# Database performance
docker exec cybershield_postgres psql -U cybershield_user -d cybershield -c "SELECT * FROM pg_stat_activity;"
```

## Backup and Recovery

### 1. Database Backup
```bash
# Create backup
docker exec cybershield_postgres pg_dump -U cybershield_user cybershield > backup/cybershield_$(date +%Y%m%d_%H%M%S).sql

# Automated backup script
#!/bin/bash
BACKUP_DIR="/backup"
DATE=$(date +%Y%m%d_%H%M%S)
docker exec cybershield_postgres pg_dump -U cybershield_user cybershield > $BACKUP_DIR/cybershield_$DATE.sql
```

### 2. Application Backup
```bash
# Backup uploads
tar -czf backup/uploads_$(date +%Y%m%d_%H%M%S).tar.gz uploads/

# Backup configuration
tar -czf backup/config_$(date +%Y%m%d_%H%M%S).tar.gz docker-compose.production.yml nginx/ scripts/
```

### 3. Recovery Procedures
```bash
# Database recovery
docker exec -i cybershield_postgres psql -U cybershield_user -d cybershield < backup/cybershield_20240101_120000.sql

# Application recovery
tar -xzf backup/uploads_20240101_120000.tar.gz
```

## Scaling and Performance

### 1. Horizontal Scaling
```bash
# Scale backend services
docker-compose -f docker-compose.production.yml up -d --scale backend=3

# Load balancer configuration
# Update nginx.conf for multiple backend instances
```

### 2. Database Optimization
```bash
# PostgreSQL tuning
# Update postgresql.conf for production
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 64MB
```

### 3. Caching Strategy
```bash
# Redis configuration
# Update redis.conf for production
maxmemory 512mb
maxmemory-policy allkeys-lru
```

## Troubleshooting

### Common Issues

#### 1. Container Won't Start
```bash
# Check logs
docker-compose -f docker-compose.production.yml logs

# Check resource usage
docker system df
docker system prune
```

#### 2. Database Connection Issues
```bash
# Test database connectivity
docker exec cybershield_backend python -c "
import asyncio
from app.core.database import engine
async def test():
    try:
        async with engine.begin() as conn:
            await conn.execute('SELECT 1')
        print('Database connection successful')
    except Exception as e:
        print(f'Database connection failed: {e}')
asyncio.run(test())
"
```

#### 3. Frontend Not Loading
```bash
# Check frontend container
docker exec cybershield_frontend npm run build

# Check nginx configuration
docker exec cybershield_nginx nginx -t
```

### Performance Issues

#### 1. Slow Response Times
```bash
# Check database performance
docker exec cybershield_postgres psql -U cybershield_user -d cybershield -c "
SELECT query, calls, total_time, mean_time 
FROM pg_stat_statements 
ORDER BY total_time DESC 
LIMIT 10;
"
```

#### 2. High Memory Usage
```bash
# Monitor container resources
docker stats --no-stream

# Optimize container limits
# Update docker-compose.production.yml with memory limits
```

## Maintenance

### 1. Regular Updates
```bash
# Update containers
docker-compose -f docker-compose.production.yml pull
docker-compose -f docker-compose.production.yml up -d

# Update application code
git pull origin main
docker-compose -f docker-compose.production.yml up --build -d
```

### 2. Security Updates
```bash
# Update base images
docker-compose -f docker-compose.production.yml build --no-cache

# Scan for vulnerabilities
docker scan cybershield_backend
docker scan cybershield_frontend
```

### 3. Cleanup
```bash
# Remove unused containers and images
docker system prune -a

# Clean up logs
docker system prune --volumes
```

## Production Checklist

- [ ] Change all default passwords
- [ ] Configure SSL/TLS certificates
- [ ] Set up monitoring and alerting
- [ ] Configure automated backups
- [ ] Set up log rotation
- [ ] Configure firewall rules
- [ ] Test disaster recovery procedures
- [ ] Set up CI/CD pipeline
- [ ] Configure rate limiting
- [ ] Set up error tracking
- [ ] Configure performance monitoring
- [ ] Test load balancing
- [ ] Set up automated scaling
- [ ] Configure security headers
- [ ] Set up audit logging

## Support and Resources

- **Documentation**: Check the `/docs` endpoint for API documentation
- **Logs**: Use `docker-compose logs` for troubleshooting
- **Health Checks**: Monitor `/health` endpoint
- **GitHub Issues**: Report bugs and feature requests
- **Community**: Join our Discord/Slack for support

## Next Steps

1. **Customize Configuration**: Update environment variables for your environment
2. **Set Up Monitoring**: Implement comprehensive monitoring and alerting
3. **Configure Backups**: Set up automated backup procedures
4. **Security Hardening**: Implement additional security measures
5. **Performance Tuning**: Optimize for your specific use case
6. **Scaling Preparation**: Plan for horizontal scaling as needed 