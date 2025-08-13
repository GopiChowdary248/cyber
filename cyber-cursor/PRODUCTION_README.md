# 🚀 CyberShield Production Deployment

This document provides everything you need to run the CyberShield application in production mode using Docker containers, **excluding mobile application components**.

## 📋 Quick Start

### Prerequisites
- ✅ Docker Desktop installed and running
- ✅ Docker Compose available
- ✅ At least 4GB RAM available
- ✅ At least 10GB disk space available

### One-Command Deployment

**Windows (PowerShell - Recommended):**
```powershell
.\scripts\switch-to-production.ps1
```

**Windows (Batch):**
```cmd
.\scripts\start-production.bat
```

**Linux/macOS:**
```bash
chmod +x scripts/start-production.sh
./scripts/start-production.sh
```

## 🏗️ Production Architecture

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

## 📁 Scripts Overview

| Script | Purpose | Platform |
|--------|---------|----------|
| `switch-to-production.ps1` | **Switch from dev to production** | Windows PowerShell |
| `start-production.ps1` | Start production services | Windows PowerShell |
| `start-production.bat` | Start production services | Windows Batch |
| `start-production.sh` | Start production services | Linux/macOS |
| `stop-production.ps1` | Stop production services | Windows PowerShell |
| `check-production-status.ps1` | Check service health | Windows PowerShell |

## 🔄 Switching from Development Mode

If you currently have development services running:

```powershell
# This will safely stop dev services and start production
.\scripts\switch-to-production.ps1
```

## 🌐 Access Points

Once deployed, access your application at:

- **Main Application**: http://localhost
- **Frontend Direct**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 📊 Monitoring & Management

### Check Service Status
```powershell
.\scripts\check-production-status.ps1
```

### View Service Logs
```bash
# Backend logs
docker-compose -f docker-compose.production-no-mobile.yml logs -f backend

# Frontend logs
docker-compose -f docker-compose.production-no-mobile.yml logs -f frontend

# Database logs
docker-compose -f docker-compose.production-no-mobile.yml logs -f postgres
```

### Stop Production Services
```powershell
.\scripts\stop-production.ps1
```

### Restart Specific Service
```bash
docker-compose -f docker-compose.production-no-mobile.yml restart [service_name]
```

## ⚙️ Configuration

### Environment Variables

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

## 🔒 Production Features

### Security Hardening
- ✅ Non-root user execution
- ✅ Health checks with auto-restart
- ✅ Rate limiting (10 req/sec)
- ✅ Security headers (XSS, frame options)
- ✅ Network isolation
- ✅ Gzip compression

### Performance Optimization
- ✅ 4 Uvicorn workers
- ✅ Async database connections
- ✅ Redis caching layer
- ✅ Production React build
- ✅ Nginx reverse proxy
- ✅ Connection pooling

## 🚨 Troubleshooting

### Common Issues

**1. Port Conflicts**
```bash
# Check what's using ports
netstat -ano | findstr :80
netstat -ano | findstr :3000
netstat -ano | findstr :8000
```

**2. Service Health Issues**
```bash
# Check container status
docker-compose -f docker-compose.production-no-mobile.yml ps

# Check health endpoints
curl http://localhost:8000/health
curl http://localhost:3000
```

**3. Memory Issues**
```bash
# Check resource usage
docker stats

# Increase Docker memory limit in Docker Desktop settings
```

### Debug Mode
```powershell
# PowerShell with verbose output
.\scripts\start-production.ps1 -Verbose
```

## 🔄 Updates & Maintenance

### Update Application
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

### Cleanup
```bash
# View disk usage
docker system df

# Clean up old images/containers
docker system prune -f
```

## 📚 File Structure

```
cyber-cursor/
├── docker-compose.production-no-mobile.yml  # Production compose file
├── backend/
│   ├── Dockerfile.production               # Production backend image
│   └── requirements.production.txt         # Production dependencies
├── frontend/
│   └── Dockerfile.production               # Production frontend image
├── nginx/
│   └── nginx.production.conf              # Production nginx config
├── scripts/
│   ├── switch-to-production.ps1           # Switch from dev to prod
│   ├── start-production.ps1               # Start production services
│   ├── start-production.bat                # Windows batch alternative
│   ├── start-production.sh                 # Linux/macOS script
│   ├── stop-production.ps1                # Stop production services
│   └── check-production-status.ps1        # Check service health
└── scripts/
    └── init-production-db.sql             # Production database init
```

## 🆘 Support & Commands

### Quick Commands Reference

| Action | Command |
|--------|---------|
| **Start Production** | `.\scripts\switch-to-production.ps1` |
| **Check Status** | `.\scripts\check-production-status.ps1` |
| **Stop Services** | `.\scripts\stop-production.ps1` |
| **View Logs** | `docker-compose -f docker-compose.production-no-mobile.yml logs -f [service]` |
| **Restart Service** | `docker-compose -f docker-compose.production-no-mobile.yml restart [service]` |
| **Switch Back to Dev** | `docker-compose up -d` |

### Health Check Endpoints

- **Backend**: http://localhost:8000/health
- **Frontend**: http://localhost:3000
- **Nginx**: http://localhost

### Container Names

- `cybershield-postgres` - PostgreSQL database
- `cybershield-redis` - Redis cache
- `cybershield-backend` - FastAPI backend
- `cybershield-frontend` - React frontend
- `cybershield-nginx` - Nginx reverse proxy

## 🎯 What's Excluded

**Mobile Application Components:**
- ❌ React Native mobile app
- ❌ Mobile-specific Docker containers
- ❌ Mobile build processes
- ❌ Mobile deployment scripts

**Development Components:**
- ❌ Development Docker images
- ❌ Hot reloading
- ❌ Debug mode
- ❌ Development dependencies

## 🚀 Next Steps

1. **Deploy**: Run `.\scripts\switch-to-production.ps1`
2. **Verify**: Check `.\scripts\check-production-status.ps1`
3. **Access**: Open http://localhost in your browser
4. **Monitor**: Use the status check script regularly
5. **Maintain**: Follow the update procedures above

---

**Happy Production Deploying! 🎉**

For additional assistance, refer to the main `PRODUCTION_DEPLOYMENT.md` file or create an issue in the project repository.
