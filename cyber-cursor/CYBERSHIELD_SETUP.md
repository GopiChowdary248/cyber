# 🛡️ CyberShield - Complete Setup Guide

## Overview
CyberShield is a comprehensive cybersecurity platform built with:
- **Backend**: Python FastAPI with PostgreSQL database
- **Frontend**: React Native Web (not mobile app)
- **Database**: PostgreSQL in Docker containers
- **Cache**: Redis in Docker containers
- **Authentication**: JWT-based with role-based access control

## 🚀 Quick Start

### Prerequisites
- **Docker Desktop** - For PostgreSQL and Redis containers
- **Python 3.8+** - For backend API
- **Node.js 16+** - For frontend development server
- **Git** - For version control

### Option 1: Automated Startup (Recommended)
```bash
# Windows PowerShell
.\start-cybershield.ps1

# Python (Cross-platform)
python start-cybershield.py
```

### Option 2: Manual Startup
```bash
# 1. Start containers
docker-compose -f docker-compose.dev.yml up -d

# 2. Start backend (in one terminal)
python start-backend.py

# 3. Start frontend (in another terminal)
cd frontend
npm start
```

## 📁 Project Structure
```
cyber-cursor/
├── backend/                 # Python FastAPI backend
│   ├── app/                # Application code
│   ├── main.py            # Main FastAPI application
│   ├── requirements.txt   # Python dependencies
│   └── env.dev           # Development environment
├── frontend/              # React Native web frontend
│   ├── src/              # Source code
│   ├── package.json      # Node.js dependencies
│   └── public/           # Public assets
├── scripts/               # Database scripts
├── docker-compose.dev.yml # Development containers
└── start-cybershield.py  # Automated startup script
```

## 🗄️ Database Setup

### PostgreSQL Container
- **Database**: `cybershield_dev`
- **User**: `cybershield_user`
- **Password**: `cybershield_password`
- **Port**: `5432`

### Redis Container
- **Port**: `6379`
- **Password**: `redis_password`
- **Database**: `0`

### Initial Data
The database automatically creates:
- Demo users with roles (admin, analyst, user)
- System health monitoring tables
- Audit logging tables

## 🔐 Authentication

### Demo Accounts
| Role | Email | Password | Access Level |
|------|-------|----------|--------------|
| Admin | admin@cybershield.com | password | Full system access |
| Analyst | analyst@cybershield.com | password | Security analysis tools |
| User | user@cybershield.com | password | Basic user features |

### JWT Tokens
- **Access Token**: 30 minutes
- **Refresh Token**: 7 days
- **Algorithm**: HS256

## 🌐 API Endpoints

### Core Endpoints
- `GET /health` - System health check
- `POST /api/v1/auth/login` - User authentication
- `POST /api/v1/auth/refresh` - Token refresh
- `GET /api/v1/users/profile` - User profile

### Security Modules
- **SAST**: `/api/v1/sast/*` - Static Application Security Testing
- **DAST**: `/api/v1/dast/*` - Dynamic Application Security Testing
- **RASP**: `/api/v1/rasp/*` - Runtime Application Self-Protection
- **Cloud Security**: `/api/v1/cloud-security/*` - Cloud security management
- **IAM**: `/api/v1/iam/*` - Identity and Access Management
- **Network Security**: `/api/v1/network-security/*` - Network security tools

### API Documentation
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🎨 Frontend Features

### React Native Web Components
- **Responsive Design** - Works on all screen sizes
- **Modern UI** - Tailwind CSS with Framer Motion
- **Role-based Navigation** - Different menus for different user roles
- **Real-time Updates** - WebSocket integration for live data

### Key Screens
- **Dashboard** - Overview of security metrics
- **Security Modules** - SAST, DAST, RASP, Cloud Security
- **User Management** - Admin tools for user administration
- **Reports** - Security analysis and compliance reports
- **Settings** - User preferences and system configuration

## 🐍 Backend Features

### FastAPI Application
- **Async Support** - High-performance async operations
- **Automatic Documentation** - OpenAPI/Swagger generation
- **Middleware Stack** - Security, CORS, logging, monitoring
- **Database Integration** - Async PostgreSQL with SQLAlchemy
- **Redis Integration** - Caching and session management

### Security Features
- **JWT Authentication** - Secure token-based auth
- **Role-based Access Control** - Fine-grained permissions
- **Rate Limiting** - API abuse prevention
- **Input Validation** - Pydantic model validation
- **Audit Logging** - Complete activity tracking

## 🔧 Development

### Backend Development
```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Run with auto-reload
python start-backend.py

# Or use uvicorn directly
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Development
```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm run build
```

### Database Development
```bash
# Connect to PostgreSQL
psql -h localhost -U cybershield_user -d cybershield_dev

# View container logs
docker-compose -f docker-compose.dev.yml logs postgres
docker-compose -f docker-compose.dev.yml logs redis
```

## 🐳 Container Management

### Start Containers
```bash
docker-compose -f docker-compose.dev.yml up -d
```

### Stop Containers
```bash
docker-compose -f docker-compose.dev.yml down
```

### View Container Status
```bash
docker-compose -f docker-compose.dev.yml ps
```

### View Container Logs
```bash
docker-compose -f docker-compose.dev.yml logs -f
```

## 📊 Monitoring & Health

### Health Checks
- **Backend**: http://localhost:8000/health
- **Database**: Container health check
- **Redis**: Container health check
- **Frontend**: React development server status

### Logging
- **Structured Logging** - JSON format for easy parsing
- **Log Levels** - DEBUG, INFO, WARNING, ERROR
- **Audit Logs** - User actions and system events
- **Performance Metrics** - Response times and resource usage

## 🚨 Troubleshooting

### Common Issues

#### Backend Won't Start
```bash
# Check Python dependencies
pip install -r backend/requirements.txt

# Check environment variables
python -c "import os; print(os.environ.get('DATABASE_URL'))"

# Check database connection
python backend/check_db.py
```

#### Frontend Won't Start
```bash
# Clear npm cache
npm cache clean --force

# Remove node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

#### Database Connection Issues
```bash
# Check container status
docker-compose -f docker-compose.dev.yml ps

# Check container logs
docker-compose -f docker-compose.dev.yml logs postgres

# Restart containers
docker-compose -f docker-compose.dev.yml restart
```

#### Port Conflicts
```bash
# Check what's using the ports
netstat -an | findstr :8000  # Windows
lsof -i :8000                # Mac/Linux

# Change ports in docker-compose.dev.yml if needed
```

### Performance Issues
- **Database**: Check connection pool settings
- **Redis**: Monitor memory usage
- **Backend**: Check async operation efficiency
- **Frontend**: Optimize bundle size and lazy loading

## 🔒 Security Considerations

### Development Environment
- **Weak Passwords** - Demo accounts use simple passwords
- **Local Access** - Services only accessible from localhost
- **Debug Mode** - Detailed error messages enabled

### Production Deployment
- **Strong Passwords** - Use secure password generation
- **HTTPS Only** - Enable SSL/TLS encryption
- **Environment Variables** - Secure secret management
- **Network Security** - Firewall and access controls
- **Monitoring** - Security event logging and alerting

## 📚 Additional Resources

### Documentation
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React Native Web](https://necolas.github.io/react-native-web/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Redis Documentation](https://redis.io/documentation)

### API Testing
```bash
# Test health endpoint
curl http://localhost:8000/health

# Test authentication
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin@cybershield.com","password":"password"}'
```

## 🤝 Support

### Getting Help
1. **Check Logs** - Review container and application logs
2. **Health Checks** - Verify service status endpoints
3. **Documentation** - Review API docs at /docs
4. **Issues** - Report problems with detailed error messages

### Contributing
- Follow Python PEP 8 style guide
- Use TypeScript for frontend components
- Add tests for new features
- Update documentation for API changes

---

**🎯 Ready to secure your applications with CyberShield!**

Start the application and access it at:
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
