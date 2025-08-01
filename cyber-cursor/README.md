# 🛡️ CyberShield - Comprehensive Cybersecurity Platform

A modern, containerized cybersecurity platform built with React, FastAPI, PostgreSQL, and Redis.

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Chrome browser (recommended)

### Running the Application

1. **Start all services:**
   ```bash
   docker-compose up -d
   ```

2. **Access the application:**
   - **Frontend:** http://localhost:3000
   - **Backend API:** http://localhost:8000
   - **API Documentation:** http://localhost:8000/docs

3. **Check service status:**
   ```bash
   docker-compose ps
   ```

## 🔐 Demo Accounts

The application includes pre-configured demo accounts for testing:

| Role | Email | Password | Permissions |
|------|-------|----------|-------------|
| **Admin** | `admin@cybershield.com` | `password` | Full access to all features |
| **Analyst** | `analyst@cybershield.com` | `password` | Read all, write incidents |
| **User** | `user@cybershield.com` | `password` | Read/write own data |

## 🏗️ Architecture

### Frontend (React)
- **Port:** 3000
- **Features:**
  - Modern React with TypeScript
  - Enhanced UI components
  - Responsive design with dark theme
  - Real-time dashboard updates

### Backend (FastAPI)
- **Port:** 8000
- **Features:**
  - RESTful API with automatic documentation
  - Mock authentication system
  - Structured logging
  - CORS support

### Database (PostgreSQL)
- **Port:** 5432
- **Features:**
  - Persistent data storage
  - Initialized with security schemas
  - Health monitoring

### Cache (Redis)
- **Port:** 6379
- **Features:**
  - Session storage
  - Background task queue
  - Performance optimization

## 📊 Available Features

### 1. **Dashboard**
- Security metrics overview
- Real-time threat monitoring
- Incident tracking
- Performance analytics

### 2. **Threat Intelligence**
- Threat indicator management
- Campaign tracking
- Hunting queries
- Intelligence feeds

### 3. **Data Protection**
- Data classification
- Privacy management
- Compliance monitoring
- Breach detection

### 4. **Endpoint Security**
- Device management
- Antivirus scanning
- EDR alerts
- Application whitelisting

### 5. **Cloud Security**
- Cloud configuration monitoring
- Security posture assessment
- Compliance reporting
- Risk management

## 🔧 Development

### Project Structure
```
cyber-cursor/
├── frontend/                 # React application
│   ├── src/
│   │   ├── components/      # Reusable UI components
│   │   ├── pages/          # Page components
│   │   ├── contexts/       # React contexts
│   │   └── utils/          # Utility functions
│   └── public/             # Static assets
├── backend/                 # FastAPI application
│   ├── app/
│   │   ├── api/           # API routes
│   │   ├── core/          # Core configuration
│   │   ├── models/        # Database models
│   │   └── schemas/       # Pydantic schemas
│   └── main_simple.py     # Simplified entry point
├── scripts/                # Database initialization
├── docker-compose.yml      # Container orchestration
└── README.md              # This file
```

### Making Changes

1. **Frontend changes:**
   ```bash
   docker-compose up frontend --build -d
   ```

2. **Backend changes:**
   ```bash
   docker-compose up backend --build -d
   ```

3. **Database changes:**
   ```bash
   docker-compose down
   docker volume rm cyber-cursor_postgres_data
   docker-compose up -d
   ```

## 🐛 Troubleshooting

### Common Issues

1. **Port conflicts:**
   - Ensure ports 3000, 8000, 5432, and 6379 are available
   - Stop other services using these ports

2. **Docker issues:**
   - Make sure Docker Desktop is running
   - Check Docker logs: `docker-compose logs [service-name]`

3. **Authentication errors:**
   - Clear browser cache and local storage
   - Use demo accounts with correct credentials

4. **Build failures:**
   - Clean Docker cache: `docker system prune -a`
   - Rebuild containers: `docker-compose up --build -d`

### Logs and Debugging

```bash
# View all logs
docker-compose logs

# View specific service logs
docker-compose logs frontend
docker-compose logs backend
docker-compose logs postgres

# Follow logs in real-time
docker-compose logs -f [service-name]
```

## 🔒 Security Notes

⚠️ **Important:** This is a demo application with mock authentication. In production:

- Implement proper JWT token validation
- Use secure password hashing
- Enable HTTPS
- Configure proper CORS policies
- Implement rate limiting
- Add input validation and sanitization

## 📈 Performance

### Optimization Tips

1. **Development:**
   - Use React DevTools for component profiling
   - Monitor API response times
   - Check database query performance

2. **Production:**
   - Enable gzip compression
   - Use CDN for static assets
   - Implement caching strategies
   - Monitor resource usage

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is for educational and demonstration purposes.

---

## 🎯 Next Steps

The application is now fully functional with:
- ✅ Containerized deployment
- ✅ Mock authentication system
- ✅ Modern React frontend
- ✅ FastAPI backend
- ✅ PostgreSQL database
- ✅ Redis caching
- ✅ Health monitoring

You can now:
1. **Explore the dashboard** at http://localhost:3000
2. **Test different user roles** using the demo accounts
3. **View API documentation** at http://localhost:8000/docs
4. **Customize features** by modifying the source code
5. **Deploy to production** using the containerized setup

Happy hacking! 🛡️ 