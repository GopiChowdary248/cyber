# CyberShield - Containerized Full-Stack Application

This guide will help you containerize and run the CyberShield full-stack cybersecurity platform using Docker and Docker Compose.

## 🏗️ Architecture Overview

The application follows a microservices architecture with proper separation of concerns:

- **Backend**: FastAPI (Python) - RESTful API with async database operations
- **Frontend**: React (TypeScript) - Modern, responsive web interface
- **Database**: PostgreSQL - Primary data store with async support
- **Cache**: Redis - Session storage and background task queue
- **Reverse Proxy**: Nginx - Load balancing and SSL termination
- **Background Tasks**: Celery - Asynchronous task processing

## 📋 Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- At least 4GB RAM available
- Ports 80, 3000, 5432, 6379, 8000 available

## 🚀 Quick Start

### 1. Clone and Setup

```bash
# Clone the repository
git clone <your-repo-url>
cd cyber-cursor

# Copy environment template
cp env.example .env

# Edit environment variables (optional)
nano .env
```

### 2. Build and Run

```bash
# Build and start all services
docker-compose up --build -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

### 3. Access the Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Admin Interface**: http://localhost:8000/admin
- **Health Check**: http://localhost:8000/health

## 🔧 Configuration

### Environment Variables

The application uses environment variables for configuration. Key variables:

```bash
# Database
DATABASE_URL=postgresql+asyncpg://cybershield_user:cybershield_password@postgres:5432/cybershield

# Redis
REDIS_URL=redis://:redis_password@redis:6379/0

# Security
SECRET_KEY=your-super-secret-key-change-in-production

# CORS
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001,http://frontend:80
```

### Production Deployment

For production deployment, use the production profile:

```bash
# Start with production services (includes Nginx, Celery workers)
docker-compose --profile production up -d

# Or build and start
docker-compose --profile production up --build -d
```

## 📊 Service Details

### Backend (FastAPI)
- **Port**: 8000
- **Health Check**: `/health`
- **API Docs**: `/docs`
- **Features**:
  - Async database operations
  - JWT authentication
  - Rate limiting
  - Structured logging
  - Background task processing

### Frontend (React)
- **Port**: 3000 (mapped to 80 in container)
- **Features**:
  - TypeScript support
  - Tailwind CSS
  - React Router
  - Chart.js integration
  - Responsive design

### Database (PostgreSQL)
- **Port**: 5432
- **Database**: cybershield
- **User**: cybershield_user
- **Features**:
  - Async driver support
  - UUID extensions
  - Encryption support
  - Connection pooling

### Cache (Redis)
- **Port**: 6379
- **Features**:
  - Session storage
  - Task queue backend
  - Caching layer
  - Password protected

## 🛠️ Development Commands

### Basic Operations

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# Restart services
docker-compose restart

# View logs
docker-compose logs -f [service-name]

# Execute commands in containers
docker-compose exec backend python manage.py migrate
docker-compose exec frontend npm install
docker-compose exec postgres psql -U cybershield_user -d cybershield
```

### Database Operations

```bash
# Run migrations
docker-compose exec backend alembic upgrade head

# Create migration
docker-compose exec backend alembic revision --autogenerate -m "description"

# Reset database
docker-compose down -v
docker-compose up -d postgres
```

### Frontend Development

```bash
# Install dependencies
docker-compose exec frontend npm install

# Run development server
docker-compose exec frontend npm start

# Build for production
docker-compose exec frontend npm run build

# Run tests
docker-compose exec frontend npm test
```

## 🔍 Monitoring and Debugging

### Health Checks

All services include health checks:

```bash
# Check service health
docker-compose ps

# View health check logs
docker-compose logs backend | grep health
```

### Logs

```bash
# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f postgres

# View last 100 lines
docker-compose logs --tail=100 backend
```

### Performance Monitoring

```bash
# Check resource usage
docker stats

# Monitor specific container
docker stats cybershield-backend
```

## 🔒 Security Considerations

### Production Security

1. **Change Default Passwords**:
   - Update database passwords in `.env`
   - Change Redis password
   - Generate strong SECRET_KEY

2. **SSL/TLS Configuration**:
   - Uncomment SSL settings in `nginx/nginx.conf`
   - Add SSL certificates to `nginx/ssl/`
   - Configure HTTPS redirects

3. **Network Security**:
   - Use Docker networks for service isolation
   - Configure firewall rules
   - Implement rate limiting

4. **Environment Variables**:
   - Never commit `.env` files
   - Use secrets management in production
   - Rotate credentials regularly

### Security Headers

The Nginx configuration includes security headers:
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Content-Security-Policy
- Referrer-Policy

## 📈 Scaling

### Horizontal Scaling

```bash
# Scale backend services
docker-compose up -d --scale backend=3

# Scale Celery workers
docker-compose --profile production up -d --scale celery-worker=2
```

### Load Balancing

The Nginx configuration includes:
- Upstream load balancing
- Health checks
- Connection pooling
- Rate limiting

## 🐛 Troubleshooting

### Common Issues

1. **Port Conflicts**:
   ```bash
   # Check port usage
   netstat -tulpn | grep :8000
   
   # Change ports in docker-compose.yml
   ports:
     - "8001:8000"  # Change host port
   ```

2. **Database Connection Issues**:
   ```bash
   # Check database status
   docker-compose exec postgres pg_isready -U cybershield_user
   
   # View database logs
   docker-compose logs postgres
   ```

3. **Memory Issues**:
   ```bash
   # Check memory usage
   docker stats
   
   # Increase memory limits in docker-compose.yml
   deploy:
     resources:
       limits:
         memory: 2G
   ```

4. **Build Failures**:
   ```bash
   # Clean build cache
   docker-compose build --no-cache
   
   # Remove all containers and images
   docker-compose down --rmi all --volumes
   ```

### Debug Mode

Enable debug mode for development:

```bash
# Set debug environment variable
export DEBUG=true

# Or update .env file
DEBUG=true

# Restart services
docker-compose restart backend
```

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React Documentation](https://reactjs.org/docs/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with Docker Compose
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details. 