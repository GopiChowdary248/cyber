# CyberShield - Comprehensive Cybersecurity Platform

A modern, full-stack cybersecurity platform built with Python FastAPI backend, React frontend, and PostgreSQL database, designed for threat detection, incident response, and security management.

## 🏗️ Architecture

### Backend (Python FastAPI)
- **Framework**: FastAPI with async support
- **Database**: PostgreSQL (production) / SQLite (development)
- **Cache**: Redis
- **Authentication**: JWT with MFA support
- **API Documentation**: Auto-generated Swagger UI

### Frontend (React)
- **Framework**: React 18 with TypeScript
- **Styling**: Tailwind CSS
- **State Management**: React Query
- **UI Components**: Headless UI, Heroicons
- **Charts**: Chart.js with React Chart.js 2

### Database (PostgreSQL)
- **Primary Database**: PostgreSQL 15
- **Extensions**: UUID, PGCrypto, Trigram
- **Schemas**: Public, Audit, Analytics
- **Connection Pooling**: SQLAlchemy async

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- PostgreSQL (optional for development)
- Docker & Docker Compose (for containerized deployment)

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cyber-cursor
   ```

2. **Set up environment variables**
   ```bash
   copy env.example .env
   # Edit .env file with your configuration
   ```

3. **Install dependencies**
   ```bash
   # Backend dependencies
   cd backend
   pip install -r requirements.txt
   
   # Frontend dependencies
   cd ../frontend
   npm install
   ```

4. **Start the application**
   ```bash
   # Start backend (in one terminal)
   cd backend
   set USE_SQLITE=true  # For local development
   python main.py
   
   # Start frontend (in another terminal)
   cd frontend
   npm start
   ```

5. **Access the application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs

### Containerized Deployment

1. **Build and start all services**
   ```bash
   docker-compose up --build
   ```

2. **Start with production profile (includes Nginx, Celery)**
   ```bash
   docker-compose --profile production up --build
   ```

3. **Access the application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs
   - Nginx (production): http://localhost:80

## 📁 Project Structure

```
cyber-cursor/
├── backend/                 # Python FastAPI backend
│   ├── app/
│   │   ├── api/v1/         # API endpoints
│   │   ├── core/           # Core configuration
│   │   ├── models/         # Database models
│   │   ├── schemas/        # Pydantic schemas
│   │   └── services/       # Business logic services
│   ├── main.py             # Application entry point
│   ├── requirements.txt    # Python dependencies
│   └── Dockerfile          # Backend container
├── frontend/               # React frontend
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── pages/          # Page components
│   │   ├── contexts/       # React contexts
│   │   └── services/       # API services
│   ├── package.json        # Node.js dependencies
│   └── Dockerfile          # Frontend container
├── scripts/                # Database and utility scripts
├── nginx/                  # Nginx configuration
├── docker-compose.yml      # Container orchestration
├── .env                    # Environment variables
└── README.md              # This file
```

## 🔧 Configuration

### Environment Variables

Key environment variables for configuration:

```bash
# Database
DATABASE_URL=postgresql+asyncpg://user:password@host:port/db
USE_SQLITE=true  # For local development

# Security
SECRET_KEY=your-super-secret-key
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Redis
REDIS_URL=redis://:password@host:port/db

# CORS
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000

# Frontend
REACT_APP_API_URL=http://localhost:8000
```

### Database Configuration

The application supports both PostgreSQL and SQLite:

- **Production**: PostgreSQL with connection pooling
- **Development**: SQLite for easy local development

Database initialization is handled automatically when the application starts.

## 🔐 Security Features

- **Authentication**: JWT-based authentication with refresh tokens
- **Authorization**: Role-based access control (Admin, Analyst, User)
- **MFA**: Two-factor authentication support
- **Rate Limiting**: API rate limiting with Redis
- **CORS**: Configurable CORS policies
- **Security Headers**: HSTS, CSP, XSS protection
- **Input Validation**: Comprehensive input sanitization
- **Audit Logging**: Complete audit trail

## 📊 Features

### Core Security Features
- **Threat Detection**: AI-powered threat detection and analysis
- **Incident Management**: Complete incident lifecycle management
- **Vulnerability Management**: Asset and vulnerability tracking
- **Compliance**: Regulatory compliance monitoring and reporting
- **Security Analytics**: Real-time security metrics and dashboards

### Advanced Features
- **SOAR Integration**: Security orchestration and automated response
- **Cloud Security**: Multi-cloud security monitoring
- **Network Security**: Firewall, IDS/IPS, VPN management
- **Endpoint Security**: EDR, antivirus, application whitelisting
- **Data Protection**: Encryption, DLP, database monitoring

## 🐳 Docker Services

The containerized environment includes:

- **postgres**: PostgreSQL database
- **redis**: Redis cache and message broker
- **backend**: FastAPI application
- **frontend**: React application
- **nginx**: Reverse proxy (production)
- **celery-worker**: Background task processing
- **celery-beat**: Scheduled task management

## 🚀 Deployment

### Production Deployment

1. **Environment Setup**
   ```bash
   # Set production environment variables
   export ENVIRONMENT=production
   export DEBUG=false
   ```

2. **Database Migration**
   ```bash
   # Run database migrations
   cd backend
   alembic upgrade head
   ```

3. **Container Deployment**
   ```bash
   # Deploy with production profile
   docker-compose --profile production up -d
   ```

### Scaling

The application is designed for horizontal scaling:

- **Backend**: Multiple FastAPI workers
- **Database**: PostgreSQL with read replicas
- **Cache**: Redis cluster
- **Frontend**: CDN distribution

## 🔍 Monitoring

- **Health Checks**: Built-in health check endpoints
- **Logging**: Structured logging with different levels
- **Metrics**: Prometheus metrics integration
- **Tracing**: Distributed tracing support

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the API documentation at `/docs`
- Review the security implementation guide

## 🔄 Updates

To update the application:

```bash
# Pull latest changes
git pull origin main

# Update dependencies
cd backend && pip install -r requirements.txt
cd ../frontend && npm install

# Restart services
docker-compose down && docker-compose up --build
``` 