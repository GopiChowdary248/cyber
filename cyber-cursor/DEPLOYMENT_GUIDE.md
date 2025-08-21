# 🚀 Cyber Cursor Security Platform - Deployment Guide

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Database Setup](#database-setup)
4. [Backend Deployment](#backend-deployment)
5. [Frontend Deployment](#frontend-deployment)
6. [Production Deployment](#production-deployment)
7. [Docker Deployment](#docker-deployment)
8. [Monitoring & Maintenance](#monitoring--maintenance)
9. [Troubleshooting](#troubleshooting)
10. [Security Considerations](#security-considerations)

## 🎯 Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+), macOS 10.15+, or Windows 10+
- **CPU**: 4+ cores recommended
- **Memory**: 8GB+ RAM recommended
- **Storage**: 50GB+ available disk space
- **Network**: Internet access for package installation

### Software Requirements

- **Python**: 3.8+ with pip
- **Node.js**: 16+ with npm
- **PostgreSQL**: 12+ (recommended) or 10+
- **Redis**: 6+ (optional, for caching)
- **Docker**: 20+ (optional, for containerized deployment)
- **Git**: Latest version

### Development Tools

- **Code Editor**: VS Code, PyCharm, or similar
- **Database Client**: pgAdmin, DBeaver, or psql
- **API Testing**: Postman, Insomnia, or curl

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone <repository-url>
cd cyber-cursor
```

### 2. Install Dependencies

```bash
# Backend dependencies
cd backend
pip install -r requirements.txt

# Frontend dependencies
cd ../frontend
npm install
```

### 3. Start Services

```bash
# Terminal 1: Start Backend
cd backend
python main.py

# Terminal 2: Start Frontend
cd frontend
npm start
```

### 4. Access the Platform

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 🗄️ Database Setup

### PostgreSQL Installation

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### macOS
```bash
brew install postgresql
brew services start postgresql
```

#### Windows
Download and install from [PostgreSQL official website](https://www.postgresql.org/download/windows/)

### Database Configuration

#### 1. Create Database and User

```bash
# Connect to PostgreSQL as superuser
sudo -u postgres psql

# Create database and user
CREATE DATABASE cyber_cursor;
CREATE USER cyber_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE cyber_cursor TO cyber_user;
ALTER USER cyber_user CREATEDB;
\q
```

#### 2. Environment Configuration

Create `.env` file in the backend directory:

```env
# Database Configuration
DATABASE_URL=postgresql://cyber_user:secure_password@localhost:5432/cyber_cursor
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cyber_cursor
DB_USER=cyber_user
DB_PASSWORD=secure_password

# Security Configuration
SECRET_KEY=your-super-secret-key-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Server Configuration
HOST=0.0.0.0
PORT=8000
DEBUG=false
ENVIRONMENT=production

# External APIs (optional)
OPENAI_API_KEY=your-openai-key
VIRUSTOTAL_API_KEY=your-virustotal-key
SHODAN_API_KEY=your-shodan-key
```

#### 3. Initialize Database

```bash
cd backend
python scripts/setup_database.py
```

## 🔧 Backend Deployment

### Development Mode

```bash
cd backend
python main.py
```

### Production Mode

#### Using Uvicorn

```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

#### Using Gunicorn

```bash
cd backend
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

#### Using Systemd Service

Create `/etc/systemd/system/cyber-cursor.service`:

```ini
[Unit]
Description=Cyber Cursor Security Platform
After=network.target postgresql.service

[Service]
Type=exec
User=cyber
Group=cyber
WorkingDirectory=/opt/cyber-cursor/backend
Environment=PATH=/opt/cyber-cursor/backend/venv/bin
ExecStart=/opt/cyber-cursor/backend/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cyber-cursor
sudo systemctl start cyber-cursor
sudo systemctl status cyber-cursor
```

## 🎨 Frontend Deployment

### Development Mode

```bash
cd frontend
npm start
```

### Production Build

```bash
cd frontend
npm run build
```

### Serve Production Build

#### Using nginx

Install nginx:

```bash
# Ubuntu/Debian
sudo apt install nginx

# macOS
brew install nginx
```

Configure nginx (`/etc/nginx/sites-available/cyber-cursor`):

```nginx
server {
    listen 80;
    server_name your-domain.com;
    root /opt/cyber-cursor/frontend/build;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/cyber-cursor /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

#### Using Node.js serve

```bash
npm install -g serve
cd frontend/build
serve -s . -l 3000
```

## 🏭 Production Deployment

### 1. Production Environment Setup

```bash
# Create production user
sudo useradd -m -s /bin/bash cyber
sudo passwd cyber

# Create application directory
sudo mkdir -p /opt/cyber-cursor
sudo chown cyber:cyber /opt/cyber-cursor

# Switch to cyber user
sudo su - cyber
```

### 2. Application Deployment

```bash
# Clone repository
git clone <repository-url> /opt/cyber-cursor
cd /opt/cyber-cursor

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
cd backend
pip install -r requirements.txt

# Build frontend
cd ../frontend
npm install
npm run build
```

### 3. Environment Configuration

```bash
# Production environment variables
export ENVIRONMENT=production
export DEBUG=false
export LOG_LEVEL=warning
export DATABASE_URL=postgresql://cyber_user:secure_password@localhost:5432/cyber_cursor
export SECRET_KEY=your-production-secret-key
```

### 4. SSL/TLS Configuration

#### Using Let's Encrypt

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

#### Using Self-Signed Certificate

```bash
# Generate self-signed certificate
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/cyber-cursor.key \
    -out /etc/ssl/certs/cyber-cursor.crt
```

### 5. Firewall Configuration

```bash
# Ubuntu/Debian (ufw)
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# CentOS/RHEL (firewalld)
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

## 🐳 Docker Deployment

### 1. Docker Compose Setup

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:13
    environment:
      POSTGRES_DB: cyber_cursor
      POSTGRES_USER: cyber_user
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    restart: unless-stopped

  redis:
    image: redis:6-alpine
    ports:
      - "6379:6379"
    restart: unless-stopped

  backend:
    build: ./backend
    environment:
      - DATABASE_URL=postgresql://cyber_user:secure_password@postgres:5432/cyber_cursor
      - REDIS_URL=redis://redis:6379/0
      - SECRET_KEY=your-docker-secret-key
    ports:
      - "8000:8000"
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  frontend:
    build: ./frontend
    ports:
      - "3000:80"
    depends_on:
      - backend
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
    depends_on:
      - backend
      - frontend
    restart: unless-stopped

volumes:
  postgres_data:
```

### 2. Docker Backend

Create `backend/Dockerfile`:

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 3. Docker Frontend

Create `frontend/Dockerfile`:

```dockerfile
FROM node:16-alpine as build

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

### 4. Deploy with Docker

```bash
# Build and start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## 📊 Monitoring & Maintenance

### 1. Health Monitoring

```bash
# Health check endpoint
curl http://localhost:8000/health

# API status
curl http://localhost:8000/api/status

# System metrics
curl http://localhost:8000/metrics
```

### 2. Log Management

```bash
# Backend logs
sudo journalctl -u cyber-cursor -f

# nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-*.log
```

### 3. Database Maintenance

```bash
# Connect to database
psql -h localhost -U cyber_user -d cyber_cursor

# Check table sizes
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

# Vacuum database
VACUUM ANALYZE;
```

### 4. Backup Strategy

```bash
# Create backup script
cat > /opt/cyber-cursor/backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/opt/backups/cyber-cursor"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Database backup
pg_dump -h localhost -U cyber_user cyber_cursor > $BACKUP_DIR/db_backup_$DATE.sql

# Application backup
tar -czf $BACKUP_DIR/app_backup_$DATE.tar.gz /opt/cyber-cursor

# Clean old backups (keep last 7 days)
find $BACKUP_DIR -name "*.sql" -mtime +7 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete
EOF

# Make executable and add to cron
chmod +x /opt/cyber-cursor/backup.sh
crontab -e
# Add: 0 2 * * * /opt/cyber-cursor/backup.sh
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Database Connection Issues

```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check connection
psql -h localhost -U cyber_user -d cyber_cursor

# Check logs
sudo tail -f /var/log/postgresql/postgresql-*.log
```

#### 2. Port Conflicts

```bash
# Check port usage
sudo netstat -tlnp | grep :8000
sudo lsof -i :8000

# Kill process using port
sudo kill -9 <PID>
```

#### 3. Permission Issues

```bash
# Fix file permissions
sudo chown -R cyber:cyber /opt/cyber-cursor
sudo chmod -R 755 /opt/cyber-cursor

# Fix database permissions
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE cyber_cursor TO cyber_user;"
```

#### 4. Service Won't Start

```bash
# Check service status
sudo systemctl status cyber-cursor

# Check logs
sudo journalctl -u cyber-cursor -n 50

# Test configuration
sudo systemctl daemon-reload
sudo systemctl restart cyber-cursor
```

### Performance Issues

#### 1. Slow Response Times

```bash
# Check database performance
psql -h localhost -U cyber_user -d cyber_cursor -c "SELECT * FROM pg_stat_activity;"

# Check system resources
htop
iostat -x 1
```

#### 2. High Memory Usage

```bash
# Check memory usage
free -h
ps aux --sort=-%mem | head -10

# Restart services if needed
sudo systemctl restart cyber-cursor
sudo systemctl restart postgresql
```

## 🔒 Security Considerations

### 1. Network Security

- Use firewalls to restrict access
- Implement VPN for remote access
- Use HTTPS/TLS for all communications
- Regular security updates

### 2. Application Security

- Change default passwords
- Use strong secret keys
- Implement rate limiting
- Regular security audits

### 3. Data Security

- Encrypt sensitive data
- Regular backups
- Access control and logging
- Compliance with regulations

### 4. Monitoring and Alerting

```bash
# Set up monitoring alerts
# Example: Monitor disk space
df -h | awk '$5 > "80%" {print "WARNING: Disk space low on " $1}'

# Monitor service status
systemctl is-active cyber-cursor || echo "ALERT: Cyber Cursor service is down"
```

## 📚 Additional Resources

### Documentation

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React Documentation](https://reactjs.org/docs/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Nginx Documentation](https://nginx.org/en/docs/)

### Support

- GitHub Issues: [Repository Issues](https://github.com/your-repo/issues)
- Documentation: `/docs` endpoint when platform is running
- Community: [Discussions](https://github.com/your-repo/discussions)

---

**🎉 Congratulations!** You have successfully deployed the Cyber Cursor Security Platform.

For additional support or questions, please refer to the documentation or create an issue in the repository. 