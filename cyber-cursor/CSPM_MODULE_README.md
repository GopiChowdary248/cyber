# 🚀 CyberShield CSPM Module

**Comprehensive Cloud Security Posture Management (CSPM) Module for Enterprise Security**

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Security Features](#security-features)
- [Monitoring & Observability](#monitoring--observability)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## 🌟 Overview

The CyberShield CSPM Module is a comprehensive, enterprise-grade Cloud Security Posture Management solution that provides continuous visibility, compliance monitoring, and automated remediation for cloud infrastructure. Built with modern technologies and security best practices, it rivals commercial solutions like Wiz, Prisma Cloud, and AWS Security Hub.

### 🎯 Key Benefits

- **Continuous Visibility**: Real-time monitoring of cloud security posture
- **Compliance Automation**: Automated compliance checking and reporting
- **Risk Management**: Proactive risk identification and mitigation
- **Operational Efficiency**: Streamlined security workflows
- **Cost Optimization**: Reduced manual security overhead
- **Enterprise Ready**: Scalable architecture for large organizations

## ✨ Features

### 🔍 **Core CSPM Capabilities**

#### **Asset Management**
- Cloud asset inventory (AWS, Azure, GCP)
- Asset relationship mapping
- Risk scoring and assessment
- Tag-based organization
- Change tracking and history

#### **Policy Management**
- Security policy library
- Custom policy creation
- Policy framework support (CIS, NIST, PCI, SOC2)
- Real-time policy evaluation
- Policy violation tracking

#### **Compliance Management**
- Framework-based compliance tracking
- Control mapping to policies
- Compliance reporting and dashboards
- Audit trail management
- Remediation tracking

#### **Risk Assessment**
- Comprehensive risk scoring
- Factor-based risk analysis
- Risk mitigation recommendations
- Historical risk tracking
- Risk trend analysis

#### **Remediation Workflows**
- Automated remediation playbooks
- Manual remediation tasks
- Risk-based approval workflows
- Integration with ticketing systems
- Remediation tracking and reporting

### 🛡️ **Security Features**

#### **Advanced Policy Engine**
- OPA (Open Policy Agent) integration
- Rego policy language support
- Custom policy templates
- Policy testing and validation
- Policy versioning

#### **Access Control**
- Role-based access control (RBAC)
- Multi-factor authentication (MFA)
- JWT-based authentication
- API rate limiting
- Audit logging

#### **Data Protection**
- Data encryption at rest and in transit
- Secure credential management
- Vault integration for secrets
- Data anonymization options
- Compliance with data protection regulations

### 📊 **Monitoring & Analytics**

#### **Real-time Dashboards**
- Security posture overview
- Risk distribution visualization
- Compliance score tracking
- Finding trends and patterns
- SLA monitoring

#### **Reporting & Analytics**
- Custom report generation
- Scheduled reporting
- Export capabilities (PDF, CSV, JSON)
- Executive dashboards
- Compliance reports

#### **Integration Capabilities**
- Webhook support
- SIEM integration
- Ticketing system integration
- Cloud provider APIs
- Third-party security tools

## 🏗️ Architecture

### **Technology Stack**

#### **Backend**
- **Framework**: FastAPI (Python 3.9+)
- **Database**: PostgreSQL 15+ with JSONB support
- **ORM**: SQLAlchemy 2.0+ with async support
- **Migrations**: Alembic
- **Background Jobs**: Celery with Redis
- **Policy Engine**: OPA (Open Policy Agent)
- **Authentication**: JWT with OAuth2 support

#### **Frontend**
- **Web**: React 18 with TypeScript
- **Mobile**: React Native with React Native Web
- **UI Framework**: Tailwind CSS
- **State Management**: React Context + Hooks
- **Icons**: Heroicons

#### **Infrastructure**
- **Containerization**: Docker & Docker Compose
- **Database Pooling**: pgBouncer
- **Caching**: Redis
- **Monitoring**: Prometheus + Grafana
- **Reverse Proxy**: Nginx
- **Secrets**: HashiCorp Vault

### **System Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Mobile App    │    │   API Gateway   │
│   (React)       │    │ (React Native)  │    │   (Nginx)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Backend API   │
                    │   (FastAPI)     │
                    └─────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │     Redis       │    │      OPA       │
│   Database      │    │   (Cache/Celery)│    │ (Policy Engine)│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │
┌─────────────────┐    ┌─────────────────┐
│   pgBouncer     │    │   Celery        │
│ (Connection Pool)│    │ (Background Jobs)│
└─────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### **Prerequisites**

- Docker Desktop 4.0+
- Docker Compose 2.0+
- 8GB+ RAM available
- 20GB+ disk space

### **One-Command Deployment**

#### **Windows (PowerShell)**
```powershell
# Navigate to project directory
cd cyber-cursor

# Run deployment script
.\scripts\deploy_cspm.ps1
```

#### **Linux/macOS (Bash)**
```bash
# Navigate to project directory
cd cyber-cursor

# Make script executable
chmod +x scripts/deploy_cspm.sh

# Run deployment script
./scripts/deploy_cspm.sh
```

### **Manual Deployment**

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cyber-cursor
   ```

2. **Create environment file**
   ```bash
   cp .env.example .env.cspm
   # Edit .env.cspm with your configuration
   ```

3. **Start services**
   ```bash
   docker-compose -f docker-compose.cspm.yml up -d
   ```

4. **Run migrations**
   ```bash
   docker-compose -f docker-compose.cspm.yml exec backend python scripts/run_cspm_migration.py
   ```

## 📦 Installation

### **System Requirements**

#### **Minimum Requirements**
- **CPU**: 4 cores
- **RAM**: 8GB
- **Storage**: 20GB SSD
- **OS**: Windows 10+, macOS 10.15+, Ubuntu 20.04+

#### **Recommended Requirements**
- **CPU**: 8+ cores
- **RAM**: 16GB+
- **Storage**: 100GB+ SSD
- **OS**: Ubuntu 22.04 LTS, CentOS 8+

### **Dependencies**

#### **Backend Dependencies**
```bash
# Python packages
pip install -r backend/requirements.txt

# System packages (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y postgresql-client redis-tools curl
```

#### **Frontend Dependencies**
```bash
# Node.js packages
cd frontend
npm install

# Mobile dependencies
cd ../mobile
npm install
```

### **Database Setup**

#### **PostgreSQL Configuration**
```sql
-- Create database
CREATE DATABASE cybershield_cspm;

-- Create user
CREATE USER cybershield WITH PASSWORD 'secure_password';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE cybershield_cspm TO cybershield;
```

#### **Redis Configuration**
```bash
# Install Redis
sudo apt-get install redis-server

# Configure Redis
sudo nano /etc/redis/redis.conf

# Set password and enable persistence
requirepass your_redis_password
appendonly yes
```

## ⚙️ Configuration

### **Environment Variables**

#### **Core Configuration**
```bash
# Application
ENVIRONMENT=production
LOG_LEVEL=INFO
SECRET_KEY=your-secret-key-here

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/cybershield_cspm
REDIS_URL=redis://:password@localhost:6379/0

# Security
JWT_SECRET_KEY=your-jwt-secret
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
```

#### **Cloud Provider Configuration**
```bash
# AWS
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_DEFAULT_REGION=us-east-1

# Azure
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret

# GCP
GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json
```

#### **Integration Configuration**
```bash
# Slack
SLACK_WEBHOOK_URL=your-webhook-url
SLACK_CHANNEL=#security

# Jira
JIRA_URL=your-jira-url
JIRA_USERNAME=your-username
JIRA_API_TOKEN=your-api-token

# ServiceNow
SERVICENOW_URL=your-servicenow-url
SERVICENOW_USERNAME=your-username
SERVICENOW_PASSWORD=your-password
```

### **Policy Configuration**

#### **OPA Policy Structure**
```rego
package aws.security_groups

import future.keywords.if
import future.keywords.in

deny[msg] {
    input.resource_type == "aws_security_group"
    rule := input.ingress_rules[_]
    rule.from_port == 22
    rule.to_port == 22
    rule.cidr_blocks[_] == "0.0.0.0/0"
    msg := sprintf("Security group %v allows SSH access from anywhere", [input.group_name])
}
```

#### **Custom Policy Templates**
```bash
# Create policy directory
mkdir -p policies/custom

# Add your custom policies
nano policies/custom/my_policy.rego

# Test policy syntax
opa check policies/custom/my_policy.rego
```

## 📖 Usage

### **Web Interface**

#### **Dashboard Overview**
1. Access the web interface at `http://localhost:3000`
2. Log in with your credentials
3. Navigate to the CSPM dashboard
4. View security posture overview and key metrics

#### **Asset Management**
1. Go to **Assets & Relationships** tab
2. View cloud asset inventory
3. Create asset relationships
4. Update asset tags and metadata
5. Review risk assessments

#### **Policy Management**
1. Navigate to **Policies & Evaluation** tab
2. Create new security policies
3. Evaluate policies against assets
4. Review evaluation results
5. Customize policy rules

#### **Compliance Management**
1. Access **Compliance** tab
2. Select compliance framework
3. Map controls to policies
4. Generate compliance reports
5. Track remediation progress

### **API Usage**

#### **Authentication**
```bash
# Login to get access token
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'

# Use token in subsequent requests
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8000/api/v1/cspm/assets"
```

#### **Asset Operations**
```bash
# Get all assets
GET /api/v1/cspm/assets

# Get asset details
GET /api/v1/cspm/assets/{asset_id}

# Create asset relationship
POST /api/v1/cspm/assets/{asset_id}/relationships

# Update asset tags
PATCH /api/v1/cspm/assets/{asset_id}
```

#### **Policy Operations**
```bash
# Get all policies
GET /api/v1/cspm/policies

# Evaluate policy on asset
POST /api/v1/cspm/policies/{policy_id}/evaluate?asset_id={asset_id}

# Get evaluation results
GET /api/v1/cspm/policies/{policy_id}/evaluation-results
```

### **Mobile App**

#### **Installation**
1. Build the mobile app: `cd mobile && npm run build`
2. Install on your device
3. Configure backend URL
4. Log in with your credentials

#### **Features**
- View security dashboard
- Monitor asset status
- Review findings
- Execute remediation tasks
- Receive security alerts

## 📚 API Documentation

### **OpenAPI Specification**

The complete API documentation is available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

### **API Endpoints**

#### **Authentication**
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/refresh` - Refresh token
- `POST /api/v1/auth/logout` - User logout

#### **Assets**
- `GET /api/v1/cspm/assets` - List assets
- `GET /api/v1/cspm/assets/{id}` - Get asset details
- `POST /api/v1/cspm/assets/{id}/relationships` - Create relationship
- `GET /api/v1/cspm/assets/{id}/relationships` - Get relationships

#### **Policies**
- `GET /api/v1/cspm/policies` - List policies
- `POST /api/v1/cspm/policies/{id}/evaluate` - Evaluate policy
- `GET /api/v1/cspm/policies/{id}/evaluation-results` - Get results

#### **Compliance**
- `GET /api/v1/cspm/compliance/frameworks` - List frameworks
- `POST /api/v1/cspm/compliance/controls` - Create control
- `GET /api/v1/cspm/compliance/frameworks/{id}/controls` - Get controls

#### **Remediation**
- `POST /api/v1/cspm/remediation/playbooks` - Create playbook
- `GET /api/v1/cspm/remediation/playbooks` - List playbooks
- `POST /api/v1/cspm/remediation/playbooks/{id}/execute` - Execute playbook

### **Data Models**

#### **Asset Model**
```json
{
  "id": "uuid",
  "name": "string",
  "resource_type": "string",
  "cloud": "string",
  "region": "string",
  "tags": {},
  "risk_score": 0.0,
  "compliance_score": 0.0,
  "metadata": {},
  "created_at": "datetime",
  "last_seen": "datetime"
}
```

#### **Policy Model**
```json
{
  "id": "uuid",
  "name": "string",
  "description": "string",
  "rule": {},
  "severity": "string",
  "category": "string",
  "framework": "string",
  "enabled": true,
  "created_at": "datetime"
}
```

## 🛡️ Security Features

### **Authentication & Authorization**

#### **Multi-Factor Authentication**
- TOTP-based MFA
- SMS-based MFA
- Hardware token support
- Backup codes

#### **Role-Based Access Control**
- **Admin**: Full system access
- **Security Analyst**: Security operations
- **Compliance Auditor**: Compliance management
- **Remediation Engineer**: Remediation tasks
- **Viewer**: Read-only access

#### **API Security**
- JWT token authentication
- Rate limiting
- Request validation
- CORS configuration
- Security headers

### **Data Protection**

#### **Encryption**
- Data encryption at rest (AES-256)
- Data encryption in transit (TLS 1.3)
- Key rotation policies
- Hardware security modules (HSM) support

#### **Access Control**
- Principle of least privilege
- Session management
- Audit logging
- Data anonymization

### **Compliance & Governance**

#### **Standards Compliance**
- SOC 2 Type II
- ISO 27001
- GDPR compliance
- HIPAA compliance
- PCI DSS compliance

#### **Audit & Logging**
- Comprehensive audit trails
- Immutable logs
- Log retention policies
- Compliance reporting

## 📊 Monitoring & Observability

### **Metrics Collection**

#### **Application Metrics**
- API response times
- Error rates
- Throughput
- Resource utilization

#### **Security Metrics**
- Policy evaluation times
- Finding counts by severity
- Compliance scores
- Remediation success rates

### **Dashboards**

#### **Grafana Dashboards**
- Security overview dashboard
- Compliance tracking dashboard
- Performance monitoring dashboard
- Custom dashboards

#### **Prometheus Metrics**
- System health metrics
- Business metrics
- Custom metrics
- Alert rules

### **Alerting**

#### **Alert Rules**
- High-risk findings
- Compliance violations
- System health issues
- Performance degradation

#### **Notification Channels**
- Email notifications
- Slack integration
- PagerDuty integration
- Webhook support

## 🔧 Troubleshooting

### **Common Issues**

#### **Database Connection Issues**
```bash
# Check PostgreSQL status
docker-compose -f docker-compose.cspm.yml ps postgres

# Check logs
docker-compose -f docker-compose.cspm.yml logs postgres

# Test connection
docker-compose -f docker-compose.cspm.yml exec postgres pg_isready
```

#### **Redis Connection Issues**
```bash
# Check Redis status
docker-compose -f docker-compose.cspm.yml ps redis

# Check logs
docker-compose -f docker-compose.cspm.yml logs redis

# Test connection
docker-compose -f docker-compose.cspm.yml exec redis redis-cli ping
```

#### **Backend API Issues**
```bash
# Check backend status
docker-compose -f docker-compose.cspm.yml ps backend

# Check logs
docker-compose -f docker-compose.cspm.yml logs backend

# Test health endpoint
curl http://localhost:8000/health
```

### **Log Analysis**

#### **Log Locations**
```bash
# Application logs
tail -f logs/app.log

# Database logs
docker-compose -f docker-compose.cspm.yml logs postgres

# Redis logs
docker-compose -f docker-compose.cspm.yml logs redis
```

#### **Log Levels**
- **DEBUG**: Detailed debugging information
- **INFO**: General information
- **WARNING**: Warning messages
- **ERROR**: Error messages
- **CRITICAL**: Critical errors

### **Performance Tuning**

#### **Database Optimization**
```sql
-- Check slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- Analyze table statistics
ANALYZE;

-- Vacuum tables
VACUUM ANALYZE;
```

#### **Redis Optimization**
```bash
# Check memory usage
redis-cli info memory

# Check key statistics
redis-cli info keyspace

# Monitor commands
redis-cli monitor
```

## 🤝 Contributing

### **Development Setup**

#### **Local Development**
```bash
# Clone repository
git clone <repository-url>
cd cyber-cursor

# Set up virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r backend/requirements.txt
cd frontend && npm install
cd ../mobile && npm install

# Set up database
docker-compose -f docker-compose.cspm.yml up -d postgres redis
alembic upgrade head

# Run development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### **Testing**
```bash
# Run backend tests
cd backend
pytest

# Run frontend tests
cd frontend
npm test

# Run integration tests
docker-compose -f docker-compose.cspm.yml up -d
pytest tests/integration/
```

### **Code Standards**

#### **Python**
- Follow PEP 8 style guide
- Use type hints
- Write docstrings
- Maintain 90%+ test coverage

#### **JavaScript/TypeScript**
- Use ESLint configuration
- Follow Prettier formatting
- Write unit tests
- Use TypeScript strict mode

### **Pull Request Process**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Update documentation
6. Submit pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Open Policy Agent (OPA)** for policy evaluation
- **FastAPI** for high-performance API framework
- **React** for modern frontend development
- **PostgreSQL** for reliable database storage
- **Docker** for containerization
- **Prometheus & Grafana** for monitoring

## 📞 Support

### **Getting Help**

- **Documentation**: [Wiki](https://github.com/your-repo/wiki)
- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/discussions)
- **Email**: support@cybershield.com

### **Community**

- **Slack**: [Join our Slack](https://cybershield.slack.com)
- **Discord**: [Join our Discord](https://discord.gg/cybershield)
- **Twitter**: [@CyberShield](https://twitter.com/CyberShield)

---

**Made with ❤️ by the CyberShield Team**

*Building the future of cloud security, one policy at a time.*
