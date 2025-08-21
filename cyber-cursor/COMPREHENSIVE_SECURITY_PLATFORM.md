# Cyber Cursor Security Platform

## 🚀 Overview

Cyber Cursor is a comprehensive security testing and management platform that provides enterprise-grade security tools for modern organizations. The platform integrates multiple security disciplines into a unified interface, enabling security teams to manage, monitor, and respond to security threats effectively.

## 🏗️ Architecture

The platform is built with a modern, scalable architecture:

- **Backend**: FastAPI-based Python API with PostgreSQL database
- **Frontend**: React-based web application with TypeScript
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Real-time**: WebSocket support for live updates
- **Authentication**: JWT-based security with role-based access control
- **Containerization**: Docker support for easy deployment

## 🔒 Security Modules

### 1. DAST (Dynamic Application Security Testing)
**Endpoint**: `/api/v1/dast`

**Features**:
- Web application vulnerability scanning
- Crawler for site mapping
- Proxy for traffic interception
- Intruder for automated testing
- Repeater for manual request manipulation
- Match/Replace rules for traffic modification

**Use Cases**:
- Web application security testing
- API security assessment
- Penetration testing
- Security research and development

### 2. SAST (Static Application Security Testing)
**Endpoint**: `/api/v1/sast`

**Features**:
- Source code analysis
- Vulnerability detection
- Quality metrics
- Security rules engine
- Compliance checking

**Use Cases**:
- Code review automation
- Security code analysis
- Quality assurance
- Compliance validation

### 3. RASP (Runtime Application Self-Protection)
**Endpoint**: `/api/v1/rasp`

**Features**:
- Runtime protection
- Behavior monitoring
- Attack prevention
- Real-time detection
- Response automation

**Use Cases**:
- Production application protection
- Zero-day attack prevention
- Behavioral analysis
- Automated response

### 4. Cloud Security
**Endpoint**: `/api/v1/cloud-security`

**Features**:
- Multi-cloud support (AWS, Azure, GCP)
- Kubernetes security
- Container security
- Infrastructure as Code security
- Compliance monitoring

**Use Cases**:
- Cloud security posture management
- Container security assessment
- Infrastructure security validation
- Multi-cloud governance

### 5. Endpoint Security
**Endpoint**: `/api/v1/endpoint-security`

**Features**:
- Device control
- Threat detection
- Response automation
- Policy management
- Compliance monitoring

**Use Cases**:
- Endpoint protection
- Device management
- Threat response
- Policy enforcement

### 6. Network Security
**Endpoint**: `/api/v1/network-security`

**Features**:
- Traffic analysis
- Firewall management
- IDS/IPS
- Network monitoring
- Threat detection

**Use Cases**:
- Network security monitoring
- Traffic analysis
- Intrusion detection
- Security event correlation

### 7. IAM (Identity and Access Management)
**Endpoint**: `/api/v1/iam`

**Features**:
- User management
- Role-based access control
- Multi-factor authentication
- Single sign-on
- Policy management

**Use Cases**:
- User access management
- Identity governance
- Access control
- Compliance management

### 8. Data Security
**Endpoint**: `/api/v1/data-security`

**Features**:
- Data encryption
- Data loss prevention
- Privacy management
- Classification
- Compliance

**Use Cases**:
- Data protection
- Privacy compliance
- Encryption management
- Data governance

### 9. Incident Management
**Endpoint**: `/api/v1/incidents`

**Features**:
- Incident detection
- Response automation
- Remediation tracking
- Workflow management
- Reporting

**Use Cases**:
- Security incident response
- Threat management
- Response coordination
- Incident tracking

### 10. Threat Intelligence
**Endpoint**: `/api/v1/threat-intelligence`

**Features**:
- IOC management
- Threat feeds
- Analysis tools
- Sharing capabilities
- Automation

**Use Cases**:
- Threat intelligence gathering
- IOC analysis
- Threat sharing
- Intelligence automation

### 11. Compliance
**Endpoint**: `/api/v1/compliance`

**Features**:
- Framework support (ISO27001, SOC2, PCI-DSS, GDPR, HIPAA, NIST, OWASP)
- Audit management
- Reporting tools
- Gap analysis
- Remediation tracking

**Use Cases**:
- Compliance management
- Audit preparation
- Regulatory reporting
- Gap assessment

### 12. DevSecOps
**Endpoint**: `/api/v1/devsecops`

**Features**:
- CI/CD security
- Container security
- Infrastructure as Code security
- Pipeline security
- Automation

**Use Cases**:
- Secure development pipeline
- Container security
- Infrastructure security
- Automation security

### 13. AI/ML
**Endpoint**: `/api/v1/ai-ml`

**Features**:
- Anomaly detection
- Predictive analytics
- Automation
- Pattern recognition
- Threat prediction

**Use Cases**:
- Security analytics
- Threat prediction
- Anomaly detection
- Automated response

### 14. Administration
**Endpoint**: `/api/v1/admin`

**Features**:
- System administration
- User management
- Configuration management
- Monitoring
- Maintenance

**Use Cases**:
- System administration
- User management
- Configuration control
- System monitoring

### 15. User Management
**Endpoint**: `/api/v1/users`

**Features**:
- User registration
- Profile management
- Role assignment
- Access control
- Account recovery

**Use Cases**:
- User administration
- Access management
- Profile management
- Account management

### 16. Audit & Logging
**Endpoint**: `/api/v1/audit`

**Features**:
- Activity logging
- Security events
- Compliance auditing
- Log retention
- Real-time monitoring

**Use Cases**:
- Security auditing
- Compliance logging
- Activity monitoring
- Event correlation

### 17. Reporting & Analytics
**Endpoint**: `/api/v1/reporting`

**Features**:
- Security reports
- Compliance reports
- Analytics dashboard
- Custom reports
- Scheduled reports

**Use Cases**:
- Security reporting
- Compliance reporting
- Analytics
- Executive reporting

### 18. Integrations
**Endpoint**: `/api/v1/integrations`

**Features**:
- SIEM integration
- Ticketing systems
- Cloud providers
- Security tools
- API connectors

**Use Cases**:
- Tool integration
- Workflow automation
- Data sharing
- Process integration

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- PostgreSQL 12+
- Node.js 16+
- Docker (optional)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cyber-cursor
   ```

2. **Set up the database**
   ```bash
   docker-compose up -d postgres
   ```

3. **Install backend dependencies**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

4. **Install frontend dependencies**
   ```bash
   cd ../frontend
   npm install
   ```

5. **Start the services**
   ```bash
   # Start backend
   cd ../backend
   python main.py
   
   # Start frontend (in another terminal)
   cd ../frontend
   npm start
   ```

### Quick Start Scripts

- **Windows**: `start.bat`
- **Linux/Mac**: `start.sh`

## 📊 API Documentation

Once the backend is running, you can access:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

## 🔐 Authentication

The platform uses JWT-based authentication. All API endpoints (except health and root) require authentication.

**Headers**:
```
Authorization: Bearer <your-jwt-token>
```

## 🧪 Testing

### Backend Testing
```bash
cd backend
python test_comprehensive_backend.py
```

### Frontend Testing
```bash
cd frontend
npm test
```

## 📈 Monitoring

### Health Checks
- **Health Endpoint**: `GET /health`
- **API Status**: `GET /api/status`

### Metrics
- Prometheus metrics available at `/metrics`
- Custom security metrics
- Performance monitoring

## 🔧 Configuration

### Environment Variables
Create a `.env` file in the backend directory:

```env
# Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/cyber_cursor

# Security
SECRET_KEY=your-secret-key-here
ALGORITHM=HS256

# Server
HOST=0.0.0.0
PORT=8000
DEBUG=false

# External APIs
OPENAI_API_KEY=your-openai-key
VIRUSTOTAL_API_KEY=your-virustotal-key
```

### Database Configuration
The platform supports:
- PostgreSQL (recommended for production)
- SQLite (development only)

## 🚀 Deployment

### Docker Deployment
```bash
docker-compose up -d
```

### Production Deployment
1. Set `ENVIRONMENT=production`
2. Configure production database
3. Set up reverse proxy (nginx)
4. Configure SSL certificates
5. Set up monitoring and logging

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Documentation**: Check the `/docs` endpoint
- **Issues**: Create an issue on GitHub
- **Discussions**: Use GitHub Discussions

## 🔮 Roadmap

### Phase 1 (Completed)
- ✅ Core security modules
- ✅ Basic API endpoints
- ✅ Authentication system
- ✅ Database models

### Phase 2 (In Progress)
- 🔄 Advanced scanning capabilities
- 🔄 Real-time monitoring
- 🔄 Advanced reporting
- 🔄 Integration framework

### Phase 3 (Planned)
- 📋 AI-powered threat detection
- 📋 Advanced automation
- 📋 Machine learning models
- 📋 Advanced analytics

---

**Cyber Cursor Security Platform** - Empowering security teams with comprehensive tools for modern threat landscape.
