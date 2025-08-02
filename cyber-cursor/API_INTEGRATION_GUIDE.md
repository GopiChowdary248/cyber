# CyberShield API Integration Guide

## Overview

This guide provides comprehensive documentation for all integrated API components in the CyberShield cybersecurity platform. The application now includes **24 different API modules** covering all aspects of cybersecurity management.

## 🚀 Quick Start

### Base URL
```
http://localhost:8000
```

### API Documentation
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 📋 Integrated API Components

### 1. Authentication & Authorization
**Base Path**: `/api/v1/auth`
- User login/logout
- Token management
- Password reset
- Session management

### 2. User Management
**Base Path**: `/api/v1/users`
- User CRUD operations
- Role management
- Permission management
- User profiles

### 3. Administration
**Base Path**: `/api/v1/admin`
- System configuration
- User administration
- Audit logs
- System monitoring

### 4. Dashboard & Analytics
**Base Path**: `/api/v1/dashboard`
- Security metrics
- Performance analytics
- Custom dashboards
- Real-time monitoring

### 5. Health Monitoring
**Base Path**: `/api/v1/health`
- System health checks
- Service status
- Performance metrics
- Dependency monitoring

### 6. Security Management
**Base Path**: `/api/v1/security`
- Security policies
- Access control
- Security configurations
- Risk assessment

### 7. Incident Management
**Base Path**: `/api/v1/incidents`
- Incident creation/tracking
- Incident response
- Escalation procedures
- Resolution workflows

### 8. Threat Intelligence
**Base Path**: `/api/v1/threat-intelligence`
- Threat feeds
- IOC management
- Threat analysis
- Intelligence sharing

### 9. Monitoring & SIEM
**Base Path**: `/api/v1/monitoring`
- Log collection
- Event correlation
- Alert management
- SIEM integration

### 10. Data Protection
**Base Path**: `/api/v1/data-protection`
- Data classification
- Encryption management
- Privacy compliance
- Data loss prevention

### 11. Application Security
**Base Path**: `/api/v1/application-security`
- SAST/DAST integration
- Code analysis
- Vulnerability scanning
- Security testing

### 12. Endpoint Security
**Base Path**: `/api/v1/endpoint-security`
- Endpoint protection
- Device management
- Malware detection
- Endpoint monitoring

### 13. Network Security
**Base Path**: `/api/v1/network-security`
- Firewall management
- Network monitoring
- Traffic analysis
- Network segmentation

### 14. Compliance Management
**Base Path**: `/api/v1/compliance`
- Compliance frameworks
- Audit management
- Policy enforcement
- Regulatory reporting

### 15. AI & Machine Learning
**Base Path**: `/api/v1/ai-ml`
- AI-powered threat detection
- Machine learning models
- Predictive analytics
- Behavioral analysis

### 16. Third-party Integrations
**Base Path**: `/api/v1/integrations`
- External tool integration
- API connectors
- Data synchronization
- Workflow automation

### 17. Multi-Factor Authentication
**Base Path**: `/api/v1/mfa`
- MFA setup/management
- Authentication methods
- Security tokens
- Biometric integration

### 18. Phishing Detection
**Base Path**: `/api/v1/phishing`
- Phishing detection
- Email security
- URL analysis
- Threat prevention

### 19. Cloud Security
**Base Path**: `/api/v1/cloud-security`
- Cloud infrastructure security
- Cloud compliance
- Cloud monitoring
- Multi-cloud management

### 20. Workflow Management
**Base Path**: `/api/v1/workflows`
- Security workflows
- Process automation
- Approval workflows
- Task management

### 21. Analytics
**Base Path**: `/api/v1/analytics`
- Security analytics
- Performance metrics
- Trend analysis
- Reporting

### 22. WebSocket Real-time Updates
**Base Path**: `/api/v1/websocket`
- Real-time notifications
- Live monitoring
- Event streaming
- Instant updates

### 23. SAST Code Analysis
**Base Path**: `/api/v1/sast`
- Static code analysis
- Vulnerability scanning
- Code quality assessment
- Security recommendations

## 🔧 API Usage Examples

### Authentication
```bash
# Login
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@cybershield.com&password=password"

# Get current user
curl -X GET "http://localhost:8000/api/v1/auth/me" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Security Metrics
```bash
# Get security metrics
curl -X GET "http://localhost:8000/api/v1/security/metrics" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Incident Management
```bash
# Get all incidents
curl -X GET "http://localhost:8000/api/v1/incidents" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Create new incident
curl -X POST "http://localhost:8000/api/v1/incidents" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Security Breach Detected",
    "description": "Unauthorized access attempt",
    "severity": "high",
    "category": "unauthorized_access"
  }'
```

### SAST Analysis
```bash
# Upload code for analysis
curl -X POST "http://localhost:8000/api/v1/sast/upload" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@your_code.zip"

# Get scan results
curl -X GET "http://localhost:8000/api/v1/sast/results" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 🔐 Authentication

The API uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:

```
Authorization: Bearer YOUR_JWT_TOKEN
```

### Mock Credentials (for testing)
- **Admin**: admin@cybershield.com / password
- **Analyst**: analyst@cybershield.com / password
- **User**: user@cybershield.com / password

## 📊 Response Formats

### Success Response
```json
{
  "status": "success",
  "data": {...},
  "message": "Operation completed successfully"
}
```

### Error Response
```json
{
  "status": "error",
  "error": {
    "code": "ERROR_CODE",
    "message": "Error description",
    "details": {...}
  }
}
```

## 🚀 Deployment

### Using Docker
```bash
# Build and run with all components
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f backend
```

### Manual Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Run the integrated API
python main_integrated.py
```

## 🔍 Testing

### Health Check
```bash
curl http://localhost:8000/health
```

### API Root
```bash
curl http://localhost:8000/
```

### Swagger Documentation
Visit http://localhost:8000/docs for interactive API documentation.

## 📈 Monitoring

### Key Metrics
- API response times
- Error rates
- Request volume
- System resource usage

### Logs
- Application logs: `logs/app.log`
- Access logs: `logs/access.log`
- Error logs: `logs/error.log`

## 🔧 Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=postgresql+asyncpg://user:pass@localhost/db

# Redis
REDIS_URL=redis://localhost:6379

# Security
SECRET_KEY=your-secret-key
DEBUG=false

# CORS
ALLOWED_ORIGINS=["http://localhost:3000"]
```

## 🛠️ Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check PostgreSQL is running
   - Verify connection string
   - Check network connectivity

2. **Authentication Errors**
   - Verify JWT token is valid
   - Check token expiration
   - Ensure proper Authorization header

3. **CORS Issues**
   - Check ALLOWED_ORIGINS configuration
   - Verify frontend URL is included
   - Check browser console for errors

### Debug Mode
Set `DEBUG=true` in environment variables for detailed error messages.

## 📚 Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Pydantic Documentation](https://pydantic-docs.helpmanual.io/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [JWT Documentation](https://jwt.io/)

## 🤝 Support

For technical support or questions about the API integration:
- Check the logs for error details
- Review the Swagger documentation
- Test endpoints individually
- Verify all dependencies are installed

---

**Version**: 2.0.0  
**Last Updated**: August 2024  
**Status**: Production Ready 