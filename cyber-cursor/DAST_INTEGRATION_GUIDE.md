# DAST Integration Guide

## Overview

This guide provides comprehensive documentation for the Dynamic Application Security Testing (DAST) integration into the CyberShield platform. The DAST module includes a modern React Native frontend and PostgreSQL backend with full separation of concerns, maintainability, and scalability.

## Architecture

### Backend Components

#### 1. Database Models (`backend/app/models/dast.py`)
- **DASTProject**: Project management with authentication and scan configuration
- **DASTScan**: Scan execution and monitoring
- **DASTVulnerability**: Vulnerability discovery and management
- **DASTPayload**: Payload library for different attack vectors
- **DASTReport**: Report generation and management
- **DASTSession**: Session management for authenticated scans

#### 2. Services (`backend/app/services/`)
- **dast_service.py**: Core DAST business logic
- **dast_scanner.py**: Dynamic scanning engine
- **dast_payloads.py**: Payload library management

#### 3. API Endpoints (`backend/app/api/v1/endpoints/dast.py`)
- Project management (CRUD operations)
- Scan orchestration and monitoring
- Vulnerability analysis and reporting
- Payload management
- CI/CD integration

### Frontend Components

#### 1. React Native Components (`frontend/src/components/DAST/`)
- **DASTDashboard.tsx**: Overview dashboard with statistics and quick actions
- **DASTProjects.tsx**: Project management with create/edit/delete functionality
- **DASTScans.tsx**: Scan monitoring and management
- **DASTVulnerabilities.tsx**: Vulnerability viewing and filtering

## Features

### 1. Project Management
- Create and configure DAST projects
- Set target URLs and authentication
- Configure scan parameters
- Track project statistics

### 2. Dynamic Scanning
- Multiple scan types (Full, Passive, Active, Custom)
- Real-time scan monitoring
- Background scan execution
- Scan status tracking

### 3. Vulnerability Management
- Comprehensive vulnerability detection
- Severity classification (Critical, High, Medium, Low, Info)
- Vulnerability filtering and search
- Detailed vulnerability information
- Remediation guidance

### 4. Authentication Support
- No authentication
- Basic authentication
- Cookie-based authentication
- JWT token authentication
- OAuth2 integration
- API key authentication

### 5. Payload Library
- SQL Injection payloads
- Cross-Site Scripting (XSS) payloads
- Command Injection payloads
- Path Traversal payloads
- SSRF payloads
- Custom payload creation

## API Endpoints

### Projects
```
GET    /api/v1/dast/projects          # List all projects
POST   /api/v1/dast/projects          # Create new project
GET    /api/v1/dast/projects/{id}     # Get project details
PUT    /api/v1/dast/projects/{id}     # Update project
DELETE /api/v1/dast/projects/{id}     # Delete project
```

### Scans
```
GET    /api/v1/dast/scans             # List all scans
POST   /api/v1/dast/scans             # Create new scan
GET    /api/v1/dast/scans/{id}        # Get scan details
POST   /api/v1/dast/scans/{id}/stop   # Stop running scan
```

### Vulnerabilities
```
GET    /api/v1/dast/vulnerabilities   # List vulnerabilities
GET    /api/v1/dast/scans/{id}/vulnerabilities  # Get scan vulnerabilities
```

### Reports
```
GET    /api/v1/dast/reports/{scan_id} # Generate scan report
```

## Database Schema

### DAST Projects Table
```sql
CREATE TABLE dast_projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    target_url TEXT NOT NULL,
    description TEXT,
    auth_type VARCHAR(20) DEFAULT 'none',
    auth_config JSONB,
    scan_config JSONB,
    scope_config JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    tags JSONB,
    total_scans INTEGER DEFAULT 0,
    total_vulnerabilities INTEGER DEFAULT 0,
    security_score FLOAT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_scan TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);
```

### DAST Scans Table
```sql
CREATE TABLE dast_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES dast_projects(id),
    scan_type VARCHAR(20) NOT NULL DEFAULT 'full',
    status VARCHAR(20) DEFAULT 'queued',
    scan_config JSONB,
    auth_config JSONB,
    vulnerabilities_found INTEGER DEFAULT 0,
    urls_scanned INTEGER DEFAULT 0,
    requests_made INTEGER DEFAULT 0,
    scan_duration FLOAT,
    scan_logs JSONB,
    scan_summary JSONB,
    evidence_files JSONB,
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    initiated_by INTEGER REFERENCES users(id)
);
```

### DAST Vulnerabilities Table
```sql
CREATE TABLE dast_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES dast_scans(id),
    project_id UUID REFERENCES dast_projects(id),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) DEFAULT 'open',
    url TEXT NOT NULL,
    http_method VARCHAR(10) NOT NULL,
    param_name VARCHAR(100),
    param_value TEXT,
    cwe_id VARCHAR(20),
    owasp_category VARCHAR(100),
    vuln_type VARCHAR(50),
    payload TEXT,
    evidence JSONB,
    proof_of_concept TEXT,
    response_code INTEGER,
    response_time FLOAT,
    response_size INTEGER,
    tags JSONB,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    fixed_at TIMESTAMP
);
```

## Setup Instructions

### 1. Database Setup
```bash
# Run database migrations
psql -d cybershield -f scripts/init-dast-db.sql
```

### 2. Backend Setup
```bash
# Install dependencies
cd backend
pip install -r requirements.txt

# Start the backend
python main.py
```

### 3. Frontend Setup
```bash
# Install dependencies
cd frontend
npm install

# Start the frontend
npm start
```

### 4. Docker Setup
```bash
# Start all services
docker-compose up -d
```

## Usage Examples

### Creating a DAST Project
```javascript
const projectData = {
  name: "E-commerce Website",
  target_url: "https://example.com",
  description: "Security testing for e-commerce application",
  auth_type: "none",
  scan_config: {
    scan_type: "full",
    max_depth: 3,
    timeout: 30
  }
};

const response = await fetch('/api/v1/dast/projects', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify(projectData)
});
```

### Starting a DAST Scan
```javascript
const scanData = {
  project_id: "project-uuid",
  scan_type: "full",
  scan_config: {
    max_depth: 3,
    timeout: 30
  }
};

const response = await fetch('/api/v1/dast/scans', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify(scanData)
});
```

### Getting Vulnerabilities
```javascript
const response = await fetch('/api/v1/dast/vulnerabilities?severity=critical', {
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
});

const vulnerabilities = await response.json();
```

## Security Features

### 1. Input Validation
- All user inputs are validated using Pydantic schemas
- SQL injection prevention through parameterized queries
- XSS prevention through proper encoding

### 2. Authentication & Authorization
- JWT token-based authentication
- Role-based access control
- API key management for external integrations

### 3. Data Protection
- Sensitive data encryption
- Audit logging for all operations
- Secure session management

### 4. Rate Limiting
- API rate limiting to prevent abuse
- Scan throttling to avoid overwhelming targets
- Concurrent scan limits

## Monitoring & Logging

### 1. Application Logs
```python
import logging

logger = logging.getLogger(__name__)
logger.info("DAST scan started", scan_id=scan_id, project_id=project_id)
logger.error("Scan failed", error=str(error), scan_id=scan_id)
```

### 2. Metrics Collection
- Scan duration tracking
- Vulnerability discovery rates
- Performance metrics
- Error rates and types

### 3. Health Checks
```bash
# Check DAST service health
curl http://localhost:8000/api/v1/dast/health
```

## Troubleshooting

### Common Issues

#### 1. Scan Not Starting
- Check project configuration
- Verify target URL accessibility
- Review authentication settings
- Check scan logs for errors

#### 2. No Vulnerabilities Found
- Verify scan configuration
- Check target application accessibility
- Review payload library
- Enable debug logging

#### 3. Performance Issues
- Adjust scan timeouts
- Reduce concurrent scans
- Optimize payload library
- Review network configuration

### Debug Mode
```python
# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Enable detailed scan logging
scan_config = {
    "debug": True,
    "verbose_logging": True
}
```

## Best Practices

### 1. Scan Configuration
- Start with passive scans for reconnaissance
- Use appropriate scan depths for target size
- Set reasonable timeouts
- Configure authentication properly

### 2. Vulnerability Management
- Regularly review and update payload library
- Implement proper vulnerability triage process
- Track remediation progress
- Generate regular reports

### 3. Security Considerations
- Only scan authorized targets
- Respect robots.txt and rate limits
- Secure sensitive scan data
- Implement proper access controls

### 4. Performance Optimization
- Use background tasks for long-running scans
- Implement scan result caching
- Optimize database queries
- Monitor resource usage

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: DAST Security Scan
on: [push, pull_request]

jobs:
  dast-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run DAST Scan
        run: |
          curl -X POST http://localhost:8000/api/v1/dast/scans \
            -H "Authorization: Bearer ${{ secrets.DAST_TOKEN }}" \
            -H "Content-Type: application/json" \
            -d '{"project_id": "${{ secrets.PROJECT_ID }}", "scan_type": "full"}'
      
      - name: Check Scan Results
        run: |
          curl -X GET http://localhost:8000/api/v1/dast/vulnerabilities?severity=critical \
            -H "Authorization: Bearer ${{ secrets.DAST_TOKEN }}"
```

## API Documentation

Complete API documentation is available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Support

For technical support and questions:
- Check the troubleshooting section
- Review application logs
- Contact the development team
- Submit issues through the project repository

## Contributing

To contribute to the DAST module:
1. Follow the coding standards
2. Add comprehensive tests
3. Update documentation
4. Submit pull requests

## License

This DAST integration is part of the CyberShield platform and follows the same licensing terms. 