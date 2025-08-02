# Application Security Module Documentation

## Overview

The Application Security module provides comprehensive security analysis and monitoring capabilities through three main security testing approaches:

1. **Static Application Security Testing (SAST)** - Code analysis for vulnerabilities
2. **Dynamic Application Security Testing (DAST)** - Runtime vulnerability scanning
3. **Runtime Application Self-Protection (RASP)** - Real-time threat monitoring and blocking

## Architecture

### Tech Stack
- **Frontend**: React with TypeScript, Enhanced UI components
- **Backend**: FastAPI (Python) with structured logging
- **Database**: PostgreSQL for persistent storage
- **Cache**: Redis for session management
- **Deployment**: Docker containers for scalability

### Flow Diagram
```
User (Admin/DevSecOps) → React UI → FastAPI Backend → Security Tools API/CLI → PostgreSQL → UI Reports
```

## Features

### 1. Static Application Security Testing (SAST)

**Objective**: Detect vulnerabilities in source code before deployment

**Tools Integration**:
- SonarQube (Recommended for CI/CD integration)
- Checkmarx
- Veracode

**Capabilities**:
- Automated code scanning on commits/upload
- Vulnerability detection with severity classification
- Detailed remediation recommendations
- Integration with CI/CD pipelines

**Sample Vulnerabilities Detected**:
- SQL Injection vulnerabilities
- Cross-Site Scripting (XSS)
- Hardcoded credentials
- Insecure authentication
- Input validation issues

### 2. Dynamic Application Security Testing (DAST)

**Objective**: Detect vulnerabilities during runtime by scanning running applications

**Tools Integration**:
- OWASP ZAP (Recommended for open-source automation)
- Burp Suite
- Acunetix

**Capabilities**:
- Automated web application scanning
- Authentication bypass detection
- Session management testing
- API security testing
- Cross-site scripting detection

**Scan Types**:
- Crawl and audit scans
- API endpoint testing
- Authentication testing
- Custom scan configurations

### 3. Runtime Application Self-Protection (RASP)

**Objective**: Monitor and protect applications in real-time against attacks

**Tools Integration**:
- Contrast Security (API + agent integration)
- Imperva RASP
- Signal Sciences

**Capabilities**:
- Real-time threat detection and blocking
- Attack vector identification
- Incident logging and alerting
- Automatic response actions
- Performance monitoring

**Protection Features**:
- SQL Injection prevention
- XSS attack blocking
- Brute force attack detection
- API abuse prevention
- Zero-day attack detection

## API Endpoints

### Security Summary
```http
GET /api/v1/security/summary
Authorization: Bearer <token>
```

**Response**:
```json
{
  "sast_critical": 1,
  "sast_high": 1,
  "sast_medium": 1,
  "sast_low": 0,
  "dast_critical": 1,
  "dast_high": 1,
  "dast_medium": 1,
  "dast_low": 0,
  "rasp_blocked": 2,
  "rasp_incidents": 3
}
```

### SAST Operations

#### Get SAST Results
```http
GET /api/v1/security/sast/results
Authorization: Bearer <token>
```

#### Trigger SAST Scan
```http
POST /api/v1/security/sast/scan
Authorization: Bearer <token>
```

**Response**:
```json
{
  "message": "SAST scan triggered successfully",
  "scan_id": "sast_scan_123",
  "estimated_duration": "5-10 minutes"
}
```

### DAST Operations

#### Get DAST Results
```http
GET /api/v1/security/dast/results
Authorization: Bearer <token>
```

#### Trigger DAST Scan
```http
POST /api/v1/security/dast/scan
Authorization: Bearer <token>
```

**Response**:
```json
{
  "message": "DAST scan triggered successfully",
  "scan_id": "dast_scan_456",
  "estimated_duration": "15-30 minutes"
}
```

### RASP Operations

#### Get RASP Logs
```http
GET /api/v1/security/rasp/logs
Authorization: Bearer <token>
```

#### Get RASP Status
```http
GET /api/v1/security/rasp/status
Authorization: Bearer <token>
```

**Response**:
```json
{
  "status": "active",
  "protection_enabled": true,
  "threats_blocked_today": 15,
  "active_rules": 25,
  "last_incident": "2024-01-15T12:40:00Z"
}
```

## Database Schema

### SAST Results Table
```sql
CREATE TABLE sast_results (
    id SERIAL PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    scan_date TIMESTAMP NOT NULL,
    line_number INTEGER,
    rule_id VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### DAST Results Table
```sql
CREATE TABLE dast_results (
    id SERIAL PRIMARY KEY,
    url VARCHAR(500) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    vulnerability_type VARCHAR(100) NOT NULL,
    recommendation TEXT NOT NULL,
    scan_date TIMESTAMP NOT NULL,
    status VARCHAR(50) NOT NULL,
    cwe_id VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### RASP Logs Table
```sql
CREATE TABLE rasp_logs (
    id SERIAL PRIMARY KEY,
    incident_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    blocked BOOLEAN NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    source_ip INET,
    attack_vector VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Frontend Components

### Application Security Page
- **Location**: `/application-security`
- **Access**: Protected route (requires authentication)
- **Features**:
  - Overview dashboard with summary cards
  - Tabbed interface for SAST, DAST, and RASP
  - Real-time scan triggering
  - Detailed vulnerability reports
  - Export functionality

### Key Components

#### Security Summary Cards
- SAST Analysis summary with severity breakdown
- DAST Analysis summary with vulnerability counts
- RASP Protection status and metrics
- Quick action buttons for scan triggering

#### SAST Results View
- File-based vulnerability listing
- Severity classification with color coding
- Line number and rule ID information
- Detailed recommendations
- Scan history and timestamps

#### DAST Results View
- URL-based vulnerability listing
- CWE ID references
- Status tracking (open, resolved, false positive)
- Remediation guidance
- Scan configuration options

#### RASP Monitoring View
- Real-time incident logs
- Attack vector classification
- Blocking status indicators
- Source IP tracking
- Timeline visualization

## Usage Instructions

### Accessing the Module

1. **Login** to the CyberShield platform
2. **Navigate** to "Application Security" in the left sidebar
3. **View** the overview dashboard for security summary

### Running Security Scans

#### SAST Scan
1. Go to the **SAST Results** tab
2. Click **"New Scan"** button
3. Configure scan parameters (optional)
4. Monitor scan progress
5. Review results when complete

#### DAST Scan
1. Go to the **DAST Results** tab
2. Click **"New Scan"** button
3. Enter target URL(s)
4. Configure scan depth and options
5. Monitor scan progress
6. Review vulnerability findings

### Monitoring RASP Protection

1. Go to the **RASP Monitoring** tab
2. View real-time incident logs
3. Monitor blocked threats
4. Review attack patterns
5. Configure protection rules

### Exporting Reports

1. Click **"Export Report"** button in the header
2. Select report format (PDF/CSV)
3. Choose date range and content
4. Download generated report

## Security Considerations

### Access Control
- Role-based access (Admin/DevSecOps only)
- JWT token authentication
- Session management
- API rate limiting

### Data Protection
- Encrypted data transmission (HTTPS)
- Secure API communication
- Sensitive data encryption
- Audit logging

### Integration Security
- Secure tool API credentials
- Network isolation for scanning
- Input validation and sanitization
- Output encoding

## Configuration

### Environment Variables
```bash
# Security Tool Integration
SAST_TOOL_URL=https://sonarqube.company.com
SAST_API_TOKEN=your_sast_token
DAST_TOOL_URL=https://zap.company.com
DAST_API_KEY=your_dast_key
RASP_TOOL_URL=https://contrast.company.com
RASP_API_KEY=your_rasp_key

# Database Configuration
DATABASE_URL=postgresql://user:pass@localhost/cybershield
REDIS_URL=redis://localhost:6379

# Security Settings
SECRET_KEY=your-super-secret-key
ALLOWED_ORIGINS=http://localhost:3000
```

### Scan Configuration
```json
{
  "sast": {
    "scan_depth": "full",
    "exclude_patterns": ["node_modules", "vendor"],
    "severity_threshold": "medium"
  },
  "dast": {
    "scan_type": "crawl_and_audit",
    "max_depth": 5,
    "exclude_urls": ["/admin", "/api/internal"]
  },
  "rasp": {
    "protection_mode": "block",
    "learning_mode": false,
    "alert_threshold": "high"
  }
}
```

## Troubleshooting

### Common Issues

#### Scan Failures
- **Issue**: SAST/DAST scans failing
- **Solution**: Check tool connectivity and API credentials
- **Debug**: Review backend logs for error details

#### Performance Issues
- **Issue**: Slow scan execution
- **Solution**: Optimize scan configuration and resource allocation
- **Debug**: Monitor system resources during scans

#### Authentication Errors
- **Issue**: API authentication failures
- **Solution**: Verify JWT tokens and user permissions
- **Debug**: Check authentication logs

### Log Locations
- **Backend Logs**: `/app/logs/` in container
- **Frontend Logs**: Browser developer console
- **Database Logs**: PostgreSQL container logs
- **Tool Logs**: Individual security tool logs

## Future Enhancements

### Planned Features
- **SCA Integration**: Software Composition Analysis
- **Container Security**: Docker image scanning
- **Infrastructure as Code**: IaC security scanning
- **Compliance Reporting**: SOC2, PCI-DSS, ISO27001
- **Advanced Analytics**: ML-powered threat detection
- **Integration Hub**: Third-party tool connectors

### Roadmap
- **Q1 2024**: SCA and container security
- **Q2 2024**: Compliance reporting and analytics
- **Q3 2024**: Advanced threat detection
- **Q4 2024**: Integration hub and automation

## Support

### Documentation
- API Documentation: `http://localhost:8000/docs`
- Swagger UI: `http://localhost:8000/redoc`
- Component Library: In-app design system

### Contact
- **Technical Support**: security-support@company.com
- **Bug Reports**: github.com/company/cybershield/issues
- **Feature Requests**: github.com/company/cybershield/discussions

---

*This documentation is part of the CyberShield Application Security module. For the latest updates, please refer to the official repository.* 