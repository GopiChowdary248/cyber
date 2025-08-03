# DAST (Dynamic Application Security Testing) Implementation

## Overview

This comprehensive DAST implementation provides a complete dynamic application security testing solution that combines the best features of OWASP ZAP and Burp Suite. The system is designed to detect OWASP Top 10 vulnerabilities, security misconfigurations, and logic flaws in web applications and APIs.

## Features

### Core Functionality
- **Spider & Crawler**: Discovers URLs, forms, and JavaScript-generated endpoints
- **Passive Scanner**: Analyzes traffic for security headers, information disclosure, and misconfigurations
- **Active Scanner**: Injects payloads to detect SQL injection, XSS, command injection, and more
- **Authentication Support**: Handles JWT, OAuth2, session cookies, and API keys
- **WebSocket & API Scanning**: Supports modern web technologies and API testing
- **Real-time Dashboard**: Web-based interface for scan management and results
- **CI/CD Integration**: Webhook support for automated scanning in pipelines

### Advanced Features
- **Comprehensive Payload Library**: 50+ payloads covering OWASP Top 10
- **Multi-threaded Scanning**: High-performance scanning with configurable concurrency
- **Custom Payload Support**: Add and manage custom payloads
- **Report Generation**: Multiple formats (JSON, PDF, HTML, CSV)
- **Session Management**: Proxy-like functionality for manual testing
- **Vulnerability Tracking**: Status management and remediation tracking

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Dashboard (ReactJS)                  │
│  - Scan Management & Monitoring                             │
│  - Vulnerability Reports & Analytics                        │
│  - Project Management & Configuration                       │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                 Backend API (Python FastAPI)               │
│  - RESTful API endpoints                                    │
│  - Scan orchestration & scheduling                          │
│  - Authentication & authorization                           │
│  - Report generation & export                               │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┘
│                DAST Scanner Engine                          │
│  - Spider & Crawler (aiohttp + BeautifulSoup)              │
│  - Passive Scanner (security headers, info disclosure)     │
│  - Active Scanner (payload injection & analysis)           │
│  - Authentication Handler (JWT, OAuth2, cookies)           │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                    Data Storage                             │
│  - PostgreSQL: Projects, scans, vulnerabilities            │
│  - Redis: Scan queue & caching                             │
│  - File Storage: Evidence files & reports                  │
└─────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites
- Python 3.8+
- PostgreSQL 12+
- Redis 6+
- Node.js 16+ (for frontend)

### Backend Setup

1. **Clone the repository**
```bash
git clone <repository-url>
cd cyber-cursor
```

2. **Install Python dependencies**
```bash
cd backend
pip install -r requirements.txt
```

3. **Set up environment variables**
```bash
cp env.example .env
# Edit .env with your database and Redis configuration
```

4. **Initialize the database**
```bash
# Run the DAST database initialization script
psql -U your_user -d your_database -f scripts/init-dast-db.sql
```

5. **Start the backend server**
```bash
python main.py
```

### Frontend Setup

1. **Install Node.js dependencies**
```bash
cd frontend
npm install
```

2. **Start the development server**
```bash
npm start
```

## Usage

### Web Interface

1. **Access the dashboard** at `http://localhost:3000`
2. **Create a new project** with target URL and configuration
3. **Start a scan** and monitor progress in real-time
4. **Review results** and generate reports

### Command Line Interface

The DAST CLI provides comprehensive command-line functionality:

#### Quick Scan
```bash
# Quick scan with automatic project creation
python dast_cli.py quick-scan https://example.com --wait --output results.json
```

#### Project Management
```bash
# Create a new project
python dast_cli.py create-project "My Web App" https://example.com --auth-type jwt

# List all projects
python dast_cli.py list-projects
```

#### Scan Operations
```bash
# Start a scan
python dast_cli.py start-scan project_id --scan-type full --wait

# Check scan status
python dast_cli.py scan-status scan_id

# Get vulnerabilities
python dast_cli.py vulnerabilities scan_id --format table
```

#### Report Generation
```bash
# Generate report
python dast_cli.py report scan_id --format pdf
```

### API Usage

#### Create Project
```bash
curl -X POST http://localhost:8000/api/v1/dast/projects \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_token" \
  -d '{
    "name": "Test Project",
    "target_url": "https://example.com",
    "description": "Test web application",
    "auth_type": "none"
  }'
```

#### Start Scan
```bash
curl -X POST http://localhost:8000/api/v1/dast/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_token" \
  -d '{
    "project_id": "project_uuid",
    "scan_type": "full",
    "scan_config": {
      "max_urls": 100,
      "max_depth": 3,
      "scan_timeout": 300
    }
  }'
```

#### Get Scan Results
```bash
curl -X GET http://localhost:8000/api/v1/dast/scans/scan_uuid/vulnerabilities \
  -H "Authorization: Bearer your_token"
```

### CI/CD Integration

#### GitHub Actions Example
```yaml
name: DAST Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run DAST Scan
        run: |
          python dast_cli.py quick-scan ${{ secrets.TARGET_URL }} \
            --wait \
            --timeout 1800 \
            --output dast-results.json
      
      - name: Check for Critical Vulnerabilities
        run: |
          if jq '.vulnerabilities[] | select(.severity == "critical")' dast-results.json; then
            echo "Critical vulnerabilities found!"
            exit 1
          fi
```

#### Jenkins Pipeline Example
```groovy
pipeline {
    agent any
    stages {
        stage('DAST Scan') {
            steps {
                script {
                    def scanResult = sh(
                        script: "python dast_cli.py quick-scan ${env.TARGET_URL} --wait --output dast-results.json",
                        returnStatus: true
                    )
                    
                    if (scanResult != 0) {
                        error "DAST scan failed"
                    }
                    
                    // Parse results and fail on critical vulnerabilities
                    def results = readJSON file: 'dast-results.json'
                    def criticalVulns = results.vulnerabilities.findAll { it.severity == 'critical' }
                    
                    if (criticalVulns.size() > 0) {
                        error "Critical vulnerabilities found: ${criticalVulns.size()}"
                    }
                }
            }
        }
    }
}
```

## Configuration

### Scan Configuration

```yaml
# scan-config.yaml
max_urls: 100                    # Maximum URLs to scan
max_depth: 3                     # Maximum crawl depth
scan_timeout: 300               # Scan timeout in seconds
threads: 10                     # Number of concurrent threads
user_agent: "DAST Scanner/1.0"  # Custom user agent

# Authentication configuration
auth:
  type: "jwt"
  token: "your_jwt_token"
  refresh_url: "https://example.com/refresh"

# Scope configuration
scope:
  include_patterns:
    - "https://example.com/*"
  exclude_patterns:
    - "https://example.com/admin/*"
    - "https://example.com/api/health"

# Payload configuration
payloads:
  sql_injection: true
  xss: true
  command_injection: true
  path_traversal: true
  ssrf: true
  custom_payloads:
    - name: "Custom Test"
      payload: "test_payload"
      vuln_type: "custom"
```

### Project Configuration

```yaml
# project-config.yaml
name: "Production Web App"
target_url: "https://example.com"
description: "Production web application for security testing"
auth_type: "jwt"

auth_config:
  jwt_token: "your_jwt_token"
  refresh_interval: 3600
  refresh_url: "https://example.com/auth/refresh"

scan_config:
  max_urls: 200
  max_depth: 4
  scan_timeout: 600
  threads: 20

scope_config:
  include_patterns:
    - "https://example.com/*"
  exclude_patterns:
    - "https://example.com/admin/*"
    - "https://example.com/api/health"
    - "https://example.com/static/*"
```

## Payload Library

The DAST implementation includes a comprehensive payload library covering:

### SQL Injection
- Basic authentication bypass
- UNION-based data extraction
- Boolean-based blind injection
- Time-based blind injection
- Stacked queries

### Cross-Site Scripting (XSS)
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Event handler injection
- JavaScript URI scheme

### Command Injection
- Basic command execution
- Time-based detection
- File read operations
- Process listing
- Reverse shell attempts

### Path Traversal
- Basic directory traversal
- URL-encoded traversal
- Double-encoded traversal
- Windows-style paths
- Null byte injection

### Server-Side Request Forgery (SSRF)
- AWS metadata service
- Azure metadata service
- GCP metadata service
- Internal network access
- Localhost services

### Additional Payloads
- Open redirects
- XML External Entity (XXE)
- Template injection
- NoSQL injection
- Custom payloads

## Vulnerability Detection

### Passive Scanning
- **Security Headers**: Missing CSP, HSTS, X-Frame-Options, etc.
- **Information Disclosure**: Server information, error messages, sensitive data
- **TLS Configuration**: Weak ciphers, certificate issues
- **Directory Listing**: Exposed directory contents

### Active Scanning
- **SQL Injection**: Error-based, time-based, boolean-based detection
- **XSS**: Reflected, stored, DOM-based XSS detection
- **Command Injection**: Command execution and time-based detection
- **Path Traversal**: File read and directory traversal detection
- **SSRF**: Internal service access detection

### Response Analysis
- **Error Patterns**: Database errors, stack traces, system information
- **Time Delays**: Suspicious response times indicating injection
- **Content Reflection**: Payload reflection in responses
- **Status Codes**: Unusual HTTP status codes

## Reporting

### Report Formats
- **JSON**: Machine-readable format for integration
- **PDF**: Professional reports for stakeholders
- **HTML**: Interactive web-based reports
- **CSV**: Spreadsheet-compatible format

### Report Content
- Executive summary with security score
- Detailed vulnerability findings
- Evidence and proof-of-concept
- Remediation recommendations
- OWASP Top 10 mapping
- CWE classification

### Custom Reports
```python
from app.services.dast_service import DASTService

# Generate custom report
service = DASTService(db_session)
report = await service.generate_report(
    scan_id="scan_uuid",
    format="json",
    custom_template="custom_template.html"
)
```

## Security Considerations

### Data Protection
- All communications use TLS 1.2/1.3
- Scan evidence encrypted at rest (AES-256)
- Secure storage of authentication credentials
- Data retention and cleanup policies

### Access Control
- Role-based access control (RBAC)
- API key management and rotation
- Session timeout and automatic logout
- Audit logging for all operations

### Compliance
- GDPR compliance for data handling
- SOC 2 Type II compliance
- ISO 27001 security standards
- Industry-specific compliance (PCI DSS, HIPAA)

## Performance Optimization

### Scalability
- Horizontal scaling with Kubernetes
- Load balancing across scanning workers
- Database connection pooling
- Redis caching for performance

### Resource Management
- Memory-efficient scanning algorithms
- Configurable scan depth and breadth
- Rate limiting to prevent target overload
- Resource monitoring and alerting

## Monitoring and Alerting

### Metrics
- Scan success/failure rates
- Vulnerability detection rates
- Performance metrics (duration, throughput)
- Resource utilization

### Alerting
- Critical vulnerability detection
- Scan failures and errors
- Performance degradation
- Security incidents

### Logging
- Structured logging with correlation IDs
- Audit trail for all actions
- Error tracking and debugging
- Compliance reporting

## Troubleshooting

### Common Issues

#### Scan Timeout
```bash
# Increase timeout in scan configuration
python dast_cli.py start-scan project_id --config scan-config.yaml
```

#### Authentication Issues
```bash
# Check authentication configuration
python dast_cli.py create-project "Test" https://example.com --auth-type jwt --config auth-config.yaml
```

#### Database Connection Issues
```bash
# Verify database configuration
psql -U your_user -d your_database -c "SELECT version();"
```

#### Memory Issues
```bash
# Reduce scan scope and concurrency
# Edit scan-config.yaml to reduce max_urls and threads
```

### Debug Mode
```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python dast_cli.py quick-scan https://example.com --wait
```

## Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Testing
```bash
# Run unit tests
pytest tests/unit/

# Run integration tests
pytest tests/integration/

# Run end-to-end tests
pytest tests/e2e/
```

### Code Style
- Follow PEP 8 for Python code
- Use type hints
- Add docstrings for all functions
- Write comprehensive tests

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

### Documentation
- [API Documentation](docs/api.md)
- [User Guide](docs/user-guide.md)
- [Developer Guide](docs/developer-guide.md)
- [Troubleshooting Guide](docs/troubleshooting.md)

### Community
- [GitHub Issues](https://github.com/your-repo/issues)
- [Discussions](https://github.com/your-repo/discussions)
- [Wiki](https://github.com/your-repo/wiki)

### Professional Support
- Email: support@example.com
- Phone: +1-555-123-4567
- [Support Portal](https://support.example.com)

## Roadmap

### Upcoming Features
- **AI/ML Integration**: Automated vulnerability classification
- **Advanced Scanning**: Container and cloud-native scanning
- **Mobile Testing**: Mobile application security testing
- **IoT Security**: IoT device security testing
- **Blockchain Security**: Blockchain application security

### Version History
- **v1.0.0**: Initial release with core DAST functionality
- **v1.1.0**: Added advanced payload library and reporting
- **v1.2.0**: Enhanced authentication support and CI/CD integration
- **v2.0.0**: Major rewrite with improved performance and scalability

---

For more information, visit the [project website](https://example.com) or contact the development team. 