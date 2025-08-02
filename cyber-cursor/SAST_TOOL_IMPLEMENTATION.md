# SAST (Static Application Security Testing) Tool - Full Implementation Guide

## Overview

This document provides a comprehensive guide to the SAST tool implementation in the CyberShield platform. The SAST tool performs static code analysis to identify security vulnerabilities, code smells, and best practice violations in source code.

## Architecture

### High-Level Architecture

```
Developer → Upload Code / Trigger Scan
        ↓
Python Backend (FastAPI) → Scanning Engine (Bandit, ESLint, Semgrep)
        ↓
PostgreSQL → Stores vulnerabilities and history
        ↓
React Native Frontend (Application Security → SAST Tab)
        ↓
Summary Dashboard + Detailed Reports + Export to PDF/CSV
        ↓
Optional: CI/CD Integration (GitHub Actions/Jenkins)
```

### Components

1. **Frontend (React Native)**
   - SAST Dashboard (Summary + Detailed Results)
   - Vulnerability Drill-Down
   - Export PDF/CSV Reports
   - Trigger Scan Button
   - Upload Interface

2. **Backend (Python – FastAPI)**
   - Handles code upload or Git repo input
   - Triggers static analysis (SAST)
   - Stores results in PostgreSQL
   - Provides REST APIs to UI

3. **Database (PostgreSQL)**
   - Stores scan results, history, projects, and user info
   - Comprehensive schema for vulnerability tracking

4. **Scanning Engine (Open-Source Tools)**
   - Bandit → Python vulnerabilities
   - ESLint → JavaScript vulnerabilities and code smells
   - Semgrep → Multi-language & OWASP rules
   - Pylint → Python code analysis

5. **CI/CD Integration**
   - Trigger scans on code push or PR
   - Fail builds if critical vulnerabilities detected

## Database Schema

### Core Tables

```sql
-- Projects table
CREATE TABLE projects (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  repo_url TEXT,
  description TEXT,
  language VARCHAR(50),
  framework VARCHAR(50),
  created_by INTEGER REFERENCES users(id),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- SAST Scans table
CREATE TABLE sast_scans (
  id SERIAL PRIMARY KEY,
  project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
  triggered_by VARCHAR(255) NOT NULL,
  start_time TIMESTAMP DEFAULT NOW(),
  end_time TIMESTAMP,
  status VARCHAR(20) DEFAULT 'running',
  scan_type VARCHAR(50) DEFAULT 'full',
  scan_config JSONB,
  total_files INTEGER DEFAULT 0,
  scanned_files INTEGER DEFAULT 0,
  vulnerabilities_found INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW()
);

-- SAST Results table
CREATE TABLE sast_results (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER REFERENCES sast_scans(id) ON DELETE CASCADE,
  file_path TEXT NOT NULL,
  line_no INTEGER,
  column_no INTEGER,
  vulnerability TEXT NOT NULL,
  severity VARCHAR(20) NOT NULL,
  recommendation TEXT,
  tool_name VARCHAR(50) NOT NULL,
  cwe_id VARCHAR(20),
  confidence VARCHAR(20) DEFAULT 'medium',
  status VARCHAR(20) DEFAULT 'open',
  detected_at TIMESTAMP DEFAULT NOW()
);

-- SAST Reports table
CREATE TABLE sast_reports (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER REFERENCES sast_scans(id) ON DELETE CASCADE,
  report_type VARCHAR(20) NOT NULL,
  report_data JSONB,
  file_path TEXT,
  generated_at TIMESTAMP DEFAULT NOW()
);
```

## Backend Implementation

### Key Files

1. **API Endpoints**: `backend/app/api/v1/endpoints/sast.py`
2. **Database Models**: `backend/app/models/sast_models.py`
3. **Schemas**: `backend/app/schemas/sast_schemas.py`
4. **Scanner Service**: `backend/app/services/sast_scanner.py`
5. **Database Service**: `backend/app/services/sast_database.py`
6. **Report Service**: `backend/app/services/sast_reports.py`

### API Endpoints

#### Project Management
- `POST /api/v1/sast/projects` - Create new project
- `GET /api/v1/sast/projects` - List all projects
- `GET /api/v1/sast/projects/{id}` - Get project details
- `DELETE /api/v1/sast/projects/{id}` - Delete project

#### Scan Management
- `POST /api/v1/sast/projects/{id}/scan` - Start scan for project
- `POST /api/v1/sast/scan/upload` - Upload code and scan
- `GET /api/v1/sast/scans` - List all scans
- `GET /api/v1/sast/scans/{id}` - Get scan details
- `GET /api/v1/sast/scans/{id}/progress` - Get scan progress

#### Vulnerability Management
- `GET /api/v1/sast/scans/{id}/vulnerabilities` - Get vulnerabilities
- `PUT /api/v1/sast/vulnerabilities/{id}/status` - Update vulnerability status

#### Reports and Analytics
- `GET /api/v1/sast/scans/{id}/summary` - Get scan summary
- `GET /api/v1/sast/projects/{id}/summary` - Get project summary
- `GET /api/v1/sast/summary` - Get overall summary
- `GET /api/v1/sast/scans/{id}/reports/{type}` - Generate reports

#### CI/CD Integration
- `POST /api/v1/sast/webhook/github` - GitHub webhook handler

### Scanning Engine

The scanning engine supports multiple tools:

#### Bandit (Python)
```python
def _run_bandit_scan(self) -> List[Vulnerability]:
    """Run Bandit security scan for Python"""
    result = subprocess.run(
        ["bandit", "-r", str(self.project_path), "-f", "json", "-q"],
        capture_output=True,
        text=True,
        timeout=300
    )
    
    if result.returncode in [0, 1]:  # Bandit returns 1 when issues found
        data = json.loads(result.stdout)
        vulnerabilities = []
        
        for issue in data.get("results", []):
            vuln = Vulnerability(
                file_path=issue["filename"],
                line_no=issue["line_number"],
                vulnerability=issue["issue_text"],
                severity=self._map_bandit_severity(issue["issue_severity"]),
                recommendation=issue.get("more_info", ""),
                tool_name="bandit",
                cwe_id=issue.get("cwe", {}).get("id"),
                confidence="medium"
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    return []
```

#### Semgrep (Multi-language)
```python
def _run_semgrep_scan(self) -> List[Vulnerability]:
    """Run Semgrep security scan"""
    result = subprocess.run(
        ["semgrep", "--config=p/owasp-top-ten", str(self.project_path), "--json"],
        capture_output=True,
        text=True,
        timeout=300
    )
    
    if result.returncode in [0, 1]:
        data = json.loads(result.stdout)
        vulnerabilities = []
        
        for result in data.get("results", []):
            vuln = Vulnerability(
                file_path=result["path"],
                line_no=result["start"]["line"],
                column_no=result["start"]["col"],
                vulnerability=result["message"],
                severity=self._map_semgrep_severity(result["extra"]["severity"]),
                recommendation=result["extra"].get("message", ""),
                tool_name="semgrep",
                cwe_id=result["extra"].get("metadata", {}).get("cwe"),
                confidence=result["extra"].get("metadata", {}).get("confidence", "medium")
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    return []
```

## Frontend Implementation

### Key Components

1. **SAST Dashboard**: `frontend/src/pages/SAST/SASTDashboard.tsx`
2. **SAST Upload**: `frontend/src/pages/SAST/SASTUpload.tsx`
3. **SAST Scan Details**: `frontend/src/pages/SAST/SASTScanDetails.tsx`

### Features

#### Dashboard Overview
- Summary cards showing vulnerability counts
- Recent scans with status indicators
- Vulnerability breakdown by severity
- Quick action buttons for new scans

#### Upload Interface
- Drag-and-drop file upload
- ZIP file support
- Project configuration
- Scan type selection (Quick/Full/Incremental)
- Tool selection (Bandit/Pylint/Semgrep/ESLint)

#### Scan Details
- Comprehensive vulnerability listing
- Filtering by severity and tool
- Vulnerability status management
- Report generation (PDF/CSV/JSON)
- Code location and recommendations

## Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql+asyncpg://user:password@localhost/cybershield

# SAST Tools
BANDIT_ENABLED=true
SEMGREP_ENABLED=true
PYLINT_ENABLED=true
ESLINT_ENABLED=true

# Scan Configuration
MAX_SCAN_DURATION=3600
PARALLEL_SCANS=3
AUTO_SCAN_ON_PUSH=false

# File Upload
MAX_FILE_SIZE=104857600  # 100MB
ALLOWED_FILE_TYPES=.zip
```

### Tool Configuration

#### Bandit Configuration
```yaml
# .bandit
exclude_dirs: ['tests', 'test', 'testsuite']
skips: ['B101', 'B601']
```

#### Semgrep Configuration
```yaml
# .semgrep.yml
rules:
  - p/owasp-top-ten
  - p/security-audit
  - p/secrets
```

#### ESLint Configuration
```json
// .eslintrc.json
{
  "extends": ["eslint:recommended", "plugin:security/recommended"],
  "plugins": ["security"],
  "rules": {
    "security/detect-object-injection": "error",
    "security/detect-non-literal-regexp": "error"
  }
}
```

## Usage Examples

### Creating a Project and Running a Scan

```python
import requests

# Authenticate
response = requests.post("http://localhost:8000/api/v1/auth/login", json={
    "email": "admin@cybershield.com",
    "password": "admin123"
})
token = response.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

# Create project
project_data = {
    "name": "My Application",
    "description": "A web application",
    "repo_url": "https://github.com/user/my-app.git",
    "language": "python",
    "framework": "flask"
}

response = requests.post(
    "http://localhost:8000/api/v1/sast/projects",
    json=project_data,
    headers=headers
)
project_id = response.json()["id"]

# Start scan
scan_data = {
    "scan_type": "full",
    "scan_config": {
        "tools_enabled": ["bandit", "semgrep"],
        "severity_threshold": "medium"
    }
}

response = requests.post(
    f"http://localhost:8000/api/v1/sast/projects/{project_id}/scan",
    json=scan_data,
    headers=headers
)
scan_id = response.json()["id"]

# Get results
response = requests.get(
    f"http://localhost:8000/api/v1/sast/scans/{scan_id}/vulnerabilities",
    headers=headers
)
vulnerabilities = response.json()
```

### Upload and Scan Code

```python
# Upload ZIP file and scan
with open("project.zip", "rb") as f:
    files = {"file": ("project.zip", f, "application/zip")}
    data = {
        "project_name": "Uploaded Project",
        "scan_config": json.dumps({
            "tools_enabled": ["bandit", "pylint", "semgrep"],
            "severity_threshold": "low"
        })
    }
    
    response = requests.post(
        "http://localhost:8000/api/v1/sast/scan/upload",
        files=files,
        data=data,
        headers=headers
    )
```

## CI/CD Integration

### GitHub Actions Workflow

```yaml
name: SAST Security Scan
on: [push, pull_request]

jobs:
  sast-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run SAST Scan
        run: |
          curl -X POST http://your-sast-api/api/v1/sast/scan/upload \
            -H "Authorization: Bearer ${{ secrets.SAST_TOKEN }}" \
            -F "file=@$(git archive --format=zip HEAD)" \
            -F "project_name=${{ github.repository }}" \
            -F "scan_config={\"tools_enabled\":[\"bandit\",\"semgrep\"],\"severity_threshold\":\"medium\"}"
      
      - name: Check for Critical Vulnerabilities
        run: |
          # Get scan results and fail if critical vulnerabilities found
          # Implementation depends on your specific requirements
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('SAST Scan') {
            steps {
                script {
                    // Archive source code
                    archiveArtifacts artifacts: '**/*', fingerprint: true
                    
                    // Upload to SAST tool
                    sh '''
                        curl -X POST http://your-sast-api/api/v1/sast/scan/upload \
                          -H "Authorization: Bearer ${SAST_TOKEN}" \
                          -F "file=@workspace.zip" \
                          -F "project_name=${JOB_NAME}" \
                          -F "scan_config={\"tools_enabled\":[\"bandit\",\"semgrep\"]}"
                    '''
                }
            }
        }
        
        stage('Security Gate') {
            steps {
                script {
                    // Check scan results and fail if critical issues found
                    // Implementation depends on your security requirements
                }
            }
        }
    }
}
```

## Testing

### Running the Test Suite

```bash
# Run comprehensive SAST tool tests
python test-sast-tool.py
```

The test suite covers:
- Project management
- Code scanning
- Vulnerability analysis
- Report generation
- API endpoints
- Error handling

### Test Coverage

- ✅ Health check endpoint
- ✅ Project creation and management
- ✅ File upload and scanning
- ✅ Scan progress monitoring
- ✅ Vulnerability retrieval and filtering
- ✅ Report generation
- ✅ Status updates
- ✅ Error handling

## Security Considerations

### Input Validation
- File type validation (ZIP only)
- File size limits (100MB max)
- Path traversal protection
- Malicious file detection

### Authentication & Authorization
- JWT token-based authentication
- Role-based access control
- API rate limiting
- Session management

### Data Protection
- Secure file handling
- Temporary file cleanup
- Database connection security
- Audit logging

### Tool Security
- Tool execution isolation
- Timeout limits
- Resource constraints
- Sandboxed execution

## Performance Optimization

### Scanning Optimization
- Parallel tool execution
- Incremental scanning
- Caching of results
- Background processing

### Database Optimization
- Indexed queries
- Connection pooling
- Query optimization
- Data archiving

### Frontend Optimization
- Lazy loading
- Pagination
- Caching
- Progressive loading

## Monitoring and Logging

### Metrics to Track
- Scan duration
- Vulnerability detection rates
- Tool performance
- Error rates
- User activity

### Logging
```python
import structlog

logger = structlog.get_logger()

# Log scan events
logger.info("SAST scan started", 
           scan_id=scan_id, 
           project_id=project_id, 
           tools=tools_enabled)

# Log vulnerabilities
logger.warning("Vulnerability detected",
              scan_id=scan_id,
              severity=severity,
              tool=tool_name,
              file_path=file_path)
```

## Troubleshooting

### Common Issues

1. **Scan Timeout**
   - Increase `MAX_SCAN_DURATION`
   - Check tool performance
   - Optimize scan configuration

2. **Memory Issues**
   - Reduce parallel scans
   - Increase system memory
   - Optimize tool configuration

3. **Database Connection Issues**
   - Check connection pool settings
   - Verify database connectivity
   - Monitor connection limits

4. **Tool Installation Issues**
   - Verify tool installation
   - Check PATH environment
   - Update tool versions

### Debug Mode

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Future Enhancements

### Planned Features
- Support for additional languages (Java, C#, Go)
- Advanced vulnerability correlation
- Machine learning-based false positive reduction
- Integration with issue trackers (Jira, GitHub Issues)
- Custom rule creation interface
- Advanced reporting and analytics
- Real-time scanning for development environments

### Scalability Improvements
- Microservices architecture
- Kubernetes deployment
- Horizontal scaling
- Load balancing
- Distributed scanning

## Conclusion

The SAST tool provides comprehensive static application security testing capabilities with a modern, scalable architecture. It supports multiple programming languages, integrates with CI/CD pipelines, and provides detailed reporting and analytics.

The implementation follows security best practices, includes comprehensive testing, and is designed for production use in enterprise environments. 