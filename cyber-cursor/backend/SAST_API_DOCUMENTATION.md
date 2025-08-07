# SAST API Documentation

## Overview

The SAST (Static Application Security Testing) API provides comprehensive functionality for managing security analysis projects, similar to SonarQube. This API includes endpoints for project management, vulnerability analysis, code quality metrics, and comprehensive reporting.

## Base URL

```
http://localhost:8000/api/v1/sast
```

## Authentication

All endpoints require authentication. Include the JWT token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

## Endpoints

### 1. Dashboard & Overview

#### Get SAST Dashboard
```http
GET /dashboard
```

Returns comprehensive dashboard statistics including project counts, vulnerability metrics, and quality indicators.

**Response:**
```json
{
  "total_projects": 15,
  "active_scans": 3,
  "total_issues": 245,
  "critical_issues": 12,
  "security_rating": "B",
  "recent_activity": [...]
}
```

#### Get SAST Overview
```http
GET /overview
```

Returns high-level overview of all SAST projects and their current status.

**Response:**
```json
{
  "total_projects": 15,
  "total_issues": 245,
  "total_vulnerabilities": 89,
  "total_bugs": 67,
  "total_code_smells": 89,
  "total_security_hotspots": 45,
  "average_coverage": 78.5,
  "average_duplication": 3.2
}
```

### 2. Project Management

#### Get All Projects
```http
GET /projects?skip=0&limit=100&search=web&language=JavaScript&status_filter=active
```

**Query Parameters:**
- `skip` (int): Number of records to skip (default: 0)
- `limit` (int): Maximum number of records to return (default: 100, max: 1000)
- `search` (string): Search term for project name or key
- `language` (string): Filter by programming language
- `status_filter` (string): Filter by project status

**Response:**
```json
{
  "projects": [
    {
      "id": 1,
      "name": "Web Application Security",
      "key": "web-app-sec",
      "language": "JavaScript",
      "quality_gate": "PASSED",
      "security_rating": "B",
      "reliability_rating": "A",
      "maintainability_rating": "A",
      "vulnerability_count": 5,
      "bug_count": 3,
      "code_smell_count": 12,
      "security_hotspot_count": 8,
      "coverage": 85.5,
      "duplicated_lines": 450,
      "technical_debt": 120,
      "last_analysis": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 15,
  "skip": 0,
  "limit": 100
}
```

#### Get Project Details
```http
GET /projects/{project_id}
```

Returns detailed information about a specific project.

#### Create Project
```http
POST /projects
```

**Request Body:**
```json
{
  "name": "New Security Project",
  "key": "new-sec-project",
  "language": "Python",
  "repository_url": "https://github.com/example/project",
  "branch": "main"
}
```

#### Update Project
```http
PUT /projects/{project_id}
```

#### Delete Project
```http
DELETE /projects/{project_id}
```

### 3. Project-Specific Analysis

#### Get Project Duplications
```http
GET /projects/{project_id}/duplications
```

Returns comprehensive duplication analysis for a project.

**Response:**
```json
{
  "duplicatedLines": 1250,
  "duplicatedFiles": 23,
  "duplicatedBlocks": 45,
  "duplicationDensity": 8.5,
  "duplicationsByLanguage": [
    {
      "language": "JavaScript",
      "duplicatedLines": 450,
      "duplicatedFiles": 15,
      "duplicationDensity": 12.3,
      "color": "#3b82f6"
    }
  ],
  "duplicationsByFile": [
    {
      "file": "src/components/Button.jsx",
      "duplicatedLines": 45,
      "duplicatedBlocks": 3,
      "duplicationDensity": 15.2,
      "lastModified": "2024-01-15T10:30:00Z"
    }
  ],
  "duplicationTrend": [
    {
      "date": "2024-01-10",
      "duplicatedLines": 1200,
      "duplicatedFiles": 20,
      "duplicationDensity": 8.2
    }
  ]
}
```

#### Get Project Security Reports
```http
GET /projects/{project_id}/security-reports
```

Returns comprehensive security analysis including OWASP Top 10 and CWE mappings.

**Response:**
```json
{
  "overallSecurityRating": "B",
  "securityScore": 75,
  "vulnerabilitiesByCategory": [
    {
      "category": "SQL Injection",
      "count": 3,
      "severity": "CRITICAL",
      "percentage": 25,
      "color": "#ef4444"
    }
  ],
  "owaspTop10Mapping": [
    {
      "category": "A01:2021 - Broken Access Control",
      "count": 2,
      "severity": "CRITICAL",
      "description": "Access control vulnerabilities",
      "color": "#ef4444"
    }
  ],
  "cweMapping": [
    {
      "cweId": "CWE-89",
      "name": "SQL Injection",
      "count": 3,
      "severity": "CRITICAL",
      "description": "SQL injection vulnerabilities"
    }
  ],
  "securityTrend": [
    {
      "date": "2024-01-10",
      "vulnerabilities": 15,
      "securityScore": 65,
      "securityRating": "C"
    }
  ]
}
```

#### Get Project Reliability
```http
GET /projects/{project_id}/reliability
```

Returns reliability metrics and bug analysis.

**Response:**
```json
{
  "reliabilityRating": "A",
  "bugCount": 8,
  "bugDensity": 0.5,
  "bugsBySeverity": [
    {
      "severity": "BLOCKER",
      "count": 1,
      "percentage": 12.5,
      "color": "#dc2626"
    }
  ],
  "bugsByCategory": [
    {
      "category": "Null Pointer Exception",
      "count": 3,
      "description": "Null pointer dereference bugs",
      "color": "#ef4444"
    }
  ],
  "reliabilityTrend": [
    {
      "date": "2024-01-10",
      "bugCount": 12,
      "bugDensity": 0.8,
      "reliabilityRating": "B"
    }
  ],
  "newBugs": 2,
  "resolvedBugs": 6
}
```

#### Get Project Maintainability
```http
GET /projects/{project_id}/maintainability
```

Returns maintainability metrics and code smell analysis.

**Response:**
```json
{
  "maintainabilityRating": "A",
  "codeSmellCount": 15,
  "codeSmellDensity": 1.2,
  "complexity": 45.3,
  "cognitiveComplexity": 23.1,
  "codeSmellsByCategory": [
    {
      "category": "Code Smells",
      "count": 10,
      "description": "General code smell issues",
      "color": "#f59e0b"
    }
  ],
  "maintainabilityTrend": [
    {
      "date": "2024-01-10",
      "codeSmellCount": 18,
      "complexity": 48.2,
      "maintainabilityRating": "B"
    }
  ]
}
```

#### Get Project Activity
```http
GET /projects/{project_id}/activity
```

Returns project activity timeline and contributor analysis.

**Response:**
```json
{
  "recentCommits": [
    {
      "id": "abc123",
      "author": "john.doe",
      "message": "Fix security vulnerability in authentication",
      "timestamp": "2024-01-15T10:30:00Z",
      "filesChanged": 3,
      "linesAdded": 15,
      "linesRemoved": 8
    }
  ],
  "recentIssues": [
    {
      "id": 123,
      "type": "VULNERABILITY",
      "severity": "CRITICAL",
      "status": "OPEN",
      "createdAt": "2024-01-15T09:00:00Z"
    }
  ],
  "contributors": [
    {
      "username": "john.doe",
      "email": "john.doe@example.com",
      "commitsCount": 45,
      "issuesCount": 12,
      "hotspotsCount": 3,
      "lastActivity": "2024-01-15T10:30:00Z"
    }
  ],
  "activityMetrics": {
    "totalCommits": 156,
    "totalIssues": 89,
    "totalHotspots": 23,
    "activeContributors": 8
  },
  "activityTrend": [
    {
      "date": "2024-01-10",
      "commits": 12,
      "issues": 5,
      "hotspots": 2
    }
  ]
}
```

#### Get Project Configuration
```http
GET /projects/{project_id}/configuration
```

Returns project configuration settings.

**Response:**
```json
{
  "projectSettings": {
    "scanSchedule": "0 2 * * *",
    "autoScan": true,
    "qualityProfile": "Sonar way",
    "qualityGate": "Default",
    "exclusions": ["**/test/**", "**/node_modules/**"]
  },
  "notificationSettings": {
    "email": true,
    "slack": false,
    "webhook": "https://hooks.slack.com/..."
  },
  "integrationSettings": {
    "github": true,
    "gitlab": false,
    "bitbucket": false,
    "jenkins": true
  },
  "projectPermissions": [
    {
      "userId": 1,
      "username": "admin",
      "role": "Admin",
      "permissions": ["read", "write", "admin"]
    }
  ]
}
```

#### Update Project Configuration
```http
PUT /projects/{project_id}/configuration
```

**Request Body:**
```json
{
  "projectSettings": {
    "autoScan": true,
    "qualityProfile": "Sonar way"
  },
  "notificationSettings": {
    "email": true,
    "slack": false
  }
}
```

#### Get Project Metrics
```http
GET /projects/{project_id}/metrics
```

Returns comprehensive project metrics.

**Response:**
```json
{
  "linesOfCode": 15000,
  "filesCount": 245,
  "functionsCount": 567,
  "classesCount": 89,
  "complexity": 45.3,
  "maintainabilityRating": "A",
  "securityRating": "B",
  "reliabilityRating": "A",
  "coverage": 85.5,
  "duplicationDensity": 3.2,
  "totalIssues": 89,
  "bugsCount": 23,
  "vulnerabilitiesCount": 34,
  "codeSmellsCount": 32,
  "securityHotspotsCount": 15,
  "totalDebt": 480,
  "debtRatio": 2.1
}
```

#### Get Project Trends
```http
GET /projects/{project_id}/trends?days=30
```

Returns project trends over time.

**Query Parameters:**
- `days` (int): Number of days to include in trends (default: 30, max: 365)

**Response:**
```json
{
  "trends": [
    {
      "date": "2024-01-10",
      "totalIssues": 95,
      "bugsCount": 25,
      "vulnerabilitiesCount": 38,
      "codeSmellsCount": 32,
      "coverage": 82.1,
      "duplicationDensity": 3.5,
      "complexity": 47.2,
      "maintainabilityRating": "A",
      "securityRating": "B",
      "reliabilityRating": "A"
    }
  ]
}
```

### 4. Global Analysis

#### Get All Vulnerabilities
```http
GET /vulnerabilities?severity=CRITICAL&type=VULNERABILITY&project_id=1&skip=0&limit=100
```

**Query Parameters:**
- `severity` (string): Filter by severity (BLOCKER, CRITICAL, MAJOR, MINOR, INFO)
- `type` (string): Filter by type (BUG, VULNERABILITY, CODE_SMELL, SECURITY_HOTSPOT)
- `status` (string): Filter by status (OPEN, CONFIRMED, RESOLVED, CLOSED, REOPENED)
- `project_id` (string): Filter by project ID
- `cwe_id` (string): Filter by CWE ID
- `owasp_category` (string): Filter by OWASP category
- `skip` (int): Number of records to skip
- `limit` (int): Maximum number of records to return

#### Get All Security Hotspots
```http
GET /security-hotspots?status=TO_REVIEW&project_id=1&skip=0&limit=100
```

#### Get All Quality Gates
```http
GET /quality-gates?project_id=1&status=PASSED
```

#### Get All Code Coverage
```http
GET /code-coverage?project_id=1&min_coverage=80.0
```

#### Get All Duplications
```http
GET /duplications?project_id=1&min_duplicated_lines=100
```

#### Get SAST Statistics
```http
GET /statistics
```

Returns comprehensive statistics across all projects.

#### Get Detection Rules
```http
GET /rules?language=Python&severity=CRITICAL&category=Security
```

**Query Parameters:**
- `language` (string): Filter by programming language
- `severity` (string): Filter by severity
- `category` (string): Filter by rule category

#### Get Supported Languages
```http
GET /languages
```

Returns list of supported programming languages.

### 5. Scan Management

#### Start SAST Scan
```http
POST /scans
```

**Request Body:**
```json
{
  "project_id": 1,
  "scan_type": "full",
  "branch": "main"
}
```

#### Get Scan Status
```http
GET /scans/{scan_id}
```

#### Get Project Scan History
```http
GET /projects/{project_id}/scans
```

## Error Responses

All endpoints return consistent error responses:

```json
{
  "detail": "Error message description"
}
```

Common HTTP status codes:
- `200`: Success
- `201`: Created
- `400`: Bad Request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not Found
- `422`: Validation Error
- `500`: Internal Server Error

## Data Models

### Project
```json
{
  "id": 1,
  "name": "Project Name",
  "key": "project-key",
  "language": "JavaScript",
  "repository_url": "https://github.com/example/project",
  "branch": "main",
  "quality_gate": "PASSED",
  "security_rating": "B",
  "reliability_rating": "A",
  "maintainability_rating": "A",
  "vulnerability_count": 5,
  "bug_count": 3,
  "code_smell_count": 12,
  "security_hotspot_count": 8,
  "lines_of_code": 15000,
  "coverage": 85.5,
  "duplicated_lines": 450,
  "technical_debt": 120,
  "debt_ratio": 2.1,
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-15T10:30:00Z",
  "last_analysis": "2024-01-15T10:30:00Z"
}
```

### Issue
```json
{
  "id": 1,
  "project_id": 1,
  "rule_id": "S1481",
  "rule_name": "Local variables should not be declared and then immediately returned or thrown",
  "message": "Remove this useless assignment to local variable 'result'.",
  "file_path": "src/main/java/com/example/Service.java",
  "line_number": 25,
  "severity": "MINOR",
  "type": "CODE_SMELL",
  "status": "OPEN",
  "effort": 5,
  "debt": 5,
  "created_at": "2024-01-15T10:30:00Z"
}
```

## Rate Limiting

API requests are rate-limited to prevent abuse. Limits are:
- 1000 requests per hour per user
- 100 requests per minute per user

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642233600
```

## Pagination

List endpoints support pagination with the following parameters:
- `skip`: Number of records to skip
- `limit`: Maximum number of records to return

Response includes pagination metadata:
```json
{
  "data": [...],
  "total": 150,
  "skip": 0,
  "limit": 100,
  "has_more": true
}
```

## Webhooks

The API supports webhooks for real-time notifications. Configure webhooks in project settings to receive notifications for:
- New vulnerabilities
- Quality gate status changes
- Scan completion
- Issue updates

## Integration Examples

### Python Client Example
```python
import aiohttp
import asyncio

async def get_sast_projects():
    async with aiohttp.ClientSession() as session:
        headers = {"Authorization": "Bearer your-token"}
        async with session.get("http://localhost:8000/api/v1/sast/projects", headers=headers) as response:
            return await response.json()

# Usage
projects = await get_sast_projects()
```

### JavaScript Client Example
```javascript
const getSASTProjects = async () => {
  const response = await fetch('http://localhost:8000/api/v1/sast/projects', {
    headers: {
      'Authorization': 'Bearer your-token'
    }
  });
  return await response.json();
};
```

## Database Schema

The SAST API uses PostgreSQL with the following key tables:
- `sast_projects`: Project information
- `sast_scans`: Scan history and results
- `sast_issues`: Security issues and vulnerabilities
- `sast_security_hotspots`: Security hotspots
- `sast_duplications`: Code duplication analysis
- `sast_code_coverage`: Code coverage metrics
- `sast_quality_gates`: Quality gate configurations
- `sast_activities`: Project activity timeline
- `sast_contributors`: Contributor information

## Performance Considerations

- Use pagination for large datasets
- Implement caching for frequently accessed data
- Use filters to reduce data transfer
- Consider async processing for long-running operations

## Security

- All endpoints require authentication
- Input validation on all parameters
- SQL injection protection via parameterized queries
- Rate limiting to prevent abuse
- CORS configuration for web applications 