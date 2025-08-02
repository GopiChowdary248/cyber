# Cloud Security API Documentation

## Overview
The Cloud Security module provides comprehensive management of cloud security posture across multiple providers including CSPM (Cloud Security Posture Management), CASB (Cloud Access Security Broker), and Cloud-Native Security tools.

## Base URL
```
http://localhost:8000/api/v1/cloud-security
```

## Authentication
All endpoints require Bearer token authentication. Include the Authorization header:
```
Authorization: Bearer <your_token>
```

## Endpoints

### Health Check
**GET** `/health`
- **Description**: Check the health status of the Cloud Security module
- **Response**: Module status and provider counts
- **Authentication**: Required

### CSPM (Cloud Security Posture Management)

#### Get All CSPM Providers
**GET** `/cspm`
- **Description**: Retrieve all CSPM providers and their status
- **Response**: List of CSPM providers with metrics
- **Authentication**: Required

#### Get Specific CSPM Provider
**GET** `/cspm/{provider_name}`
- **Description**: Get detailed information for a specific CSPM provider
- **Parameters**: `provider_name` (string) - Name of the provider
- **Response**: CSPM provider details
- **Authentication**: Required

#### Trigger CSPM Scan
**POST** `/cspm/{provider_name}/scan`
- **Description**: Trigger a new security scan for a CSPM provider
- **Parameters**: `provider_name` (string) - Name of the provider
- **Response**: Scan initiation status
- **Authentication**: Required

### CASB (Cloud Access Security Broker)

#### Get All CASB Providers
**GET** `/casb`
- **Description**: Retrieve all CASB providers and their status
- **Response**: List of CASB providers with metrics
- **Authentication**: Required

#### Get Specific CASB Provider
**GET** `/casb/{provider_name}`
- **Description**: Get detailed information for a specific CASB provider
- **Parameters**: `provider_name` (string) - Name of the provider
- **Response**: CASB provider details
- **Authentication**: Required

#### Trigger CASB Sync
**POST** `/casb/{provider_name}/sync`
- **Description**: Trigger a new data sync for a CASB provider
- **Parameters**: `provider_name` (string) - Name of the provider
- **Response**: Sync initiation status
- **Authentication**: Required

### Cloud-Native Security

#### Get All Cloud-Native Providers
**GET** `/cloud-native`
- **Description**: Retrieve all Cloud-Native security providers and their status
- **Response**: List of Cloud-Native providers with metrics
- **Authentication**: Required

#### Get Specific Cloud-Native Provider
**GET** `/cloud-native/{provider_name}`
- **Description**: Get detailed information for a specific Cloud-Native provider
- **Parameters**: `provider_name` (string) - Name of the provider
- **Response**: Cloud-Native provider details
- **Authentication**: Required

### Security Findings

#### Get Security Findings
**GET** `/findings`
- **Description**: Retrieve security findings with optional filters
- **Query Parameters**:
  - `severity` (optional): Filter by severity (high, medium, low)
  - `provider` (optional): Filter by provider name
  - `category` (optional): Filter by category (CSPM, CASB, Cloud-Native)
  - `status` (optional): Filter by status (open, in_progress, resolved)
- **Response**: List of security findings
- **Authentication**: Required

#### Get Specific Finding
**GET** `/findings/{finding_id}`
- **Description**: Get detailed information for a specific security finding
- **Parameters**: `finding_id` (string) - ID of the finding
- **Response**: Security finding details
- **Authentication**: Required

#### Update Finding Status
**PUT** `/findings/{finding_id}/status`
- **Description**: Update the status of a security finding
- **Parameters**: 
  - `finding_id` (string) - ID of the finding
  - `status` (string) - New status
- **Response**: Update confirmation
- **Authentication**: Required

### Metrics and Overview

#### Get Cloud Security Metrics
**GET** `/metrics`
- **Description**: Get overall cloud security metrics
- **Response**: Comprehensive security metrics
- **Authentication**: Required

#### Get Cloud Security Overview
**GET** `/overview`
- **Description**: Get comprehensive overview of all cloud security components
- **Response**: Overview data for CSPM, CASB, Cloud-Native, and findings
- **Authentication**: Required

## Data Models

### CSPMProvider
```json
{
  "name": "string",
  "status": "string",
  "last_scan": "datetime",
  "vulnerabilities_found": "integer",
  "compliance_score": "float",
  "misconfigurations": "integer",
  "recommendations": "integer"
}
```

### CASBProvider
```json
{
  "name": "string",
  "status": "string",
  "monitored_apps": "integer",
  "dlp_violations": "integer",
  "threat_detections": "integer",
  "policy_violations": "integer",
  "last_sync": "datetime"
}
```

### CloudNativeProvider
```json
{
  "name": "string",
  "status": "string",
  "protected_resources": "integer",
  "active_threats": "integer",
  "security_score": "float",
  "last_updated": "datetime"
}
```

### SecurityFinding
```json
{
  "id": "string",
  "severity": "string",
  "title": "string",
  "description": "string",
  "provider": "string",
  "category": "string",
  "created_at": "datetime",
  "status": "string"
}
```

## Supported Providers

### CSPM Providers
- Prisma Cloud
- Dome9
- Wiz

### CASB Providers
- Netskope
- McAfee MVISION
- Microsoft Defender for Cloud Apps

### Cloud-Native Providers
- AWS Shield
- Azure Security Center
- GCP Security Command Center

## Frontend Integration

The Cloud Security module includes a comprehensive React frontend with:

1. **CloudSecuritySidebar**: Collapsible navigation menu with all providers
2. **CloudSecurityDashboard**: Main dashboard component
3. **CSPMDashboard**: Detailed CSPM provider dashboard
4. **CASBDashboard**: Detailed CASB provider dashboard
5. **CloudNativeDashboard**: Detailed Cloud-Native provider dashboard
6. **SecurityOverview**: Overall security metrics and status
7. **SecurityFindings**: Security findings management with filtering
8. **CloudApps**: Cloud applications monitoring

## Usage Examples

### Get CSPM Providers
```bash
curl -X GET "http://localhost:8000/api/v1/cloud-security/cspm" \
  -H "Authorization: Bearer your_token_here"
```

### Trigger CSPM Scan
```bash
curl -X POST "http://localhost:8000/api/v1/cloud-security/cspm/Prisma%20Cloud/scan" \
  -H "Authorization: Bearer your_token_here"
```

### Get Security Findings
```bash
curl -X GET "http://localhost:8000/api/v1/cloud-security/findings?severity=high" \
  -H "Authorization: Bearer your_token_here"
```

### Get Overview
```bash
curl -X GET "http://localhost:8000/api/v1/cloud-security/overview" \
  -H "Authorization: Bearer your_token_here"
```

## Error Handling

The API returns standard HTTP status codes:
- `200`: Success
- `401`: Authentication required
- `404`: Resource not found
- `500`: Internal server error

Error responses include a `detail` field with error information.

## Rate Limiting

Currently, no rate limiting is implemented. In production, consider implementing appropriate rate limiting based on your requirements.

## Security Considerations

1. All endpoints require authentication
2. Use HTTPS in production
3. Implement proper token validation
4. Consider implementing role-based access control
5. Log all API access for audit purposes 