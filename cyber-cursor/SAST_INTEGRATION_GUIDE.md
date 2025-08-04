# SAST Integration Guide

## Overview

This guide provides comprehensive instructions for integrating Static Application Security Testing (SAST) functionality into your CyberShield security platform. The integration includes a complete backend service, modern React Native frontend components, and PostgreSQL database integration.

## Architecture

### Backend Components

1. **SAST Service** (`backend/app/services/sast_service.py`)
   - Core business logic for SAST operations
   - Project management, scanning, and vulnerability analysis
   - Mock vulnerability generation for demonstration

2. **SAST API Endpoints** (`backend/app/api/v1/endpoints/sast.py`)
   - RESTful API for SAST functionality
   - Dashboard, projects, scans, and vulnerabilities endpoints
   - Comprehensive filtering and statistics

3. **SAST Schemas** (`backend/app/schemas/sast_schemas.py`)
   - Request/response models for API validation
   - Type-safe data structures for all SAST operations

### Frontend Components

1. **SAST Dashboard** (`frontend/src/components/SAST/SASTDashboard.tsx`)
   - Main dashboard with statistics and overview
   - Security score visualization
   - Recent activity and quick actions

2. **SAST Projects** (`frontend/src/components/SAST/SASTProjects.tsx`)
   - Project management interface
   - Create, view, and manage SAST projects
   - Language-specific project configuration

3. **SAST Vulnerabilities** (`frontend/src/components/SAST/SASTVulnerabilities.tsx`)
   - Vulnerability listing and filtering
   - Detailed vulnerability information
   - Severity-based categorization

### Database Integration

- **PostgreSQL Tables**: `sast_projects`, `sast_scans`, `sast_vulnerabilities`
- **Relationships**: Projects → Scans → Vulnerabilities
- **Indexing**: Optimized for query performance

## Installation & Setup

### 1. Backend Setup

```bash
# Navigate to backend directory
cd backend

# Install dependencies
pip install -r requirements.txt

# The SAST service is already integrated into the main backend
# No additional setup required
```

### 2. Frontend Setup

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Install additional required packages
npm install @react-native-picker/picker expo-linear-gradient

# Start the development server
npm start
```

### 3. Database Setup

The SAST tables are already included in the main database schema. No additional setup is required.

## API Endpoints

### Dashboard & Overview

- `GET /api/v1/sast/dashboard` - Get SAST dashboard statistics
- `GET /api/v1/sast/overview` - Get SAST overview data
- `GET /api/v1/sast/statistics` - Get comprehensive SAST statistics

### Project Management

- `GET /api/v1/sast/projects` - List all SAST projects
- `POST /api/v1/sast/projects` - Create new SAST project
- `GET /api/v1/sast/projects/{project_id}` - Get project details

### Scan Management

- `POST /api/v1/sast/scans` - Start new SAST scan
- `GET /api/v1/sast/scans/{scan_id}` - Get scan details
- `GET /api/v1/sast/projects/{project_id}/scans` - Get project scan history

### Vulnerability Management

- `GET /api/v1/sast/vulnerabilities` - List vulnerabilities with filtering
- `GET /api/v1/sast/projects/{project_id}/vulnerabilities` - Get project vulnerabilities

### Configuration

- `GET /api/v1/sast/rules` - Get detection rules
- `GET /api/v1/sast/languages` - Get supported languages

## Usage Examples

### Creating a New SAST Project

```javascript
const createProject = async (projectData) => {
  const response = await fetch('http://localhost:8000/api/v1/sast/projects', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      name: 'My Web Application',
      repository_url: 'https://github.com/user/my-app',
      language: 'javascript',
      description: 'React-based web application'
    })
  });
  
  return response.json();
};
```

### Starting a SAST Scan

```javascript
const startScan = async (projectId) => {
  const response = await fetch('http://localhost:8000/api/v1/sast/scans', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      project_id: projectId,
      scan_type: 'static',
      scan_config: {
        include_patterns: ['**/*.js', '**/*.jsx'],
        exclude_patterns: ['**/node_modules/**']
      }
    })
  });
  
  return response.json();
};
```

### Fetching Vulnerabilities

```javascript
const getVulnerabilities = async (filters = {}) => {
  const params = new URLSearchParams(filters);
  const response = await fetch(`http://localhost:8000/api/v1/sast/vulnerabilities?${params}`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    }
  });
  
  return response.json();
};
```

## Frontend Integration

### Navigation Setup

Add SAST routes to your navigation:

```javascript
// In your navigation configuration
const SASTStack = createStackNavigator();

function SASTNavigator() {
  return (
    <SASTStack.Navigator>
      <SASTStack.Screen name="SASTDashboard" component={SASTDashboard} />
      <SASTStack.Screen name="SASTProjects" component={SASTProjects} />
      <SASTStack.Screen name="SASTVulnerabilities" component={SASTVulnerabilities} />
      <SASTStack.Screen name="SASTProjectDetail" component={SASTProjectDetail} />
      <SASTStack.Screen name="StartSASTScan" component={StartSASTScan} />
    </SASTStack.Navigator>
  );
}
```

### Component Usage

```javascript
import SASTDashboard from './components/SAST/SASTDashboard';
import SASTProjects from './components/SAST/SASTProjects';
import SASTVulnerabilities from './components/SAST/SASTVulnerabilities';

// Use in your main app
<SASTDashboard />
```

## Features

### 1. Dashboard Overview
- **Security Score**: Visual representation of overall security posture
- **Statistics**: Total projects, scans, and vulnerabilities
- **Vulnerability Breakdown**: Severity-based categorization
- **Recent Activity**: Latest scan results and findings

### 2. Project Management
- **Multi-language Support**: Java, Python, JavaScript, PHP, Go, Ruby, C#, C++
- **Repository Integration**: GitHub/GitLab URL support
- **Scan Configuration**: Customizable scan settings
- **Project Statistics**: Security scores and scan history

### 3. Vulnerability Analysis
- **Severity Levels**: Critical, High, Medium, Low
- **CWE Integration**: Common Weakness Enumeration support
- **Code Location**: File path and line number identification
- **Vulnerable Code**: Code snippet highlighting

### 4. Advanced Features
- **Real-time Scanning**: Background scan processing
- **Filtering & Search**: Advanced vulnerability filtering
- **Detailed Reports**: Comprehensive vulnerability reports
- **Security Recommendations**: Remediation guidance

## Security Considerations

### 1. Authentication
- All API endpoints require authentication
- JWT token-based authorization
- Role-based access control

### 2. Input Validation
- Comprehensive input validation using Pydantic schemas
- SQL injection prevention
- XSS protection

### 3. Data Protection
- Sensitive data encryption
- Secure API communication (HTTPS)
- Audit logging for all operations

## Customization

### Adding New Languages

1. Update `supported_languages` in `sast_service.py`
2. Add language-specific rules in `scan_rules`
3. Update frontend language picker options

### Custom Detection Rules

1. Extend the `SASTService` class
2. Add custom rule patterns
3. Implement language-specific analyzers

### UI Customization

1. Modify component styles in StyleSheet
2. Update color schemes and themes
3. Add custom icons and branding

## Testing

### Backend Testing

```bash
# Run SAST service tests
cd backend
python -m pytest tests/test_sast_service.py

# Run API endpoint tests
python -m pytest tests/test_sast_endpoints.py
```

### Frontend Testing

```bash
# Run component tests
cd frontend
npm test

# Run integration tests
npm run test:integration
```

## Troubleshooting

### Common Issues

1. **API Connection Errors**
   - Verify backend server is running
   - Check authentication token
   - Ensure correct API endpoints

2. **Database Connection Issues**
   - Verify PostgreSQL is running
   - Check database credentials
   - Ensure tables are created

3. **Frontend Build Errors**
   - Clear npm cache: `npm cache clean --force`
   - Reinstall dependencies: `rm -rf node_modules && npm install`
   - Check React Native version compatibility

### Debug Mode

Enable debug logging:

```python
# In backend/app/services/sast_service.py
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Performance Optimization

### Backend Optimization

1. **Database Indexing**: Optimize query performance
2. **Caching**: Implement Redis caching for frequently accessed data
3. **Async Processing**: Use background tasks for long-running scans

### Frontend Optimization

1. **Lazy Loading**: Implement component lazy loading
2. **Image Optimization**: Optimize icons and images
3. **Memory Management**: Proper cleanup of event listeners

## Deployment

### Production Setup

1. **Environment Variables**: Configure production settings
2. **SSL/TLS**: Enable HTTPS for secure communication
3. **Monitoring**: Implement application monitoring
4. **Backup**: Regular database backups

### Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build individual containers
docker build -t sast-backend ./backend
docker build -t sast-frontend ./frontend
```

## Support & Maintenance

### Regular Maintenance

1. **Security Updates**: Keep dependencies updated
2. **Database Maintenance**: Regular cleanup and optimization
3. **Performance Monitoring**: Monitor application performance
4. **Backup Verification**: Test backup and recovery procedures

### Support Resources

- **Documentation**: This guide and API documentation
- **Code Comments**: Inline code documentation
- **Logs**: Application and error logs
- **Community**: GitHub issues and discussions

## Conclusion

This SAST integration provides a comprehensive, scalable, and secure solution for static application security testing. The modular architecture allows for easy customization and extension while maintaining high performance and security standards.

For additional support or feature requests, please refer to the project documentation or create an issue in the repository. 