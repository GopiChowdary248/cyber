# Network Security Module Documentation

## Overview

The Network Security module provides comprehensive network security management capabilities including Firewalls, IDS/IPS, VPNs, and Network Access Control (NAC). This module integrates with various security tools and provides a unified interface for monitoring and managing network security infrastructure.

## Architecture

### Backend (FastAPI)
- **Framework**: FastAPI with Python 3.11
- **Database**: PostgreSQL for persistent storage
- **API Documentation**: Swagger/OpenAPI at `/docs`
- **Location**: `backend/app/api/v1/endpoints/network_security.py`

### Frontend (React)
- **Framework**: React with TypeScript
- **Styling**: Tailwind CSS
- **Icons**: Heroicons
- **Location**: `frontend/src/components/`

## Components

### 1. Firewalls
**Tools Integrated:**
- Cisco ASA
- Palo Alto
- Fortinet

**Features:**
- Real-time status monitoring
- Rule count tracking
- Connection statistics (blocked/allowed)
- Version management
- Sync capabilities

**API Endpoints:**
- `GET /api/v1/network-security/firewalls` - List all firewalls
- `GET /api/v1/network-security/firewalls/{name}` - Get specific firewall details
- `POST /api/v1/network-security/firewalls/{name}/sync` - Trigger firewall sync

### 2. IDS/IPS (Intrusion Detection/Prevention Systems)
**Tools Integrated:**
- Snort
- Suricata
- Bro/Zeek

**Features:**
- Alert monitoring
- Attack detection and blocking
- False positive tracking
- Detection rate calculation
- System testing capabilities

**API Endpoints:**
- `GET /api/v1/network-security/idsips` - List all IDS/IPS systems
- `GET /api/v1/network-security/idsips/{name}` - Get specific IDS/IPS details
- `POST /api/v1/network-security/idsips/{name}/test` - Test IDS/IPS functionality

### 3. VPNs (Virtual Private Networks)
**Tools Integrated:**
- OpenVPN
- IPsec
- WireGuard

**Features:**
- Connection monitoring
- User management
- Bandwidth usage tracking
- Service restart capabilities
- Connection rate analysis

**API Endpoints:**
- `GET /api/v1/network-security/vpns` - List all VPN systems
- `GET /api/v1/network-security/vpns/{name}` - Get specific VPN details
- `POST /api/v1/network-security/vpns/{name}/restart` - Restart VPN service

### 4. NAC (Network Access Control)
**Tools Integrated:**
- Cisco ISE
- Aruba ClearPass

**Features:**
- Device management
- Compliance monitoring
- Quarantine capabilities
- Policy enforcement
- Compliance scoring

**API Endpoints:**
- `GET /api/v1/network-security/nac` - List all NAC systems
- `GET /api/v1/network-security/nac/{name}` - Get specific NAC details

## Frontend Components

### 1. NetworkSecuritySidebar
**Location**: `frontend/src/components/NetworkSecuritySidebar.tsx`

**Features:**
- Collapsible navigation menu
- Category-based organization
- Quick action buttons
- Visual status indicators

**Navigation Structure:**
```
Network Security
├── Firewalls
│   ├── Cisco ASA
│   ├── Palo Alto
│   └── Fortinet
├── IDS/IPS
│   ├── Snort
│   ├── Suricata
│   └── Bro/Zeek
├── VPNs
│   ├── OpenVPN
│   ├── IPsec
│   └── WireGuard
└── NAC
    ├── Cisco ISE
    └── Aruba ClearPass
```

### 2. NetworkSecurityDashboard
**Location**: `frontend/src/components/NetworkSecurityDashboard.tsx`

**Features:**
- Main dashboard container
- Dynamic content rendering
- State management
- Category and provider selection

### 3. Individual Dashboard Components

#### FirewallDashboard
**Location**: `frontend/src/components/FirewallDashboard.tsx`

**Features:**
- Real-time metrics display
- Status indicators
- Sync functionality
- Performance analytics

#### IDSIPSDashboard
**Location**: `frontend/src/components/IDSIPSDashboard.tsx`

**Features:**
- Alert monitoring
- Threat detection metrics
- System testing
- Performance analysis

#### VPNDashboard
**Location**: `frontend/src/components/VPNDashboard.tsx`

**Features:**
- Connection monitoring
- User statistics
- Bandwidth tracking
- Service management

#### NACDashboard
**Location**: `frontend/src/components/NACDashboard.tsx`

**Features:**
- Device compliance monitoring
- Quarantine management
- Policy enforcement
- Compliance scoring

### 4. Overview and Management Components

#### NetworkSecurityOverview
**Location**: `frontend/src/components/NetworkSecurityOverview.tsx`

**Features:**
- Aggregated metrics
- Component status overview
- Security score calculation
- Recent activity monitoring

#### SecurityAlerts
**Location**: `frontend/src/components/SecurityAlerts.tsx`

**Features:**
- Alert filtering and management
- Severity-based categorization
- Source tracking
- Status management

#### NetworkDevices
**Location**: `frontend/src/components/NetworkDevices.tsx`

**Features:**
- Device inventory management
- Compliance status tracking
- Quarantine/release actions
- Device type categorization

## API Data Models

### FirewallProvider
```typescript
interface FirewallProvider {
  name: string;
  status: string;
  version: string;
  rules_count: number;
  blocked_connections: number;
  allowed_connections: number;
  last_updated: string;
}
```

### IDSIPSProvider
```typescript
interface IDSIPSProvider {
  name: string;
  status: string;
  version: string;
  alerts_count: number;
  blocked_attacks: number;
  false_positives: number;
  last_updated: string;
}
```

### VPNProvider
```typescript
interface VPNProvider {
  name: string;
  status: string;
  version: string;
  active_connections: number;
  total_users: number;
  bandwidth_usage: number;
  last_updated: string;
}
```

### NACProvider
```typescript
interface NACProvider {
  name: string;
  status: string;
  version: string;
  managed_devices: number;
  quarantined_devices: number;
  compliance_score: number;
  last_updated: string;
}
```

### SecurityAlert
```typescript
interface SecurityAlert {
  id: string;
  title: string;
  description: string;
  severity: string;
  source: string;
  timestamp: string;
  status: string;
  device: string;
}
```

### NetworkDevice
```typescript
interface NetworkDevice {
  id: string;
  name: string;
  type: string;
  ip_address: string;
  status: string;
  last_seen: string;
  compliance_status: string;
}
```

## Installation and Setup

### Prerequisites
- Docker and Docker Compose
- Node.js 16+ (for development)
- Python 3.11+ (for development)

### Backend Setup
1. Navigate to the backend directory
2. Install dependencies: `pip install -r requirements.txt`
3. The Network Security module is automatically included in the main API

### Frontend Setup
1. Navigate to the frontend directory
2. Install dependencies: `npm install`
3. The Network Security components are automatically available

### Docker Deployment
```bash
# Build and start all services
docker-compose up --build

# Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Documentation: http://localhost:8000/docs
```

## Usage

### Accessing the Network Security Module
1. Navigate to the application frontend
2. Access the Network Security section
3. Use the left sidebar to navigate between different security components
4. Select specific tools to view detailed dashboards

### API Usage Examples

#### Get Network Security Metrics
```bash
curl http://localhost:8000/api/v1/network-security/metrics
```

#### Get Firewall Status
```bash
curl http://localhost:8000/api/v1/network-security/firewalls
```

#### Get Security Alerts
```bash
curl http://localhost:8000/api/v1/network-security/alerts
```

#### Quarantine a Device
```bash
curl -X POST http://localhost:8000/api/v1/network-security/devices/{device_id}/quarantine
```

## Security Features

### Authentication
- Bearer token authentication
- Role-based access control
- Session management

### Data Protection
- Input validation
- SQL injection prevention
- XSS protection
- CSRF protection

### Monitoring
- Real-time status monitoring
- Alert generation
- Performance metrics
- Compliance tracking

## Integration Capabilities

### External Tools
The module is designed to integrate with:
- Security information and event management (SIEM) systems
- Threat intelligence platforms
- Configuration management databases (CMDB)
- Ticketing systems

### API Integration
- RESTful API endpoints
- WebSocket support for real-time updates
- Webhook support for external integrations
- Standardized data formats (JSON)

## Testing

### Backend Testing
```bash
# Run backend tests
cd backend
pytest tests/test_network_security.py
```

### Frontend Testing
```bash
# Run frontend tests
cd frontend
npm test
```

### API Testing
```bash
# Test API endpoints
curl http://localhost:8000/api/v1/network-security/health
```

## Monitoring and Maintenance

### Health Checks
- Automatic health monitoring
- Component status tracking
- Performance metrics collection
- Error logging and alerting

### Backup and Recovery
- Database backup procedures
- Configuration backup
- Disaster recovery planning
- Data retention policies

## Troubleshooting

### Common Issues

#### API Connection Issues
1. Check if the backend container is running
2. Verify the API endpoint is accessible
3. Check authentication tokens
4. Review error logs

#### Frontend Display Issues
1. Clear browser cache
2. Check browser console for errors
3. Verify API responses
4. Check component state

#### Data Synchronization Issues
1. Check network connectivity
2. Verify API credentials
3. Review sync logs
4. Check data format compatibility

### Log Locations
- Backend logs: `backend/logs/`
- Frontend logs: Browser console
- Docker logs: `docker-compose logs`

## Future Enhancements

### Planned Features
- Advanced threat intelligence integration
- Machine learning-based anomaly detection
- Automated incident response
- Enhanced reporting and analytics
- Mobile application support

### Integration Roadmap
- Additional security tool integrations
- Third-party threat feeds
- Compliance framework support
- Advanced automation capabilities

## Support and Documentation

### Additional Resources
- API Documentation: `http://localhost:8000/docs`
- Swagger UI: `http://localhost:8000/redoc`
- Component Library: Frontend component documentation
- Integration Guides: Tool-specific integration documentation

### Contact Information
For technical support and questions about the Network Security module, please refer to the main project documentation and support channels. 