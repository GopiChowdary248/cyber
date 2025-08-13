import React, { useState, useEffect } from 'react';
import { apiIntegrationService, APIResponse } from '../../services/apiIntegrationService';
import { 
  CheckCircleIcon, 
  XCircleIcon, 
  ExclamationTriangleIcon,
  ClockIcon,
  ServerIcon,
  ShieldCheckIcon,
  UserGroupIcon,
  CloudIcon,
  NetworkIcon,
  DatabaseIcon,
  DevicePhoneMobileIcon,
  LockClosedIcon,
  EyeIcon,
  CogIcon
} from '@heroicons/react/24/outline';

interface EndpointStatus {
  name: string;
  endpoint: string;
  status: 'connected' | 'disconnected' | 'error' | 'checking';
  lastCheck: string;
  responseTime?: number;
  error?: string;
  icon: React.ComponentType<any>;
  description: string;
}

const BackendIntegrationStatus: React.FC = () => {
  const [endpoints, setEndpoints] = useState<EndpointStatus[]>([
    {
      name: 'Health Check',
      endpoint: '/health',
      status: 'checking',
      lastCheck: '-',
      icon: ServerIcon,
      description: 'Backend service health status'
    },
    {
      name: 'Authentication',
      endpoint: '/api/v1/auth',
      status: 'checking',
      lastCheck: '-',
      icon: ShieldCheckIcon,
      description: 'User authentication and authorization'
    },
    {
      name: 'User Management',
      endpoint: '/api/v1/users',
      status: 'checking',
      lastCheck: '-',
      icon: UserGroupIcon,
      description: 'User CRUD operations and management'
    },
    {
      name: 'IAM',
      endpoint: '/api/v1/iam',
      status: 'checking',
      lastCheck: '-',
      icon: LockClosedIcon,
      description: 'Identity and Access Management'
    },
    {
      name: 'DAST',
      endpoint: '/api/v1/dast',
      status: 'checking',
      lastCheck: '-',
      icon: EyeIcon,
      description: 'Dynamic Application Security Testing'
    },
    {
      name: 'RASP',
      endpoint: '/api/v1/rasp',
      status: 'checking',
      lastCheck: '-',
      icon: CogIcon,
      description: 'Runtime Application Self-Protection'
    },
    {
      name: 'Cloud Security',
      endpoint: '/api/v1/cloud-security',
      status: 'checking',
      lastCheck: '-',
      icon: CloudIcon,
      description: 'Multi-cloud security management'
    },
    {
      name: 'Network Security',
      endpoint: '/api/v1/network-security',
      status: 'checking',
      lastCheck: '-',
      icon: NetworkIcon,
      description: 'Network monitoring and protection'
    },
    {
      name: 'Data Security',
      endpoint: '/api/v1/data-security',
      status: 'checking',
      lastCheck: '-',
      icon: DatabaseIcon,
      description: 'Data protection and encryption'
    },
    {
      name: 'Endpoint Security',
      endpoint: '/api/v1/endpoint-antivirus-edr',
      status: 'checking',
      lastCheck: '-',
      icon: DevicePhoneMobileIcon,
      description: 'Device and antivirus management'
    },
    {
      name: 'Device Control',
      endpoint: '/api/v1/device-control',
      status: 'checking',
      lastCheck: '-',
      icon: CogIcon,
      description: 'Device control and policies'
    },
    {
      name: 'Data Protection',
      endpoint: '/api/v1/data-protection',
      status: 'checking',
      lastCheck: '-',
      icon: LockClosedIcon,
      description: 'Privacy and compliance management'
    },
    {
      name: 'Security Operations',
      endpoint: '/api/v1/security',
      status: 'checking',
      lastCheck: '-',
      icon: ShieldCheckIcon,
      description: 'Security operations and incidents'
    },
    {
      name: 'Monitoring',
      endpoint: '/api/v1/monitoring',
      status: 'checking',
      lastCheck: '-',
      icon: EyeIcon,
      description: 'Security monitoring and alerts'
    },
    {
      name: 'SIEM/SOAR',
      endpoint: '/api/v1/siem-soar',
      status: 'checking',
      lastCheck: '-',
      icon: ServerIcon,
      description: 'Security monitoring and automation'
    }
  ]);

  const [overallStatus, setOverallStatus] = useState<'healthy' | 'warning' | 'critical'>('checking');
  const [lastFullCheck, setLastFullCheck] = useState<string>('-');
  const [isChecking, setIsChecking] = useState(false);

  const checkEndpoint = async (endpoint: EndpointStatus): Promise<void> => {
    const startTime = Date.now();
    
    try {
      let response: APIResponse;
      
      switch (endpoint.name) {
        case 'Health Check':
          response = await apiIntegrationService.checkHealth();
          break;
        case 'Authentication':
          response = await apiIntegrationService.getCurrentUser();
          break;
        case 'User Management':
          response = await apiIntegrationService.getUsers({ page: 1, limit: 1 });
          break;
        case 'IAM':
          response = await apiIntegrationService.getIAMUsers({ page: 1, limit: 1 });
          break;
        case 'DAST':
          response = await apiIntegrationService.getDASTProjects({ page: 1, limit: 1 });
          break;
        case 'RASP':
          response = await apiIntegrationService.getRASPProjects({ page: 1, limit: 1 });
          break;
        case 'Cloud Security':
          response = await apiIntegrationService.getCloudSecurityStatus();
          break;
        case 'Network Security':
          response = await apiIntegrationService.getNetworkSecurityStatus();
          break;
        case 'Data Security':
          response = await apiIntegrationService.getDataSecurityStatus();
          break;
        case 'Endpoint Security':
          response = await apiIntegrationService.getEndpointSecurityStatus();
          break;
        case 'Device Control':
          response = await apiIntegrationService.getDeviceControlStatus();
          break;
        case 'Data Protection':
          response = await apiIntegrationService.getDataProtectionStatus();
          break;
        case 'Security Operations':
          response = await apiIntegrationService.getSecurityOperationsStatus();
          break;
        case 'Monitoring':
          response = await apiIntegrationService.getMonitoringStatus();
          break;
        case 'SIEM/SOAR':
          response = await apiIntegrationService.getSIEMSOARStatus();
          break;
        default:
          response = { success: false, error: 'Unknown endpoint', timestamp: new Date().toISOString() };
      }

      const responseTime = Date.now() - startTime;
      
      setEndpoints(prev => prev.map(ep => 
        ep.name === endpoint.name 
          ? {
              ...ep,
              status: response.success ? 'connected' : 'error',
              lastCheck: new Date().toLocaleTimeString(),
              responseTime,
              error: response.error
            }
          : ep
      ));

    } catch (error: any) {
      const responseTime = Date.now() - startTime;
      
      setEndpoints(prev => prev.map(ep => 
        ep.name === endpoint.name 
          ? {
              ...ep,
              status: 'error',
              lastCheck: new Date().toLocaleTimeString(),
              responseTime,
              error: error.message || 'Connection failed'
            }
          : ep
      ));
    }
  };

  const checkAllEndpoints = async (): Promise<void> => {
    setIsChecking(true);
    setLastFullCheck(new Date().toLocaleTimeString());
    
    // Check all endpoints concurrently
    const promises = endpoints.map(endpoint => checkEndpoint(endpoint));
    await Promise.all(promises);
    
    setIsChecking(false);
  };

  useEffect(() => {
    checkAllEndpoints();
    
    // Set up periodic health checks every 5 minutes
    const interval = setInterval(checkAllEndpoints, 5 * 60 * 1000);
    
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const connectedCount = endpoints.filter(ep => ep.status === 'connected').length;
    const errorCount = endpoints.filter(ep => ep.status === 'error').length;
    const totalCount = endpoints.length;
    
    if (connectedCount === totalCount) {
      setOverallStatus('healthy');
    } else if (errorCount > totalCount / 2) {
      setOverallStatus('critical');
    } else if (errorCount > 0) {
      setOverallStatus('warning');
    }
  }, [endpoints]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'connected':
        return <CheckCircleIcon className="h-6 w-6 text-green-500" />;
      case 'disconnected':
        return <XCircleIcon className="h-6 w-6 text-red-500" />;
      case 'error':
        return <ExclamationTriangleIcon className="h-6 w-6 text-red-500" />;
      case 'checking':
        return <ClockIcon className="h-6 w-6 text-yellow-500" />;
      default:
        return <ClockIcon className="h-6 w-6 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'disconnected':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'error':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'checking':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getOverallStatusColor = () => {
    switch (overallStatus) {
      case 'healthy':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'warning':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'critical':
        return 'bg-red-100 text-red-800 border-red-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="bg-white rounded-lg shadow-lg overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-2xl font-bold text-gray-900">Backend Integration Status</h2>
              <p className="text-sm text-gray-600">
                Real-time status of all backend API endpoints and services
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <div className={`px-3 py-1 rounded-full text-sm font-medium border ${getOverallStatusColor()}`}>
                Overall: {overallStatus === 'healthy' ? 'Healthy' : overallStatus === 'warning' ? 'Warning' : 'Critical'}
              </div>
              <button
                onClick={checkAllEndpoints}
                disabled={isChecking}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isChecking ? 'Checking...' : 'Refresh All'}
              </button>
            </div>
          </div>
          <div className="mt-2 text-sm text-gray-500">
            Last full check: {lastFullCheck} | Auto-refresh every 5 minutes
          </div>
        </div>

        {/* Statistics */}
        <div className="px-6 py-4 bg-gray-50 border-b border-gray-200">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-white p-4 rounded-lg border">
              <div className="flex items-center">
                <CheckCircleIcon className="h-8 w-8 text-green-500" />
                <div className="ml-3">
                  <p className="text-sm font-medium text-gray-500">Connected</p>
                  <p className="text-2xl font-bold text-green-600">
                    {endpoints.filter(ep => ep.status === 'connected').length}
                  </p>
                </div>
              </div>
            </div>
            <div className="bg-white p-4 rounded-lg border">
              <div className="flex items-center">
                <ExclamationTriangleIcon className="h-8 w-8 text-yellow-500" />
                <div className="ml-3">
                  <p className="text-sm font-medium text-gray-500">Checking</p>
                  <p className="text-2xl font-bold text-yellow-600">
                    {endpoints.filter(ep => ep.status === 'checking').length}
                  </p>
                </div>
              </div>
            </div>
            <div className="bg-white p-4 rounded-lg border">
              <div className="flex items-center">
                <XCircleIcon className="h-8 w-8 text-red-500" />
                <div className="ml-3">
                  <p className="text-sm font-medium text-gray-500">Errors</p>
                  <p className="text-2xl font-bold text-red-600">
                    {endpoints.filter(ep => ep.status === 'error').length}
                  </p>
                </div>
              </div>
            </div>
            <div className="bg-white p-4 rounded-lg border">
              <div className="flex items-center">
                <ServerIcon className="h-8 w-8 text-blue-500" />
                <div className="ml-3">
                  <p className="text-sm font-medium text-gray-500">Total</p>
                  <p className="text-2xl font-bold text-blue-600">{endpoints.length}</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Endpoints Grid */}
        <div className="px-6 py-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {endpoints.map((endpoint) => (
              <div key={endpoint.name} className="bg-white border rounded-lg p-4 hover:shadow-md transition-shadow">
                <div className="flex items-start justify-between">
                  <div className="flex items-center space-x-3">
                    <endpoint.icon className="h-6 w-6 text-gray-600" />
                    <div>
                      <h3 className="text-sm font-medium text-gray-900">{endpoint.name}</h3>
                      <p className="text-xs text-gray-500">{endpoint.description}</p>
                    </div>
                  </div>
                  {getStatusIcon(endpoint.status)}
                </div>
                
                <div className="mt-3 space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-gray-500">Endpoint:</span>
                    <span className="font-mono text-gray-700">{endpoint.endpoint}</span>
                  </div>
                  
                  <div className="flex justify-between text-xs">
                    <span className="text-gray-500">Status:</span>
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(endpoint.status)}`}>
                      {endpoint.status}
                    </span>
                  </div>
                  
                  <div className="flex justify-between text-xs">
                    <span className="text-gray-500">Last Check:</span>
                    <span className="text-gray-700">{endpoint.lastCheck}</span>
                  </div>
                  
                  {endpoint.responseTime && (
                    <div className="flex justify-between text-xs">
                      <span className="text-gray-500">Response Time:</span>
                      <span className="text-gray-700">{endpoint.responseTime}ms</span>
                    </div>
                  )}
                  
                  {endpoint.error && (
                    <div className="mt-2 p-2 bg-red-50 border border-red-200 rounded">
                      <p className="text-xs text-red-700">{endpoint.error}</p>
                    </div>
                  )}
                </div>
                
                <div className="mt-3">
                  <button
                    onClick={() => checkEndpoint(endpoint)}
                    disabled={endpoint.status === 'checking'}
                    className="w-full px-3 py-1 text-xs bg-gray-100 text-gray-700 rounded hover:bg-gray-200 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {endpoint.status === 'checking' ? 'Checking...' : 'Test Connection'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-gray-50 border-t border-gray-200">
          <div className="text-center text-sm text-gray-500">
            <p>Backend API Integration Status Dashboard</p>
            <p className="mt-1">
              Monitors {endpoints.length} endpoints across authentication, security, and management services
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BackendIntegrationStatus;
