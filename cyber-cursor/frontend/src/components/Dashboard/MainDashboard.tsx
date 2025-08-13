import React, { useState, useEffect } from 'react';
import {
  Shield, 
  Code, 
  Search, 
  Cloud, 
  Monitor, 
  Usb,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Activity,
  RefreshCw,
  TrendingUp,
  AlertCircle,
  CheckCircle2
} from 'lucide-react';
import { integrationService, IntegrationStatus } from '../../services/integrationService';
import { integrationsService, IntegrationMetrics } from '../../services/integrationsService';

interface SecurityModule {
  id: string;
  name: string;
  description: string;
  icon: string;
  color: string;
  status: 'active' | 'warning' | 'error' | 'inactive';
  endpoint: string;
  alerts?: number;
  health_score?: number;
  response_time?: number;
}

const MainDashboard: React.FC = () => {
  const [modules, setModules] = useState<SecurityModule[]>([]);
  const [integrationMetrics, setIntegrationMetrics] = useState<IntegrationMetrics | null>(null);
  const [moduleStatuses, setModuleStatuses] = useState<IntegrationStatus[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefhing] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<string>('');

  // Initialize modules with default data
  const initializeModules = (): SecurityModule[] => [
    {
      id: 'sast',
      name: 'Static Application Security Testing',
      description: 'Code analysis and vulnerability detection',
      icon: 'code',
      color: '#2196F3',
      status: 'inactive',
      endpoint: '/api/v1/sast',
      alerts: 0,
      health_score: 0,
      response_time: 0
    },
    {
      id: 'dast',
      name: 'Dynamic Application Security Testing',
      description: 'Runtime security testing and vulnerability scanning',
      icon: 'security',
      color: '#FF5722',
      status: 'inactive',
      endpoint: '/api/v1/dast',
      alerts: 0,
      health_score: 0,
      response_time: 0
    },
    {
      id: 'rasp',
      name: 'Runtime Application Self-Protection',
      description: 'Real-time application protection and monitoring',
      icon: 'shield',
      color: '#4CAF50',
      status: 'inactive',
      endpoint: '/api/v1/rasp',
      alerts: 0,
      health_score: 0,
      response_time: 0
    },
    {
      id: 'cloud-security',
      name: 'Cloud Security',
      description: 'CSPM, CASB, and Cloud-Native Security',
      icon: 'cloud',
      color: '#9C27B0',
      status: 'inactive',
      endpoint: '/api/v1/cloud-security',
      alerts: 0,
      health_score: 0,
      response_time: 0
    },
    {
      id: 'endpoint-security',
      name: 'Endpoint Security',
      description: 'Antivirus/EDR and Device Control',
      icon: 'computer',
      color: '#FF9800',
      status: 'inactive',
      endpoint: '/api/v1/endpoint-antivirus-edr',
      alerts: 0,
      health_score: 0,
      response_time: 0
    },
    {
      id: 'device-control',
      name: 'Device Control',
      description: 'USB, media, and device access management',
      icon: 'usb',
      color: '#607D8B',
      status: 'inactive',
      endpoint: '/api/v1/device-control',
      alerts: 0,
      health_score: 0,
      response_time: 0
    },
    {
      id: 'network-security',
      name: 'Network Security',
      description: 'Network monitoring and threat detection',
      icon: 'monitor',
      color: '#795548',
      status: 'inactive',
      endpoint: '/api/v1/network-security',
      alerts: 0,
      health_score: 0,
      response_time: 0
    },
    {
      id: 'iam',
      name: 'Identity & Access Management',
      description: 'User authentication and authorization',
      icon: 'users',
      color: '#607D8B',
      status: 'inactive',
      endpoint: '/api/v1/iam',
      alerts: 0,
      health_score: 0,
      response_time: 0
    },
    {
      id: 'data-protection',
      name: 'Data Protection',
      description: 'Data loss prevention and encryption',
      icon: 'shield',
      color: '#E91E63',
      status: 'inactive',
      endpoint: '/api/v1/data-protection',
      alerts: 0,
      health_score: 0,
      response_time: 0
    },
    {
      id: 'threat-intelligence',
      name: 'Threat Intelligence',
      description: 'Threat analysis and intelligence sharing',
      icon: 'alert-triangle',
      color: '#F44336',
      status: 'inactive',
      endpoint: '/api/v1/threat-intelligence',
      alerts: 0,
      health_score: 0,
      response_time: 0
    }
  ];

  useEffect(() => {
    setModules(initializeModules());
    checkAllModulesStatus();
    fetchIntegrationMetrics();
  }, []);

  const checkAllModulesStatus = async () => {
    try {
      setLoading(true);
      const statuses = await integrationService.checkAllEndpoints();
      const statusArray = Array.from(statuses.values());
      setModuleStatuses(statusArray);
      
      // Update modules with real-time status
      setModules(prevModules => 
        prevModules.map(module => {
          const status = statusArray.find(s => s.service === module.id);
          if (status) {
            return {
              ...module,
              status: status.status === 'connected' ? 'active' : 
                     status.status === 'error' ? 'error' : 'inactive',
              health_score: status.responseTime ? Math.max(0, 100 - status.responseTime) : 0,
              response_time: status.responseTime || 0,
              alerts: 0
            };
          }
          return module;
        })
      );
      
      setLastUpdate(new Date().toLocaleTimeString());
    } catch (error) {
      console.error('Error checking module status:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchIntegrationMetrics = async () => {
    try {
      const metrics = await integrationsService.getIntegrationMetrics();
      setIntegrationMetrics(metrics);
    } catch (error) {
      console.error('Error fetching integration metrics:', error);
    }
  };

  const onRefresh = async () => {
    setRefhing(true);
    await Promise.all([
      checkAllModulesStatus(),
      fetchIntegrationMetrics()
    ]);
    setRefhing(false);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-600 bg-green-100 border-green-200';
      case 'warning':
        return 'text-yellow-600 bg-yellow-100 border-yellow-200';
      case 'error':
        return 'text-red-600 bg-red-100 border-red-200';
      case 'inactive':
        return 'text-gray-600 bg-gray-100 border-gray-200';
      default:
        return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <CheckCircle2 className="w-5 h-5 text-green-600" />;
      case 'warning':
        return <AlertCircle className="w-5 h-5 text-yellow-600" />;
      case 'error':
        return <XCircle className="w-5 h-5 text-red-600" />;
      case 'inactive':
        return <Clock className="w-5 h-5 text-gray-600" />;
      default:
        return <Clock className="w-5 h-5 text-gray-600" />;
    }
  };

  const getModuleIcon = (icon: string) => {
    const iconMap: Record<string, React.ReactNode> = {
      code: <Code className="w-6 h-6" />,
      security: <Shield className="w-6 h-6" />,
      shield: <Shield className="w-6 h-6" />,
      cloud: <Cloud className="w-6 h-6" />,
      computer: <Monitor className="w-6 h-6" />,
      usb: <Usb className="w-6 h-6" />,
      monitor: <Monitor className="w-6 h-6" />,
      users: <Shield className="w-6 h-6" />,
      'alert-triangle': <AlertTriangle className="w-6 h-6" />
    };
    return iconMap[icon] || <Shield className="w-6 h-6" />;
  };

  const handleModulePress = (module: SecurityModule) => {
    // Navigate to module-specific dashboard
    const moduleRoutes: Record<string, string> = {
      'sast': '/sast',
      'dast': '/dast',
      'rasp': '/rasp',
      'cloud-security': '/cloud-security',
      'endpoint-security': '/endpoint-security',
      'device-control': '/device-control',
      'network-security': '/network-security',
      'iam': '/iam',
      'data-protection': '/data-protection',
      'threat-intelligence': '/threat-intelligence'
    };
    
    const route = moduleRoutes[module.id];
    if (route) {
      window.location.href = route;
    }
  };

  const getHealthScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-600';
    if (score >= 70) return 'text-yellow-600';
    if (score >= 50) return 'text-orange-600';
    return 'text-red-600';
  };

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">Security Operations Dashboard</h1>
              <p className="text-gray-600 mt-2">Comprehensive security monitoring and management</p>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <p className="text-sm text-gray-500">Last Updated</p>
                <p className="text-sm font-medium">{lastUpdate || 'Never'}</p>
              </div>
              <button
                onClick={onRefresh}
                disabled={refreshing}
                className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </button>
            </div>
          </div>
        </div>

        {/* Integration Metrics Overview */}
        {integrationMetrics && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div className="bg-white p-6 rounded-lg shadow-sm border">
              <div className="flex items-center">
                <div className="p-2 bg-blue-100 rounded-lg">
                  <Activity className="w-6 h-6 text-blue-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Total Modules</p>
                  <p className="text-2xl font-bold text-gray-900">{integrationMetrics.total_integrations}</p>
                </div>
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border">
              <div className="flex items-center">
                <div className="p-2 bg-green-100 rounded-lg">
                  <CheckCircle className="w-6 h-6 text-green-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Active Modules</p>
                  <p className="text-2xl font-bold text-gray-900">{integrationMetrics.active_integrations}</p>
                </div>
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border">
              <div className="flex items-center">
                <div className="p-2 bg-yellow-100 rounded-lg">
                  <TrendingUp className="w-6 h-6 text-yellow-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Health Score</p>
                  <p className="text-2xl font-bold text-gray-900">{integrationMetrics.sync_success_rate}%</p>
                </div>
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border">
              <div className="flex items-center">
                <div className="p-2 bg-red-100 rounded-lg">
                  <AlertTriangle className="w-6 h-6 text-red-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Total Alerts</p>
                  <p className="text-2xl font-bold text-gray-900">{integrationMetrics.error_rate}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Security Modules Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
          {modules.map((module) => (
            <div
              key={module.id}
              onClick={() => handleModulePress(module)}
              className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 hover:shadow-md transition-shadow cursor-pointer group"
            >
              <div className="flex items-start justify-between mb-4">
                <div 
                  className="p-3 rounded-lg"
                  style={{ backgroundColor: `${module.color}20`, color: module.color }}
                >
                  {getModuleIcon(module.icon)}
                </div>
                <div className="flex items-center space-x-2">
                  {getStatusIcon(module.status)}
                  <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getStatusColor(module.status)}`}>
                    {module.status}
                  </span>
                </div>
              </div>
              
              <h3 className="text-lg font-semibold text-gray-900 mb-2 group-hover:text-blue-600 transition-colors">
                {module.name}
              </h3>
              
              <p className="text-sm text-gray-600 mb-4 line-clamp-2">
                {module.description}
              </p>
              
              <div className="space-y-2">
                {module.health_score !== undefined && (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-500">Health Score:</span>
                    <span className={`font-medium ${getHealthScoreColor(module.health_score)}`}>
                      {module.health_score}%
                    </span>
                  </div>
                )}
                
                {module.response_time !== undefined && (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-500">Response:</span>
                    <span className="font-medium text-gray-900">
                      {module.response_time}ms
                    </span>
                  </div>
                )}
                
                {module.alerts !== undefined && (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-500">Alerts:</span>
                    <span className="font-medium text-gray-900">
                      {module.alerts}
                    </span>
                  </div>
                )}
              </div>
              
              <div className="mt-4 pt-4 border-t border-gray-100">
                <div className="text-xs text-gray-500 truncate">
                  {module.endpoint}
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Loading State */}
        {loading && (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <span className="ml-2 text-gray-600">Checking module status...</span>
          </div>
        )}
      </div>
    </div>
  );
};

export default MainDashboard; 