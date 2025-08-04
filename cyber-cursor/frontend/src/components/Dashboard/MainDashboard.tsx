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
  Clock
} from 'lucide-react';

interface SecurityModule {
  id: string;
  name: string;
  description: string;
  icon: string;
  color: string;
  status: 'active' | 'warning' | 'error' | 'inactive';
  endpoint: string;
  alerts?: number;
}

const MainDashboard: React.FC = () => {
  const [modules, setModules] = useState<SecurityModule[]>([
    {
      id: 'sast',
      name: 'Static Application Security Testing',
      description: 'Code analysis and vulnerability detection',
      icon: 'code',
      color: '#2196F3',
      status: 'active',
      endpoint: '/api/v1/sast',
      alerts: 5,
    },
    {
      id: 'dast',
      name: 'Dynamic Application Security Testing',
      description: 'Runtime security testing and vulnerability scanning',
      icon: 'security',
      color: '#FF5722',
      status: 'active',
      endpoint: '/api/v1/dast',
      alerts: 3,
    },
    {
      id: 'rasp',
      name: 'Runtime Application Self-Protection',
      description: 'Real-time application protection and monitoring',
      icon: 'shield',
      color: '#4CAF50',
      status: 'active',
      endpoint: '/api/rasp',
      alerts: 2,
    },
    {
      id: 'cloud-security',
      name: 'Cloud Security',
      description: 'CSPM, CASB, and Cloud-Native Security',
      icon: 'cloud',
      color: '#9C27B0',
      status: 'active',
      endpoint: '/api/v1/cloud-security',
      alerts: 8,
    },
    {
      id: 'endpoint-security',
      name: 'Endpoint Security',
      description: 'Antivirus/EDR and Device Control',
      icon: 'computer',
      color: '#FF9800',
      status: 'active',
      endpoint: '/api/v1/endpoint-antivirus-edr',
      alerts: 12,
    },
    {
      id: 'device-control',
      name: 'Device Control',
      description: 'USB, media, and device access management',
      icon: 'usb',
      color: '#607D8B',
      status: 'active',
      endpoint: '/api/v1/device-control',
      alerts: 4,
    },
  ]);

  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const checkModuleStatus = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token') || '';
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      };

      const updatedModules = await Promise.all(
        modules.map(async (module) => {
          try {
            const response = await fetch(`${module.endpoint}/health`, {
              method: 'GET',
              headers,
            });
            
            if (response.ok) {
              return { ...module, status: 'active' as const };
            } else {
              return { ...module, status: 'warning' as const };
            }
          } catch (error) {
            console.error(`Error checking ${module.name}:`, error);
            return { ...module, status: 'error' as const };
          }
        })
      );

      setModules(updatedModules);
    } catch (error) {
      console.error('Error checking module status:', error);
      alert('Failed to check module status');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkModuleStatus();
  }, []);

  const onRefresh = () => {
    setRefreshing(true);
    checkModuleStatus().finally(() => setRefreshing(false));
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-600 bg-green-100';
      case 'warning':
        return 'text-yellow-600 bg-yellow-100';
      case 'error':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <CheckCircle className="w-4 h-4" />;
      case 'warning':
        return <AlertTriangle className="w-4 h-4" />;
      case 'error':
        return <XCircle className="w-4 h-4" />;
      default:
        return <Clock className="w-4 h-4" />;
    }
  };

  const getModuleIcon = (icon: string) => {
    switch (icon) {
      case 'code':
        return <Code className="w-8 h-8" />;
      case 'security':
        return <Search className="w-8 h-8" />;
      case 'shield':
        return <Shield className="w-8 h-8" />;
      case 'cloud':
        return <Cloud className="w-8 h-8" />;
      case 'computer':
        return <Monitor className="w-8 h-8" />;
      case 'usb':
        return <Usb className="w-8 h-8" />;
      default:
        return <Shield className="w-8 h-8" />;
    }
  };

  const handleModulePress = (module: SecurityModule) => {
    // Navigate to module dashboard
    window.location.href = `/${module.id}`;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            CyberShield Security Dashboard
          </h1>
          <p className="text-gray-600">
            Comprehensive cybersecurity platform monitoring and management
          </p>
        </div>

        {/* Refresh Button */}
        <div className="mb-6">
          <button
            onClick={onRefresh}
            disabled={refreshing}
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {refreshing ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                Refreshing...
              </>
            ) : (
              'Refresh Status'
            )}
          </button>
        </div>

        {/* Security Modules Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {modules.map((module) => (
            <div
              key={module.id}
              onClick={() => handleModulePress(module)}
              className="bg-white rounded-lg shadow-md hover:shadow-lg transition-shadow duration-200 cursor-pointer border border-gray-200"
            >
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div 
                    className="p-3 rounded-lg"
                    style={{ backgroundColor: `${module.color}20` }}
                  >
                    <div style={{ color: module.color }}>
                      {getModuleIcon(module.icon)}
                    </div>
                  </div>
                  <div className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(module.status)}`}>
                    {getStatusIcon(module.status)}
                    <span className="ml-1 capitalize">{module.status}</span>
                  </div>
                </div>

                <h3 className="text-lg font-semibold text-gray-900 mb-2">
                  {module.name}
                </h3>
                <p className="text-gray-600 text-sm mb-4">
                  {module.description}
                </p>

                {module.alerts && module.alerts > 0 && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-500">
                      Active Alerts
                    </span>
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                      {module.alerts}
                    </span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Quick Stats */}
        <div className="mt-8 grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="p-2 bg-blue-100 rounded-lg">
                <Shield className="w-6 h-6 text-blue-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Total Modules</p>
                <p className="text-2xl font-semibold text-gray-900">{modules.length}</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="p-2 bg-green-100 rounded-lg">
                <CheckCircle className="w-6 h-6 text-green-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Active</p>
                <p className="text-2xl font-semibold text-gray-900">
                  {modules.filter(m => m.status === 'active').length}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="p-2 bg-yellow-100 rounded-lg">
                <AlertTriangle className="w-6 h-6 text-yellow-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Warnings</p>
                <p className="text-2xl font-semibold text-gray-900">
                  {modules.filter(m => m.status === 'warning').length}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="p-2 bg-red-100 rounded-lg">
                <XCircle className="w-6 h-6 text-red-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Errors</p>
                <p className="text-2xl font-semibold text-gray-900">
                  {modules.filter(m => m.status === 'error').length}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MainDashboard; 