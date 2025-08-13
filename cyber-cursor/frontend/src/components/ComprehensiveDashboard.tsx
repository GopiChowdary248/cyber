import React, { useState, useEffect } from 'react';
import { comprehensiveIntegrationService, API_ENDPOINTS, SERVICE_MAPPING } from '../services/comprehensiveIntegrationService';
import { 
  Shield, 
  Bug, 
  Eye, 
  Cloud, 
  Network, 
  Database, 
  Brain, 
  Workflow, 
  Integration, 
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Activity
} from 'lucide-react';

interface DashboardMetrics {
  totalServices: number;
  healthyServices: number;
  partialServices: number;
  unhealthyServices: number;
  overallHealth: number;
}

interface ServiceCardProps {
  serviceName: string;
  serviceKey: string;
  icon: React.ReactNode;
  status: 'healthy' | 'partial' | 'unhealthy' | 'unknown';
  onViewDetails: () => void;
}

const ServiceCard: React.FC<ServiceCardProps> = ({ 
  serviceName, 
  serviceKey, 
  icon, 
  status, 
  onViewDetails 
}) => {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-green-600 bg-green-100';
      case 'partial': return 'text-yellow-600 bg-yellow-100';
      case 'unhealthy': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return <CheckCircle className="w-4 h-4" />;
      case 'partial': return <AlertTriangle className="w-4 h-4" />;
      case 'unhealthy': return <XCircle className="w-4 h-4" />;
      default: return <Clock className="w-4 h-4" />;
    }
  };

  return (
    <div 
      className="bg-white rounded-lg shadow-md p-6 cursor-pointer hover:shadow-lg transition-shadow"
      onClick={onViewDetails}
    >
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-blue-100 rounded-lg">
            {icon}
          </div>
          <h3 className="text-lg font-semibold text-gray-800">{serviceName}</h3>
        </div>
        <div className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(status)}`}>
          <div className="flex items-center space-x-1">
            {getStatusIcon(status)}
            <span className="capitalize">{status}</span>
          </div>
        </div>
      </div>
      
      <div className="text-sm text-gray-600 mb-4">
        {SERVICE_MAPPING[serviceKey as keyof typeof SERVICE_MAPPING] || 'Security Service'}
      </div>
      
      <div className="flex items-center justify-between text-xs text-gray-500">
        <span>Click to view details</span>
        <Activity className="w-4 h-4" />
      </div>
    </div>
  );
};

const ComprehensiveDashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<DashboardMetrics>({
    totalServices: 0,
    healthyServices: 0,
    partialServices: 0,
    unhealthyServices: 0,
    overallHealth: 0
  });
  const [loading, setLoading] = useState(true);
  const [selectedService, setSelectedService] = useState<string | null>(null);
  const [serviceHealth, setServiceHealth] = useState<any>(null);

  const services = [
    { key: 'SAST', name: 'SAST', icon: <Bug className="w-6 h-6" /> },
    { key: 'DAST', name: 'DAST', icon: <Eye className="w-6 h-6" /> },
    { key: 'RASP', name: 'RASP', icon: <Shield className="w-6 h-6" /> },
    { key: 'CLOUD_SECURITY', name: 'Cloud Security', icon: <Cloud className="w-6 h-6" /> },
    { key: 'NETWORK_SECURITY', name: 'Network Security', icon: <Network className="w-6 h-6" /> },
    { key: 'DATA_SECURITY', name: 'Data Security', icon: <Database className="w-6 h-6" /> },
    { key: 'THREAT_INTELLIGENCE', name: 'Threat Intelligence', icon: <Brain className="w-6 h-6" /> },
    { key: 'WORKFLOWS', name: 'Workflows', icon: <Workflow className="w-6 h-6" /> },
    { key: 'INTEGRATIONS', name: 'Integrations', icon: <Integration className="w-6 h-6" /> },
    { key: 'INCIDENTS', name: 'Incidents', icon: <AlertTriangle className="w-6 h-6" /> },
    { key: 'COMPLIANCE', name: 'Compliance', icon: <CheckCircle className="w-6 h-6" /> },
    { key: 'AI_ML', name: 'AI/ML Security', icon: <Brain className="w-6 h-6" /> }
  ];

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      
      // Check all endpoints
      await comprehensiveIntegrationService.checkAllEndpoints();
      
      // Get overall health
      const health = comprehensiveIntegrationService.getOverallHealth();
      
      // Calculate metrics
      const totalServices = services.length;
      const healthyServices = Math.floor((health.percentage / 100) * totalServices);
      const partialServices = Math.floor((totalServices - healthyServices) * 0.3);
      const unhealthyServices = totalServices - healthyServices - partialServices;
      
      setMetrics({
        totalServices,
        healthyServices,
        partialServices,
        unhealthyServices,
        overallHealth: health.percentage
      });
      
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleServiceClick = async (serviceKey: string) => {
    try {
      setSelectedService(serviceKey);
      const health = await comprehensiveIntegrationService.testServiceComprehensive(serviceKey);
      setServiceHealth(health);
    } catch (error) {
      console.error(`Failed to test service ${serviceKey}:`, error);
    }
  };

  const refreshData = () => {
    comprehensiveIntegrationService.clearHealthCache();
    loadDashboardData();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading comprehensive dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            CyberShield Comprehensive Dashboard
          </h1>
          <p className="text-gray-600">
            Monitor and manage all security services from a unified interface
          </p>
        </div>

        {/* Metrics Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="p-2 bg-blue-100 rounded-lg">
                <Shield className="w-6 h-6 text-blue-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Total Services</p>
                <p className="text-2xl font-bold text-gray-900">{metrics.totalServices}</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="p-2 bg-green-100 rounded-lg">
                <CheckCircle className="w-6 h-6 text-green-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Healthy</p>
                <p className="text-2xl font-bold text-green-600">{metrics.healthyServices}</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="p-2 bg-yellow-100 rounded-lg">
                <AlertTriangle className="w-6 h-6 text-yellow-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Partial</p>
                <p className="text-2xl font-bold text-yellow-600">{metrics.partialServices}</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="p-2 bg-red-100 rounded-lg">
                <XCircle className="w-6 h-6 text-red-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Unhealthy</p>
                <p className="text-2xl font-bold text-red-600">{metrics.unhealthyServices}</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="p-2 bg-purple-100 rounded-lg">
                <Activity className="w-6 h-6 text-purple-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Overall Health</p>
                <p className="text-2xl font-bold text-purple-600">{metrics.overallHealth}%</p>
              </div>
            </div>
          </div>
        </div>

        {/* Action Bar */}
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl font-semibold text-gray-800">Security Services</h2>
          <button
            onClick={refreshData}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            Refresh Status
          </button>
        </div>

        {/* Services Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6 mb-8">
          {services.map((service) => (
            <ServiceCard
              key={service.key}
              serviceName={service.name}
              serviceKey={service.key}
              icon={service.icon}
              status={selectedService === service.key && serviceHealth ? serviceHealth.overallStatus : 'unknown'}
              onViewDetails={() => handleServiceClick(service.key)}
            />
          ))}
        </div>

        {/* Service Details Modal */}
        {selectedService && serviceHealth && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto">
              <div className="p-6">
                <div className="flex justify-between items-center mb-6">
                  <h3 className="text-2xl font-bold text-gray-900">
                    {SERVICE_MAPPING[selectedService as keyof typeof SERVICE_MAPPING]} Details
                  </h3>
                  <button
                    onClick={() => setSelectedService(null)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    <XCircle className="w-6 h-6" />
                  </button>
                </div>

                {/* Service Health Summary */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-sm text-gray-600">Overall Status</p>
                    <p className={`text-lg font-semibold capitalize ${
                      serviceHealth.overallStatus === 'healthy' ? 'text-green-600' :
                      serviceHealth.overallStatus === 'partial' ? 'text-yellow-600' : 'text-red-600'
                    }`}>
                      {serviceHealth.overallStatus}
                    </p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-sm text-gray-600">Success Rate</p>
                    <p className="text-lg font-semibold text-gray-900">{serviceHealth.successRate.toFixed(1)}%</p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-sm text-gray-600">Avg Response Time</p>
                    <p className="text-lg font-semibold text-gray-900">{serviceHealth.averageResponseTime.toFixed(0)}ms</p>
                  </div>
                </div>

                {/* Endpoint Details */}
                <div>
                  <h4 className="text-lg font-semibold text-gray-800 mb-4">Endpoint Status</h4>
                  <div className="space-y-3">
                    {serviceHealth.endpoints.map((endpoint: any, index: number) => (
                      <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div className="flex items-center space-x-3">
                          <span className="text-sm font-medium text-gray-700">{endpoint.endpoint}</span>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                            endpoint.status === 'success' ? 'bg-green-100 text-green-600' :
                            endpoint.status === 'failed' ? 'bg-red-100 text-red-600' :
                            endpoint.status === 'timeout' ? 'bg-yellow-100 text-yellow-600' :
                            'bg-gray-100 text-gray-600'
                          }`}>
                            {endpoint.status}
                          </span>
                        </div>
                        <div className="text-sm text-gray-600">
                          {endpoint.responseTime}ms
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ComprehensiveDashboard;
