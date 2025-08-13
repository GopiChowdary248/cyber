import React, { useState, useEffect } from 'react';
import {
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  RefreshCw,
  Download,
  Activity,
  Server,
  Database,
  Shield,
  Code,
  Cloud,
  Network,
  Monitor,
  Settings,
  BarChart3,
  TrendingUp,
  AlertCircle,
  Info,
  Zap,
  Target,
  Lock,
  Unlock,
  Eye,
  EyeOff
} from 'lucide-react';
import integrationVerificationService, {
  IntegrationReport,
  ServiceIntegrationStatus,
  EndpointTestResult
} from '../../services/integrationVerificationService';

interface IntegrationStatusDashboardProps {
  autoRefresh?: boolean;
  refreshInterval?: number;
}

const IntegrationStatusDashboard: React.FC<IntegrationStatusDashboardProps> = ({
  autoRefresh = true,
  refreshInterval = 30000
}) => {
  const [report, setReport] = useState<IntegrationReport | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [selectedService, setSelectedService] = useState<string | null>(null);
  const [showDetails, setShowDetails] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadIntegrationStatus();
    
    if (autoRefresh) {
      const interval = setInterval(loadIntegrationStatus, refreshInterval);
      return () => clearInterval(interval);
    }
  }, [autoRefresh, refreshInterval]);

  const loadIntegrationStatus = async () => {
    try {
      setIsLoading(true);
      setError(null);
      const status = await integrationVerificationService.verifyAllIntegrations();
      setReport(status);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load integration status');
    } finally {
      setIsLoading(false);
    }
  };

  const handleManualVerification = async () => {
    try {
      setIsVerifying(true);
      setError(null);
      const status = await integrationVerificationService.verifyAllIntegrations();
      setReport(status);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setIsVerifying(false);
    }
  };

  const exportReport = () => {
    if (!report) return;
    
    const dataStr = integrationVerificationService.exportVerificationReport();
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `integration-status-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'partial':
        return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
      case 'unhealthy':
        return <XCircle className="w-5 h-5 text-red-500" />;
      default:
        return <Clock className="w-5 h-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'partial':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'unhealthy':
        return 'bg-red-100 text-red-800 border-red-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getEndpointStatusIcon = (status: EndpointTestResult['status']) => {
    switch (status) {
      case 'success':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'failed':
        return <XCircle className="w-4 h-4 text-red-500" />;
      case 'timeout':
        return <Clock className="w-4 h-4 text-yellow-500" />;
      case 'unauthorized':
        return <Lock className="w-4 h-4 text-orange-500" />;
      default:
        return <Info className="w-4 h-4 text-gray-500" />;
    }
  };

  const getServiceIcon = (serviceName: string) => {
    const iconMap: Record<string, React.ReactNode> = {
      'sastService': <Code className="w-5 h-5" />,
      'dastService': <Target className="w-5 h-5" />,
      'raspService': <Shield className="w-5 h-5" />,
      'cloudSecurityService': <Cloud className="w-5 h-5" />,
      'networkSecurityService': <Network className="w-5 h-5" />,
      'endpointSecurityService': <Monitor className="w-5 h-5" />,
      'dataSecurityService': <Database className="w-5 h-5" />,
      'siemSoarService': <Activity className="w-5 h-5" />,
      'analyticsService': <BarChart3 className="w-5 h-5" />,
      'threatIntelligenceService': <AlertCircle className="w-5 h-5" />,
      'complianceService': <CheckCircle className="w-5 h-5" />,
      'incidentService': <AlertTriangle className="w-5 h-5" />,
      'authService': <Lock className="w-5 h-5" />,
      'adminService': <Settings className="w-5 h-5" />,
      'default': <Server className="w-5 h-5" />
    };
    
    return iconMap[serviceName] || iconMap.default;
  };

  if (isLoading && !report) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="text-center">
          <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-4 text-blue-500" />
          <p className="text-gray-600">Loading integration status...</p>
        </div>
      </div>
    );
  }

  if (error && !report) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-6">
        <div className="flex items-center mb-4">
          <XCircle className="w-6 h-6 text-red-500 mr-2" />
          <h3 className="text-lg font-semibold text-red-800">Integration Status Error</h3>
        </div>
        <p className="text-red-700 mb-4">{error}</p>
        <button
          onClick={loadIntegrationStatus}
          className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 transition-colors"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!report) {
    return null;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Integration Status Dashboard</h1>
            <p className="text-gray-600">
              Last updated: {report.timestamp.toLocaleString()}
            </p>
          </div>
          <div className="flex space-x-3">
            <button
              onClick={handleManualVerification}
              disabled={isVerifying}
              className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 transition-colors flex items-center"
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${isVerifying ? 'animate-spin' : ''}`} />
              {isVerifying ? 'Verifying...' : 'Verify All'}
            </button>
            <button
              onClick={exportReport}
              className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700 transition-colors flex items-center"
            >
              <Download className="w-4 h-4 mr-2" />
              Export Report
            </button>
          </div>
        </div>

        {/* Overall Health Summary */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="flex items-center">
              <Server className="w-6 h-6 text-gray-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-600">Total Services</p>
                <p className="text-2xl font-bold text-gray-900">{report.services.length}</p>
              </div>
            </div>
          </div>
          
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="flex items-center">
              <CheckCircle className="w-6 h-6 text-green-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-600">Healthy</p>
                <p className="text-2xl font-bold text-green-600">
                  {report.services.filter(s => s.overallStatus === 'healthy').length}
                </p>
              </div>
            </div>
          </div>
          
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="flex items-center">
              <AlertTriangle className="w-6 h-6 text-yellow-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-600">Partial</p>
                <p className="text-2xl font-bold text-yellow-600">
                  {report.services.filter(s => s.overallStatus === 'partial').length}
                </p>
              </div>
            </div>
          </div>
          
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="flex items-center">
              <XCircle className="w-6 h-6 text-red-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-600">Unhealthy</p>
                <p className="text-2xl font-bold text-red-600">
                  {report.services.filter(s => s.overallStatus === 'unhealthy').length}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Overall Health Status */}
        <div className="mt-6">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900">Overall System Health</h3>
            <div className={`px-3 py-1 rounded-full text-sm font-medium border ${getStatusColor(report.overallHealth)}`}>
              {getStatusIcon(report.overallHealth)}
              <span className="ml-2 capitalize">{report.overallHealth}</span>
            </div>
          </div>
          
          <div className="mt-4 bg-gray-200 rounded-full h-2">
            <div
              className="bg-blue-600 h-2 rounded-full transition-all duration-300"
              style={{ width: `${(report.summary.successfulEndpoints / report.summary.totalEndpoints) * 100}%` }}
            />
          </div>
          <p className="text-sm text-gray-600 mt-2">
            {report.summary.successfulEndpoints} of {report.summary.totalEndpoints} endpoints healthy
          </p>
        </div>
      </div>

      {/* Services Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        {report.services.map((service) => (
          <div
            key={service.service}
            className={`bg-white rounded-lg shadow-sm border border-gray-200 p-6 cursor-pointer transition-all hover:shadow-md ${
              selectedService === service.service ? 'ring-2 ring-blue-500' : ''
            }`}
            onClick={() => setSelectedService(selectedService === service.service ? null : service.service)}
          >
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center">
                <div className="p-2 bg-gray-100 rounded-lg mr-3">
                  {getServiceIcon(service.service)}
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900">
                    {service.service.replace('Service', '').replace(/([A-Z])/g, ' $1').trim()}
                  </h3>
                  <p className="text-sm text-gray-500">
                    {service.endpoints.length} endpoints
                  </p>
                </div>
              </div>
              <div className={`px-2 py-1 rounded-full text-xs font-medium border ${getStatusColor(service.overallStatus)}`}>
                {getStatusIcon(service.overallStatus)}
              </div>
            </div>

            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-gray-600">Success Rate:</span>
                <span className={`font-medium ${
                  service.successRate >= 90 ? 'text-green-600' :
                  service.successRate >= 50 ? 'text-yellow-600' : 'text-red-600'
                }`}>
                  {service.successRate.toFixed(1)}%
                </span>
              </div>
              
              <div className="flex justify-between text-sm">
                <span className="text-gray-600">Avg Response:</span>
                <span className="font-medium text-gray-900">
                  {service.averageResponseTime.toFixed(0)}ms
                </span>
              </div>

              <div className="flex justify-between text-sm">
                <span className="text-gray-600">Last Check:</span>
                <span className="font-medium text-gray-900">
                  {service.lastVerified.toLocaleTimeString()}
                </span>
              </div>
            </div>

            {/* Endpoint Details */}
            {selectedService === service.service && (
              <div className="mt-4 pt-4 border-t border-gray-200">
                <h4 className="font-medium text-gray-900 mb-3">Endpoint Details</h4>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {service.endpoints.map((endpoint, index) => (
                    <div key={index} className="flex items-center justify-between text-sm">
                      <div className="flex items-center">
                        {getEndpointStatusIcon(endpoint.status)}
                        <span className="ml-2 text-gray-700 truncate max-w-32">
                          {endpoint.endpoint}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-1 rounded text-xs ${
                          endpoint.status === 'success' ? 'bg-green-100 text-green-800' :
                          endpoint.status === 'failed' ? 'bg-red-100 text-red-800' :
                          endpoint.status === 'timeout' ? 'bg-yellow-100 text-yellow-800' :
                          'bg-orange-100 text-orange-800'
                        }`}>
                          {endpoint.status}
                        </span>
                        {endpoint.responseTime > 0 && (
                          <span className="text-xs text-gray-500">
                            {endpoint.responseTime}ms
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Services Needing Attention */}
      {integrationVerificationService.getServicesNeedingAttention().length > 0 && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-6">
          <div className="flex items-center mb-4">
            <AlertTriangle className="w-6 h-6 text-yellow-600 mr-2" />
            <h3 className="text-lg font-semibold text-yellow-800">Services Needing Attention</h3>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {integrationVerificationService.getServicesNeedingAttention().map((service) => (
              <div key={service.service} className="bg-white rounded-lg p-4 border border-yellow-200">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-medium text-yellow-800">
                    {service.service.replace('Service', '').replace(/([A-Z])/g, ' $1').trim()}
                  </h4>
                  <div className={`px-2 py-1 rounded-full text-xs font-medium border ${getStatusColor(service.overallStatus)}`}>
                    {getStatusIcon(service.overallStatus)}
                  </div>
                </div>
                <p className="text-sm text-yellow-700">
                  Success rate: {service.successRate.toFixed(1)}%
                </p>
                <p className="text-sm text-yellow-700">
                  {service.endpoints.filter(e => e.status !== 'success').length} endpoints failing
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default IntegrationStatusDashboard;
