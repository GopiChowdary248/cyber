import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  CheckCircleIcon, 
  ExclamationTriangleIcon, 
  XCircleIcon,
  ArrowPathIcon,
  DocumentArrowDownIcon,
  ClockIcon,
  ServerIcon,
  ShieldCheckIcon
} from '@heroicons/react/24/outline';
import { comprehensiveIntegrationService, IntegrationTestResult } from '../../services/comprehensiveIntegrationService';

interface IntegrationHealth {
  totalServices: number;
  healthyServices: number;
  partialServices: number;
  unhealthyServices: number;
  overallHealth: number;
  services: IntegrationTestResult[];
}

const ComprehensiveIntegrationDashboard: React.FC = () => {
  const [health, setHealth] = useState<IntegrationHealth | null>(null);
  const [loading, setLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [selectedService, setSelectedService] = useState<string | null>(null);

  const loadIntegrationHealth = async () => {
    setLoading(true);
    try {
      const healthData = await comprehensiveIntegrationService.getOverallHealth();
      setHealth(healthData);
      setLastUpdated(new Date());
    } catch (error) {
      console.error('Failed to load integration health:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIntegrationHealth();
  }, []);

  const getHealthColor = (health: number) => {
    if (health >= 80) return 'text-green-500';
    if (health >= 60) return 'text-yellow-500';
    return 'text-red-500';
  };

  const getHealthBgColor = (health: number) => {
    if (health >= 80) return 'bg-green-500/10';
    if (health >= 60) return 'bg-yellow-500/10';
    return 'bg-red-500/10';
  };

  const getStatusIcon = (success: boolean, workingEndpoints: number, totalEndpoints: number) => {
    if (success) return <CheckCircleIcon className="h-6 w-6 text-green-500" />;
    if (workingEndpoints > 0) return <ExclamationTriangleIcon className="h-6 w-6 text-yellow-500" />;
    return <XCircleIcon className="h-6 w-6 text-red-500" />;
  };

  const getStatusColor = (success: boolean, workingEndpoints: number, totalEndpoints: number) => {
    if (success) return 'text-green-500';
    if (workingEndpoints > 0) return 'text-yellow-500';
    return 'text-red-500';
  };

  const getStatusBgColor = (success: boolean, workingEndpoints: number, totalEndpoints: number) => {
    if (success) return 'bg-green-500/10';
    if (workingEndpoints > 0) return 'bg-yellow-500/10';
    return 'bg-red-500/10';
  };

  const exportReport = () => {
    if (!health) return;
    
    const report = comprehensiveIntegrationService.exportReport(health.services);
    const blob = new Blob([report], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybershield-integration-report-${new Date().toISOString().split('T')[0]}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (!health) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Comprehensive Integration Dashboard
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Monitor the health of all frontend-backend integrations
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={loadIntegrationHealth}
            disabled={loading}
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
          >
            <ArrowPathIcon className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={exportReport}
            className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-600 dark:hover:bg-gray-700"
          >
            <DocumentArrowDownIcon className="h-4 w-4 mr-2" />
            Export Report
          </button>
        </div>
      </div>

      {/* Last Updated */}
      {lastUpdated && (
        <div className="flex items-center text-sm text-gray-500 dark:text-gray-400">
          <ClockIcon className="h-4 w-4 mr-2" />
          Last updated: {lastUpdated.toLocaleString()}
        </div>
      )}

      {/* Overall Health Summary */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="grid grid-cols-1 md:grid-cols-4 gap-6"
      >
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 rounded-full bg-blue-100 dark:bg-blue-900">
              <ServerIcon className="h-6 w-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Total Services</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">{health.totalServices}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 rounded-full bg-green-100 dark:bg-green-900">
              <CheckCircleIcon className="h-6 w-6 text-green-600 dark:text-green-400" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Healthy</p>
              <p className="text-2xl font-semibold text-green-600 dark:text-green-400">{health.healthyServices}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 rounded-full bg-yellow-100 dark:bg-yellow-900">
              <ExclamationTriangleIcon className="h-6 w-6 text-yellow-600 dark:text-yellow-400" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Partial</p>
              <p className="text-2xl font-semibold text-yellow-600 dark:text-yellow-400">{health.partialServices}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 rounded-full bg-red-100 dark:bg-red-900">
              <XCircleIcon className="h-6 w-6 text-red-600 dark:text-red-400" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Unhealthy</p>
              <p className="text-2xl font-semibold text-red-600 dark:text-red-400">{health.unhealthyServices}</p>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Overall Health Score */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="bg-white dark:bg-gray-800 rounded-lg shadow p-6"
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">Overall Health Score</h3>
          <span className={`text-2xl font-bold ${getHealthColor(health.overallHealth)}`}>
            {health.overallHealth}%
          </span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-3 dark:bg-gray-700">
          <div
            className={`h-3 rounded-full transition-all duration-500 ${getHealthBgColor(health.overallHealth)}`}
            style={{ width: `${health.overallHealth}%` }}
          ></div>
        </div>
        <div className="mt-2 text-sm text-gray-600 dark:text-gray-400">
          {health.overallHealth >= 80 && 'Excellent integration health'}
          {health.overallHealth >= 60 && health.overallHealth < 80 && 'Good integration health with some issues'}
          {health.overallHealth < 60 && 'Integration health needs attention'}
        </div>
      </motion.div>

      {/* Services List */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="bg-white dark:bg-gray-800 rounded-lg shadow"
      >
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">Service Details</h3>
        </div>
        <div className="divide-y divide-gray-200 dark:divide-gray-700">
          {health.services.map((service, index) => (
            <motion.div
              key={service.service}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.1 * index }}
              className="p-6 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors cursor-pointer"
              onClick={() => setSelectedService(selectedService === service.service ? null : service.service)}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  {getStatusIcon(service.success, service.workingEndpoints, service.totalEndpoints)}
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                      {service.service}
                    </h4>
                    <div className="flex items-center space-x-4 mt-1">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusBgColor(service.success, service.workingEndpoints, service.totalEndpoints)} ${getStatusColor(service.success, service.workingEndpoints, service.totalEndpoints)}`}>
                        {service.success ? 'Healthy' : service.workingEndpoints > 0 ? 'Partial' : 'Unhealthy'}
                      </span>
                      <span className="text-sm text-gray-500 dark:text-gray-400">
                        {service.workingEndpoints}/{service.totalEndpoints} endpoints working
                      </span>
                      {service.averageResponseTime > 0 && (
                        <span className="text-sm text-gray-500 dark:text-gray-400">
                          {service.averageResponseTime.toFixed(0)}ms avg
                        </span>
                      )}
                    </div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm text-gray-500 dark:text-gray-400">
                    {Math.round((service.workingEndpoints / service.totalEndpoints) * 100)}%
                  </div>
                  <div className="w-20 bg-gray-200 rounded-full h-2 mt-1 dark:bg-gray-700">
                    <div
                      className={`h-2 rounded-full transition-all duration-300 ${getStatusBgColor(service.success, service.workingEndpoints, service.totalEndpoints)}`}
                      style={{ width: `${(service.workingEndpoints / service.totalEndpoints) * 100}%` }}
                    ></div>
                  </div>
                </div>
              </div>

              {/* Expanded Endpoint Details */}
              {selectedService === service.service && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700"
                >
                  <h5 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Endpoint Details</h5>
                  <div className="space-y-2">
                    {service.endpoints.map((endpoint, endpointIndex) => (
                      <div key={endpointIndex} className="flex items-center justify-between text-sm">
                        <div className="flex items-center space-x-2">
                          {endpoint.status === 'working' && <CheckCircleIcon className="h-4 w-4 text-green-500" />}
                          {endpoint.status === 'failing' && <XCircleIcon className="h-4 w-4 text-red-500" />}
                          {endpoint.status === 'not_tested' && <ExclamationTriangleIcon className="h-4 w-4 text-yellow-500" />}
                          <span className="font-mono text-xs bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
                            {endpoint.method} {endpoint.endpoint}
                          </span>
                        </div>
                        <div className="flex items-center space-x-3">
                          <span className={`px-2 py-1 rounded text-xs ${endpoint.status === 'working' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : endpoint.status === 'failing' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'}`}>
                            {endpoint.status}
                          </span>
                          {endpoint.responseTime && (
                            <span className="text-xs text-gray-500 dark:text-gray-400">
                              {endpoint.responseTime}ms
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}
            </motion.div>
          ))}
        </div>
      </motion.div>

      {/* Recommendations */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="bg-white dark:bg-gray-800 rounded-lg shadow p-6"
      >
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Recommendations</h3>
        <div className="space-y-3">
          {health.unhealthyServices > 0 && (
            <div className="flex items-start space-x-3 p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
              <XCircleIcon className="h-5 w-5 text-red-500 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-red-800 dark:text-red-200">
                  {health.unhealthyServices} service(s) are completely unhealthy
                </p>
                <p className="text-sm text-red-700 dark:text-red-300">
                  These services need immediate attention as they cannot communicate with the backend.
                </p>
              </div>
            </div>
          )}
          
          {health.partialServices > 0 && (
            <div className="flex items-start space-x-3 p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
              <ExclamationTriangleIcon className="h-5 w-5 text-yellow-500 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
                  {health.partialServices} service(s) have partial functionality
                </p>
                <p className="text-sm text-yellow-700 dark:text-yellow-300">
                  These services are working but some endpoints are failing. Review and fix the failing endpoints.
                </p>
              </div>
            </div>
          )}

          {health.overallHealth >= 80 && (
            <div className="flex items-start space-x-3 p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
              <ShieldCheckIcon className="h-5 w-5 text-green-500 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-green-800 dark:text-green-200">
                  Excellent integration health
                </p>
                <p className="text-sm text-green-700 dark:text-green-300">
                  All services are communicating properly with the backend. Continue monitoring for any issues.
                </p>
              </div>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
};

export default ComprehensiveIntegrationDashboard;
