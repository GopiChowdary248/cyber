import React, { useState, useEffect } from 'react';
import { 
  ServerIcon, 
  ExclamationTriangleIcon, 
  CheckCircleIcon,
  ClockIcon,
  ChartBarIcon,
  CogIcon,
  ArrowPathIcon,
  ShieldCheckIcon
} from '@heroicons/react/24/outline';

interface CloudNativeProvider {
  name: string;
  status: string;
  protected_resources: number;
  active_threats: number;
  security_score: number;
  last_updated: string;
}

interface CloudNativeDashboardProps {
  providerName: string;
}

const CloudNativeDashboard: React.FC<CloudNativeDashboardProps> = ({ providerName }) => {
  const [provider, setProvider] = useState<CloudNativeProvider | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchProviderData();
  }, [providerName]);

  const fetchProviderData = async () => {
    try {
      setLoading(true);
      const response = await fetch(`/api/v1/cloud-security/cloud-native/${encodeURIComponent(providerName)}`);
      if (response.ok) {
        const data = await response.json();
        setProvider(data);
      } else {
        console.error('Failed to fetch Cloud-Native provider data');
      }
    } catch (error) {
      console.error('Error fetching Cloud-Native provider data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'active':
        return 'text-green-500';
      case 'inactive':
        return 'text-red-500';
      case 'warning':
        return 'text-yellow-500';
      default:
        return 'text-gray-500';
    }
  };

  const getSecurityScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-500';
    if (score >= 70) return 'text-yellow-500';
    return 'text-red-500';
  };

  const getThreatColor = (count: number) => {
    if (count === 0) return 'text-green-500';
    if (count <= 2) return 'text-yellow-500';
    return 'text-red-500';
  };

  if (loading) {
    return (
      <div className="p-6">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
        </div>
      </div>
    );
  }

  if (!provider) {
    return (
      <div className="p-6">
        <div className="bg-red-900/20 border border-red-700/50 rounded-lg p-6">
          <p className="text-red-400">Failed to load provider data for {providerName}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white mb-2">{provider.name}</h1>
          <p className="text-gray-400">Cloud-Native Security</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center">
            <div className={`w-3 h-3 rounded-full mr-2 ${getStatusColor(provider.status).replace('text-', 'bg-')}`}></div>
            <span className={`text-sm font-medium ${getStatusColor(provider.status)}`}>
              {provider.status.toUpperCase()}
            </span>
          </div>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Protected Resources</p>
              <p className="text-2xl font-bold text-blue-500">{provider.protected_resources}</p>
            </div>
            <ShieldCheckIcon className="h-8 w-8 text-blue-500" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Active Threats</p>
              <p className={`text-2xl font-bold ${getThreatColor(provider.active_threats)}`}>
                {provider.active_threats}
              </p>
            </div>
            <ExclamationTriangleIcon className="h-8 w-8 text-orange-500" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Security Score</p>
              <p className={`text-2xl font-bold ${getSecurityScoreColor(provider.security_score)}`}>
                {provider.security_score}%
              </p>
            </div>
            <ChartBarIcon className="h-8 w-8 text-green-500" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Protection Rate</p>
              <p className="text-2xl font-bold text-green-500">
                {provider.active_threats === 0 ? 100 : Math.round(((provider.protected_resources - provider.active_threats) / provider.protected_resources) * 100)}%
              </p>
            </div>
            <CheckCircleIcon className="h-8 w-8 text-green-500" />
          </div>
        </div>
      </div>

      {/* Details Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Last Update Information */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <ClockIcon className="h-5 w-5 mr-2 text-blue-400" />
            Last Update Information
          </h3>
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Last Updated:</span>
              <span className="text-white">{new Date(provider.last_updated).toLocaleString()}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Status:</span>
              <span className={`font-medium ${getStatusColor(provider.status)}`}>
                {provider.status.toUpperCase()}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Provider:</span>
              <span className="text-white">{provider.name}</span>
            </div>
          </div>
        </div>

        {/* Security Overview */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <ShieldCheckIcon className="h-5 w-5 mr-2 text-green-400" />
            Security Overview
          </h3>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between items-center mb-2">
                <span className="text-gray-400">Security Score</span>
                <span className={`font-medium ${getSecurityScoreColor(provider.security_score)}`}>
                  {provider.security_score}%
                </span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div 
                  className={`h-2 rounded-full ${
                    provider.security_score >= 90 ? 'bg-green-500' :
                    provider.security_score >= 70 ? 'bg-yellow-500' : 'bg-red-500'
                  }`}
                  style={{ width: `${provider.security_score}%` }}
                ></div>
              </div>
            </div>
            
            <div className="grid grid-cols-2 gap-4">
              <div className="text-center">
                <p className="text-2xl font-bold text-blue-500">{provider.protected_resources}</p>
                <p className="text-sm text-gray-400">Protected Resources</p>
              </div>
              <div className="text-center">
                <p className={`text-2xl font-bold ${getThreatColor(provider.active_threats)}`}>
                  {provider.active_threats}
                </p>
                <p className="text-sm text-gray-400">Active Threats</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Threat Analysis */}
      <div className="mt-8 bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Threat Analysis</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <div className="bg-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-300 font-medium">DDoS Protection</span>
              <span className="text-green-400 font-bold">Active</span>
            </div>
            <p className="text-sm text-gray-400">Distributed Denial of Service protection is enabled and monitoring traffic</p>
          </div>
          
          <div className="bg-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-300 font-medium">Threat Detection</span>
              <span className={`font-bold ${provider.active_threats > 0 ? 'text-red-400' : 'text-green-400'}`}>
                {provider.active_threats > 0 ? 'Threats Detected' : 'Clear'}
              </span>
            </div>
            <p className="text-sm text-gray-400">
              {provider.active_threats > 0 
                ? `${provider.active_threats} active threats detected and being mitigated`
                : 'No active threats detected'
              }
            </p>
          </div>
          
          <div className="bg-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-300 font-medium">Security Monitoring</span>
              <span className="text-blue-400 font-bold">24/7</span>
            </div>
            <p className="text-sm text-gray-400">Continuous security monitoring and threat intelligence updates</p>
          </div>
        </div>
      </div>

      {/* Resource Protection Status */}
      <div className="mt-8 bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Resource Protection Status</h3>
        <div className="space-y-4">
          <div className="flex items-center justify-between p-4 bg-gray-700 rounded-lg">
            <div className="flex items-center">
              <ServerIcon className="h-5 w-5 text-blue-400 mr-3" />
              <div>
                <p className="text-white font-medium">Protected Resources</p>
                <p className="text-sm text-gray-400">All resources are under security protection</p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-2xl font-bold text-blue-500">{provider.protected_resources}</p>
              <p className="text-sm text-gray-400">resources</p>
            </div>
          </div>
          
          <div className="flex items-center justify-between p-4 bg-gray-700 rounded-lg">
            <div className="flex items-center">
              <ExclamationTriangleIcon className="h-5 w-5 text-orange-400 mr-3" />
              <div>
                <p className="text-white font-medium">Threat Mitigation</p>
                <p className="text-sm text-gray-400">Active threats being mitigated</p>
              </div>
            </div>
            <div className="text-right">
              <p className={`text-2xl font-bold ${getThreatColor(provider.active_threats)}`}>
                {provider.active_threats}
              </p>
              <p className="text-sm text-gray-400">threats</p>
            </div>
          </div>
        </div>
      </div>

      {/* Actions Section */}
      <div className="mt-8 bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Quick Actions</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button className="flex items-center justify-center p-4 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
            <ShieldCheckIcon className="h-5 w-5 mr-2" />
            View Security Logs
          </button>
          
          <button className="flex items-center justify-center p-4 bg-gray-700 text-white rounded-lg hover:bg-gray-600">
            <ChartBarIcon className="h-5 w-5 mr-2" />
            Security Reports
          </button>
          
          <button className="flex items-center justify-center p-4 bg-gray-700 text-white rounded-lg hover:bg-gray-600">
            <CogIcon className="h-5 w-5 mr-2" />
            Configure Protection
          </button>
        </div>
      </div>
    </div>
  );
};

export default CloudNativeDashboard; 