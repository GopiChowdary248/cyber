import React, { useState, useEffect } from 'react';
import { 
  EyeIcon, 
  ExclamationTriangleIcon, 
  CheckCircleIcon,
  ClockIcon,
  ChartBarIcon,
  CogIcon,
  ArrowPathIcon,
  ShieldExclamationIcon
} from '@heroicons/react/24/outline';

interface CASBProvider {
  name: string;
  status: string;
  monitored_apps: number;
  dlp_violations: number;
  threat_detections: number;
  policy_violations: number;
  last_sync: string;
}

interface CASBDashboardProps {
  providerName: string;
}

const CASBDashboard: React.FC<CASBDashboardProps> = ({ providerName }) => {
  const [provider, setProvider] = useState<CASBProvider | null>(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);

  useEffect(() => {
    fetchProviderData();
  }, [providerName]);

  const fetchProviderData = async () => {
    try {
      setLoading(true);
      const response = await fetch(`/api/v1/cloud-security/casb/${encodeURIComponent(providerName)}`);
      if (response.ok) {
        const data = await response.json();
        setProvider(data);
      } else {
        console.error('Failed to fetch CASB provider data');
      }
    } catch (error) {
      console.error('Error fetching CASB provider data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSync = async () => {
    try {
      setSyncing(true);
      const response = await fetch(`/api/v1/cloud-security/casb/${encodeURIComponent(providerName)}/sync`, {
        method: 'POST',
      });
      if (response.ok) {
        // Refresh data after sync
        setTimeout(() => {
          fetchProviderData();
          setSyncing(false);
        }, 2000);
      }
    } catch (error) {
      console.error('Error triggering sync:', error);
      setSyncing(false);
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

  const getViolationColor = (count: number) => {
    if (count === 0) return 'text-green-500';
    if (count <= 5) return 'text-yellow-500';
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
          <p className="text-gray-400">Cloud Access Security Broker</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center">
            <div className={`w-3 h-3 rounded-full mr-2 ${getStatusColor(provider.status).replace('text-', 'bg-')}`}></div>
            <span className={`text-sm font-medium ${getStatusColor(provider.status)}`}>
              {provider.status.toUpperCase()}
            </span>
          </div>
          <button
            onClick={handleSync}
            disabled={syncing}
            className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <ArrowPathIcon className={`h-4 w-4 mr-2 ${syncing ? 'animate-spin' : ''}`} />
            {syncing ? 'Syncing...' : 'Sync Data'}
          </button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Monitored Apps</p>
              <p className="text-2xl font-bold text-blue-500">{provider.monitored_apps}</p>
            </div>
            <EyeIcon className="h-8 w-8 text-blue-500" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">DLP Violations</p>
              <p className={`text-2xl font-bold ${getViolationColor(provider.dlp_violations)}`}>
                {provider.dlp_violations}
              </p>
            </div>
            <ShieldExclamationIcon className="h-8 w-8 text-red-500" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Threat Detections</p>
              <p className={`text-2xl font-bold ${getViolationColor(provider.threat_detections)}`}>
                {provider.threat_detections}
              </p>
            </div>
            <ExclamationTriangleIcon className="h-8 w-8 text-orange-500" />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Policy Violations</p>
              <p className={`text-2xl font-bold ${getViolationColor(provider.policy_violations)}`}>
                {provider.policy_violations}
              </p>
            </div>
            <CogIcon className="h-8 w-8 text-yellow-500" />
          </div>
        </div>
      </div>

      {/* Details Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Last Sync Information */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <ClockIcon className="h-5 w-5 mr-2 text-blue-400" />
            Last Sync Information
          </h3>
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Last Sync:</span>
              <span className="text-white">{new Date(provider.last_sync).toLocaleString()}</span>
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

        {/* Security Metrics */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <ChartBarIcon className="h-5 w-5 mr-2 text-green-400" />
            Security Metrics
          </h3>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between items-center mb-2">
                <span className="text-gray-400">Total Violations</span>
                <span className="font-medium text-red-500">
                  {provider.dlp_violations + provider.threat_detections + provider.policy_violations}
                </span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div 
                  className="h-2 rounded-full bg-red-500"
                  style={{ 
                    width: `${Math.min(100, ((provider.dlp_violations + provider.threat_detections + provider.policy_violations) / provider.monitored_apps) * 100)}%` 
                  }}
                ></div>
              </div>
            </div>
            
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center">
                <p className="text-lg font-bold text-red-500">{provider.dlp_violations}</p>
                <p className="text-xs text-gray-400">DLP Violations</p>
              </div>
              <div className="text-center">
                <p className="text-lg font-bold text-orange-500">{provider.threat_detections}</p>
                <p className="text-xs text-gray-400">Threats</p>
              </div>
              <div className="text-center">
                <p className="text-lg font-bold text-yellow-500">{provider.policy_violations}</p>
                <p className="text-xs text-gray-400">Policy Violations</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Cloud Apps Overview */}
      <div className="mt-8 bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Monitored Applications</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <div className="bg-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-300 font-medium">Total Apps</span>
              <span className="text-blue-400 font-bold">{provider.monitored_apps}</span>
            </div>
            <p className="text-sm text-gray-400">Applications being monitored for security threats and policy violations</p>
          </div>
          
          <div className="bg-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-300 font-medium">High Risk</span>
              <span className="text-red-400 font-bold">{provider.threat_detections}</span>
            </div>
            <p className="text-sm text-gray-400">Applications with detected security threats</p>
          </div>
          
          <div className="bg-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-300 font-medium">Compliant</span>
              <span className="text-green-400 font-bold">
                {provider.monitored_apps - provider.policy_violations}
              </span>
            </div>
            <p className="text-sm text-gray-400">Applications compliant with security policies</p>
          </div>
        </div>
      </div>

      {/* Actions Section */}
      <div className="mt-8 bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Quick Actions</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button
            onClick={handleSync}
            disabled={syncing}
            className="flex items-center justify-center p-4 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <ArrowPathIcon className={`h-5 w-5 mr-2 ${syncing ? 'animate-spin' : ''}`} />
            {syncing ? 'Syncing...' : 'Sync Data'}
          </button>
          
          <button className="flex items-center justify-center p-4 bg-gray-700 text-white rounded-lg hover:bg-gray-600">
            <EyeIcon className="h-5 w-5 mr-2" />
            View Applications
          </button>
          
          <button className="flex items-center justify-center p-4 bg-gray-700 text-white rounded-lg hover:bg-gray-600">
            <CogIcon className="h-5 w-5 mr-2" />
            Configure Policies
          </button>
        </div>
      </div>
    </div>
  );
};

export default CASBDashboard; 