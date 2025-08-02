import React, { useState, useEffect } from 'react';
import { 
  LockClosedIcon, 
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ArrowPathIcon,
  ChartBarIcon,
  ClockIcon,
  UserGroupIcon,
  ShieldExclamationIcon
} from '@heroicons/react/24/outline';

interface CASBDashboardProps {
  provider: string;
}

interface CASBProvider {
  name: string;
  status: string;
  last_sync: string;
  total_apps_monitored: number;
  blocked_apps: number;
  allowed_apps: number;
  dlp_violations: number;
  threat_detections: number;
}

const CASBDashboard: React.FC<CASBDashboardProps> = ({ provider }) => {
  const [providerData, setProviderData] = useState<CASBProvider | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchProviderData();
  }, [provider]);

  const fetchProviderData = async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/v1/cloud-security/casb/providers/${provider}`);
      if (response.ok) {
        const data = await response.json();
        setProviderData(data);
      }
    } catch (error) {
      console.error('Error fetching CASB provider data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-600 bg-green-100';
      case 'inactive':
        return 'text-red-600 bg-red-100';
      case 'warning':
        return 'text-yellow-600 bg-yellow-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!providerData) {
    return (
      <div className="text-center py-12">
        <ExclamationTriangleIcon className="w-12 h-12 text-yellow-500 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">Provider Not Found</h3>
        <p className="text-gray-600">The selected CASB provider could not be loaded.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">{providerData.name}</h2>
          <p className="text-gray-600">Cloud Access Security Broker</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(providerData.status)}`}>
            {providerData.status}
          </div>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Apps Monitored</p>
              <p className="text-2xl font-bold text-gray-900">{providerData.total_apps_monitored}</p>
            </div>
            <ChartBarIcon className="w-8 h-8 text-blue-500" />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Blocked Apps</p>
              <p className="text-2xl font-bold text-red-600">{providerData.blocked_apps}</p>
            </div>
            <XCircleIcon className="w-8 h-8 text-red-500" />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Allowed Apps</p>
              <p className="text-2xl font-bold text-green-600">{providerData.allowed_apps}</p>
            </div>
            <CheckCircleIcon className="w-8 h-8 text-green-500" />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">DLP Violations</p>
              <p className="text-2xl font-bold text-orange-600">{providerData.dlp_violations}</p>
            </div>
            <ShieldExclamationIcon className="w-8 h-8 text-orange-500" />
          </div>
        </div>
      </div>

      {/* Detailed Metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* App Distribution */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">App Distribution</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <div className="w-3 h-3 bg-green-500 rounded-full mr-3"></div>
                <span className="text-sm font-medium">Allowed</span>
              </div>
              <span className="text-sm text-gray-600">{providerData.allowed_apps}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <div className="w-3 h-3 bg-red-500 rounded-full mr-3"></div>
                <span className="text-sm font-medium">Blocked</span>
              </div>
              <span className="text-sm text-gray-600">{providerData.blocked_apps}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <div className="w-3 h-3 bg-blue-500 rounded-full mr-3"></div>
                <span className="text-sm font-medium">Monitored</span>
              </div>
              <span className="text-sm text-gray-600">{providerData.total_apps_monitored}</span>
            </div>
          </div>
        </div>

        {/* Security Events */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Events</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">DLP Violations</span>
              <span className="text-sm font-medium text-orange-600">{providerData.dlp_violations}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Threat Detections</span>
              <span className="text-sm font-medium text-red-600">{providerData.threat_detections}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Last Sync</span>
              <div className="flex items-center">
                <ClockIcon className="w-4 h-4 text-gray-400 mr-1" />
                <span className="text-sm text-gray-900">
                  {new Date(providerData.last_sync).toLocaleString()}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Activity</h3>
        <div className="space-y-3">
          <div className="flex items-center justify-between py-2 border-b border-gray-100">
            <div className="flex items-center">
              <ShieldExclamationIcon className="w-4 h-4 text-orange-500 mr-3" />
              <span className="text-sm text-gray-900">DLP violation detected in Dropbox</span>
            </div>
            <span className="text-xs text-gray-500">5 minutes ago</span>
          </div>
          <div className="flex items-center justify-between py-2 border-b border-gray-100">
            <div className="flex items-center">
              <XCircleIcon className="w-4 h-4 text-red-500 mr-3" />
              <span className="text-sm text-gray-900">Unknown app blocked automatically</span>
            </div>
            <span className="text-xs text-gray-500">15 minutes ago</span>
          </div>
          <div className="flex items-center justify-between py-2">
            <div className="flex items-center">
              <CheckCircleIcon className="w-4 h-4 text-green-500 mr-3" />
              <span className="text-sm text-gray-900">Slack app usage policy updated</span>
            </div>
            <span className="text-xs text-gray-500">1 hour ago</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CASBDashboard; 