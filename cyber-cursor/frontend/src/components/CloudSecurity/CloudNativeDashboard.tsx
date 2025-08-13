import React, { useState, useEffect } from 'react';
import { 
  CloudIcon, 
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ShieldCheckIcon,
  ClockIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline';
import { cloudSecurityService, CloudSecurityConfig } from '../../services/cloudSecurityService';

interface CloudNativeDashboardProps {
  provider: string;
}

interface CloudNativeProvider {
  name: string;
  status: string;
  last_sync: string;
  protected_resources: number;
  active_threats: number;
  security_alerts: number;
  compliance_status: string;
}

const CloudNativeDashboard: React.FC<CloudNativeDashboardProps> = ({ provider }) => {
  const [providerData, setProviderData] = useState<CloudNativeProvider | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchProviderData();
  }, [provider]);

  const fetchProviderData = async () => {
    setLoading(true);
    setError(null);
    try {
      // Use the cloud security service to get provider data
      const configs = await cloudSecurityService.getCloudSecurityConfigs();
      const providerConfig = configs.find(config => 
        config.provider.toLowerCase() === provider.toLowerCase()
      );

      if (providerConfig) {
        // Get real-time data for the provider
        const dashboard = await cloudSecurityService.getCloudSecurityDashboard();
        const findings = await cloudSecurityService.getCloudSecurityFindings(0, 10, {
          provider: providerConfig.provider as any
        });

        // Transform data to match the interface
        setProviderData({
          name: providerConfig.account_name,
          status: providerConfig.is_active ? 'active' : 'inactive',
          last_sync: providerConfig.last_sync,
          protected_resources: dashboard.total_accounts,
          active_threats: findings.findings.filter(f => f.status === 'open').length,
          security_alerts: findings.total,
          compliance_status: dashboard.compliance_score > 80 ? 'compliant' : 'non-compliant'
        });
      } else {
        setError('Provider configuration not found');
      }
    } catch (error) {
      console.error('Error fetching Cloud Native provider data:', error);
      setError('Failed to load provider data');
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = () => {
    fetchProviderData();
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

  const getComplianceColor = (status: string) => {
    switch (status) {
      case 'compliant':
        return 'text-green-600 bg-green-100';
      case 'non-compliant':
        return 'text-red-600 bg-red-100';
      case 'partial':
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
        <p className="text-gray-600">The selected Cloud Native provider could not be loaded.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">{providerData.name}</h2>
          <p className="text-gray-600">Cloud-Native Security</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(providerData.status)}`}>
            {providerData.status}
          </div>
          <div className={`px-3 py-1 rounded-full text-sm font-medium ${getComplianceColor(providerData.compliance_status)}`}>
            {providerData.compliance_status}
          </div>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Protected Resources</p>
              <p className="text-2xl font-bold text-gray-900">{providerData.protected_resources}</p>
            </div>
            <ShieldCheckIcon className="w-8 h-8 text-green-500" />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Active Threats</p>
              <p className="text-2xl font-bold text-red-600">{providerData.active_threats}</p>
            </div>
            <ExclamationTriangleIcon className="w-8 h-8 text-red-500" />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Security Alerts</p>
              <p className="text-2xl font-bold text-orange-600">{providerData.security_alerts}</p>
            </div>
            <XCircleIcon className="w-8 h-8 text-orange-500" />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Compliance</p>
              <p className="text-2xl font-bold text-blue-600">{providerData.compliance_status}</p>
            </div>
            <CheckCircleIcon className="w-8 h-8 text-blue-500" />
          </div>
        </div>
      </div>

      {/* Detailed Metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Protection Overview */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Protection Overview</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Protected Resources</span>
              <span className="text-sm font-medium text-green-600">{providerData.protected_resources}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Active Threats</span>
              <span className="text-sm font-medium text-red-600">{providerData.active_threats}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Security Alerts</span>
              <span className="text-sm font-medium text-orange-600">{providerData.security_alerts}</span>
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

        {/* Compliance Status */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Compliance Status</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Overall Status</span>
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getComplianceColor(providerData.compliance_status)}`}>
                {providerData.compliance_status}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Provider</span>
              <span className="text-sm font-medium text-gray-900">{providerData.name}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Service Status</span>
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(providerData.status)}`}>
                {providerData.status}
              </span>
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
              <ShieldCheckIcon className="w-4 h-4 text-green-500 mr-3" />
              <span className="text-sm text-gray-900">DDoS protection activated</span>
            </div>
            <span className="text-xs text-gray-500">2 minutes ago</span>
          </div>
          <div className="flex items-center justify-between py-2 border-b border-gray-100">
            <div className="flex items-center">
              <ExclamationTriangleIcon className="w-4 h-4 text-yellow-500 mr-3" />
              <span className="text-sm text-gray-900">Security alert: suspicious activity detected</span>
            </div>
            <span className="text-xs text-gray-500">15 minutes ago</span>
          </div>
          <div className="flex items-center justify-between py-2">
            <div className="flex items-center">
              <CheckCircleIcon className="w-4 h-4 text-blue-500 mr-3" />
              <span className="text-sm text-gray-900">Compliance scan completed</span>
            </div>
            <span className="text-xs text-gray-500">1 hour ago</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CloudNativeDashboard; 