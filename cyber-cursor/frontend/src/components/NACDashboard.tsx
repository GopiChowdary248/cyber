import React, { useState, useEffect } from 'react';
import { 
  UserGroupIcon, 
  ShieldCheckIcon, 
  ExclamationTriangleIcon,
  ComputerDesktopIcon,
  CheckCircleIcon,
  XCircleIcon,
  EyeIcon
} from '@heroicons/react/24/outline';

interface NACProvider {
  name: string;
  status: string;
  version: string;
  managed_devices: number;
  quarantined_devices: number;
  compliance_score: number;
  last_updated: string;
}

interface NACDashboardProps {
  provider: string;
}

const NACDashboard: React.FC<NACDashboardProps> = ({ provider }) => {
  const [nacData, setNacData] = useState<NACProvider | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchNACData();
  }, [provider]);

  const fetchNACData = async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/v1/network-security/nac/${provider}`);
      if (response.ok) {
        const data = await response.json();
        setNacData(data);
      } else {
        console.error('Failed to fetch NAC data');
      }
    } catch (error) {
      console.error('Error fetching NAC data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getProviderDisplayName = (provider: string) => {
    const nameMap: { [key: string]: string } = {
      'cisco-ise': 'Cisco ISE',
      'aruba-clearpass': 'Aruba ClearPass'
    };
    return nameMap[provider] || provider;
  };

  const getStatusColor = (status: string) => {
    return status === 'active' ? 'text-green-600' : 'text-red-600';
  };

  const getStatusIcon = (status: string) => {
    return status === 'active' ? (
      <CheckCircleIcon className="h-5 w-5 text-green-600" />
    ) : (
      <XCircleIcon className="h-5 w-5 text-red-600" />
    );
  };

  const getComplianceColor = (score: number) => {
    if (score >= 90) return 'text-green-600';
    if (score >= 70) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getComplianceStatus = (score: number) => {
    if (score >= 90) return 'Excellent';
    if (score >= 70) return 'Good';
    if (score >= 50) return 'Fair';
    return 'Poor';
  };

  if (loading) {
    return (
      <div className="p-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-1/4 mb-4"></div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-32 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (!nacData) {
    return (
      <div className="p-6">
        <div className="text-center">
          <XCircleIcon className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">NAC Not Found</h3>
          <p className="text-gray-600">The selected NAC provider could not be loaded.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <UserGroupIcon className="h-8 w-8 text-purple-500" />
          <div>
            <h2 className="text-2xl font-bold text-gray-900">
              {getProviderDisplayName(provider)}
            </h2>
            <p className="text-gray-600">Network Access Control Management</p>
          </div>
        </div>
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2">
            {getStatusIcon(nacData.status)}
            <span className={`font-medium ${getStatusColor(nacData.status)}`}>
              {nacData.status.charAt(0).toUpperCase() + nacData.status.slice(1)}
            </span>
          </div>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {/* Managed Devices */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Managed Devices</p>
              <p className="text-2xl font-bold text-blue-600">{nacData.managed_devices.toLocaleString()}</p>
            </div>
            <ComputerDesktopIcon className="h-8 w-8 text-blue-500" />
          </div>
        </div>

        {/* Quarantined Devices */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Quarantined Devices</p>
              <p className="text-2xl font-bold text-red-600">{nacData.quarantined_devices.toLocaleString()}</p>
            </div>
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
          </div>
        </div>

        {/* Compliance Score */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Compliance Score</p>
              <p className={`text-2xl font-bold ${getComplianceColor(nacData.compliance_score)}`}>
                {nacData.compliance_score.toFixed(1)}%
              </p>
            </div>
            <ShieldCheckIcon className="h-8 w-8 text-green-500" />
          </div>
        </div>

        {/* Active Devices */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Devices</p>
              <p className="text-2xl font-bold text-green-600">
                {(nacData.managed_devices - nacData.quarantined_devices).toLocaleString()}
              </p>
            </div>
            <CheckCircleIcon className="h-8 w-8 text-green-500" />
          </div>
        </div>
      </div>

      {/* Device Status Overview */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 mb-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Device Status Overview</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center p-4 bg-green-50 rounded-lg">
            <div className="flex items-center justify-center mb-2">
              <CheckCircleIcon className="h-6 w-6 text-green-500" />
            </div>
            <p className="text-sm font-medium text-gray-900">Compliant</p>
            <p className="text-2xl font-bold text-green-600">
              {nacData.managed_devices - nacData.quarantined_devices}
            </p>
          </div>
          <div className="text-center p-4 bg-red-50 rounded-lg">
            <div className="flex items-center justify-center mb-2">
              <ExclamationTriangleIcon className="h-6 w-6 text-red-500" />
            </div>
            <p className="text-sm font-medium text-gray-900">Quarantined</p>
            <p className="text-2xl font-bold text-red-600">{nacData.quarantined_devices}</p>
          </div>
          <div className="text-center p-4 bg-blue-50 rounded-lg">
            <div className="flex items-center justify-center mb-2">
              <EyeIcon className="h-6 w-6 text-blue-500" />
            </div>
            <p className="text-sm font-medium text-gray-900">Compliance Rate</p>
            <p className="text-2xl font-bold text-blue-600">
              {nacData.managed_devices > 0 ? ((nacData.managed_devices - nacData.quarantined_devices) / nacData.managed_devices * 100).toFixed(1) : '0.0'}%
            </p>
          </div>
        </div>
      </div>

      {/* Additional Information */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">NAC Details</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="font-medium text-gray-900 mb-2">System Information</h4>
            <dl className="space-y-2">
              <div className="flex justify-between">
                <dt className="text-gray-600">Status:</dt>
                <dd className={`font-medium ${getStatusColor(nacData.status)}`}>
                  {nacData.status.charAt(0).toUpperCase() + nacData.status.slice(1)}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">Version:</dt>
                <dd className="font-medium">{nacData.version}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">Last Updated:</dt>
                <dd className="font-medium">{new Date(nacData.last_updated).toLocaleString()}</dd>
              </div>
            </dl>
          </div>
          <div>
            <h4 className="font-medium text-gray-900 mb-2">Compliance Metrics</h4>
            <dl className="space-y-2">
              <div className="flex justify-between">
                <dt className="text-gray-600">Overall Score:</dt>
                <dd className={`font-medium ${getComplianceColor(nacData.compliance_score)}`}>
                  {nacData.compliance_score.toFixed(1)}%
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">Status:</dt>
                <dd className={`font-medium ${getComplianceColor(nacData.compliance_score)}`}>
                  {getComplianceStatus(nacData.compliance_score)}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">Quarantine Rate:</dt>
                <dd className="font-medium">
                  {nacData.managed_devices > 0 ? ((nacData.quarantined_devices / nacData.managed_devices) * 100).toFixed(2) : '0.00'}%
                </dd>
              </div>
            </dl>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 mt-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Device Activity</h3>
        <div className="space-y-4">
          <div className="flex items-center justify-between p-4 bg-red-50 rounded-lg">
            <div className="flex items-center space-x-3">
              <ExclamationTriangleIcon className="h-5 w-5 text-red-500" />
              <div>
                <p className="font-medium text-gray-900">Device Quarantined</p>
                <p className="text-sm text-gray-600">Workstation-03 (192.168.1.103) - Missing security patches</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">5 minutes ago</span>
          </div>
          <div className="flex items-center justify-between p-4 bg-green-50 rounded-lg">
            <div className="flex items-center space-x-3">
              <CheckCircleIcon className="h-5 w-5 text-green-500" />
              <div>
                <p className="font-medium text-gray-900">Device Compliant</p>
                <p className="text-sm text-gray-600">Laptop-07 (192.168.1.107) - All security requirements met</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">12 minutes ago</span>
          </div>
          <div className="flex items-center justify-between p-4 bg-blue-50 rounded-lg">
            <div className="flex items-center space-x-3">
              <EyeIcon className="h-5 w-5 text-blue-500" />
              <div>
                <p className="font-medium text-gray-900">Policy Update</p>
                <p className="text-sm text-gray-600">Updated compliance policy for mobile devices</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">1 hour ago</span>
          </div>
        </div>
      </div>

      {/* Compliance Breakdown */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 mt-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Compliance Breakdown</h3>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <CheckCircleIcon className="h-5 w-5 text-green-500" />
              <span className="font-medium text-gray-900">Security Patches</span>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-32 bg-gray-200 rounded-full h-2">
                <div className="bg-green-500 h-2 rounded-full" style={{ width: '95%' }}></div>
              </div>
              <span className="text-sm font-medium text-gray-600">95%</span>
            </div>
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <CheckCircleIcon className="h-5 w-5 text-green-500" />
              <span className="font-medium text-gray-900">Antivirus Software</span>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-32 bg-gray-200 rounded-full h-2">
                <div className="bg-green-500 h-2 rounded-full" style={{ width: '98%' }}></div>
              </div>
              <span className="text-sm font-medium text-gray-600">98%</span>
            </div>
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <ExclamationTriangleIcon className="h-5 w-5 text-yellow-500" />
              <span className="font-medium text-gray-900">Firewall Configuration</span>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-32 bg-gray-200 rounded-full h-2">
                <div className="bg-yellow-500 h-2 rounded-full" style={{ width: '87%' }}></div>
              </div>
              <span className="text-sm font-medium text-gray-600">87%</span>
            </div>
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <CheckCircleIcon className="h-5 w-5 text-green-500" />
              <span className="font-medium text-gray-900">Encryption</span>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-32 bg-gray-200 rounded-full h-2">
                <div className="bg-green-500 h-2 rounded-full" style={{ width: '92%' }}></div>
              </div>
              <span className="text-sm font-medium text-gray-600">92%</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NACDashboard; 