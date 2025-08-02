import React, { useState, useEffect } from 'react';
import { 
  EyeIcon, 
  ExclamationTriangleIcon, 
  ShieldExclamationIcon,
  PlayIcon,
  StopIcon,
  CheckCircleIcon,
  XCircleIcon
} from '@heroicons/react/24/outline';

interface IDSIPSProvider {
  name: string;
  status: string;
  version: string;
  alerts_count: number;
  blocked_attacks: number;
  false_positives: number;
  last_updated: string;
}

interface IDSIPSDashboardProps {
  provider: string;
}

const IDSIPSDashboard: React.FC<IDSIPSDashboardProps> = ({ provider }) => {
  const [idsipsData, setIdsipsData] = useState<IDSIPSProvider | null>(null);
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    fetchIDSIPSData();
  }, [provider]);

  const fetchIDSIPSData = async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/v1/network-security/idsips/${provider}`);
      if (response.ok) {
        const data = await response.json();
        setIdsipsData(data);
      } else {
        console.error('Failed to fetch IDS/IPS data');
      }
    } catch (error) {
      console.error('Error fetching IDS/IPS data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    try {
      const response = await fetch(`/api/v1/network-security/idsips/${provider}/test`, {
        method: 'POST',
      });
      if (response.ok) {
        const result = await response.json();
        alert(`Test completed: ${result.message}`);
      } else {
        alert('Test failed');
      }
    } catch (error) {
      console.error('Error testing IDS/IPS:', error);
      alert('Test failed');
    } finally {
      setTesting(false);
    }
  };

  const getProviderDisplayName = (provider: string) => {
    const nameMap: { [key: string]: string } = {
      'snort': 'Snort',
      'suricata': 'Suricata',
      'bro-zeek': 'Bro/Zeek'
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

  const getDetectionRate = () => {
    if (!idsipsData) return 0;
    const totalAlerts = idsipsData.alerts_count;
    const falsePositives = idsipsData.false_positives;
    return totalAlerts > 0 ? ((totalAlerts - falsePositives) / totalAlerts * 100).toFixed(2) : '0.00';
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

  if (!idsipsData) {
    return (
      <div className="p-6">
        <div className="text-center">
          <ExclamationTriangleIcon className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">IDS/IPS Not Found</h3>
          <p className="text-gray-600">The selected IDS/IPS provider could not be loaded.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <EyeIcon className="h-8 w-8 text-yellow-500" />
          <div>
            <h2 className="text-2xl font-bold text-gray-900">
              {getProviderDisplayName(provider)}
            </h2>
            <p className="text-gray-600">Intrusion Detection/Prevention System</p>
          </div>
        </div>
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2">
            {getStatusIcon(idsipsData.status)}
            <span className={`font-medium ${getStatusColor(idsipsData.status)}`}>
              {idsipsData.status.charAt(0).toUpperCase() + idsipsData.status.slice(1)}
            </span>
          </div>
          <button
            onClick={handleTest}
            disabled={testing}
            className="flex items-center space-x-2 px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {testing ? (
              <StopIcon className="h-4 w-4" />
            ) : (
              <PlayIcon className="h-4 w-4" />
            )}
            <span>{testing ? 'Testing...' : 'Test System'}</span>
          </button>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {/* Total Alerts */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Alerts</p>
              <p className="text-2xl font-bold text-gray-900">{idsipsData.alerts_count.toLocaleString()}</p>
            </div>
            <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
          </div>
        </div>

        {/* Blocked Attacks */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Blocked Attacks</p>
              <p className="text-2xl font-bold text-green-600">{idsipsData.blocked_attacks.toLocaleString()}</p>
            </div>
            <ShieldExclamationIcon className="h-8 w-8 text-green-500" />
          </div>
        </div>

        {/* False Positives */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">False Positives</p>
              <p className="text-2xl font-bold text-yellow-600">{idsipsData.false_positives.toLocaleString()}</p>
            </div>
            <XCircleIcon className="h-8 w-8 text-yellow-500" />
          </div>
        </div>

        {/* Detection Rate */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Detection Rate</p>
              <p className="text-2xl font-bold text-blue-600">{getDetectionRate()}%</p>
            </div>
            <div className="h-8 w-8 bg-blue-100 rounded-lg flex items-center justify-center">
              <span className="text-xs font-medium text-blue-600">%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Additional Information */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">IDS/IPS Details</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="font-medium text-gray-900 mb-2">System Information</h4>
            <dl className="space-y-2">
              <div className="flex justify-between">
                <dt className="text-gray-600">Status:</dt>
                <dd className={`font-medium ${getStatusColor(idsipsData.status)}`}>
                  {idsipsData.status.charAt(0).toUpperCase() + idsipsData.status.slice(1)}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">Version:</dt>
                <dd className="font-medium">{idsipsData.version}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">Last Updated:</dt>
                <dd className="font-medium">{new Date(idsipsData.last_updated).toLocaleString()}</dd>
              </div>
            </dl>
          </div>
          <div>
            <h4 className="font-medium text-gray-900 mb-2">Performance Metrics</h4>
            <dl className="space-y-2">
              <div className="flex justify-between">
                <dt className="text-gray-600">Success Rate:</dt>
                <dd className="font-medium">
                  {idsipsData.alerts_count > 0 ? ((idsipsData.blocked_attacks / idsipsData.alerts_count) * 100).toFixed(2) : '0.00'}%
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">False Positive Rate:</dt>
                <dd className="font-medium">
                  {idsipsData.alerts_count > 0 ? ((idsipsData.false_positives / idsipsData.alerts_count) * 100).toFixed(2) : '0.00'}%
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">Total Detections:</dt>
                <dd className="font-medium">{idsipsData.alerts_count.toLocaleString()}</dd>
              </div>
            </dl>
          </div>
        </div>
      </div>

      {/* Threat Intelligence */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 mt-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Threat Activity</h3>
        <div className="space-y-4">
          <div className="flex items-center justify-between p-4 bg-red-50 rounded-lg">
            <div className="flex items-center space-x-3">
              <ExclamationTriangleIcon className="h-5 w-5 text-red-500" />
              <div>
                <p className="font-medium text-gray-900">Port Scan Detected</p>
                <p className="text-sm text-gray-600">Multiple connection attempts on port 22</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">2 minutes ago</span>
          </div>
          <div className="flex items-center justify-between p-4 bg-yellow-50 rounded-lg">
            <div className="flex items-center space-x-3">
              <ShieldExclamationIcon className="h-5 w-5 text-yellow-500" />
              <div>
                <p className="font-medium text-gray-900">Suspicious Traffic</p>
                <p className="text-sm text-gray-600">Unusual data transfer pattern detected</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">15 minutes ago</span>
          </div>
          <div className="flex items-center justify-between p-4 bg-green-50 rounded-lg">
            <div className="flex items-center space-x-3">
              <CheckCircleIcon className="h-5 w-5 text-green-500" />
              <div>
                <p className="font-medium text-gray-900">Attack Blocked</p>
                <p className="text-sm text-gray-600">DDoS attempt successfully mitigated</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">1 hour ago</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default IDSIPSDashboard; 