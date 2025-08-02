import React, { useState, useEffect } from 'react';
import { 
  ShieldCheckIcon, 
  FireIcon, 
  EyeIcon, 
  LockClosedIcon, 
  UserGroupIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ComputerDesktopIcon
} from '@heroicons/react/24/outline';

interface NetworkSecurityMetrics {
  total_devices: number;
  active_devices: number;
  blocked_threats: number;
  security_score: number;
  last_updated: string;
}

const NetworkSecurityOverview: React.FC = () => {
  const [metrics, setMetrics] = useState<NetworkSecurityMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchMetrics();
  }, []);

  const fetchMetrics = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/v1/network-security/metrics');
      if (response.ok) {
        const data = await response.json();
        setMetrics(data);
      } else {
        console.error('Failed to fetch network security metrics');
      }
    } catch (error) {
      console.error('Error fetching network security metrics:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSecurityScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-600';
    if (score >= 70) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getSecurityScoreStatus = (score: number) => {
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
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-32 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (!metrics) {
    return (
      <div className="p-6">
        <div className="text-center">
          <ExclamationTriangleIcon className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">Metrics Not Available</h3>
          <p className="text-gray-600">Network security metrics could not be loaded.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900">Network Security Overview</h2>
        <p className="text-gray-600">Comprehensive view of your network security infrastructure</p>
      </div>

      {/* Main Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {/* Total Devices */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Devices</p>
              <p className="text-2xl font-bold text-blue-600">{metrics.total_devices.toLocaleString()}</p>
            </div>
            <ComputerDesktopIcon className="h-8 w-8 text-blue-500" />
          </div>
        </div>

        {/* Active Devices */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Devices</p>
              <p className="text-2xl font-bold text-green-600">{metrics.active_devices.toLocaleString()}</p>
            </div>
            <CheckCircleIcon className="h-8 w-8 text-green-500" />
          </div>
        </div>

        {/* Blocked Threats */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Blocked Threats</p>
              <p className="text-2xl font-bold text-red-600">{metrics.blocked_threats.toLocaleString()}</p>
            </div>
            <ShieldCheckIcon className="h-8 w-8 text-red-500" />
          </div>
        </div>

        {/* Security Score */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Security Score</p>
              <p className={`text-2xl font-bold ${getSecurityScoreColor(metrics.security_score)}`}>
                {metrics.security_score.toFixed(1)}%
              </p>
            </div>
            <div className="h-8 w-8 bg-gray-100 rounded-lg flex items-center justify-center">
              <span className="text-xs font-medium text-gray-600">%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Security Components Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Firewalls */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center space-x-3 mb-4">
            <FireIcon className="h-6 w-6 text-red-500" />
            <h3 className="text-lg font-semibold text-gray-900">Firewalls</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Cisco ASA</span>
              <div className="flex items-center space-x-2">
                <CheckCircleIcon className="h-4 w-4 text-green-500" />
                <span className="text-sm font-medium text-green-600">Active</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Palo Alto</span>
              <div className="flex items-center space-x-2">
                <CheckCircleIcon className="h-4 w-4 text-green-500" />
                <span className="text-sm font-medium text-green-600">Active</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Fortinet</span>
              <div className="flex items-center space-x-2">
                <XCircleIcon className="h-4 w-4 text-red-500" />
                <span className="text-sm font-medium text-red-600">Inactive</span>
              </div>
            </div>
          </div>
        </div>

        {/* IDS/IPS */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center space-x-3 mb-4">
            <EyeIcon className="h-6 w-6 text-yellow-500" />
            <h3 className="text-lg font-semibold text-gray-900">IDS/IPS</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Snort</span>
              <div className="flex items-center space-x-2">
                <CheckCircleIcon className="h-4 w-4 text-green-500" />
                <span className="text-sm font-medium text-green-600">Active</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Suricata</span>
              <div className="flex items-center space-x-2">
                <CheckCircleIcon className="h-4 w-4 text-green-500" />
                <span className="text-sm font-medium text-green-600">Active</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Bro/Zeek</span>
              <div className="flex items-center space-x-2">
                <XCircleIcon className="h-4 w-4 text-red-500" />
                <span className="text-sm font-medium text-red-600">Inactive</span>
              </div>
            </div>
          </div>
        </div>

        {/* VPNs */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center space-x-3 mb-4">
            <LockClosedIcon className="h-6 w-6 text-green-500" />
            <h3 className="text-lg font-semibold text-gray-900">VPNs</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">OpenVPN</span>
              <div className="flex items-center space-x-2">
                <CheckCircleIcon className="h-4 w-4 text-green-500" />
                <span className="text-sm font-medium text-green-600">Active</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">IPsec</span>
              <div className="flex items-center space-x-2">
                <CheckCircleIcon className="h-4 w-4 text-green-500" />
                <span className="text-sm font-medium text-green-600">Active</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">WireGuard</span>
              <div className="flex items-center space-x-2">
                <XCircleIcon className="h-4 w-4 text-red-500" />
                <span className="text-sm font-medium text-red-600">Inactive</span>
              </div>
            </div>
          </div>
        </div>

        {/* NAC */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center space-x-3 mb-4">
            <UserGroupIcon className="h-6 w-6 text-purple-500" />
            <h3 className="text-lg font-semibold text-gray-900">NAC</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Cisco ISE</span>
              <div className="flex items-center space-x-2">
                <CheckCircleIcon className="h-4 w-4 text-green-500" />
                <span className="text-sm font-medium text-green-600">Active</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Aruba ClearPass</span>
              <div className="flex items-center space-x-2">
                <CheckCircleIcon className="h-4 w-4 text-green-500" />
                <span className="text-sm font-medium text-green-600">Active</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Security Status */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 mb-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Overall Security Status</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center p-4 bg-green-50 rounded-lg">
            <div className="flex items-center justify-center mb-2">
              <CheckCircleIcon className="h-6 w-6 text-green-500" />
            </div>
            <p className="text-sm font-medium text-gray-900">Security Score</p>
            <p className={`text-2xl font-bold ${getSecurityScoreColor(metrics.security_score)}`}>
              {metrics.security_score.toFixed(1)}%
            </p>
            <p className="text-sm text-gray-600">{getSecurityScoreStatus(metrics.security_score)}</p>
          </div>
          <div className="text-center p-4 bg-blue-50 rounded-lg">
            <div className="flex items-center justify-center mb-2">
              <ShieldCheckIcon className="h-6 w-6 text-blue-500" />
            </div>
            <p className="text-sm font-medium text-gray-900">Threats Blocked</p>
            <p className="text-2xl font-bold text-blue-600">{metrics.blocked_threats.toLocaleString()}</p>
            <p className="text-sm text-gray-600">This month</p>
          </div>
          <div className="text-center p-4 bg-purple-50 rounded-lg">
            <div className="flex items-center justify-center mb-2">
              <UserGroupIcon className="h-6 w-6 text-purple-500" />
            </div>
            <p className="text-sm font-medium text-gray-900">Device Coverage</p>
            <p className="text-2xl font-bold text-purple-600">
              {metrics.total_devices > 0 ? ((metrics.active_devices / metrics.total_devices) * 100).toFixed(1) : '0.0'}%
            </p>
            <p className="text-sm text-gray-600">Protected</p>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Security Events</h3>
        <div className="space-y-4">
          <div className="flex items-center justify-between p-4 bg-red-50 rounded-lg">
            <div className="flex items-center space-x-3">
              <ExclamationTriangleIcon className="h-5 w-5 text-red-500" />
              <div>
                <p className="font-medium text-gray-900">DDoS Attack Blocked</p>
                <p className="text-sm text-gray-600">Large volume attack mitigated by firewall</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">2 hours ago</span>
          </div>
          <div className="flex items-center justify-between p-4 bg-yellow-50 rounded-lg">
            <div className="flex items-center space-x-3">
              <EyeIcon className="h-5 w-5 text-yellow-500" />
              <div>
                <p className="font-medium text-gray-900">Suspicious Activity Detected</p>
                <p className="text-sm text-gray-600">IDS detected unusual traffic pattern</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">4 hours ago</span>
          </div>
          <div className="flex items-center justify-between p-4 bg-green-50 rounded-lg">
            <div className="flex items-center space-x-3">
              <CheckCircleIcon className="h-5 w-5 text-green-500" />
              <div>
                <p className="font-medium text-gray-900">Device Compliance Updated</p>
                <p className="text-sm text-gray-600">All devices now meet security requirements</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">6 hours ago</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkSecurityOverview; 