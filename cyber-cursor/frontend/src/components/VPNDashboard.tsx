import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheckIcon,
  CheckCircleIcon,
  XCircleIcon,
  CogIcon,
  UserGroupIcon,
  GlobeAltIcon
} from '@heroicons/react/24/outline';

interface VPNProvider {
  name: string;
  status: string;
  version: string;
  active_connections: number;
  total_users: number;
  bandwidth_usage: number;
  last_updated: string;
}

interface VPNDashboardProps {
  provider: string;
}

const VPNDashboard: React.FC<VPNDashboardProps> = ({ provider }) => {
  const [vpnData, setVpnData] = useState<VPNProvider | null>(null);
  const [loading, setLoading] = useState(true);
  const [restarting, setRestarting] = useState(false);

  const mockVPNData: VPNProvider = {
    name: 'OpenVPN',
    status: 'active',
    version: '2.0.0',
    active_connections: 120,
    total_users: 150,
    bandwidth_usage: 85,
    last_updated: '2023-10-27T10:00:00Z',
  };

  const fetchVPNData = useCallback(async () => {
    try {
      setLoading(true);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      setVpnData(mockVPNData);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching VPN data:', error);
      setLoading(false);
    }
  }, [mockVPNData]);

  useEffect(() => {
    fetchVPNData();
  }, [fetchVPNData]);

  const handleRestart = async () => {
    setRestarting(true);
    try {
      const response = await fetch(`/api/v1/network-security/vpns/${provider}/restart`, {
        method: 'POST',
      });
      if (response.ok) {
        // Refresh data after restart
        setTimeout(() => {
          fetchVPNData();
          setRestarting(false);
        }, 3000);
      } else {
        setRestarting(false);
      }
    } catch (error) {
      console.error('Error restarting VPN:', error);
      setRestarting(false);
    }
  };

  const getProviderDisplayName = (provider: string) => {
    const nameMap: { [key: string]: string } = {
      'openvpn': 'OpenVPN',
      'ipsec': 'IPsec',
      'wireguard': 'WireGuard'
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

  const getConnectionRate = () => {
    if (!vpnData) return 0;
    return vpnData.total_users > 0 ? ((vpnData.active_connections / vpnData.total_users) * 100).toFixed(2) : '0.00';
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

  if (!vpnData) {
    return (
      <div className="p-6">
        <div className="text-center">
          <XCircleIcon className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">VPN Not Found</h3>
          <p className="text-gray-600">The selected VPN provider could not be loaded.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <ShieldCheckIcon className="h-8 w-8 text-green-500" />
          <div>
            <h2 className="text-2xl font-bold text-gray-900">
              {getProviderDisplayName(provider)}
            </h2>
            <p className="text-gray-600">Virtual Private Network Management</p>
          </div>
        </div>
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2">
            {getStatusIcon(vpnData.status)}
            <span className={`font-medium ${getStatusColor(vpnData.status)}`}>
              {vpnData.status.charAt(0).toUpperCase() + vpnData.status.slice(1)}
            </span>
          </div>
          <button
            onClick={handleRestart}
            disabled={restarting}
            className="flex items-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <CogIcon className={`h-4 w-4 ${restarting ? 'animate-spin' : ''}`} />
            <span>{restarting ? 'Restarting...' : 'Restart Service'}</span>
          </button>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {/* Active Connections */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Connections</p>
              <p className="text-2xl font-bold text-green-600">{vpnData.active_connections.toLocaleString()}</p>
            </div>
            <UserGroupIcon className="h-8 w-8 text-green-500" />
          </div>
        </div>

        {/* Total Users */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Users</p>
              <p className="text-2xl font-bold text-blue-600">{vpnData.total_users.toLocaleString()}</p>
            </div>
            <UserGroupIcon className="h-8 w-8 text-blue-500" />
          </div>
        </div>

        {/* Bandwidth Usage */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Bandwidth Usage</p>
              <p className="text-2xl font-bold text-purple-600">{vpnData.bandwidth_usage.toFixed(1)}%</p>
            </div>
            <GlobeAltIcon className="h-8 w-8 text-purple-500" />
          </div>
        </div>

        {/* Connection Rate */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Connection Rate</p>
              <p className="text-2xl font-bold text-orange-600">{getConnectionRate()}%</p>
            </div>
            <div className="h-8 w-8 bg-orange-100 rounded-lg flex items-center justify-center">
              <span className="text-xs font-medium text-orange-600">%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Connection Status */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 mb-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Connection Status</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center p-4 bg-green-50 rounded-lg">
            <div className="flex items-center justify-center mb-2">
              <CheckCircleIcon className="h-6 w-6 text-green-500" />
            </div>
            <p className="text-sm font-medium text-gray-900">Connected</p>
            <p className="text-2xl font-bold text-green-600">{vpnData.active_connections}</p>
          </div>
          <div className="text-center p-4 bg-gray-50 rounded-lg">
            <div className="flex items-center justify-center mb-2">
              <UserGroupIcon className="h-6 w-6 text-gray-500" />
            </div>
            <p className="text-sm font-medium text-gray-900">Available</p>
            <p className="text-2xl font-bold text-gray-600">{vpnData.total_users - vpnData.active_connections}</p>
          </div>
          <div className="text-center p-4 bg-blue-50 rounded-lg">
            <div className="flex items-center justify-center mb-2">
              <GlobeAltIcon className="h-6 w-6 text-blue-500" />
            </div>
            <p className="text-sm font-medium text-gray-900">Utilization</p>
            <p className="text-2xl font-bold text-blue-600">{getConnectionRate()}%</p>
          </div>
        </div>
      </div>

      {/* Additional Information */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">VPN Details</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="font-medium text-gray-900 mb-2">System Information</h4>
            <dl className="space-y-2">
              <div className="flex justify-between">
                <dt className="text-gray-600">Status:</dt>
                <dd className={`font-medium ${getStatusColor(vpnData.status)}`}>
                  {vpnData.status.charAt(0).toUpperCase() + vpnData.status.slice(1)}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">Version:</dt>
                <dd className="font-medium">{vpnData.version}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">Last Updated:</dt>
                <dd className="font-medium">{new Date(vpnData.last_updated).toLocaleString()}</dd>
              </div>
            </dl>
          </div>
          <div>
            <h4 className="font-medium text-gray-900 mb-2">Performance Metrics</h4>
            <dl className="space-y-2">
              <div className="flex justify-between">
                <dt className="text-gray-600">Connection Efficiency:</dt>
                <dd className="font-medium">{getConnectionRate()}%</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">Bandwidth Utilization:</dt>
                <dd className="font-medium">{vpnData.bandwidth_usage.toFixed(1)}%</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">Average per User:</dt>
                <dd className="font-medium">
                  {vpnData.active_connections > 0 ? (vpnData.bandwidth_usage / vpnData.active_connections).toFixed(2) : '0.00'}%
                </dd>
              </div>
            </dl>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 mt-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Connection Activity</h3>
        <div className="space-y-4">
          <div className="flex items-center justify-between p-4 bg-green-50 rounded-lg">
            <div className="flex items-center space-x-3">
              <CheckCircleIcon className="h-5 w-5 text-green-500" />
              <div>
                <p className="font-medium text-gray-900">User Connected</p>
                <p className="text-sm text-gray-600">john.doe@company.com connected from 192.168.1.100</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">2 minutes ago</span>
          </div>
          <div className="flex items-center justify-between p-4 bg-red-50 rounded-lg">
            <div className="flex items-center space-x-3">
              <XCircleIcon className="h-5 w-5 text-red-500" />
              <div>
                <p className="font-medium text-gray-900">Connection Failed</p>
                <p className="text-sm text-gray-600">Failed authentication attempt from 203.0.113.45</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">5 minutes ago</span>
          </div>
          <div className="flex items-center justify-between p-4 bg-blue-50 rounded-lg">
            <div className="flex items-center space-x-3">
              <GlobeAltIcon className="h-5 w-5 text-blue-500" />
              <div>
                <p className="font-medium text-gray-900">Bandwidth Alert</p>
                <p className="text-sm text-gray-600">High bandwidth usage detected on server-01</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">15 minutes ago</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default VPNDashboard; 