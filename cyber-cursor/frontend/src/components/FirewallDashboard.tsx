import React, { useState, useEffect } from 'react';
import { 
  FireIcon, 
  ShieldCheckIcon, 
  ExclamationTriangleIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  XCircleIcon
} from '@heroicons/react/24/outline';

interface FirewallProvider {
  name: string;
  status: string;
  version: string;
  rules_count: number;
  blocked_connections: number;
  allowed_connections: number;
  last_updated: string;
}

interface FirewallDashboardProps {
  provider: string;
}

const FirewallDashboard: React.FC<FirewallDashboardProps> = ({ provider }) => {
  const [firewallData, setFirewallData] = useState<FirewallProvider | null>(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);

  useEffect(() => {
    fetchFirewallData();
  }, [provider]);

  const fetchFirewallData = async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/v1/network-security/firewalls/${provider}`);
      if (response.ok) {
        const data = await response.json();
        setFirewallData(data);
      } else {
        console.error('Failed to fetch firewall data');
      }
    } catch (error) {
      console.error('Error fetching firewall data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSync = async () => {
    setSyncing(true);
    try {
      const response = await fetch(`/api/v1/network-security/firewalls/${provider}/sync`, {
        method: 'POST',
      });
      if (response.ok) {
        // Refresh data after sync
        setTimeout(() => {
          fetchFirewallData();
          setSyncing(false);
        }, 2000);
      } else {
        setSyncing(false);
      }
    } catch (error) {
      console.error('Error syncing firewall:', error);
      setSyncing(false);
    }
  };

  const getProviderDisplayName = (provider: string) => {
    const nameMap: { [key: string]: string } = {
      'cisco-asa': 'Cisco ASA',
      'palo-alto': 'Palo Alto',
      'fortinet': 'Fortinet'
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

  if (!firewallData) {
    return (
      <div className="p-6">
        <div className="text-center">
          <ExclamationTriangleIcon className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">Firewall Not Found</h3>
          <p className="text-gray-600">The selected firewall provider could not be loaded.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <FireIcon className="h-8 w-8 text-red-500" />
          <div>
            <h2 className="text-2xl font-bold text-gray-900">
              {getProviderDisplayName(provider)}
            </h2>
            <p className="text-gray-600">Firewall Management Dashboard</p>
          </div>
        </div>
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2">
            {getStatusIcon(firewallData.status)}
            <span className={`font-medium ${getStatusColor(firewallData.status)}`}>
              {firewallData.status.charAt(0).toUpperCase() + firewallData.status.slice(1)}
            </span>
          </div>
          <button
            onClick={handleSync}
            disabled={syncing}
            className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <ArrowPathIcon className={`h-4 w-4 ${syncing ? 'animate-spin' : ''}`} />
            <span>{syncing ? 'Syncing...' : 'Sync'}</span>
          </button>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {/* Rules Count */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Rules</p>
              <p className="text-2xl font-bold text-gray-900">{firewallData.rules_count.toLocaleString()}</p>
            </div>
            <ShieldCheckIcon className="h-8 w-8 text-blue-500" />
          </div>
        </div>

        {/* Blocked Connections */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Blocked Connections</p>
              <p className="text-2xl font-bold text-red-600">{firewallData.blocked_connections.toLocaleString()}</p>
            </div>
            <XCircleIcon className="h-8 w-8 text-red-500" />
          </div>
        </div>

        {/* Allowed Connections */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Allowed Connections</p>
              <p className="text-2xl font-bold text-green-600">{firewallData.allowed_connections.toLocaleString()}</p>
            </div>
            <CheckCircleIcon className="h-8 w-8 text-green-500" />
          </div>
        </div>

        {/* Version */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Version</p>
              <p className="text-2xl font-bold text-gray-900">{firewallData.version}</p>
            </div>
            <div className="h-8 w-8 bg-gray-100 rounded-lg flex items-center justify-center">
              <span className="text-xs font-medium text-gray-600">v</span>
            </div>
          </div>
        </div>
      </div>

      {/* Additional Information */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Firewall Details</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="font-medium text-gray-900 mb-2">Configuration</h4>
            <dl className="space-y-2">
              <div className="flex justify-between">
                <dt className="text-gray-600">Status:</dt>
                <dd className={`font-medium ${getStatusColor(firewallData.status)}`}>
                  {firewallData.status.charAt(0).toUpperCase() + firewallData.status.slice(1)}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">Version:</dt>
                <dd className="font-medium">{firewallData.version}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">Last Updated:</dt>
                <dd className="font-medium">{new Date(firewallData.last_updated).toLocaleString()}</dd>
              </div>
            </dl>
          </div>
          <div>
            <h4 className="font-medium text-gray-900 mb-2">Performance Metrics</h4>
            <dl className="space-y-2">
              <div className="flex justify-between">
                <dt className="text-gray-600">Block Rate:</dt>
                <dd className="font-medium">
                  {((firewallData.blocked_connections / (firewallData.blocked_connections + firewallData.allowed_connections)) * 100).toFixed(2)}%
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">Total Connections:</dt>
                <dd className="font-medium">{(firewallData.blocked_connections + firewallData.allowed_connections).toLocaleString()}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-600">Rules per Connection:</dt>
                <dd className="font-medium">
                  {((firewallData.blocked_connections + firewallData.allowed_connections) / firewallData.rules_count).toFixed(2)}
                </dd>
              </div>
            </dl>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FirewallDashboard; 