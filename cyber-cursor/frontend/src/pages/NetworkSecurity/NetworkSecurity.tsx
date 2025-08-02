import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  WifiIcon, 
  ShieldCheckIcon, 
  BellIcon, 
  UserCircleIcon, 
  ComputerDesktopIcon,
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon
} from '@heroicons/react/24/outline';

interface NetworkSecurityData {
  overview: {
    totalDevices: number;
    activeConnections: number;
    blockedThreats: number;
    securityScore: number;
  };
  firewall: {
    totalRules: number;
    activeRules: number;
    blockedAttempts: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  idsIps: {
    totalAlerts: number;
    criticalAlerts: number;
    falsePositives: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  vpn: {
    activeSessions: number;
    totalUsers: number;
    bandwidthUsage: number;
    status: 'healthy' | 'warning' | 'critical';
  };
  nac: {
    connectedDevices: number;
    authorizedDevices: number;
    quarantinedDevices: number;
    status: 'healthy' | 'warning' | 'critical';
  };
}

const NetworkSecurity: React.FC = () => {
  const [data, setData] = useState<NetworkSecurityData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    // Simulate API call
    const fetchData = async () => {
      try {
        // Mock data - in real app, this would be an API call
        const mockData: NetworkSecurityData = {
          overview: {
            totalDevices: 156,
            activeConnections: 89,
            blockedThreats: 234,
            securityScore: 92
          },
          firewall: {
            totalRules: 1250,
            activeRules: 1180,
            blockedAttempts: 1567,
            status: 'healthy'
          },
          idsIps: {
            totalAlerts: 45,
            criticalAlerts: 3,
            falsePositives: 12,
            status: 'warning'
          },
          vpn: {
            activeSessions: 67,
            totalUsers: 89,
            bandwidthUsage: 78,
            status: 'healthy'
          },
          nac: {
            connectedDevices: 134,
            authorizedDevices: 128,
            quarantinedDevices: 6,
            status: 'healthy'
          }
        };
        
        setData(mockData);
      } catch (error) {
        console.error('Error fetching network security data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'text-green-500 bg-green-100';
      case 'warning':
        return 'text-yellow-500 bg-yellow-100';
      case 'critical':
        return 'text-red-500 bg-red-100';
      default:
        return 'text-gray-500 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircleIcon className="w-5 h-5" />;
      case 'warning':
        return <ExclamationTriangleIcon className="w-5 h-5" />;
      case 'critical':
        return <XCircleIcon className="w-5 h-5" />;
      default:
        return <ChartBarIcon className="w-5 h-5" />;
    }
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: <ChartBarIcon className="w-4 h-4" /> },
    { id: 'firewall', label: 'Firewall', icon: <ShieldCheckIcon className="w-4 h-4" /> },
    { id: 'ids-ips', label: 'IDS/IPS', icon: <BellIcon className="w-4 h-4" /> },
    { id: 'vpn', label: 'VPN', icon: <WifiIcon className="w-4 h-4" /> },
    { id: 'nac', label: 'NAC', icon: <UserCircleIcon className="w-4 h-4" /> },
    { id: 'monitoring', label: 'Monitoring', icon: <ComputerDesktopIcon className="w-4 h-4" /> }
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <ExclamationTriangleIcon className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-900">Error Loading Data</h3>
          <p className="text-gray-600">Unable to load network security data</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Network Security</h1>
          <p className="text-gray-600">Monitor and manage network security infrastructure</p>
        </div>
        <div className="flex items-center space-x-2">
          <WifiIcon className="w-8 h-8 text-blue-600" />
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Content */}
      <motion.div
        key={activeTab}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="space-y-6"
      >
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Devices</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.totalDevices}</p>
                </div>
                <ComputerDesktopIcon className="w-8 h-8 text-blue-600" />
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Active Connections</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.activeConnections}</p>
                </div>
                <WifiIcon className="w-8 h-8 text-green-600" />
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Blocked Threats</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.blockedThreats}</p>
                </div>
                <ShieldCheckIcon className="w-8 h-8 text-red-600" />
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Security Score</p>
                  <p className="text-2xl font-bold text-gray-900">{data.overview.securityScore}%</p>
                </div>
                <ChartBarIcon className="w-8 h-8 text-purple-600" />
              </div>
            </div>
          </div>
        )}

        {activeTab === 'firewall' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">Firewall Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.firewall.status)}`}>
                  {getStatusIcon(data.firewall.status)}
                  <span className="capitalize">{data.firewall.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Rules</p>
                  <p className="text-xl font-semibold text-gray-900">{data.firewall.totalRules}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Active Rules</p>
                  <p className="text-xl font-semibold text-gray-900">{data.firewall.activeRules}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Blocked Attempts</p>
                  <p className="text-xl font-semibold text-gray-900">{data.firewall.blockedAttempts}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'ids-ips' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">IDS/IPS Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.idsIps.status)}`}>
                  {getStatusIcon(data.idsIps.status)}
                  <span className="capitalize">{data.idsIps.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Total Alerts</p>
                  <p className="text-xl font-semibold text-gray-900">{data.idsIps.totalAlerts}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Critical Alerts</p>
                  <p className="text-xl font-semibold text-red-600">{data.idsIps.criticalAlerts}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">False Positives</p>
                  <p className="text-xl font-semibold text-gray-900">{data.idsIps.falsePositives}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'vpn' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">VPN Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.vpn.status)}`}>
                  {getStatusIcon(data.vpn.status)}
                  <span className="capitalize">{data.vpn.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Active Sessions</p>
                  <p className="text-xl font-semibold text-gray-900">{data.vpn.activeSessions}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Total Users</p>
                  <p className="text-xl font-semibold text-gray-900">{data.vpn.totalUsers}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Bandwidth Usage</p>
                  <p className="text-xl font-semibold text-gray-900">{data.vpn.bandwidthUsage}%</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'nac' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">NAC Status</h3>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(data.nac.status)}`}>
                  {getStatusIcon(data.nac.status)}
                  <span className="capitalize">{data.nac.status}</span>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Connected Devices</p>
                  <p className="text-xl font-semibold text-gray-900">{data.nac.connectedDevices}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Authorized Devices</p>
                  <p className="text-xl font-semibold text-green-600">{data.nac.authorizedDevices}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Quarantined Devices</p>
                  <p className="text-xl font-semibold text-red-600">{data.nac.quarantinedDevices}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'monitoring' && (
          <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Network Security Monitoring</h3>
            <p className="text-gray-600">Real-time monitoring dashboard for network security events and alerts.</p>
            <div className="mt-4 p-4 bg-gray-50 rounded-lg">
              <p className="text-sm text-gray-500">Monitoring features coming soon...</p>
            </div>
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default NetworkSecurity; 