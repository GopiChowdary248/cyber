import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { Shield, Wifi, Lock, Eye, Activity, AlertTriangle, Users, Globe } from 'lucide-react';

interface NetworkStatus {
  status: string;
  timestamp: string;
  active_threats: number;
  blocked_ips_count: number;
  vpn_connections: number;
  network_segments: number;
  firewall_rules_active: number;
  dns_blacklist_size: number;
  dns_whitelist_size: number;
}

interface SecurityReport {
  report_generated: string;
  time_period: string;
  total_alerts: number;
  severity_breakdown: Record<string, number>;
  threat_breakdown: Record<string, number>;
  active_vpn_connections: number;
  blocked_ips: number;
  ddos_attacks: number;
  firewall_rules: number;
  nac_policies: number;
}

const NetworkSecurity: React.FC = () => {
  const { user } = useAuth();
  const [networkStatus, setNetworkStatus] = useState<NetworkStatus | null>(null);
  const [securityReport, setSecurityReport] = useState<SecurityReport | null>(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchNetworkData();
  }, []);

  const fetchNetworkData = async () => {
    try {
      setLoading(true);
      
      // Fetch network status
      const statusResponse = await fetch('/api/v1/network-security/status', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (statusResponse.ok) {
        const statusData = await statusResponse.json();
        setNetworkStatus(statusData);
      }

      // Fetch security report
      const reportResponse = await fetch('/api/v1/network-security/reports/security', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (reportResponse.ok) {
        const reportData = await reportResponse.json();
        setSecurityReport(reportData);
      }
    } catch (error) {
      console.error('Error fetching network data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'healthy':
        return 'text-green-500';
      case 'warning':
        return 'text-yellow-500';
      case 'critical':
        return 'text-red-500';
      default:
        return 'text-gray-500';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'text-red-500';
      case 'high':
        return 'text-orange-500';
      case 'medium':
        return 'text-yellow-500';
      case 'low':
        return 'text-green-500';
      default:
        return 'text-gray-500';
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-cyber-dark text-white p-6">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-cyber-dark text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2 flex items-center">
            <Shield className="mr-3 text-red-500" size={32} />
            Network Security Infrastructure
          </h1>
          <p className="text-gray-400">
            Comprehensive network security management including firewall, IDS/IPS, VPN, NAC, and DNS security
          </p>
        </div>

        {/* Network Status Overview */}
        {networkStatus && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-400 text-sm">Network Status</p>
                  <p className={`text-xl font-semibold ${getStatusColor(networkStatus.status)}`}>
                    {networkStatus.status.toUpperCase()}
                  </p>
                </div>
                <Activity className="text-red-500" size={24} />
              </div>
            </div>

            <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-400 text-sm">Active Threats</p>
                  <p className="text-xl font-semibold text-red-500">
                    {networkStatus.active_threats}
                  </p>
                </div>
                <AlertTriangle className="text-red-500" size={24} />
              </div>
            </div>

            <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-400 text-sm">Blocked IPs</p>
                  <p className="text-xl font-semibold text-orange-500">
                    {networkStatus.blocked_ips_count}
                  </p>
                </div>
                <Lock className="text-orange-500" size={24} />
              </div>
            </div>

            <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-400 text-sm">VPN Connections</p>
                  <p className="text-xl font-semibold text-blue-500">
                    {networkStatus.vpn_connections}
                  </p>
                </div>
                <Wifi className="text-blue-500" size={24} />
              </div>
            </div>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className="mb-6">
          <nav className="flex space-x-1 bg-cyber-dark border border-red-700/20 rounded-lg p-1">
            {[
              { id: 'overview', label: 'Overview', icon: Eye },
              { id: 'firewall', label: 'Firewall', icon: Shield },
              { id: 'ids', label: 'IDS/IPS', icon: AlertTriangle },
              { id: 'vpn', label: 'VPN', icon: Wifi },
              { id: 'nac', label: 'NAC', icon: Users },
              { id: 'dns', label: 'DNS Security', icon: Globe },
              { id: 'segments', label: 'Segments', icon: Lock },
              { id: 'monitoring', label: 'Monitoring', icon: Activity }
            ].map((tab) => {
              const IconComponent = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeTab === tab.id
                      ? 'bg-red-600 text-white'
                      : 'text-gray-400 hover:text-white hover:bg-red-600/20'
                  }`}
                >
                  <IconComponent size={16} className="mr-2" />
                  {tab.label}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Tab Content */}
        <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-6">
          {activeTab === 'overview' && (
            <div>
              <h2 className="text-2xl font-bold text-white mb-6">Network Security Overview</h2>
              
              {securityReport && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                  {/* Security Metrics */}
                  <div>
                    <h3 className="text-xl font-semibold text-white mb-4">Security Metrics (24h)</h3>
                    <div className="space-y-4">
                      <div className="flex justify-between items-center p-3 bg-cyber-dark border border-red-700/20 rounded-lg">
                        <span className="text-gray-400">Total Alerts</span>
                        <span className="text-white font-semibold">{securityReport.total_alerts}</span>
                      </div>
                      <div className="flex justify-between items-center p-3 bg-cyber-dark border border-red-700/20 rounded-lg">
                        <span className="text-gray-400">DDoS Attacks</span>
                        <span className="text-red-500 font-semibold">{securityReport.ddos_attacks}</span>
                      </div>
                      <div className="flex justify-between items-center p-3 bg-cyber-dark border border-red-700/20 rounded-lg">
                        <span className="text-gray-400">Active VPN</span>
                        <span className="text-blue-500 font-semibold">{securityReport.active_vpn_connections}</span>
                      </div>
                      <div className="flex justify-between items-center p-3 bg-cyber-dark border border-red-700/20 rounded-lg">
                        <span className="text-gray-400">Firewall Rules</span>
                        <span className="text-green-500 font-semibold">{securityReport.firewall_rules}</span>
                      </div>
                    </div>
                  </div>

                  {/* Threat Breakdown */}
                  <div>
                    <h3 className="text-xl font-semibold text-white mb-4">Threat Breakdown</h3>
                    <div className="space-y-3">
                      {Object.entries(securityReport.threat_breakdown).map(([threat, count]) => (
                        <div key={threat} className="flex justify-between items-center p-3 bg-cyber-dark border border-red-700/20 rounded-lg">
                          <span className="text-gray-400 capitalize">{threat.replace('_', ' ')}</span>
                          <span className="text-white font-semibold">{count}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Quick Actions */}
              <div className="mt-8">
                <h3 className="text-xl font-semibold text-white mb-4">Quick Actions</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <button
                    onClick={() => setActiveTab('firewall')}
                    className="p-4 bg-cyber-dark border border-red-700/20 rounded-lg hover:border-red-500 transition-colors text-left"
                  >
                    <Shield className="text-red-500 mb-2" size={24} />
                    <h4 className="text-white font-semibold">Manage Firewall</h4>
                    <p className="text-gray-400 text-sm">Configure firewall rules and policies</p>
                  </button>

                  <button
                    onClick={() => setActiveTab('ids')}
                    className="p-4 bg-cyber-dark border border-red-700/20 rounded-lg hover:border-red-500 transition-colors text-left"
                  >
                    <AlertTriangle className="text-red-500 mb-2" size={24} />
                    <h4 className="text-white font-semibold">View Alerts</h4>
                    <p className="text-gray-400 text-sm">Monitor IDS/IPS alerts and threats</p>
                  </button>

                  <button
                    onClick={() => setActiveTab('vpn')}
                    className="p-4 bg-cyber-dark border border-red-700/20 rounded-lg hover:border-red-500 transition-colors text-left"
                  >
                    <Wifi className="text-red-500 mb-2" size={24} />
                    <h4 className="text-white font-semibold">VPN Management</h4>
                    <p className="text-gray-400 text-sm">Monitor VPN connections and users</p>
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'firewall' && (
            <div>
              <h2 className="text-2xl font-bold text-white mb-6">Firewall Management</h2>
              <p className="text-gray-400 mb-6">
                Manage firewall rules, policies, and traffic control. Configure inbound/outbound rules,
                port filtering, and IP-based access controls.
              </p>
              <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-4">
                <p className="text-center text-gray-400">
                  Firewall management interface will be implemented here
                </p>
              </div>
            </div>
          )}

          {activeTab === 'ids' && (
            <div>
              <h2 className="text-2xl font-bold text-white mb-6">IDS/IPS Monitoring</h2>
              <p className="text-gray-400 mb-6">
                Monitor intrusion detection and prevention system alerts. View threat intelligence,
                analyze attack patterns, and manage security incidents.
              </p>
              <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-4">
                <p className="text-center text-gray-400">
                  IDS/IPS monitoring interface will be implemented here
                </p>
              </div>
            </div>
          )}

          {activeTab === 'vpn' && (
            <div>
              <h2 className="text-2xl font-bold text-white mb-6">VPN Management</h2>
              <p className="text-gray-400 mb-6">
                Monitor VPN connections, manage user access, and configure secure remote access policies.
              </p>
              <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-4">
                <p className="text-center text-gray-400">
                  VPN management interface will be implemented here
                </p>
              </div>
            </div>
          )}

          {activeTab === 'nac' && (
            <div>
              <h2 className="text-2xl font-bold text-white mb-6">Network Access Control (NAC)</h2>
              <p className="text-gray-400 mb-6">
                Configure network access policies, device compliance requirements, and user access controls.
              </p>
              <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-4">
                <p className="text-center text-gray-400">
                  NAC management interface will be implemented here
                </p>
              </div>
            </div>
          )}

          {activeTab === 'dns' && (
            <div>
              <h2 className="text-2xl font-bold text-white mb-6">DNS Security</h2>
              <p className="text-gray-400 mb-6">
                Manage DNS blacklists, whitelists, and monitor DNS traffic for malicious domains.
              </p>
              <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-4">
                <p className="text-center text-gray-400">
                  DNS security interface will be implemented here
                </p>
              </div>
            </div>
          )}

          {activeTab === 'segments' && (
            <div>
              <h2 className="text-2xl font-bold text-white mb-6">Network Segmentation</h2>
              <p className="text-gray-400 mb-6">
                Configure network segments, VLANs, and isolation policies for different departments and security levels.
              </p>
              <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-4">
                <p className="text-center text-gray-400">
                  Network segmentation interface will be implemented here
                </p>
              </div>
            </div>
          )}

          {activeTab === 'monitoring' && (
            <div>
              <h2 className="text-2xl font-bold text-white mb-6">Network Monitoring</h2>
              <p className="text-gray-400 mb-6">
                Real-time network traffic analysis, bandwidth monitoring, and performance metrics.
              </p>
              <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-4">
                <p className="text-center text-gray-400">
                  Network monitoring interface will be implemented here
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default NetworkSecurity; 