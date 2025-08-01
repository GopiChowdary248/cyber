import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { 
  Shield, 
  Monitor, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Activity, 
  Users, 
  FileText,
  Search,
  Play,
  Square,
  Settings,
  BarChart3,
  Clock,
  Zap
} from 'lucide-react';

interface Endpoint {
  id: string;
  hostname: string;
  ip_address: string;
  mac_address: string;
  os_type: string;
  os_version: string;
  status: string;
  last_seen: string;
  antivirus_version: string;
  edr_version: string;
  compliance_score: number;
  risk_score: number;
  installed_apps: string[];
  running_processes: string[];
  network_connections: string[];
}

interface AntivirusScan {
  id: string;
  endpoint_id: string;
  scan_type: string;
  status: string;
  files_scanned: number;
  threats_found: number;
  scan_duration: number;
  started_at: string;
  completed_at?: string;
  scan_path: string;
  results: any;
}

interface EDRAlert {
  id: string;
  endpoint_id: string;
  alert_type: string;
  severity: string;
  title: string;
  description: string;
  timestamp: string;
  process_name: string;
  process_path: string;
  parent_process: string;
  command_line: string;
  network_connections: string[];
  file_operations: string[];
  registry_changes: string[];
  status: string;
  ioc_indicators: string[];
}

interface WhitelistEntry {
  id: string;
  name: string;
  path: string;
  hash: string;
  publisher: string;
  action: string;
  created_at: string;
  created_by: string;
  is_active: boolean;
  description: string;
}

interface EndpointSecuritySummary {
  total_endpoints: number;
  online_endpoints: number;
  quarantined_endpoints: number;
  total_scans: number;
  completed_scans: number;
  total_alerts: number;
  new_alerts: number;
  critical_alerts: number;
  avg_compliance_score: number;
  avg_risk_score: number;
  whitelist_entries: number;
  blacklist_entries: number;
}

const EndpointSecurity: React.FC = () => {
  const { user } = useAuth();
  const [summary, setSummary] = useState<EndpointSecuritySummary | null>(null);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [scans, setScans] = useState<AntivirusScan[]>([]);
  const [alerts, setAlerts] = useState<EDRAlert[]>([]);
  const [whitelist, setWhitelist] = useState<WhitelistEntry[]>([]);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [selectedEndpoint, setSelectedEndpoint] = useState<string | null>(null);

  useEffect(() => {
    fetchEndpointData();
  }, []);

  const fetchEndpointData = async () => {
    try {
      setLoading(true);
      
      // Fetch summary
      const summaryResponse = await fetch('/api/v1/endpoint-security/summary', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      const summaryData = await summaryResponse.json();
      setSummary(summaryData);

      // Fetch endpoints
      const endpointsResponse = await fetch('/api/v1/endpoint-security/endpoints', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      const endpointsData = await endpointsResponse.json();
      setEndpoints(endpointsData);

      // Fetch recent scans
      if (endpointsData.length > 0) {
        const scansResponse = await fetch(`/api/v1/endpoint-security/antivirus/endpoint/${endpointsData[0].id}/scans`, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          }
        });
        const scansData = await scansResponse.json();
        setScans(scansData.slice(0, 5)); // Show last 5 scans
      }

      // Fetch recent alerts
      const alertsResponse = await fetch('/api/v1/endpoint-security/edr/alerts', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      const alertsData = await alertsResponse.json();
      setAlerts(alertsData.slice(0, 10)); // Show last 10 alerts

      // Fetch whitelist entries
      const whitelistResponse = await fetch('/api/v1/endpoint-security/whitelist', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      const whitelistData = await whitelistResponse.json();
      setWhitelist(whitelistData);

    } catch (error) {
      console.error('Error fetching endpoint data:', error);
    } finally {
      setLoading(false);
    }
  };

  const startScan = async (endpointId: string, scanType: string = 'quick') => {
    try {
      const response = await fetch('/api/v1/endpoint-security/antivirus/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          endpoint_id: endpointId,
          scan_type: scanType,
          scan_path: 'C:\\'
        })
      });
      
      if (response.ok) {
        // Refresh data after starting scan
        setTimeout(fetchEndpointData, 2000);
      }
    } catch (error) {
      console.error('Error starting scan:', error);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'text-green-500';
      case 'offline': return 'text-red-500';
      case 'quarantined': return 'text-yellow-500';
      case 'compromised': return 'text-red-600';
      default: return 'text-gray-500';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-red-500 bg-red-50';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getScanStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-500';
      case 'scanning': return 'text-blue-500';
      case 'pending': return 'text-yellow-500';
      case 'failed': return 'text-red-500';
      default: return 'text-gray-500';
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
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2 flex items-center">
          <Shield className="mr-3 text-red-500" size={32} />
          Endpoint Security
        </h1>
        <p className="text-gray-400">Comprehensive endpoint protection and monitoring</p>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Total Endpoints</p>
                <p className="text-2xl font-bold text-white">{summary.total_endpoints}</p>
              </div>
              <Users className="text-red-500" size={24} />
            </div>
            <div className="mt-2">
              <span className="text-green-500 text-sm">{summary.online_endpoints} online</span>
            </div>
          </div>

          <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Active Alerts</p>
                <p className="text-2xl font-bold text-white">{summary.new_alerts}</p>
              </div>
              <AlertTriangle className="text-yellow-500" size={24} />
            </div>
            <div className="mt-2">
              <span className="text-red-500 text-sm">{summary.critical_alerts} critical</span>
            </div>
          </div>

          <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Avg Compliance</p>
                <p className="text-2xl font-bold text-white">{summary.avg_compliance_score}%</p>
              </div>
              <CheckCircle className="text-green-500" size={24} />
            </div>
            <div className="mt-2">
              <span className="text-gray-400 text-sm">Risk: {summary.avg_risk_score}%</span>
            </div>
          </div>

          <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Whitelist Entries</p>
                <p className="text-2xl font-bold text-white">{summary.whitelist_entries}</p>
              </div>
              <FileText className="text-blue-500" size={24} />
            </div>
            <div className="mt-2">
              <span className="text-gray-400 text-sm">{summary.blacklist_entries} blacklisted</span>
            </div>
          </div>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="mb-6">
        <nav className="flex space-x-1 bg-cyber-dark border border-red-700/20 rounded-lg p-1">
          {[
            { id: 'overview', label: 'Overview', icon: BarChart3 },
            { id: 'endpoints', label: 'Endpoints', icon: Monitor },
            { id: 'antivirus', label: 'Antivirus', icon: Shield },
            { id: 'edr', label: 'EDR Alerts', icon: AlertTriangle },
            { id: 'whitelist', label: 'Whitelist', icon: CheckCircle }
          ].map((tab) => {
            const Icon = tab.icon;
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
                <Icon className="mr-2" size={16} />
                {tab.label}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="bg-cyber-dark border border-red-700/20 rounded-lg p-6">
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <h2 className="text-xl font-bold text-white mb-4">Endpoint Security Overview</h2>
            
            {/* Recent Activity */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <h3 className="text-lg font-semibold text-white mb-3">Recent Scans</h3>
                <div className="space-y-3">
                  {scans.slice(0, 3).map((scan) => (
                    <div key={scan.id} className="bg-cyber-dark border border-gray-700 rounded-lg p-3">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-white font-medium">{scan.scan_type} scan</p>
                          <p className="text-gray-400 text-sm">
                            {scan.files_scanned.toLocaleString()} files scanned
                          </p>
                        </div>
                        <div className="text-right">
                          <p className={`text-sm font-medium ${getScanStatusColor(scan.status)}`}>
                            {scan.status}
                          </p>
                          <p className="text-gray-400 text-xs">
                            {scan.threats_found} threats found
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h3 className="text-lg font-semibold text-white mb-3">Recent Alerts</h3>
                <div className="space-y-3">
                  {alerts.slice(0, 3).map((alert) => (
                    <div key={alert.id} className="bg-cyber-dark border border-gray-700 rounded-lg p-3">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-white font-medium">{alert.title}</p>
                          <p className="text-gray-400 text-sm">{alert.process_name}</p>
                        </div>
                        <div className="text-right">
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(alert.severity)}`}>
                            {alert.severity}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'endpoints' && (
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-white">Managed Endpoints</h2>
              <button className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg flex items-center">
                <Users className="mr-2" size={16} />
                Add Endpoint
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-4">Hostname</th>
                    <th className="text-left py-3 px-4">IP Address</th>
                    <th className="text-left py-3 px-4">OS</th>
                    <th className="text-left py-3 px-4">Status</th>
                    <th className="text-left py-3 px-4">Compliance</th>
                    <th className="text-left py-3 px-4">Risk Score</th>
                    <th className="text-left py-3 px-4">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {endpoints.map((endpoint) => (
                    <tr key={endpoint.id} className="border-b border-gray-800">
                      <td className="py-3 px-4">
                        <div>
                          <p className="text-white font-medium">{endpoint.hostname}</p>
                          <p className="text-gray-400 text-xs">{endpoint.mac_address}</p>
                        </div>
                      </td>
                      <td className="py-3 px-4 text-gray-300">{endpoint.ip_address}</td>
                      <td className="py-3 px-4 text-gray-300">
                        {endpoint.os_type} {endpoint.os_version}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(endpoint.status)}`}>
                          {endpoint.status}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center">
                          <div className="w-16 bg-gray-700 rounded-full h-2 mr-2">
                            <div 
                              className="bg-green-500 h-2 rounded-full" 
                              style={{ width: `${endpoint.compliance_score}%` }}
                            ></div>
                          </div>
                          <span className="text-gray-300">{endpoint.compliance_score}%</span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center">
                          <div className="w-16 bg-gray-700 rounded-full h-2 mr-2">
                            <div 
                              className="bg-red-500 h-2 rounded-full" 
                              style={{ width: `${endpoint.risk_score}%` }}
                            ></div>
                          </div>
                          <span className="text-gray-300">{endpoint.risk_score}%</span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex space-x-2">
                          <button
                            onClick={() => startScan(endpoint.id, 'quick')}
                            className="text-blue-400 hover:text-blue-300"
                            title="Quick Scan"
                          >
                            <Zap size={16} />
                          </button>
                          <button
                            onClick={() => startScan(endpoint.id, 'full')}
                            className="text-green-400 hover:text-green-300"
                            title="Full Scan"
                          >
                            <Search size={16} />
                          </button>
                          <button className="text-gray-400 hover:text-gray-300" title="Details">
                            <Settings size={16} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'antivirus' && (
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-white">Antivirus Scans</h2>
              <div className="flex space-x-2">
                <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center">
                  <Play className="mr-2" size={16} />
                  Quick Scan All
                </button>
                <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg flex items-center">
                  <Search className="mr-2" size={16} />
                  Full Scan All
                </button>
              </div>
            </div>

            <div className="space-y-4">
              {scans.map((scan) => (
                <div key={scan.id} className="bg-cyber-dark border border-gray-700 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center space-x-3">
                        <h3 className="text-white font-medium">{scan.scan_type} Scan</h3>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getScanStatusColor(scan.status)}`}>
                          {scan.status}
                        </span>
                      </div>
                      <p className="text-gray-400 text-sm mt-1">
                        Path: {scan.scan_path} | Duration: {scan.scan_duration}s
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-white font-medium">{scan.files_scanned.toLocaleString()} files</p>
                      <p className="text-red-500 text-sm">{scan.threats_found} threats found</p>
                    </div>
                  </div>
                  {scan.results && (
                    <div className="mt-3 pt-3 border-t border-gray-700">
                      <p className="text-gray-400 text-sm">{scan.results.scan_summary}</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'edr' && (
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-white">EDR Alerts</h2>
              <div className="flex space-x-2">
                <select className="bg-cyber-dark border border-gray-700 rounded-lg px-3 py-2 text-white">
                  <option>All Severities</option>
                  <option>Critical</option>
                  <option>High</option>
                  <option>Medium</option>
                  <option>Low</option>
                </select>
                <select className="bg-cyber-dark border border-gray-700 rounded-lg px-3 py-2 text-white">
                  <option>All Status</option>
                  <option>New</option>
                  <option>Investigating</option>
                  <option>Resolved</option>
                </select>
              </div>
            </div>

            <div className="space-y-4">
              {alerts.map((alert) => (
                <div key={alert.id} className="bg-cyber-dark border border-gray-700 rounded-lg p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <h3 className="text-white font-medium">{alert.title}</h3>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(alert.severity)}`}>
                          {alert.severity}
                        </span>
                        <span className="px-2 py-1 rounded text-xs font-medium bg-gray-600 text-gray-200">
                          {alert.status}
                        </span>
                      </div>
                      <p className="text-gray-400 text-sm mb-3">{alert.description}</p>
                      
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                        <div>
                          <p className="text-gray-500">Process</p>
                          <p className="text-white">{alert.process_name}</p>
                        </div>
                        <div>
                          <p className="text-gray-500">Parent Process</p>
                          <p className="text-white">{alert.parent_process}</p>
                        </div>
                        <div>
                          <p className="text-gray-500">Timestamp</p>
                          <p className="text-white">{new Date(alert.timestamp).toLocaleString()}</p>
                        </div>
                      </div>

                      {alert.ioc_indicators.length > 0 && (
                        <div className="mt-3">
                          <p className="text-gray-500 text-sm mb-1">IOC Indicators:</p>
                          <div className="flex flex-wrap gap-2">
                            {alert.ioc_indicators.map((ioc, index) => (
                              <span key={index} className="px-2 py-1 bg-red-600/20 text-red-400 rounded text-xs">
                                {ioc}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'whitelist' && (
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-white">Application Whitelist</h2>
              <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg flex items-center">
                <CheckCircle className="mr-2" size={16} />
                Add Application
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-4">Application</th>
                    <th className="text-left py-3 px-4">Path</th>
                    <th className="text-left py-3 px-4">Publisher</th>
                    <th className="text-left py-3 px-4">Action</th>
                    <th className="text-left py-3 px-4">Status</th>
                    <th className="text-left py-3 px-4">Created</th>
                    <th className="text-left py-3 px-4">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {whitelist.map((entry) => (
                    <tr key={entry.id} className="border-b border-gray-800">
                      <td className="py-3 px-4">
                        <div>
                          <p className="text-white font-medium">{entry.name}</p>
                          <p className="text-gray-400 text-xs">{entry.hash.substring(0, 16)}...</p>
                        </div>
                      </td>
                      <td className="py-3 px-4 text-gray-300 text-xs">{entry.path}</td>
                      <td className="py-3 px-4 text-gray-300">{entry.publisher}</td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                          entry.action === 'allow' ? 'bg-green-600/20 text-green-400' : 'bg-red-600/20 text-red-400'
                        }`}>
                          {entry.action}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                          entry.is_active ? 'bg-green-600/20 text-green-400' : 'bg-gray-600/20 text-gray-400'
                        }`}>
                          {entry.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-gray-300 text-xs">
                        {new Date(entry.created_at).toLocaleDateString()}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex space-x-2">
                          <button className="text-blue-400 hover:text-blue-300" title="Edit">
                            <Settings size={16} />
                          </button>
                          <button className="text-red-400 hover:text-red-300" title="Remove">
                            <XCircle size={16} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default EndpointSecurity; 